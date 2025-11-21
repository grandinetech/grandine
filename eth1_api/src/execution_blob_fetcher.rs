use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use dashmap::DashMap;
use eth2_libp2p::PeerId;
use execution_engine::{
    BlobAndProofV1, BlobAndProofV2, BlockOrDataColumnSidecar, EngineGetBlobsParams,
    EngineGetBlobsV1Params, EngineGetBlobsV2Params,
};
use fork_choice_control::Wait;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    StreamExt as _,
};
use helper_functions::misc;
use logging::{debug_with_peers, warn_with_peers};
use prometheus_metrics::Metrics;
use ssz::ContiguousList;
use std_ext::ArcExt as _;
use types::{
    combined::SignedBeaconBlock,
    deneb::{containers::BlobIdentifier, primitives::BlobIndex},
    fulu::{
        containers::{DataColumnIdentifier, DataColumnsByRootIdentifier},
        primitives::ColumnIndex,
    },
    phase0::primitives::Slot,
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::{
    messages::{BlobFetcherToP2p, Eth1ApiToBlobFetcher},
    ApiController, Eth1Api,
};

pub struct ExecutionBlobFetcher<P: Preset, W: Wait> {
    api: Arc<Eth1Api>,
    controller: ApiController<P, W>,
    received_blob_sidecars: Arc<DashMap<BlobIdentifier, Slot>>,
    received_data_column_sidecars: Arc<DashMap<DataColumnIdentifier, Slot>>,
    metrics: Option<Arc<Metrics>>,
    p2p_tx: UnboundedSender<BlobFetcherToP2p<P>>,
    rx: UnboundedReceiver<Eth1ApiToBlobFetcher<P>>,
}

impl<P: Preset, W: Wait> ExecutionBlobFetcher<P, W> {
    pub const fn new(
        api: Arc<Eth1Api>,
        controller: ApiController<P, W>,
        received_blob_sidecars: Arc<DashMap<BlobIdentifier, Slot>>,
        received_data_column_sidecars: Arc<DashMap<DataColumnIdentifier, Slot>>,
        metrics: Option<Arc<Metrics>>,
        p2p_tx: UnboundedSender<BlobFetcherToP2p<P>>,
        rx: UnboundedReceiver<Eth1ApiToBlobFetcher<P>>,
    ) -> Self {
        Self {
            api,
            controller,
            received_blob_sidecars,
            received_data_column_sidecars,
            metrics,
            p2p_tx,
            rx,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        while let Some(message) = self.rx.next().await {
            match message {
                Eth1ApiToBlobFetcher::GetBlobs(params) => match params {
                    EngineGetBlobsParams::V1(EngineGetBlobsV1Params {
                        block,
                        blob_identifiers,
                        peer_id,
                    }) => self.get_blobs_v1(block, blob_identifiers, peer_id).await,
                    EngineGetBlobsParams::V2(EngineGetBlobsV2Params {
                        block_or_sidecar,
                        data_column_identifiers,
                    }) => {
                        self.get_blobs_v2(block_or_sidecar, data_column_identifiers)
                            .await
                    }
                },
                Eth1ApiToBlobFetcher::Stop => break,
            }
        }

        Ok(())
    }

    async fn get_blobs_v1(
        &self,
        block: Arc<SignedBeaconBlock<P>>,
        blob_identifiers: Vec<BlobIdentifier>,
        peer_id: Option<PeerId>,
    ) {
        let slot = block.message().slot();
        let block_root = block.message().hash_tree_root();

        if self.controller.contains_block(block_root) {
            debug_with_peers!("cannot fetch blobs from EL: block has been imported");
            return;
        }

        if let Some(body) = block.message().body().with_blob_kzg_commitments() {
            let missing_blob_indices = blob_identifiers
                .iter()
                .filter(|identifier| !self.received_blob_sidecars.contains_key(identifier))
                .map(|identifier| identifier.index)
                .collect::<HashSet<BlobIndex>>();

            let kzg_commitments = body
                .blob_kzg_commitments()
                .iter()
                .zip(0..)
                .filter(|(_, index)| missing_blob_indices.contains(index))
                .collect::<Vec<_>>();

            if kzg_commitments.is_empty() {
                debug_with_peers!(
                    "cannot fetch blobs from EL: all requested blob sidecars have been received"
                );
                return;
            }

            if self.controller.is_forward_synced()
                && !self.controller.store_config().disable_engine_getblobs
            {
                let versioned_hashes = kzg_commitments
                    .iter()
                    .copied()
                    .map(|(commitment, _)| misc::kzg_commitment_to_versioned_hash(*commitment))
                    .collect();

                let mut blob_sidecars = vec![];

                match self.api.get_blobs_v1::<P>(versioned_hashes).await {
                    Ok(blobs_and_proofs) => {
                        let block_header = block.to_header();

                        for (blob_and_proof, kzg_commitment, index) in blobs_and_proofs
                            .into_iter()
                            .zip(kzg_commitments.into_iter())
                            .filter_map(|(blob_and_proof, (kzg_commitment, index))| {
                                blob_and_proof
                                    .map(|blob_and_proof| (blob_and_proof, kzg_commitment, index))
                            })
                        {
                            let BlobAndProofV1 { blob, proof } = blob_and_proof;
                            let blob_identifier = BlobIdentifier { block_root, index };

                            if self.received_blob_sidecars.contains_key(&blob_identifier) {
                                debug_with_peers!(
                                    "received blob from EL is already known: {blob_identifier:?}, \
                                     slot: {slot}"
                                );
                            } else {
                                match misc::construct_blob_sidecar(
                                    &block,
                                    block_header,
                                    index,
                                    blob,
                                    *kzg_commitment,
                                    proof,
                                ) {
                                    Ok(blob_sidecar) => {
                                        debug_with_peers!(
                                            "received blob sidecar from EL: {blob_identifier:?}, \
                                             slot: {slot}"
                                        );

                                        // Record all blob_sidecars as received first and push to controller
                                        // on a second pass to avoid spawning extra `engine_getBlobs` calls.
                                        self.received_blob_sidecars.insert(blob_identifier, slot);
                                        blob_sidecars.push(Arc::new(blob_sidecar));
                                    }
                                    Err(error) => warn_with_peers!(
                                        "failed to construct blob sidecar with blob and proof \
                                         received from execution layer: {error:?}"
                                    ),
                                }
                            }
                        }
                    }
                    Err(error) => warn_with_peers!("engine_getBlobsV1 call failed: {error}"),
                }

                for blob_sidecar in blob_sidecars {
                    self.controller.on_el_blob_sidecar(blob_sidecar);
                }
            }

            // Request remaining missing blob sidecars from P2P
            let missing_blob_identifiers = missing_blob_indices
                .into_iter()
                .filter_map(|index| {
                    let identifier = BlobIdentifier { block_root, index };
                    (!self.received_blob_sidecars.contains_key(&identifier)).then_some(identifier)
                })
                .collect::<Vec<_>>();

            debug_with_peers!("missing blob sidecars after EL: {missing_blob_identifiers:?}");

            if !missing_blob_identifiers.is_empty() {
                BlobFetcherToP2p::BlobsNeeded(missing_blob_identifiers, slot, peer_id)
                    .send(&self.p2p_tx);
            }
        }
    }

    #[expect(clippy::too_many_lines)]
    async fn get_blobs_v2(
        &self,
        block_or_sidecar: BlockOrDataColumnSidecar<P>,
        data_column_identifiers: Vec<DataColumnIdentifier>,
    ) {
        let slot = block_or_sidecar.slot();
        let block_root = block_or_sidecar.block_root();

        if self.controller.contains_block(block_root)
            || self
                .controller
                .is_sidecars_construction_started(&block_root)
        {
            debug_with_peers!(
                "cannot fetch blobs from EL: block has been imported, or is being imported"
            );
            return;
        }

        let Some(kzg_commitments) = block_or_sidecar.kzg_commitments() else {
            return;
        };

        let missing_columns_indices = data_column_identifiers
            .iter()
            .filter(|identifier| !self.received_data_column_sidecars.contains_key(identifier))
            .map(|identifier| identifier.index)
            .collect::<HashSet<ColumnIndex>>();

        if missing_columns_indices.is_empty() {
            debug_with_peers!(
                "cannot fetch blobs from EL: all missing data column sidecars have been received"
            );
            return;
        }

        if self.controller.is_forward_synced()
            && !self.controller.store_config().disable_engine_getblobs
        {
            let request_timer = self
                .metrics
                .as_ref()
                .map(|metrics| metrics.engine_get_blobs_v2_request_time.start_timer());

            if let Some(metrics) = self.metrics.as_ref() {
                metrics.engine_get_blobs_v2_requests_count.inc();
            }

            let expected_blobs_count = kzg_commitments.len();
            let versioned_hashes = kzg_commitments
                .iter()
                .copied()
                .map(misc::kzg_commitment_to_versioned_hash)
                .collect::<Vec<_>>();

            match self.api.get_blobs_v2::<P>(versioned_hashes).await {
                Ok(blobs_and_proofs_opt) => {
                    prometheus_metrics::stop_and_record(request_timer);

                    if let Some(blobs_and_proofs) = blobs_and_proofs_opt {
                        if blobs_and_proofs.len() == expected_blobs_count {
                            if let Some(metrics) = self.metrics.as_ref() {
                                metrics.engine_get_blobs_v2_responses_count.inc();
                            }

                            let (received_blobs, received_proofs): (Vec<_>, Vec<_>) =
                                blobs_and_proofs
                                    .into_iter()
                                    .map(|BlobAndProofV2 { blob, proofs }| (blob, proofs))
                                    .unzip();

                            debug_with_peers!(
                                "received all {expected_blobs_count} blob sidecars from EL at slot: {slot}",
                            );

                            let cells_proofs = received_proofs
                                .into_iter()
                                .flat_map(IntoIterator::into_iter)
                                .collect::<Vec<_>>();

                            let timer = self.metrics.as_ref().map(|metrics| {
                                metrics.data_column_sidecar_computation.start_timer()
                            });

                            let controller = self.controller.clone_arc();

                            let received_data_column_sidecars =
                                self.received_data_column_sidecars.clone_arc();

                            let reconstruction_result = tokio::task::spawn_blocking(move || {
                                let mut data_column_sidecars = vec![];

                                match eip_7594::try_convert_to_cells_and_kzg_proofs::<P>(
                                    &received_blobs,
                                    &cells_proofs,
                                    controller.store_config().kzg_backend,
                                ) {
                                    Ok(cells_and_kzg_proofs) => {
                                        let result = match block_or_sidecar {
                                            BlockOrDataColumnSidecar::Block(block) => eip_7594::construct_data_column_sidecars(
                                                &block,
                                                &cells_and_kzg_proofs,
                                            ),
                                            BlockOrDataColumnSidecar::Sidecar(sidecar) => eip_7594::construct_data_column_sidecars_from_sidecar(
                                                &sidecar,
                                                &cells_and_kzg_proofs,
                                            ),
                                        };

                                        prometheus_metrics::stop_and_record(timer);

                                        match result {
                                            Ok(data_columns) => {
                                                controller.mark_sidecar_construction_started(block_root, slot);

                                                for data_column_sidecar in
                                                    data_columns.into_iter().filter(|column| {
                                                        controller
                                                            .sampling_columns()
                                                            .contains(&column.index)
                                                    })
                                                {
                                                    let identifier = DataColumnIdentifier {
                                                        block_root,
                                                        index: data_column_sidecar.index,
                                                    };

                                                    received_data_column_sidecars.insert(identifier, slot);
                                                    data_column_sidecars.push(data_column_sidecar);
                                                }
                                            }
                                            Err(error) => {
                                                controller.mark_sidecar_construction_failed(&block_root);

                                                warn_with_peers!(
                                                    "failed to construct data column sidecars with \
                                                    cells and kzg proofs: {error:?}"
                                                );
                                            }
                                        }
                                    }
                                    Err(error) => warn_with_peers!(
                                        "failed to convert blobs received from EL into extended cells: {error:?}"
                                    ),
                                }

                                data_column_sidecars
                            }).await;

                            match reconstruction_result {
                                Ok(data_column_sidecars) => {
                                    for data_column_sidecar in data_column_sidecars {
                                        self.controller
                                            .on_el_data_column_sidecar(data_column_sidecar);
                                    }
                                }
                                Err(error) => {
                                    warn_with_peers!("failed to reconstruct data columns from EL response: {error:?}")
                                }
                            }
                        } else {
                            warn_with_peers!(
                                "EL must response all blobs or null (expected: {}, got: {})",
                                expected_blobs_count,
                                blobs_and_proofs.len(),
                            );
                        }
                    } else {
                        debug_with_peers!("EL doesn't has all blobs to response back",);
                    }
                }
                Err(error) => warn_with_peers!("engine_getBlobsV2 call failed: {error}"),
            }
        }

        if !self
            .controller
            .is_sidecars_construction_started(&block_root)
        {
            // Request remaining missing data column sidecars from P2P
            let missing_indices = missing_columns_indices
                .into_iter()
                .filter(|index| {
                    !self
                        .received_data_column_sidecars
                        .contains_key(&DataColumnIdentifier {
                            block_root,
                            index: *index,
                        })
                })
                .collect::<Vec<_>>();

            debug_with_peers!(
                "missing data columns sidecars: {missing_indices:?} at block {block_root}"
            );

            if !missing_indices.is_empty() {
                let columns = ContiguousList::try_from(missing_indices)
                    .expect("missing column indices must not be more than NUMBER_OF_COLUMNS");

                BlobFetcherToP2p::DataColumnsNeeded(
                    DataColumnsByRootIdentifier {
                        block_root,
                        columns,
                    },
                    slot,
                )
                .send(&self.p2p_tx);
            }
        }
    }
}
