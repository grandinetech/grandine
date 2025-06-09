use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use dashmap::DashMap;
use derive_more::derive::Constructor;
use eth2_libp2p::PeerId;
use execution_engine::{BlobAndProofV1, BlobAndProofV2, EngineGetBlobsParams};
use fork_choice_control::Wait;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    StreamExt as _,
};
use helper_functions::misc;
use log::{debug, warn};
use ssz::{ContiguousList, ContiguousVector, H256};
use try_from_iterator::TryFromIterator as _;
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

#[derive(Constructor)]
pub struct ExecutionBlobFetcher<P: Preset, W: Wait> {
    api: Arc<Eth1Api>,
    controller: ApiController<P, W>,
    received_blob_sidecars: Arc<DashMap<BlobIdentifier, Slot>>,
    received_data_column_sidecars: Arc<DashMap<DataColumnIdentifier, Slot>>,
    sidecars_construction_started: Arc<DashMap<H256, Slot>>,
    p2p_tx: UnboundedSender<BlobFetcherToP2p>,
    rx: UnboundedReceiver<Eth1ApiToBlobFetcher<P>>,
}

impl<P: Preset, W: Wait> ExecutionBlobFetcher<P, W> {
    pub async fn run(mut self) -> Result<()> {
        while let Some(message) = self.rx.next().await {
            match message {
                Eth1ApiToBlobFetcher::GetBlobs {
                    block,
                    params,
                    peer_id,
                } => match params {
                    EngineGetBlobsParams::Blobs(blob_identifiers) => {
                        self.get_blobs_v1(block, blob_identifiers, peer_id).await
                    }
                    EngineGetBlobsParams::DataColumns(identifiers) => {
                        self.get_blobs_v2(block, identifiers, peer_id).await
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
            debug!("cannot fetch blobs from EL: block has been imported");
            return;
        }

        if let Some(body) = block.message().body().post_deneb() {
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
                debug!(
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
                                debug!(
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
                                        debug!(
                                            "received blob sidecar from EL: {blob_identifier:?}, \
                                             slot: {slot}"
                                        );

                                        // Record all blob_sidecars as received first and push to controller
                                        // on a second pass to avoid spawning extra `engine_getBlobs` calls.
                                        self.received_blob_sidecars.insert(blob_identifier, slot);
                                        blob_sidecars.push(Arc::new(blob_sidecar));
                                    }
                                    Err(error) => warn!(
                                        "failed to construct blob sidecar with blob and proof \
                                         received from execution layer: {error:?}"
                                    ),
                                }
                            }
                        }
                    }
                    Err(error) => warn!("engine_getBlobsV1 call failed: {error}"),
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

            debug!("missing blob sidecars after EL: {missing_blob_identifiers:?}");

            if !missing_blob_identifiers.is_empty() {
                BlobFetcherToP2p::BlobsNeeded(missing_blob_identifiers, slot, peer_id)
                    .send(&self.p2p_tx);
            }
        }
    }

    #[expect(clippy::too_many_lines)]
    async fn get_blobs_v2(
        &self,
        block: Arc<SignedBeaconBlock<P>>,
        data_column_identifiers: Vec<DataColumnIdentifier>,
        _peer_id: Option<PeerId>,
    ) {
        let slot = block.message().slot();
        let block_root = block.message().hash_tree_root();

        if self.controller.contains_block(block_root)
            || self.sidecars_construction_started.contains_key(&block_root)
        {
            debug!("cannot fetch blobs from EL: block has been imported, or being importing");
            return;
        }

        if let Some(body) = block.message().body().post_deneb() {
            let block_header = block.to_header().message;
            let missing_columns_indices = data_column_identifiers
                .iter()
                .filter(|identifier| {
                    !self
                        .controller
                        .accepted_data_column_sidecar(block_header, identifier.index)
                        || !self.received_data_column_sidecars.contains_key(identifier)
                })
                .map(|identifier| identifier.index)
                .collect::<HashSet<ColumnIndex>>();

            if missing_columns_indices.is_empty() {
                debug!(
                    "cannot fetch blobs from EL: all missing data column sidecars have been received"
                );
                return;
            }

            if self.controller.is_forward_synced()
                && !self.controller.store_config().disable_engine_getblobs
            {
                let expected_blobs_count = body.blob_kzg_commitments().len();
                let versioned_hashes = body
                    .blob_kzg_commitments()
                    .iter()
                    .copied()
                    .map(misc::kzg_commitment_to_versioned_hash)
                    .collect::<Vec<_>>();
                let mut data_column_sidecars = vec![];

                match self.api.get_blobs_v2::<P>(versioned_hashes).await {
                    Ok(blobs_and_proofs_opt) => {
                        if let Some(blobs_and_proofs) = blobs_and_proofs_opt {
                            if blobs_and_proofs.len() == expected_blobs_count {
                                let (received_blobs, cells_proofs): (Vec<_>, Vec<_>) =
                                    blobs_and_proofs
                                        .into_iter()
                                        .map(|BlobAndProofV2 { blob, proofs }| (blob, proofs))
                                        .unzip();

                                debug!(
                                    "received all {expected_blobs_count} blob sidecars from EL at slot: {slot}",
                                );

                                match cells_proofs
                                    .into_iter()
                                    .map(|proofs| {
                                        ContiguousVector::try_from_iter(proofs.into_iter())
                                            .map_err(Into::into)
                                    })
                                    .collect::<Result<Vec<_>>>()
                                {
                                    Ok(ext_proofs) => {
                                        match eip_7594::try_compute_ext_cells::<P>(
                                            &received_blobs,
                                            self.controller.store_config().kzg_backend,
                                        ) {
                                            Ok(ext_cells) => {
                                                let cells_and_kzg_proofs = ext_cells
                                                    .into_iter()
                                                    .zip(ext_proofs)
                                                    .collect::<Vec<_>>();

                                                match eip_7594::construct_data_column_sidecars(
                                                    &block,
                                                    &cells_and_kzg_proofs,
                                                    self.controller.chain_config(),
                                                ) {
                                                    Ok(data_columns) => {
                                                        self.sidecars_construction_started
                                                            .insert(block_root, slot);

                                                        let sampling_columns = self
                                                            .controller
                                                            .sampling_columns()
                                                            .into_iter()
                                                            .collect::<Vec<_>>();

                                                        for data_column_sidecar in data_columns
                                                            .into_iter()
                                                            .filter(|column| {
                                                                sampling_columns
                                                                    .contains(&column.index)
                                                            })
                                                        {
                                                            let data_column_identifier =
                                                                DataColumnIdentifier {
                                                                    block_root,
                                                                    index: data_column_sidecar
                                                                        .index,
                                                                };

                                                            if self
                                                                .received_data_column_sidecars
                                                                .insert(
                                                                    data_column_identifier,
                                                                    slot,
                                                                )
                                                                .is_none()
                                                            {
                                                                data_column_sidecars.push(
                                                                    Arc::new(data_column_sidecar),
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(error) => warn!(
                                                    "failed to construct data column sidecars with \
                                                    cells and kzg proofs: {error:?}"
                                                ),
                                                }
                                            }
                                            Err(error) => warn!(
                                                "failed to convert blobs received from EL \
                                            into extended cells: {error:?}"
                                            ),
                                        }
                                    }
                                    Err(error) => warn!(
                                    "received cells proofs from EL with incorrect length: {error:?}"
                                ),
                                }
                            } else {
                                warn!(
                                    "EL must response all blobs or null (expected: {}, got: {})",
                                    expected_blobs_count,
                                    blobs_and_proofs.len(),
                                );
                            }
                        } else {
                            debug!("EL doesn't has all blobs to response back",);
                        }
                    }
                    Err(error) => warn!("engine_getBlobsV2 call failed: {error}"),
                }

                for data_column_sidecar in data_column_sidecars {
                    self.controller
                        .on_el_data_column_sidecar(data_column_sidecar);
                }
            }

            if !self.sidecars_construction_started.contains_key(&block_root) {
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

                debug!("missing data columns sidecars: {missing_indices:?} at block {block_root}");

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
}
