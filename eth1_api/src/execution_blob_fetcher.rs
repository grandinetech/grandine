use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use dashmap::DashMap;
use derive_more::derive::Constructor;
use eth2_libp2p::PeerId;
use execution_engine::BlobAndProofV1;
use fork_choice_control::Wait;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    StreamExt as _,
};
use helper_functions::misc;
use logging::{debug_with_peers, warn_with_peers};
use types::{
    combined::SignedBeaconBlock,
    deneb::{containers::BlobIdentifier, primitives::BlobIndex},
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
    p2p_tx: UnboundedSender<BlobFetcherToP2p>,
    rx: UnboundedReceiver<Eth1ApiToBlobFetcher<P>>,
}

impl<P: Preset, W: Wait> ExecutionBlobFetcher<P, W> {
    pub async fn run(mut self) -> Result<()> {
        while let Some(message) = self.rx.next().await {
            match message {
                Eth1ApiToBlobFetcher::GetBlobs {
                    block,
                    blob_identifiers,
                    peer_id,
                } => {
                    self.get_blobs(block, blob_identifiers, peer_id).await;
                }
                Eth1ApiToBlobFetcher::Stop => break,
            }
        }

        Ok(())
    }

    async fn get_blobs(
        &self,
        block: Arc<SignedBeaconBlock<P>>,
        blob_identifiers: Vec<BlobIdentifier>,
        peer_id: Option<PeerId>,
    ) {
        let slot = block.message().slot();

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
                debug_with_peers!(
                    "cannot fetch blobs from EL: all requested blob sidecars have been received"
                );
                return;
            }

            let versioned_hashes = kzg_commitments
                .iter()
                .copied()
                .map(|(commitment, _)| misc::kzg_commitment_to_versioned_hash(*commitment))
                .collect();

            let mut blob_sidecars = vec![];
            let block_root = block.message().hash_tree_root();

            match self.api.get_blobs::<P>(versioned_hashes).await {
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

            // Request remaining missing blob sidecars from P2P
            let missing_blob_identifiers = blob_identifiers
                .into_iter()
                .filter(|identifier| !self.received_blob_sidecars.contains_key(identifier))
                .collect::<Vec<_>>();

            debug_with_peers!("missing blob sidecars after EL: {missing_blob_identifiers:?}");

            if !missing_blob_identifiers.is_empty() {
                BlobFetcherToP2p::BlobsNeeded(missing_blob_identifiers, slot, peer_id)
                    .send(&self.p2p_tx);
            }
        }
    }
}
