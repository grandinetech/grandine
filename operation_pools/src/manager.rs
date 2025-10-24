use std::sync::Arc;

use anyhow::Result;
use fork_choice_control::{PoolMessage, Wait};
use futures::{channel::mpsc::UnboundedReceiver, StreamExt as _};
use types::preset::Preset;

use crate::{
    AttestationAggPool, BlobReconstructionPool, BlsToExecutionChangePool,
    PayloadAttestationAggPool, SyncCommitteeAggPool,
};

pub struct Manager<P: Preset, W: Wait> {
    pub attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    pub blob_reconstruction_pool: BlobReconstructionPool<P, W>,
    pub bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
    pub payload_attestation_agg_pool: Arc<PayloadAttestationAggPool<P, W>>,
    pub sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    pub fork_choice_to_pool_rx: UnboundedReceiver<PoolMessage<W>>,
}

impl<P: Preset, W: Wait> Manager<P, W> {
    #[must_use]
    pub const fn new(
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        blob_reconstruction_pool: BlobReconstructionPool<P, W>,
        bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
        payload_attestation_agg_pool: Arc<PayloadAttestationAggPool<P, W>>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
        fork_choice_to_pool_rx: UnboundedReceiver<PoolMessage<W>>,
    ) -> Self {
        Self {
            attestation_agg_pool,
            blob_reconstruction_pool,
            bls_to_execution_change_pool,
            payload_attestation_agg_pool,
            sync_committee_agg_pool,
            fork_choice_to_pool_rx,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        while let Some(message) = self.fork_choice_to_pool_rx.next().await {
            match message {
                PoolMessage::Slot(slot) => {
                    self.sync_committee_agg_pool.on_slot(slot);
                    self.payload_attestation_agg_pool.on_slot(slot);
                }
                PoolMessage::Tick(tick) => {
                    if tick.is_start_of_epoch::<P>() {
                        self.bls_to_execution_change_pool
                            .discard_old_bls_to_execution_changes();
                    }

                    self.attestation_agg_pool.on_tick(tick).await
                }
                PoolMessage::Stop => {
                    self.bls_to_execution_change_pool.stop();

                    break;
                }
                PoolMessage::ReconstructDataColumns {
                    wait_group,
                    block_root,
                    slot,
                } => {
                    self.blob_reconstruction_pool
                        .spawn_reconstruction(wait_group, block_root, slot);
                }
            }
        }

        Ok(())
    }
}
