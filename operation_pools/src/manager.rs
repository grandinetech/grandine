use core::time::Duration;
use std::sync::Arc;

use anyhow::Result;
use fork_choice_control::{PoolMessage, Wait};
use futures::{StreamExt as _, channel::mpsc::UnboundedReceiver};
use tokio::select;
use tokio_stream::wrappers::IntervalStream;
use types::preset::Preset;

use crate::{
    AttestationAggPool, BlobReconstructionPool, BlsToExecutionChangePool, SyncCommitteeAggPool,
};

const RECONSTRUCTION_START_DELAY_SYNCING: Duration = Duration::from_secs(2);

pub struct Manager<P: Preset, W: Wait> {
    pub attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    pub blob_reconstruction_pool: BlobReconstructionPool<P, W>,
    pub bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
    pub sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    pub fork_choice_to_pool_rx: UnboundedReceiver<PoolMessage<P, W>>,
    pub reconstruction_delay: Duration,
}

impl<P: Preset, W: Wait> Manager<P, W> {
    #[must_use]
    pub const fn new(
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        blob_reconstruction_pool: BlobReconstructionPool<P, W>,
        bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
        fork_choice_to_pool_rx: UnboundedReceiver<PoolMessage<P, W>>,
        reconstruction_delay: Duration,
    ) -> Self {
        Self {
            attestation_agg_pool,
            blob_reconstruction_pool,
            bls_to_execution_change_pool,
            sync_committee_agg_pool,
            fork_choice_to_pool_rx,
            reconstruction_delay,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let mut interval =
            IntervalStream::new(tokio::time::interval(Duration::from_millis(100))).fuse();

        loop {
            select! {
                _ = interval.select_next_some() => {
                    self.blob_reconstruction_pool.perform_scheduled_reconstructions();
                },

                message = self.fork_choice_to_pool_rx.select_next_some() => {
                    match message {
                        PoolMessage::Slot(slot) => self.sync_committee_agg_pool.on_slot(slot),
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
                            block,
                            origin,
                            slot,
                        } => {
                            // We don't want to reconstruct blobs on each block during sync
                            // if it downloads data columns relatively fast
                            let delay = if origin.is_requested() {
                                RECONSTRUCTION_START_DELAY_SYNCING
                            } else {
                                self.reconstruction_delay
                            };

                            self.blob_reconstruction_pool
                                .schedule_reconstruction(wait_group, block_root, block, slot, delay);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
