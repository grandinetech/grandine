use std::sync::Arc;

use anyhow::Result;
use fork_choice_control::{PoolMessage, Wait};
use futures::{channel::mpsc::UnboundedReceiver, StreamExt as _};
use types::preset::Preset;

use crate::{AttestationAggPool, BlsToExecutionChangePool, SyncCommitteeAggPool};

pub struct Manager<P: Preset, W: Wait> {
    pub attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    pub bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
    pub sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    pub fork_choice_to_pool_rx: UnboundedReceiver<PoolMessage>,
}

impl<P: Preset, W: Wait> Manager<P, W> {
    #[must_use]
    pub const fn new(
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
        fork_choice_to_pool_rx: UnboundedReceiver<PoolMessage>,
    ) -> Self {
        Self {
            attestation_agg_pool,
            bls_to_execution_change_pool,
            sync_committee_agg_pool,
            fork_choice_to_pool_rx,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        while let Some(message) = self.fork_choice_to_pool_rx.next().await {
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
            }
        }

        Ok(())
    }
}
