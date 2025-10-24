use std::sync::Arc;

use crate::{
    misc::PoolTask,
    payload_attestation_agg_pool::{
        pool::Pool,
        tasks::{AggregateOwnMessagesTask, HandleSlotTask, InsertPayloadAttestationTask},
    },
};
use dedicated_executor::DedicatedExecutor;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use prometheus_metrics::Metrics;
use std_ext::ArcExt;
use types::{
    combined::BeaconState, config::Config, gloas::containers::PayloadAttestationMessage,
    phase0::primitives::Slot, preset::Preset,
};

pub struct Manager<P: Preset, W: Wait = ()> {
    controller: ApiController<P, W>,
    dedicated_executor: Arc<DedicatedExecutor>,
    pool: Arc<Pool<P>>,
    metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> Manager<P, W> {
    #[must_use]
    pub fn new(
        controller: ApiController<P, W>,
        dedicated_executor: Arc<DedicatedExecutor>,
        metrics: Option<Arc<Metrics>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            controller,
            dedicated_executor,
            pool: Arc::new(Pool::new()),
            metrics,
        })
    }

    #[must_use]
    pub fn config(&self) -> &Arc<Config> {
        self.controller.chain_config()
    }

    pub fn on_slot(&self, slot: Slot) {
        self.spawn_detached(HandleSlotTask {
            pool: self.pool.clone_arc(),
            slot,
            metrics: self.metrics.clone(),
        });
    }

    pub fn insert_payload_attestation(
        &self,
        wait_group: W,
        payload_attestation: Arc<PayloadAttestationMessage>,
    ) {
        self.spawn_detached(InsertPayloadAttestationTask {
            wait_group,
            controller: self.controller.clone_arc(),
            pool: self.pool.clone_arc(),
            payload_attestation,
            metrics: self.metrics.clone(),
        });
    }

    pub fn aggregate_own_messages(
        &self,
        wait_group: W,
        messages: Vec<PayloadAttestationMessage>,
        beacon_state: Arc<BeaconState<P>>,
    ) {
        let Some(message) = messages.first().copied() else {
            return;
        };

        self.spawn_detached(AggregateOwnMessagesTask {
            wait_group,
            pool: self.pool.clone_arc(),
            data: message.data,
            messages,
            beacon_state,
            metrics: self.metrics.clone(),
        });
    }

    fn spawn_detached<T: PoolTask>(&self, task: T) {
        self.dedicated_executor.spawn(task.run()).detach()
    }
}
