use std::sync::Arc;

use dedicated_executor::DedicatedExecutor;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use types::{
    combined::SignedBeaconBlock,
    phase0::primitives::{Slot, H256},
    preset::Preset,
};

use crate::{blob_reconstruction_pool::tasks::ReconstructDataColumnSidecarsTask, misc::PoolTask};

pub struct Manager<P: Preset, W: Wait> {
    controller: ApiController<P, W>,
    dedicated_executor: DedicatedExecutor,
    metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> Manager<P, W> {
    #[must_use]
    pub const fn new(
        controller: ApiController<P, W>,
        dedicated_executor: DedicatedExecutor,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self {
            controller,
            dedicated_executor,
            metrics,
        }
    }

    pub fn spawn_reconstruction(
        &self,
        wait_group: W,
        block_root: H256,
        block: Arc<SignedBeaconBlock<P>>,
        slot: Slot,
    ) {
        self.controller
            .mark_sidecar_construction_started(block_root, slot);

        self.spawn_detached(ReconstructDataColumnSidecarsTask {
            controller: self.controller.clone_arc(),
            wait_group,
            block_root,
            block,
            metrics: self.metrics.clone(),
        })
    }

    fn spawn_detached(&self, task: impl PoolTask) {
        self.dedicated_executor.spawn(task.run()).detach()
    }
}
