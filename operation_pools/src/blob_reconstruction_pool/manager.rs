use core::time::Duration;
use std::{collections::BTreeMap, sync::Arc, time::Instant};

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

const RECONSTRUCTION_START_DELAY: Duration = Duration::from_secs(2);

pub type ReconstructionParams<P, W> = (W, H256, Arc<SignedBeaconBlock<P>>, Slot);

pub struct Manager<P: Preset, W: Wait> {
    controller: ApiController<P, W>,
    dedicated_executor: DedicatedExecutor,
    metrics: Option<Arc<Metrics>>,
    scheduled_reconstructions: BTreeMap<Instant, Vec<ReconstructionParams<P, W>>>,
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
            scheduled_reconstructions: BTreeMap::new(),
        }
    }

    pub fn perform_scheduled_reconstructions(&mut self) {
        let mut reconstructions = self.scheduled_reconstructions.split_off(&Instant::now());
        core::mem::swap(&mut self.scheduled_reconstructions, &mut reconstructions);

        for (wait_group, block_root, block, slot) in reconstructions.into_values().flatten() {
            self.spawn_reconstruction(wait_group, block_root, block, slot);
        }
    }

    pub fn schedule_reconstruction(
        &mut self,
        wait_group: W,
        block_root: H256,
        block: Arc<SignedBeaconBlock<P>>,
        slot: Slot,
    ) {
        self.scheduled_reconstructions
            .entry(Instant::now() + RECONSTRUCTION_START_DELAY)
            .or_default()
            .push((wait_group, block_root, block, slot));
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
