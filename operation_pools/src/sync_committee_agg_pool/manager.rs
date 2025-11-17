use std::sync::Arc;

use anyhow::{Context, Error, Result};
use dedicated_executor::DedicatedExecutor;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use futures::channel::mpsc::UnboundedSender;
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use types::{
    altair::{
        containers::{SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::BeaconState,
    nonstandard::ValidationOutcome,
    phase0::primitives::{H256, Slot, SubnetId, ValidatorIndex},
    preset::Preset,
};
use validator_statistics::ValidatorStatistics;

use crate::{
    messages::{PoolToLivenessMessage, PoolToP2pMessage},
    misc::{Origin, PoolTask},
    sync_committee_agg_pool::{
        pool::Pool,
        tasks::{
            AddOwnContributionTask, AggregateOwnMessagesTask, HandleExternalContributionTask,
            HandleExternalMessageTask, HandleSlotTask,
        },
        types::ContributionData,
    },
};

pub struct Manager<P: Preset, W: Wait = ()> {
    // TODO(Grandine Team): Try using a bare Tokio runtime with custom thread priorities.
    //
    //                      `DedicatedExecutor` cancels dropped `Job`s.
    //                      This is unnecessary overhead because we never drop them.
    //                      `Manager::spawn_task` immediately waits for the task to complete.
    //
    //                      `DedicatedExecutor` waits for every task to complete when dropped.
    //                      We have no need for this.
    //                      It might not even work because we only call `Manager::spawn_task`
    //                      from Tokio tasks, which are not guaranteed to complete on shutdown.
    //
    //                      `DedicatedExecutor` only changes thread priorities on Unix.
    //                      Try the `thread-priority` crate.

    // Vouch reported that HTTP API is taking tens of milliseconds to respond to
    // sync committee related requests. That seemed strange, because our own middleware
    // reports requests having sub-millisecond response times.
    // The problem is that running CPU-heavy tasks on the main `tokio` runtime delays the
    // execution of the other tasks, so for things like responding to HTTP API requests
    // it can introduce a visible delay.
    // Running sync committee agg pool tasks in dedicated executor helped to fix the problem.
    dedicated_executor: Arc<DedicatedExecutor>,
    controller: ApiController<P, W>,
    pool: Arc<Pool<P>>,
    pool_to_liveness_tx: Option<UnboundedSender<PoolToLivenessMessage>>,
    pool_to_p2p_tx: UnboundedSender<PoolToP2pMessage>,
    metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> Manager<P, W> {
    #[must_use]
    pub fn new(
        dedicated_executor: Arc<DedicatedExecutor>,
        controller: ApiController<P, W>,
        pool_to_liveness_tx: Option<UnboundedSender<PoolToLivenessMessage>>,
        pool_to_p2p_tx: UnboundedSender<PoolToP2pMessage>,
        metrics: Option<Arc<Metrics>>,
        validator_statistics: Option<Arc<ValidatorStatistics>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            dedicated_executor,
            controller,
            pool: Arc::new(Pool::new(validator_statistics)),
            pool_to_liveness_tx,
            pool_to_p2p_tx,
            metrics,
        })
    }

    pub fn on_slot(&self, slot: Slot) {
        self.spawn_detached(HandleSlotTask {
            pool: self.pool.clone_arc(),
            slot,
            metrics: self.metrics.clone(),
        })
    }

    pub fn add_own_contribution(
        &self,
        aggregator_index: ValidatorIndex,
        contribution: SyncCommitteeContribution<P>,
        beacon_state: Arc<BeaconState<P>>,
    ) {
        self.spawn_detached(AddOwnContributionTask {
            pool: self.pool.clone_arc(),
            aggregator_index,
            contribution,
            beacon_state,
            metrics: self.metrics.clone(),
        })
    }

    pub fn aggregate_own_messages(
        &self,
        wait_group: W,
        messages: Vec<SyncCommitteeMessage>,
        subcommittee_index: SubcommitteeIndex,
        beacon_state: Arc<BeaconState<P>>,
    ) {
        let Some(message) = messages.first().copied() else {
            return;
        };

        let contribution_data = ContributionData::from_message(message, subcommittee_index);

        self.spawn_detached(AggregateOwnMessagesTask {
            wait_group,
            pool: self.pool.clone_arc(),
            contribution_data,
            messages,
            beacon_state,
            metrics: self.metrics.clone(),
        })
    }

    pub async fn best_subcommittee_contribution(
        &self,
        slot: Slot,
        beacon_block_root: H256,
        subcommittee_index: SubcommitteeIndex,
    ) -> SyncCommitteeContribution<P> {
        self.pool
            .best_subcommittee_contribution(slot, beacon_block_root, subcommittee_index)
            .await
    }

    pub async fn handle_external_contribution_and_proof(
        &self,
        signed_contribution_and_proof: SignedContributionAndProof<P>,
        origin: Origin,
    ) -> Result<ValidationOutcome> {
        self.spawn_task(HandleExternalContributionTask {
            controller: self.controller.clone_arc(),
            pool: self.pool.clone_arc(),
            signed_contribution_and_proof,
            origin,
            pool_to_p2p_tx: self.pool_to_p2p_tx.clone(),
            metrics: self.metrics.clone(),
        })
        .await
    }

    pub fn handle_external_contribution_and_proof_detached(
        &self,
        signed_contribution_and_proof: SignedContributionAndProof<P>,
        origin: Origin,
    ) {
        self.spawn_detached(HandleExternalContributionTask {
            controller: self.controller.clone_arc(),
            pool: self.pool.clone_arc(),
            signed_contribution_and_proof,
            origin,
            pool_to_p2p_tx: self.pool_to_p2p_tx.clone(),
            metrics: self.metrics.clone(),
        })
    }

    pub async fn handle_external_message(
        &self,
        message: SyncCommitteeMessage,
        subnet_id: SubnetId,
        origin: Origin,
    ) -> Result<ValidationOutcome> {
        self.spawn_task(HandleExternalMessageTask {
            controller: self.controller.clone_arc(),
            pool: self.pool.clone_arc(),
            message,
            subnet_id,
            origin,
            pool_to_liveness_tx: self.pool_to_liveness_tx.clone(),
            pool_to_p2p_tx: self.pool_to_p2p_tx.clone(),
            metrics: self.metrics.clone(),
        })
        .await
    }

    pub fn handle_external_message_detached(
        &self,
        message: SyncCommitteeMessage,
        subnet_id: SubnetId,
        origin: Origin,
    ) {
        self.spawn_detached(HandleExternalMessageTask {
            controller: self.controller.clone_arc(),
            pool: self.pool.clone_arc(),
            message,
            subnet_id,
            origin,
            pool_to_liveness_tx: self.pool_to_liveness_tx.clone(),
            pool_to_p2p_tx: self.pool_to_p2p_tx.clone(),
            metrics: self.metrics.clone(),
        })
    }

    async fn spawn_task<T: PoolTask>(&self, task: T) -> Result<T::Output> {
        self.dedicated_executor
            .spawn(task.run())
            .await
            .map_err(Error::msg)
            .context("sync committee aggregation pool task failed")?
    }

    fn spawn_detached(&self, task: impl PoolTask) {
        self.dedicated_executor.spawn(task.run()).detach()
    }
}
