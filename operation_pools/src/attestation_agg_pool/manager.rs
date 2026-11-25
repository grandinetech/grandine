use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Error, Result};
use bls::PublicKeyBytes;
use clock::{Tick, TickKind};
use dedicated_executor::DedicatedExecutor;
use eth1_api::ApiController;
use features::Feature;
use fork_choice_control::Wait;
use logging::{debug_with_peers, warn_with_peers};
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use tokio::sync::Semaphore;
use tracing::instrument;
use types::{
    combined::{Attestation as CombinedAttestation, BeaconState},
    config::Config,
    gloas::containers::Attestation as GloasAttestation,
    nonstandard::Phase,
    phase0::primitives::{CommitteeIndex, Epoch, H256, Slot, ValidatorIndex},
    pq::{containers::Attestation as PqAttestation, primitives::AttestationProof},
    preset::Preset,
};
use validator_statistics::ValidatorStatistics;

use crate::{
    attestation_agg_pool::{
        conversion::{compute_pq_on_chain_aggregate, current_state},
        pool::Pool,
        pq_signature_pool::CommitteeSignatures,
        tasks::{
            BestProposableAttestationsTask, ComputeProposerIndicesTask,
            GloasProposableAttestationsTask, InsertAttestationTask, InsertPqAggregateTask,
            PackProposableAttestationsTask, PqProposableAttestationsTask,
            SetCommitteesWithAggregatorsTask, SetRegisteredValidatorsTask,
        },
        types::{AttestationKey, PoolAttestation},
    },
    misc::PoolTask,
};

pub enum PqAggregateToBroadcast<P: Preset> {
    Aggregate(PqAttestation<P>, AttestationProof<P>),
    /// No aggregate of the committee was proven or received.
    NotProven,
    /// An aggregate received or published has all the attesters of each pooled one.
    Redundant,
}

pub struct Manager<P: Preset, W: Wait> {
    controller: ApiController<P, W>,
    dedicated_executor: Arc<DedicatedExecutor>,
    metrics: Option<Arc<Metrics>>,
    pool: Arc<Pool<P>>,
    // One proof at a time. A slot whose first proofs would wait for the previous slot's is skipped.
    pq_proving: Arc<Semaphore>,
    validator_statistics: Option<Arc<ValidatorStatistics>>,
}

impl<P: Preset, W: Wait> Manager<P, W> {
    #[must_use]
    pub fn new(
        controller: ApiController<P, W>,
        dedicated_executor: Arc<DedicatedExecutor>,
        metrics: Option<Arc<Metrics>>,
        validator_statistics: Option<Arc<ValidatorStatistics>>,
    ) -> Arc<Self> {
        let chain_config = controller.chain_config().clone_arc();

        Arc::new(Self {
            controller,
            dedicated_executor,
            metrics,
            pool: Arc::new(Pool::new(chain_config)),
            pq_proving: Arc::new(Semaphore::new(1)),
            validator_statistics,
        })
    }

    #[must_use]
    pub fn config(&self) -> &Arc<Config> {
        self.controller.chain_config()
    }

    pub async fn on_tick(&self, tick: Tick) {
        let Tick { slot, kind } = tick;

        match kind {
            TickKind::Propose => {
                self.pool.on_slot(slot).await;
            }
            TickKind::Attest => {
                self.pool.clear_best_proposable_attestations().await;

                if self.config().phase_at_slot::<P>(slot) == Phase::Pq {
                    self.prove_pq_aggregates(slot);
                }
            }
            TickKind::AggregateFourth => {
                let next_slot = slot.saturating_add(1);

                if Feature::AlwaysPrepackAttestations.is_enabled()
                    || self
                        .pool
                        .has_registered_validators_proposing_in_slots(next_slot..=next_slot)
                        .await
                {
                    self.pack_proposable_attestations();
                }
            }
            _ => {}
        }
    }

    pub async fn aggregate_attestations_by_epoch(&self, epoch: Epoch) -> Vec<PoolAttestation<P>> {
        self.pool.aggregate_attestations_by_epoch(epoch).await
    }

    pub async fn best_aggregate_attestation(
        &self,
        key: AttestationKey,
    ) -> Option<PoolAttestation<P>> {
        self.pool.best_aggregate_attestation(key).await
    }

    pub async fn best_aggregate_attestation_by_data_root(
        &self,
        attestation_data_root: H256,
        epoch: Epoch,
    ) -> Option<PoolAttestation<P>> {
        self.pool
            .best_aggregate_attestation_by_data_root(attestation_data_root, epoch)
            .await
    }

    pub async fn best_aggregate_attestation_by_data_root_and_committee_index(
        &self,
        attestation_data_root: H256,
        epoch: Epoch,
        committee_index: CommitteeIndex,
    ) -> Option<PoolAttestation<P>> {
        self.pool
            .best_aggregate_attestation_by_data_root_and_committee_index(
                attestation_data_root,
                epoch,
                committee_index,
            )
            .await
    }

    pub async fn best_proposable_attestations(
        &self,
        beacon_state: Arc<BeaconState<P>>,
    ) -> Result<Vec<PoolAttestation<P>>> {
        self.spawn_task(BestProposableAttestationsTask {
            controller: self.controller.clone_arc(),
            pool: self.pool.clone_arc(),
            beacon_state,
            metrics: self.metrics.clone(),
        })
        .await
    }

    pub fn compute_proposer_indices(&self, beacon_state: Arc<BeaconState<P>>) {
        self.spawn_detached(ComputeProposerIndicesTask {
            pool: self.pool.clone_arc(),
            beacon_state,
        });
    }

    /// The state must reflect parent processing for the final proposal bid.
    pub async fn gloas_proposable_attestations(
        &self,
        scoring_state: Arc<BeaconState<P>>,
    ) -> Result<Vec<GloasAttestation<P>>> {
        self.spawn_task(GloasProposableAttestationsTask {
            controller: self.controller.clone_arc(),
            pool: self.pool.clone_arc(),
            scoring_state,
            metrics: self.metrics.clone(),
        })
        .await
    }

    /// The attestations of a PQ block with the proofs of their committees, in committee order.
    ///
    /// The state must reflect parent processing for the final proposal bid.
    pub async fn pq_proposable_attestations(
        &self,
        scoring_state: Arc<BeaconState<P>>,
    ) -> Result<Vec<(PqAttestation<P>, Vec<AttestationProof<P>>)>> {
        self.spawn_task(PqProposableAttestationsTask {
            controller: self.controller.clone_arc(),
            pool: self.pool.clone_arc(),
            scoring_state,
        })
        .await
    }

    /// The pooled PQ aggregate of `key` with the most attesters that no aggregate received or
    /// published has all of ([`should_broadcast_aggregate`]).
    ///
    /// [`should_broadcast_aggregate`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/validator.md#broadcast-aggregate
    pub async fn pq_aggregate_to_broadcast(
        &self,
        key: AttestationKey,
    ) -> Result<PqAggregateToBroadcast<P>> {
        let aggregates = self.pool.pq_aggregates(key).await;

        if aggregates.is_empty() {
            return Ok(PqAggregateToBroadcast::NotProven);
        }

        for aggregate in aggregates {
            let (attestation, mut proofs) = compute_pq_on_chain_aggregate([aggregate.as_ref()])?;

            if self
                .controller
                .is_aggregate_subset_known(&CombinedAttestation::Pq(attestation.clone()))
            {
                continue;
            }

            if let Some(proof) = proofs.pop() {
                return Ok(PqAggregateToBroadcast::Aggregate(attestation, proof));
            }
        }

        Ok(PqAggregateToBroadcast::Redundant)
    }

    /// Proves the signatures of `key` collected until the aggregation cutoff of the own aggregator
    /// at `position` in its aggregation committee, unless a pooled aggregate already has all of
    /// their attesters. Waits for earlier proofs until the aggregator's aggregate is due.
    pub fn prove_pq_aggregate_at(&self, key: AttestationKey, position: u32) {
        let controller = self.controller.clone_arc();
        let pool = self.pool.clone_arc();
        let pq_proving = self.pq_proving.clone_arc();

        tokio::spawn(async move {
            let config = controller.chain_config().clone_arc();
            let genesis_time = controller.genesis_time();
            let slot = key.data.slot;
            let delay_bps = config
                .aggregator_delay_bps
                .saturating_mul(u64::from(position));

            let until = |due_bps: u64| {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();

                clock::duration_until_due_bps(
                    &config,
                    genesis_time,
                    slot,
                    due_bps.saturating_add(delay_bps),
                    now,
                )
            };

            tokio::time::sleep(until(config.aggregation_cutoff_bps)).await;

            let now = Instant::now();
            let deadline = now
                .checked_add(until(config.aggregate_due_bps_pq))
                .unwrap_or(now);

            let Some(input) = pool.pq_committee_signatures(key).await else {
                return;
            };

            let positions = input.positions().collect::<Vec<_>>();

            if pool.is_covered_by_pq_aggregate(key, &positions).await {
                return;
            }

            let Ok(Ok(_permit)) =
                tokio::time::timeout_at(deadline.into(), pq_proving.acquire_owned()).await
            else {
                warn_with_peers!(
                    "no time to prove the PQ aggregate of committee {} in slot {slot} \
                     for aggregator position {position}",
                    key.committee_index,
                );
                return;
            };

            prove_and_pool(&controller, &pool, input, slot, deadline).await;
        });
    }

    /// Pools a validated PQ aggregate with its proof.
    pub fn insert_pq_aggregate(&self, attestation: PqAttestation<P>, proof: AttestationProof<P>) {
        self.spawn_detached(InsertPqAggregateTask {
            pool: self.pool.clone_arc(),
            attestation,
            proof,
        });
    }

    pub fn insert_attestation(
        &self,
        wait_group: W,
        attestation: Arc<CombinedAttestation<P>>,
        attester_index: Option<ValidatorIndex>,
    ) {
        self.spawn_detached(InsertAttestationTask {
            wait_group,
            pool: self.pool.clone_arc(),
            controller: self.controller.clone_arc(),
            attestation,
            attester_index,
            metrics: self.metrics.clone(),
            validator_statistics: self.validator_statistics.clone(),
        });
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn is_registered_validator(&self, validator_index: ValidatorIndex) -> bool {
        self.pool.is_registered_validator(validator_index).await
    }

    pub fn pack_proposable_attestations(&self) {
        self.spawn_detached(PackProposableAttestationsTask {
            pool: self.pool.clone_arc(),
            controller: self.controller.clone_arc(),
            metrics: self.metrics.clone(),
        });
    }

    pub async fn registered_validator_indices(&self) -> HashSet<ValidatorIndex> {
        self.pool.registered_validator_indices().await
    }

    pub fn set_committees_with_aggregators(
        &self,
        committees_with_aggregators: BTreeMap<Slot, BTreeSet<CommitteeIndex>>,
    ) {
        self.spawn_detached(SetCommitteesWithAggregatorsTask {
            pool: self.pool.clone_arc(),
            committees_with_aggregators,
        });
    }

    pub fn set_registered_validators(
        &self,
        pubkeys: Vec<PublicKeyBytes>,
        prepared_proposer_indices: Vec<ValidatorIndex>,
    ) {
        self.spawn_detached(SetRegisteredValidatorsTask {
            pool: self.pool.clone_arc(),
            controller: self.controller.clone_arc(),
            pubkeys,
            prepared_proposer_indices,
            validator_statistics: self.validator_statistics.clone(),
        });
    }

    pub async fn singular_attestations_by_epoch(
        &self,
        epoch: Epoch,
    ) -> Vec<Arc<PoolAttestation<P>>> {
        self.pool.singular_attestations_by_epoch(epoch).await
    }

    /// Proves aggregates of the PQ signatures of `slot` collected until the aggregation cutoff of
    /// the first aggregator, committee by committee, largest first, until the aggregate is due.
    fn prove_pq_aggregates(&self, slot: Slot) {
        let controller = self.controller.clone_arc();
        let pool = self.pool.clone_arc();
        let pq_proving = self.pq_proving.clone_arc();

        tokio::spawn(async move {
            let config = controller.chain_config().clone_arc();
            let genesis_time = controller.genesis_time();

            let until = |due_bps| {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();

                clock::duration_until_due_bps(&config, genesis_time, slot, due_bps, now)
            };

            tokio::time::sleep(until(config.aggregation_cutoff_bps)).await;

            let now = Instant::now();
            let deadline = now
                .checked_add(until(config.aggregate_due_bps_pq))
                .unwrap_or(now);
            let mut inputs = pool.seal_pq_signatures(slot).await;

            if inputs.is_empty() {
                return;
            }

            let Ok(_permit) = pq_proving.try_acquire_owned() else {
                warn_with_peers!(
                    "skipping PQ aggregates of slot {slot}: still proving earlier ones"
                );
                return;
            };

            inputs.sort_by_key(|input| core::cmp::Reverse(input.signature_count()));

            for input in inputs {
                if Instant::now() >= deadline {
                    warn_with_peers!("ran out of time proving PQ aggregates of slot {slot}");
                    break;
                }

                if !prove_and_pool(&controller, &pool, input, slot, deadline).await {
                    break;
                }
            }
        });
    }

    async fn spawn_task<T: PoolTask>(&self, task: T) -> Result<T::Output> {
        self.dedicated_executor
            .spawn(task.run())
            .await
            .map_err(Error::msg)
            .context("attestation aggregation pool task failed")?
    }

    fn spawn_detached(&self, task: impl PoolTask) {
        self.dedicated_executor.spawn(task.run()).detach()
    }
}

// Proves `input` and pools the aggregate if it is proven before `deadline`. Returns whether there
// may be time to prove more.
async fn prove_and_pool<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    pool: &Pool<P>,
    input: CommitteeSignatures,
    slot: Slot,
    deadline: Instant,
) -> bool {
    let controller = controller.clone_arc();

    let result = tokio::task::spawn_blocking(move || {
        let state = current_state(&controller, input.target());

        input.prove(
            controller.chain_config(),
            state.as_ref(),
            pq_prover::aggregate_backend(),
        )
    })
    .await;

    match result {
        Ok(Ok(aggregate)) if Instant::now() < deadline => {
            pool.insert_pq_aggregate(Arc::new(aggregate)).await;
            true
        }
        Ok(Ok(_)) => {
            warn_with_peers!("PQ aggregate of slot {slot} was proven too late");
            false
        }
        Ok(Err(error)) => {
            debug_with_peers!("failed to prove PQ aggregate of slot {slot}: {error:?}");
            true
        }
        Err(error) => {
            warn_with_peers!("PQ proving task of slot {slot} failed: {error:?}");
            false
        }
    }
}
