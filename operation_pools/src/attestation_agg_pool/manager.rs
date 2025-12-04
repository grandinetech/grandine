use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
};

use anyhow::{Context, Error, Result};
use bls::PublicKeyBytes;
use clock::{Tick, TickKind};
use dedicated_executor::DedicatedExecutor;
use eth1_api::ApiController;
use features::Feature;
use fork_choice_control::Wait;
use logging::warn_with_peers;
use prometheus_metrics::Metrics;
use ssz::ContiguousList;
use std_ext::ArcExt as _;
use tracing::instrument;
use types::{
    combined::{Attestation as CombinedAttestation, BeaconState},
    config::Config,
    electra::containers::Attestation as ElectraAttestation,
    nonstandard::Phase,
    phase0::{
        containers::{Attestation, AttestationData},
        primitives::{CommitteeIndex, Epoch, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
};
use validator_statistics::ValidatorStatistics;

use crate::{
    attestation_agg_pool::{
        convert_to_electra_attestation, convert_to_electra_attestation_use_pre_pool,
        pool::Pool,
        tasks::{
            BestProposableAttestationsTask, ComputeProposerIndicesTask, InsertAttestationTask,
            PackProposableAttestationsTask, SetCommitteesWithAggregatorsTask,
            SetRegisteredValidatorsTask,
        },
        types::AttestationPrePool,
    },
    misc::PoolTask,
};

pub struct Manager<P: Preset, W: Wait> {
    controller: ApiController<P, W>,
    dedicated_executor: Arc<DedicatedExecutor>,
    metrics: Option<Arc<Metrics>>,
    pool: Arc<Pool<P>>,
    validator_statistics: Option<Arc<ValidatorStatistics>>,
}

impl<P: Preset, W: Wait> Manager<P, W> {
    async fn electra_attestation_with_pre_pool(
        &self,
        attestation: Attestation<P>,
    ) -> Option<(ElectraAttestation<P>, AttestationPrePool)> {
        let data = attestation.data;
        let Some(pre_pool) = self.attestation_pre_pool_by_data(data).await else {
            warn_with_peers!(
                "missing pre-pool attestation data for attestation data (slot {}, committee {})",
                data.slot,
                data.index
            );
            return None;
        };

        let electra_attestation =
            match convert_to_electra_attestation_use_pre_pool(attestation, pre_pool) {
                Ok(electra_attestation) => electra_attestation,
                Err(error) => {
                    warn_with_peers!("unable to convert to electra attestation: {error:?}");
                    return None;
                }
            };

        Some((electra_attestation, pre_pool))
    }

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
            }
            TickKind::AggregateFourth => {
                let next_slot = slot + 1;

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

    pub async fn aggregate_attestations_by_epoch(&self, epoch: Epoch) -> Vec<Attestation<P>> {
        self.pool.aggregate_attestations_by_epoch(epoch).await
    }

    pub async fn best_aggregate_attestation(
        &self,
        data: AttestationData,
    ) -> Option<Attestation<P>> {
        self.pool.best_aggregate_attestation(data).await
    }

    pub async fn best_aggregate_attestation_by_data_root(
        &self,
        attestation_data_root: H256,
        epoch: Epoch,
    ) -> Option<Attestation<P>> {
        self.pool
            .best_aggregate_attestation_by_data_root(attestation_data_root, epoch)
            .await
    }

    pub async fn best_aggregate_attestation_by_data_root_and_committee_index(
        &self,
        attestation_data_root: H256,
        epoch: Epoch,
        committee_index: CommitteeIndex,
    ) -> Option<Attestation<P>> {
        self.pool
            .best_aggregate_attestation_by_data_root_and_committee_index(
                attestation_data_root,
                epoch,
                committee_index,
            )
            .await
    }

    pub async fn attestation_pre_pool_by_data(
        &self,
        data: AttestationData,
    ) -> Option<AttestationPrePool> {
        self.pool.attestation_pre_pool_by_data(data).await
    }

    pub async fn electra_aggregate_for_publish(
        &self,
        phase0_aggregate: Attestation<P>,
        phase: Phase,
    ) -> Option<ElectraAttestation<P>> {
        if phase < Phase::Gloas {
            return convert_to_electra_attestation(phase0_aggregate).ok();
        }
        self.electra_attestation_with_committee_for_block(phase0_aggregate, phase)
            .await
            .map(|(electra_attestation, _)| electra_attestation)
    }

    pub async fn electra_attestation_with_committee_for_block(
        &self,
        attestation: Attestation<P>,
        phase: Phase,
    ) -> Option<(ElectraAttestation<P>, CommitteeIndex)> {
        if phase < Phase::Gloas {
            let committee_index = attestation.data.index;
            return match convert_to_electra_attestation(attestation) {
                Ok(electra_attestation) => Some((electra_attestation, committee_index)),
                Err(error) => {
                    warn_with_peers!("unable to convert to electra attestation: {error:?}");
                    None
                }
            };
        }

        self.electra_attestation_with_pre_pool(attestation)
            .await
            .map(|(electra_attestation, pre_pool)| (electra_attestation, pre_pool.committee_index))
    }

    pub async fn best_proposable_attestations(
        &self,
        beacon_state: Arc<BeaconState<P>>,
    ) -> Result<ContiguousList<Attestation<P>, P::MaxAttestations>> {
        self.spawn_task(BestProposableAttestationsTask {
            controller: self.controller.clone_arc(),
            pool: self.pool.clone_arc(),
            beacon_state,
        })
        .await
    }

    pub fn compute_proposer_indices(&self, beacon_state: Arc<BeaconState<P>>) {
        self.spawn_detached(ComputeProposerIndicesTask {
            pool: self.pool.clone_arc(),
            beacon_state,
        });
    }

    #[instrument(level = "debug", skip_all)]
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

    pub async fn singular_attestations_by_epoch(&self, epoch: Epoch) -> Vec<Arc<Attestation<P>>> {
        self.pool.singular_attestations_by_epoch(epoch).await
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
