use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
    time::Instant,
};

use anyhow::Result;
use bls::{PublicKeyBytes, traits::Signature as _};
use eth1_api::ApiController;
use fork_choice_control::Wait;
use fork_choice_store::StateCacheError;
use helper_functions::accessors;
use logging::{exception, info_with_peers, warn_with_peers};
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use tap::Pipe as _;
use types::{
    combined::{Attestation as CombinedAttestation, BeaconState},
    electra::error::AttestationConversionError,
    phase0::primitives::{CommitteeIndex, Epoch, H256, Slot, ValidatorIndex},
    preset::Preset,
    traits::BeaconState as _,
};
use validator_statistics::ValidatorStatistics;

use crate::{
    attestation_agg_pool::{
        attestation_packer::{AttestationPacker, PackOutcome},
        conversion::convert_attestation_for_pool,
        pool::Pool,
        types::{Aggregate, AttestationKey, PoolAttestation},
    },
    misc::PoolTask,
};

pub struct BestProposableAttestationsTask<P: Preset, W: Wait> {
    pub pool: Arc<Pool<P>>,
    pub controller: ApiController<P, W>,
    pub beacon_state: Arc<BeaconState<P>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> PoolTask for BestProposableAttestationsTask<P, W> {
    type Output = Vec<PoolAttestation<P>>;

    async fn run(self) -> Result<Self::Output> {
        let Self {
            pool,
            controller,
            beacon_state,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            metrics
                .att_pool_best_proposable_attestations_times
                .start_timer()
        });

        let started_at = Instant::now();

        let attestations = pool.best_proposable_attestations(beacon_state.slot()).await;
        let slot = controller.slot();

        if !attestations.is_empty() {
            features::log!(
                DebugAttestationPacker,
                "optimal attestations present for slot: {slot}"
            );
            return Ok(attestations);
        }

        features::warn!(
            DebugAttestationPacker,
            "no optimal attestations for slot: {}",
            slot
        );

        let attestation_packer = AttestationPacker::new(
            controller.chain_config().clone_arc(),
            beacon_state.clone_arc(),
            true,
        )?;

        let attestations =
            pack_attestations_greedily(&controller, &attestation_packer, &pool, &beacon_state)
                .await?
                .attestations;

        features::log!(
            DebugAttestationPacker,
            "packed {} attestations for slot: {slot} in {} ms",
            attestations.len(),
            started_at.elapsed().as_millis(),
        );

        Ok(attestations)
    }
}

pub struct ComputeProposerIndicesTask<P: Preset> {
    pub pool: Arc<Pool<P>>,
    pub beacon_state: Arc<BeaconState<P>>,
}

impl<P: Preset> PoolTask for ComputeProposerIndicesTask<P> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self { pool, beacon_state } = self;
        let current_epoch = accessors::get_current_epoch(&beacon_state);

        pool.compute_proposer_indices_for_epoch(&beacon_state, current_epoch)
            .await?;
        pool.compute_proposer_indices_for_epoch(&beacon_state, current_epoch.saturating_add(1))
            .await?;

        Ok(())
    }
}

pub struct PackProposableAttestationsTask<P: Preset, W: Wait> {
    pub pool: Arc<Pool<P>>,
    pub controller: ApiController<P, W>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> PoolTask for PackProposableAttestationsTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            pool,
            controller,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            metrics
                .att_pool_pack_proposable_attestations_times
                .start_timer()
        });

        let started_at = Instant::now();

        let beacon_state = controller.preprocessed_state_at_next_slot_blocking()?;
        let slot = controller.slot().saturating_add(1);

        // Greedy packing is a single deterministic pass, so — unlike the removed solver path —
        // there is nothing to gain from an anytime loop; pre-compute once and store the result.
        let attestation_packer = AttestationPacker::new(
            controller.chain_config().clone_arc(),
            beacon_state.clone_arc(),
            false,
        )?;

        let outcome =
            pack_attestations_greedily(&controller, &attestation_packer, &pool, &beacon_state)
                .await?;

        features::log!(
            DebugAttestationPacker,
            "pack outcome for slot: {slot}, attestations: {}, deadline_reached: {}, elapsed: {} ms",
            outcome.attestations.len(),
            outcome.deadline_reached,
            started_at.elapsed().as_millis(),
        );

        pool.set_best_proposable_attestations(outcome.attestations, beacon_state.slot())
            .await;

        Ok(())
    }
}

pub struct InsertAttestationTask<P: Preset, W: Wait> {
    pub wait_group: W,
    pub pool: Arc<Pool<P>>,
    pub controller: ApiController<P, W>,
    pub attestation: Arc<CombinedAttestation<P>>,
    pub attester_index: Option<ValidatorIndex>,
    pub metrics: Option<Arc<Metrics>>,
    pub validator_statistics: Option<Arc<ValidatorStatistics>>,
}

impl<P: Preset, W: Wait> PoolTask for InsertAttestationTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            wait_group,
            pool,
            controller,
            attestation,
            mut attester_index,
            metrics,
            validator_statistics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.att_pool_insert_attestation_task_times.start_timer());

        if let CombinedAttestation::Single(single_attestation) = attestation.as_ref() {
            attester_index = Some(single_attestation.attester_index);
        }

        let attestation = match convert_attestation_for_pool(&controller, attestation) {
            Ok(attestation) => attestation,
            Err(error) => {
                match error.downcast_ref::<AttestationConversionError>() {
                    Some(AttestationConversionError::Irrelevant) => {}
                    Some(AttestationConversionError::AttesterNotInCommittee { .. }) => {
                        exception!("failed to convert attestation for pool: {error:?}");
                    }
                    _ => {
                        warn_with_peers!("failed to convert attestation for pool: {error:?}");
                    }
                }

                return Ok(());
            }
        };

        let PoolAttestation {
            aggregation_bits,
            data,
            committee_index,
            signature,
        } = attestation;

        let key = AttestationKey {
            data,
            committee_index,
        };

        let is_singular = aggregation_bits.count_ones() == 1;

        if is_singular {
            if let Some(validator_index) = attester_index {
                let _timer = metrics
                    .as_ref()
                    .map(|metrics| metrics.att_pool_attestation_tracking_times.start_timer());

                if let Some(validator_statistics) = validator_statistics.as_ref() {
                    validator_statistics
                        .track_attestation_vote::<P>(data, validator_index)
                        .await;
                }
            }

            if !pool
                .aggregate_in_committee(committee_index, data.slot)
                .await
            {
                return Ok(());
            }
        }

        let singular_attestations = pool.singular_attestations(key).await;
        let aggregates = pool.aggregates(key).await;
        let mut aggregates = aggregates.lock().await;

        if !is_singular || aggregates.is_empty() {
            let mut aggregate = Aggregate {
                aggregation_bits,
                signature: signature.try_into()?,
            };

            for existing_attestation in singular_attestations.read().await.iter() {
                aggregate_attestation(existing_attestation, &mut aggregate)?;
            }

            aggregates.push(aggregate);
        } else {
            let attestation = PoolAttestation {
                aggregation_bits,
                data,
                committee_index,
                signature,
            };

            for aggregate in aggregates.iter_mut() {
                aggregate_attestation(&attestation, aggregate)?;
            }

            if is_singular {
                singular_attestations
                    .write()
                    .await
                    .insert(Arc::new(attestation));
            }
        }

        pool.add_data_root_to_key_entry(key).await;

        drop(wait_group);

        Ok(())
    }
}

pub struct SetCommitteesWithAggregatorsTask<P: Preset> {
    pub pool: Arc<Pool<P>>,
    pub committees_with_aggregators: BTreeMap<Slot, BTreeSet<CommitteeIndex>>,
}

impl<P: Preset> PoolTask for SetCommitteesWithAggregatorsTask<P> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            pool,
            committees_with_aggregators,
        } = self;

        pool.set_committees_with_aggregators(committees_with_aggregators)
            .await;

        Ok(())
    }
}

pub struct SetRegisteredValidatorsTask<P: Preset, W: Wait> {
    pub pool: Arc<Pool<P>>,
    pub controller: ApiController<P, W>,
    pub pubkeys: Vec<PublicKeyBytes>,
    pub prepared_proposer_indices: Vec<ValidatorIndex>,
    pub validator_statistics: Option<Arc<ValidatorStatistics>>,
}

impl<P: Preset, W: Wait> PoolTask for SetRegisteredValidatorsTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            pool,
            controller,
            pubkeys,
            prepared_proposer_indices,
            validator_statistics,
        } = self;

        let beacon_state = match controller.preprocessed_state_at_current_slot_blocking() {
            Ok(state) => state,
            Err(error) => {
                if let Some(StateCacheError::StateFarBehind { .. }) = error.downcast_ref() {
                    controller.head_state().value
                } else {
                    warn_with_peers!(
                        "failed get preprocessed state at current slot needed for validating registered validator pubkeys: {error}",
                    );
                    return Ok(());
                }
            }
        };

        let mut validator_indices = pubkeys
            .into_iter()
            .filter_map(|pubkey| accessors::index_of_public_key(&beacon_state, &pubkey))
            .collect::<HashSet<_>>();

        if let Some(validator_statistics) = validator_statistics.as_ref() {
            validator_statistics
                .set_registered_validator_indices(validator_indices.clone())
                .await;
        }

        validator_indices.extend(prepared_proposer_indices);

        pool.set_registered_validator_indices(validator_indices)
            .await;

        Ok(())
    }
}

fn aggregate_attestation<P: Preset>(
    attestation: &PoolAttestation<P>,
    aggregate: &mut Aggregate<P>,
) -> Result<()> {
    if attestation
        .aggregation_bits
        .any_not_in(&aggregate.aggregation_bits)
    {
        aggregate.aggregation_bits |= &attestation.aggregation_bits;
        aggregate
            .signature
            .aggregate_in_place(attestation.signature.try_into()?);
    }

    Ok(())
}

async fn pack_attestations_greedily<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    attestation_packer: &AttestationPacker<P>,
    pool: &Pool<P>,
    state: &BeaconState<P>,
) -> Result<PackOutcome<P>> {
    let previous_epoch = accessors::get_previous_epoch(state);
    let current_epoch = accessors::get_current_epoch(state);
    let dependent_root = controller.dependent_root(state, previous_epoch)?;

    let previous_epoch_attestations = pool.aggregate_attestations_by_epoch(previous_epoch).await;
    let current_epoch_attestations = pool.aggregate_attestations_by_epoch(current_epoch).await;

    let acceptable_targets = acceptable_attestation_targets_for_packing(
        controller,
        dependent_root,
        previous_epoch,
        previous_epoch_attestations
            .iter()
            .chain(&current_epoch_attestations),
    );

    let previous_epoch_attestations = previous_epoch_attestations
        .iter()
        .filter(|attestation| acceptable_targets.contains(&attestation.data.target.root));

    let current_epoch_attestations = current_epoch_attestations
        .iter()
        .filter(|attestation| acceptable_targets.contains(&attestation.data.target.root));

    attestation_packer
        .pack_proposable_attestations_greedily(
            previous_epoch_attestations,
            current_epoch_attestations,
        )
        .pipe(Ok)
}

fn acceptable_attestation_targets_for_packing<'a, P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    dependent_root: H256,
    dependent_root_epoch: Epoch,
    attestations: impl IntoIterator<Item = &'a PoolAttestation<P>>,
) -> HashSet<H256> {
    attestations
        .into_iter()
        .map(|attestation| attestation.data.target)
        .collect::<HashSet<_>>()
        .into_iter()
        .filter_map(|target| {
            info_with_peers!("attestation packet getting target state for {target:?}");

            // `BestProposableAttestationsTask` and `PackProposableAttestationsTask` already run in `DedicatedExecutor`
            // Attestation target validity is already checked before attestation is submitted to the pool
            let target_state = controller.checkpoint_state_blocking(target).ok()??;

            info_with_peers!("attestation packet got target state for {target:?}");

            let target_dependent_root = controller.dependent_root(&target_state, dependent_root_epoch).expect(
                "only previous and current epoch attestations are selected from the pool, they should never have their target slots from the future",
            );

            (target_dependent_root == dependent_root).then_some(target.root)
        })
        .collect()
}
