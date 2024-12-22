use core::num::NonZeroU64;
use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;
use bls::{traits::BlsCachedPublicKey, PublicKeyBytes};
use eth1_api::ApiController;
use fork_choice_control::Wait;
use futures::channel::mpsc::UnboundedSender;
use genesis::AnchorCheckpointProvider;
use helper_functions::{
    accessors, misc, predicates,
    slot_report::{Assignment, Delta, RealSlotReport, SyncAggregateRewards},
};
use itertools::{chain, izip, Itertools as _};
use serde::{Deserialize, Serialize};
use std_ext::ArcExt as _;
use thiserror::Error;
use transition_functions::{
    altair::{
        EpochDeltasForReport as AltairEpochDeltasForReport, EpochReport as AltairEpochReport,
        Statistics as AltairStatistics, ValidatorSummary as AltairValidatorSummary,
    },
    combined::{self, EpochReport},
    phase0::{
        EpochDeltasForReport as Phase0EpochDeltasForReport, EpochReport as Phase0EpochReport,
        Performance as _, PerformanceForReport, StatisticsForReport as Phase0Statistics,
        ValidatorSummary as Phase0ValidatorSummary,
    },
    unphased::EpochDeltas as _,
};
use typenum::Unsigned as _;
use types::{
    altair::containers::SyncAggregate,
    combined::{BeaconState, SignedBeaconBlock},
    nonstandard::{
        AttestationEpoch, AttestationOutcome, GweiVec, RelativeEpoch, SlotVec, UsizeVec, WithStatus,
    },
    phase0::{
        consts::{GENESIS_EPOCH, GENESIS_SLOT},
        containers::Validator,
        primitives::{CommitteeIndex, Epoch, Gwei, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};
use unwrap_none::UnwrapNone as _;
use validator::ApiToValidator;

// `AttestationPerformance::for_previous_epoch` has to process slot reports in chronological order.
//
// We previously stored slot reports in `HashMap`s. The nondeterministic iteration order revealed
// some bugs in the code we were using to construct test data when we implemented snapshot tests.
type SlotReports = BTreeMap<Slot, RealSlotReport>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("genesis info not available")]
    GenesisNotAvailable,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochRangeWithKeysQuery {
    start: Epoch,
    end: Epoch,
    #[serde(default)]
    pubkeys: HashSet<PublicKeyBytes>,
}

impl EpochRangeWithKeysQuery {
    const fn is_range_empty(&self) -> bool {
        self.end < self.start
    }
}

#[derive(Serialize)]
pub struct GetBeaconHeadResponse {
    block_root: H256,
    finalized_block_root: H256,
    finalized_slot: Slot,
    slot: Slot,
}

#[derive(Serialize)]
pub struct GetValidatorStatisticsResponse {
    // The epochs are not redundant.
    // Old states may not be present in the fork choice store.
    beacon_state_reports: BTreeMap<Epoch, BeaconStateEpochReport>,
    validator_reports: BTreeMap<PublicKeyBytes, ValidatorEpochRangeReport>,
}

// TODO(Grandine Team): Find out which fields are needed in the GUI and turn this into a struct by
//                      using a common type for the `statistics` field.
#[derive(Debug, Serialize)]
enum BeaconStateEpochReport {
    Phase0 {
        post_finalized_epoch: Epoch,
        in_inactivity_leak: bool,
        statistics: Phase0Statistics,
    },
    PostAltair {
        post_finalized_epoch: Epoch,
        in_inactivity_leak: bool,
        statistics: AltairStatistics,
    },
}

#[derive(Serialize)]
struct ValidatorEpochRangeReport {
    validator_index: ValidatorIndex,
    active_epochs: usize,
    source_matches: usize,
    target_matches: usize,
    head_matches: usize,
    inclusion_delay_sum: u64,
    rewards: Gwei,
    penalties: Gwei,
    // The epochs are not redundant.
    // A validator may not be present in the registry at the start of the specified range of epochs.
    epoch_reports: BTreeMap<Epoch, ValidatorEpochReport>,
}

impl ValidatorEpochRangeReport {
    const fn new(validator_index: ValidatorIndex) -> Self {
        Self {
            validator_index,
            active_epochs: 0,
            source_matches: 0,
            target_matches: 0,
            head_matches: 0,
            inclusion_delay_sum: 0,
            rewards: 0,
            penalties: 0,
            epoch_reports: BTreeMap::new(),
        }
    }

    fn accumulate(
        &mut self,
        validator: &Validator,
        current_epoch: Epoch,
        report: ValidatorEpochReport,
    ) {
        self.active_epochs +=
            usize::from(predicates::is_active_validator(validator, current_epoch));

        match &report {
            ValidatorEpochReport::Phase0 {
                performance,
                epoch_deltas,
                slashing_penalty,
                previous_epoch_slot_deltas,
                ..
            } => {
                self.source_matches += usize::from(performance.previous_epoch_matching_source());
                self.target_matches += usize::from(performance.previous_epoch_matching_target());
                self.head_matches += usize::from(performance.previous_epoch_matching_head());

                self.inclusion_delay_sum += performance
                    .previous_epoch_fastest_inclusion()
                    .map(|inclusion| inclusion.delay.get())
                    .unwrap_or_default();

                self.rewards += epoch_deltas.combined_reward();
                self.penalties += epoch_deltas.combined_penalty();
                self.penalties += slashing_penalty.unwrap_or_default();

                self.rewards += previous_epoch_slot_deltas
                    .values()
                    .map(IndividualSlotDeltas::combined_reward)
                    .sum::<Gwei>();

                self.penalties += previous_epoch_slot_deltas
                    .values()
                    .map(IndividualSlotDeltas::combined_penalty)
                    .sum::<Gwei>();
            }
            ValidatorEpochReport::PostAltair {
                epoch_deltas,
                slashing_penalty,
                previous_epoch_attestation_performance,
                previous_epoch_slot_deltas,
                ..
            } => {
                if let Some(attestation_performance) = previous_epoch_attestation_performance {
                    self.source_matches += usize::from(attestation_performance.matching_source());
                    self.target_matches += usize::from(attestation_performance.matching_target());
                    self.head_matches += usize::from(attestation_performance.matching_head());

                    self.inclusion_delay_sum += attestation_performance
                        .inclusion_delay
                        .map(NonZeroU64::get)
                        .unwrap_or_default();
                }

                self.rewards += epoch_deltas.combined_reward();
                self.penalties += epoch_deltas.combined_penalty();
                self.penalties += slashing_penalty.unwrap_or_default();

                self.rewards += previous_epoch_slot_deltas
                    .values()
                    .map(IndividualSlotDeltas::combined_reward)
                    .sum::<Gwei>();

                self.penalties += previous_epoch_slot_deltas
                    .values()
                    .map(IndividualSlotDeltas::combined_penalty)
                    .sum::<Gwei>();
            }
        }

        self.epoch_reports
            .insert(current_epoch, report)
            .expect_none("only one set of reports is produced for each epoch");
    }
}

// TODO(Grandine Team): Find out which fields are needed in the GUI and turn this into a struct by
//                      using the type `AttestationPerformance` or `Option<AttestationPerformance>`
//                      for the field `previous_epoch_attestation_performance` in both Phase 0
//                      (instead of `performance: PerformanceForReport`) and post-Altair.
#[derive(Debug, Serialize)]
enum ValidatorEpochReport {
    Phase0 {
        summary: Phase0ValidatorSummary,
        performance: PerformanceForReport,
        epoch_deltas: Phase0EpochDeltasForReport,
        slashing_penalty: Option<Gwei>,
        post_balance: Gwei,
        previous_epoch_proposals: BTreeMap<Slot, Option<H256>>,
        previous_epoch_attestation_assignment: Option<AttestationAssignment>,
        previous_epoch_slot_deltas: BTreeMap<Slot, IndividualSlotDeltas>,
    },
    PostAltair {
        summary: AltairValidatorSummary,
        epoch_deltas: AltairEpochDeltasForReport,
        slashing_penalty: Option<Gwei>,
        post_balance: Gwei,
        previous_epoch_proposals: BTreeMap<Slot, Option<H256>>,
        previous_epoch_attestation_assignment: Option<AttestationAssignment>,
        previous_epoch_attestation_performance: Option<AttestationPerformance>,
        previous_epoch_sync_committee_assignment: Option<SyncCommitteeAssignment>,
        previous_epoch_sync_committee_performance: BTreeMap<Slot, SyncCommitteePerformance>,
        previous_epoch_slot_deltas: BTreeMap<Slot, IndividualSlotDeltas>,
    },
}

#[derive(Clone, Copy, Debug, Serialize)]
struct AttestationAssignment {
    slot: Slot,
    committee_index: CommitteeIndex,
}

#[derive(Clone, Copy, Default, Debug, Serialize)]
struct AttestationPerformance {
    source: Option<H256>,
    target: Option<AttestationOutcome>,
    head: Option<AttestationOutcome>,
    inclusion_delay: Option<NonZeroU64>,
}

impl AttestationPerformance {
    fn for_previous_epoch(
        validator_index: ValidatorIndex,
        previous_epoch_slot_reports: &SlotReports,
        current_epoch_slot_reports: &SlotReports,
    ) -> Self {
        let mut performance = Self::default();

        for slot_report in previous_epoch_slot_reports.values() {
            performance.accumulate(slot_report, (validator_index, AttestationEpoch::Current));
        }

        for slot_report in current_epoch_slot_reports.values() {
            performance.accumulate(slot_report, (validator_index, AttestationEpoch::Previous));
        }

        performance
    }

    fn accumulate(&mut self, slot_report: &RealSlotReport, assignment: Assignment) {
        let new_target = slot_report.targets.get(&assignment).copied();
        let new_head = slot_report.heads.get(&assignment).copied();

        if !self.matching_source() {
            self.source = slot_report.sources.get(&assignment).copied();
        }

        if AttestationOutcome::should_replace(self.target, new_target) {
            self.target = new_target;
        }

        if AttestationOutcome::should_replace(self.head, new_head) {
            self.head = new_head;
        }

        if self.inclusion_delay.is_none() {
            self.inclusion_delay = slot_report.inclusion_delays.get(&assignment).copied();
        }
    }

    const fn matching_source(self) -> bool {
        self.source.is_some()
    }

    const fn matching_target(self) -> bool {
        matches!(self.target, Some(AttestationOutcome::Match { .. }))
    }

    const fn matching_head(self) -> bool {
        matches!(self.head, Some(AttestationOutcome::Match { .. }))
    }
}

#[derive(Default, Debug, Serialize)]
struct SyncCommitteeAssignment {
    positions: UsizeVec,
}

#[derive(Debug, Serialize)]
struct SyncCommitteePerformance {
    positions: BTreeMap<usize, bool>,
    beacon_block_root: H256,
}

#[derive(Default, Debug, Serialize)]
struct IndividualSlotDeltas {
    slashing_penalty: Option<Gwei>,
    slashing_rewards: GweiVec,
    whistleblowing_rewards: GweiVec,
    attestation_rewards: GweiVec,
    deposits: GweiVec,
    sync_committee_delta: Option<Delta>,
    sync_aggregate_rewards: Option<SyncAggregateRewards>,
}

impl IndividualSlotDeltas {
    fn combined_reward(&self) -> Gwei {
        chain!(
            self.slashing_rewards.iter().copied(),
            self.whistleblowing_rewards.iter().copied(),
            self.attestation_rewards.iter().copied(),
            self.deposits.iter().copied(),
            self.sync_committee_delta.and_then(Delta::reward),
            self.sync_aggregate_rewards.map(SyncAggregateRewards::total),
        )
        .sum()
    }

    fn combined_penalty(&self) -> Gwei {
        chain!(
            self.slashing_penalty,
            self.sync_committee_delta.and_then(Delta::penalty),
        )
        .sum()
    }
}

/// `GET /beacon/head`
pub fn get_beacon_head<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
) -> GetBeaconHeadResponse {
    let head = controller.head().value;
    let state = controller.state_by_chain_link(&head);

    GetBeaconHeadResponse {
        block_root: head.block_root,
        finalized_block_root: state.finalized_checkpoint().root,
        finalized_slot: misc::compute_start_slot_at_epoch::<P>(state.finalized_checkpoint().epoch),
        slot: head.slot(),
    }
}

/// `GET /validator/statistics?start={start}&end={end}&pubkeys[]={pubkey}&pubkeys[]={pubkey}`
#[expect(
    clippy::too_many_lines,
    reason = "TODO(Grandine Team): Clean up when we have snapshot tests for `http_api`."
)]
pub async fn get_validator_statistics<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    validator_keys: &HashSet<PublicKeyBytes>,
    api_to_validator_tx: UnboundedSender<ApiToValidator<P>>,
    query: EpochRangeWithKeysQuery,
) -> Result<Option<GetValidatorStatisticsResponse>> {
    let mut beacon_state_reports = BTreeMap::new();
    let mut validator_reports = BTreeMap::new();

    if query.is_range_empty() {
        return Ok(Some(GetValidatorStatisticsResponse {
            beacon_state_reports,
            validator_reports,
        }));
    }

    let (sender, receiver) = futures::channel::oneshot::channel();

    ApiToValidator::RegisteredValidators(sender).send(&api_to_validator_tx);

    let registered_keys = receiver.await?;

    let skip_validator = |validator: &Validator| {
        let bytes = validator.pubkey.as_bytes();

        !registered_keys.contains(bytes)
            && !validator_keys.contains(bytes)
            && !query.pubkeys.contains(bytes)
    };

    let config = controller.chain_config().as_ref();
    let snapshot = controller.snapshot();

    let mut state;
    let mut previous_epoch_sync_committee_assignments;
    let mut previous_epoch_sync_aggregates_with_roots;
    let mut previous_epoch_slot_reports;

    if query.start == GENESIS_EPOCH {
        state = anchor_checkpoint_provider
            .checkpoint()
            .genesis()
            .map(|checkpoint| checkpoint.state)
            .ok_or(Error::GenesisNotAvailable)?;

        previous_epoch_sync_committee_assignments = HashMap::new();
        previous_epoch_sync_aggregates_with_roots = HashMap::new();
        previous_epoch_slot_reports = SlotReports::new();
    } else {
        let previous_epoch = query.start - 1;
        let start_slot = misc::compute_start_slot_at_epoch::<P>(previous_epoch);
        let slot_before_previous_epoch = misc::previous_slot(start_slot);

        state = match snapshot
            .state_at_slot(slot_before_previous_epoch)?
            .map(WithStatus::value)
        {
            Some(state) => state,
            None => return Ok(None),
        };

        assert_eq!(state.slot(), slot_before_previous_epoch);

        if previous_epoch > GENESIS_EPOCH {
            combined::process_slots(config, state.make_mut(), start_slot)?;
        }

        previous_epoch_sync_committee_assignments =
            current_epoch_sync_committee_assignments(&state);
        previous_epoch_sync_aggregates_with_roots = HashMap::with_capacity(P::SlotsPerEpoch::USIZE);
        previous_epoch_slot_reports = SlotReports::new();

        for block_with_root in
            snapshot.blocks_by_range(misc::slots_in_epoch::<P>(previous_epoch))?
        {
            let slot = block_with_root.block.message().slot();

            let slot_report = (slot > GENESIS_SLOT)
                .then(|| {
                    combined::state_transition_for_report(
                        config,
                        state.make_mut(),
                        &block_with_root.block,
                    )
                })
                .transpose()?
                .unwrap_or_default();

            previous_epoch_slot_reports.insert(slot, slot_report);

            if let Some(pair) = sync_aggregate_with_root(&block_with_root.block) {
                previous_epoch_sync_aggregates_with_roots.insert(slot, pair);
            }
        }

        let start_slot = misc::compute_start_slot_at_epoch::<P>(query.start);
        combined::process_slots(config, state.make_mut(), start_slot)?;
    }

    for current_epoch in query.start..query.end {
        assert!(misc::is_epoch_start::<P>(state.slot()));

        // These must be computed before calling `combined::epoch_report`.
        let previous_epoch_proposal_assignments = previous_epoch_proposal_assignments(&state)?;
        let previous_epoch_block_roots = previous_epoch_block_roots(&state)?;
        let previous_epoch_attestation_assignments =
            previous_epoch_attestation_assignments(&state)?;
        let current_epoch_sync_committee_assignments =
            current_epoch_sync_committee_assignments(&state);

        let mut current_epoch_slot_reports = SlotReports::new();
        let mut current_epoch_sync_aggregates_with_roots =
            HashMap::with_capacity(P::SlotsPerEpoch::USIZE);

        for block_with_root in snapshot.blocks_by_range(misc::slots_in_epoch::<P>(current_epoch))? {
            let slot = block_with_root.block.message().slot();

            let slot_report = (slot > GENESIS_SLOT)
                .then(|| {
                    combined::state_transition_for_report(
                        config,
                        state.make_mut(),
                        &block_with_root.block,
                    )
                })
                .transpose()?
                .unwrap_or_default();

            current_epoch_slot_reports.insert(slot, slot_report);

            if let Some(pair) = sync_aggregate_with_root(&block_with_root.block) {
                current_epoch_sync_aggregates_with_roots.insert(slot, pair);
            }
        }

        match combined::epoch_report(config, state.make_mut())? {
            EpochReport::Phase0(Phase0EpochReport {
                statistics,
                summaries,
                performance,
                epoch_deltas,
                slashing_penalties,
                post_balances,
            }) => {
                let beacon_state_report = BeaconStateEpochReport::Phase0 {
                    post_finalized_epoch: state.finalized_checkpoint().epoch,
                    in_inactivity_leak: predicates::is_in_inactivity_leak(&state),
                    statistics,
                };

                beacon_state_reports
                    .insert(current_epoch, beacon_state_report)
                    .expect_none("only one set of reports is produced for each epoch");

                for (
                    validator_index,
                    validator,
                    summary,
                    performance,
                    epoch_deltas,
                    post_balance,
                ) in izip!(
                    0..,
                    state.validators(),
                    summaries,
                    performance,
                    epoch_deltas,
                    post_balances,
                ) {
                    if skip_validator(validator) {
                        continue;
                    }

                    let slashing_penalty = slashing_penalties.get(&validator_index).copied();

                    let previous_epoch_proposals = previous_epoch_proposal_assignments
                        .get(&validator_index)
                        .into_iter()
                        .flatten()
                        .map(|slot| (*slot, previous_epoch_block_roots.get(slot).copied()))
                        .collect::<BTreeMap<_, _>>();

                    let previous_epoch_attestation_assignment =
                        previous_epoch_attestation_assignments
                            .get(&validator_index)
                            .copied();

                    let previous_epoch_slot_deltas = slot_deltas(
                        validator_index,
                        previous_epoch_proposal_assignments
                            .get(&validator_index)
                            .map(SlotVec::as_slice)
                            .unwrap_or_default(),
                        &previous_epoch_slot_reports,
                    );

                    let validator_report = ValidatorEpochReport::Phase0 {
                        summary,
                        performance,
                        epoch_deltas,
                        slashing_penalty,
                        post_balance,
                        previous_epoch_proposals,
                        previous_epoch_attestation_assignment,
                        previous_epoch_slot_deltas,
                    };

                    validator_reports
                        .entry(validator.pubkey.to_bytes())
                        .or_insert_with(|| ValidatorEpochRangeReport::new(validator_index))
                        .accumulate(validator, current_epoch, validator_report);
                }
            }
            EpochReport::PostAltair(AltairEpochReport {
                statistics,
                summaries,
                epoch_deltas,
                slashing_penalties,
                post_balances,
            }) => {
                let beacon_state_report = BeaconStateEpochReport::PostAltair {
                    post_finalized_epoch: state.finalized_checkpoint().epoch,
                    in_inactivity_leak: predicates::is_in_inactivity_leak(&state),
                    statistics,
                };

                beacon_state_reports
                    .insert(current_epoch, beacon_state_report)
                    .expect_none("only one set of reports is produced for each epoch");

                for (validator_index, validator, summary, epoch_deltas, post_balance) in izip!(
                    0..,
                    state.validators(),
                    summaries,
                    epoch_deltas,
                    post_balances,
                ) {
                    if skip_validator(validator) {
                        continue;
                    }

                    let slashing_penalty = slashing_penalties.get(&validator_index).copied();

                    let previous_epoch_proposals = previous_epoch_proposal_assignments
                        .get(&validator_index)
                        .into_iter()
                        .flatten()
                        .map(|slot| (*slot, previous_epoch_block_roots.get(slot).copied()))
                        .collect::<BTreeMap<_, _>>();

                    let previous_epoch_attestation_assignment =
                        previous_epoch_attestation_assignments
                            .get(&validator_index)
                            .copied();

                    let previous_epoch_attestation_performance =
                        previous_epoch_attestation_assignment.map(|_| {
                            AttestationPerformance::for_previous_epoch(
                                validator_index,
                                &previous_epoch_slot_reports,
                                &current_epoch_slot_reports,
                            )
                        });

                    let previous_epoch_sync_committee_assignment =
                        previous_epoch_sync_committee_assignments.remove(&validator_index);

                    let previous_epoch_sync_committee_performance = sync_committee_performance(
                        &previous_epoch_sync_committee_assignment,
                        &previous_epoch_sync_aggregates_with_roots,
                    );

                    let previous_epoch_slot_deltas = slot_deltas(
                        validator_index,
                        previous_epoch_proposal_assignments
                            .get(&validator_index)
                            .map(SlotVec::as_slice)
                            .unwrap_or_default(),
                        &previous_epoch_slot_reports,
                    );

                    let validator_report = ValidatorEpochReport::PostAltair {
                        summary,
                        epoch_deltas,
                        slashing_penalty,
                        post_balance,
                        previous_epoch_proposals,
                        previous_epoch_attestation_assignment,
                        previous_epoch_attestation_performance,
                        previous_epoch_sync_committee_assignment,
                        previous_epoch_sync_committee_performance,
                        previous_epoch_slot_deltas,
                    };

                    validator_reports
                        .entry(validator.pubkey.to_bytes())
                        .or_insert_with(|| ValidatorEpochRangeReport::new(validator_index))
                        .accumulate(validator, current_epoch, validator_report);
                }
            }
        }

        previous_epoch_sync_committee_assignments = current_epoch_sync_committee_assignments;
        previous_epoch_sync_aggregates_with_roots = current_epoch_sync_aggregates_with_roots;
        previous_epoch_slot_reports = current_epoch_slot_reports;
    }

    {
        assert!(misc::is_epoch_start::<P>(state.slot()));

        let current_epoch = query.end;

        // These must be computed before calling `combined::epoch_report`.
        let previous_epoch_proposal_assignments = previous_epoch_proposal_assignments(&state)?;
        let previous_epoch_block_roots = previous_epoch_block_roots(&state)?;
        let previous_epoch_attestation_assignments =
            previous_epoch_attestation_assignments(&state)?;

        let mut current_epoch_slot_reports = SlotReports::new();

        for block_with_root in snapshot.blocks_by_range(misc::slots_in_epoch::<P>(current_epoch))? {
            let slot = block_with_root.block.message().slot();

            let slot_report = (slot > GENESIS_SLOT)
                .then(|| {
                    combined::state_transition_for_report(
                        config,
                        state.make_mut(),
                        &block_with_root.block,
                    )
                })
                .transpose()?
                .unwrap_or_default();

            current_epoch_slot_reports.insert(slot, slot_report);
        }

        match combined::epoch_report(config, state.make_mut())? {
            EpochReport::Phase0(Phase0EpochReport {
                statistics,
                summaries,
                performance,
                epoch_deltas,
                slashing_penalties,
                post_balances,
            }) => {
                let beacon_state_report = BeaconStateEpochReport::Phase0 {
                    post_finalized_epoch: state.finalized_checkpoint().epoch,
                    in_inactivity_leak: predicates::is_in_inactivity_leak(&state),
                    statistics,
                };

                beacon_state_reports
                    .insert(current_epoch, beacon_state_report)
                    .expect_none("only one set of reports is produced for each epoch");

                for (
                    validator_index,
                    validator,
                    summary,
                    performance,
                    epoch_deltas,
                    post_balance,
                ) in izip!(
                    0..,
                    state.validators(),
                    summaries,
                    performance,
                    epoch_deltas,
                    post_balances,
                ) {
                    if skip_validator(validator) {
                        continue;
                    }

                    let slashing_penalty = slashing_penalties.get(&validator_index).copied();

                    let previous_epoch_proposals = previous_epoch_proposal_assignments
                        .get(&validator_index)
                        .into_iter()
                        .flatten()
                        .map(|slot| (*slot, previous_epoch_block_roots.get(slot).copied()))
                        .collect::<BTreeMap<_, _>>();

                    let previous_epoch_attestation_assignment =
                        previous_epoch_attestation_assignments
                            .get(&validator_index)
                            .copied();

                    let previous_epoch_slot_deltas = slot_deltas(
                        validator_index,
                        previous_epoch_proposal_assignments
                            .get(&validator_index)
                            .map(SlotVec::as_slice)
                            .unwrap_or_default(),
                        &previous_epoch_slot_reports,
                    );

                    let validator_report = ValidatorEpochReport::Phase0 {
                        summary,
                        performance,
                        epoch_deltas,
                        slashing_penalty,
                        post_balance,
                        previous_epoch_proposals,
                        previous_epoch_attestation_assignment,
                        previous_epoch_slot_deltas,
                    };

                    validator_reports
                        .entry(validator.pubkey.to_bytes())
                        .or_insert_with(|| ValidatorEpochRangeReport::new(validator_index))
                        .accumulate(validator, current_epoch, validator_report);
                }
            }
            EpochReport::PostAltair(AltairEpochReport {
                statistics,
                summaries,
                epoch_deltas,
                slashing_penalties,
                post_balances,
            }) => {
                let beacon_state_report = BeaconStateEpochReport::PostAltair {
                    post_finalized_epoch: state.finalized_checkpoint().epoch,
                    in_inactivity_leak: predicates::is_in_inactivity_leak(&state),
                    statistics,
                };

                beacon_state_reports
                    .insert(current_epoch, beacon_state_report)
                    .expect_none("only one set of reports is produced for each epoch");

                for (validator_index, validator, summary, epoch_deltas, post_balance) in izip!(
                    0..,
                    state.validators(),
                    summaries,
                    epoch_deltas,
                    post_balances,
                ) {
                    if skip_validator(validator) {
                        continue;
                    }

                    let slashing_penalty = slashing_penalties.get(&validator_index).copied();

                    let previous_epoch_proposals = previous_epoch_proposal_assignments
                        .get(&validator_index)
                        .into_iter()
                        .flatten()
                        .map(|slot| (*slot, previous_epoch_block_roots.get(slot).copied()))
                        .collect::<BTreeMap<_, _>>();

                    let previous_epoch_attestation_assignment =
                        previous_epoch_attestation_assignments
                            .get(&validator_index)
                            .copied();

                    let previous_epoch_attestation_performance =
                        previous_epoch_attestation_assignment.map(|_| {
                            AttestationPerformance::for_previous_epoch(
                                validator_index,
                                &previous_epoch_slot_reports,
                                &current_epoch_slot_reports,
                            )
                        });

                    let previous_epoch_sync_committee_assignment =
                        previous_epoch_sync_committee_assignments.remove(&validator_index);

                    let previous_epoch_sync_committee_performance = sync_committee_performance(
                        &previous_epoch_sync_committee_assignment,
                        &previous_epoch_sync_aggregates_with_roots,
                    );

                    let previous_epoch_slot_deltas = slot_deltas(
                        validator_index,
                        previous_epoch_proposal_assignments
                            .get(&validator_index)
                            .map(SlotVec::as_slice)
                            .unwrap_or_default(),
                        &previous_epoch_slot_reports,
                    );

                    let validator_report = ValidatorEpochReport::PostAltair {
                        summary,
                        epoch_deltas,
                        slashing_penalty,
                        post_balance,
                        previous_epoch_proposals,
                        previous_epoch_attestation_assignment,
                        previous_epoch_attestation_performance,
                        previous_epoch_sync_committee_assignment,
                        previous_epoch_sync_committee_performance,
                        previous_epoch_slot_deltas,
                    };

                    validator_reports
                        .entry(validator.pubkey.to_bytes())
                        .or_insert_with(|| ValidatorEpochRangeReport::new(validator_index))
                        .accumulate(validator, current_epoch, validator_report);
                }
            }
        }
    }

    Ok(Some(GetValidatorStatisticsResponse {
        beacon_state_reports,
        validator_reports,
    }))
}

/// `GET /validator/owned`
pub fn get_validator_owned<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    validator_keys: &HashSet<PublicKeyBytes>,
) -> BTreeMap<PublicKeyBytes, ValidatorIndex> {
    let head_state = controller.head_state().value;

    validator_keys
        .iter()
        .copied()
        .filter_map(|pubkey| {
            let validator_index = accessors::index_of_public_key(&head_state, pubkey)?;
            Some((pubkey, validator_index))
        })
        .collect()
}

/// `GET /validator/registered`
pub async fn get_validator_registered<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    api_to_validator_tx: UnboundedSender<ApiToValidator<P>>,
) -> Result<BTreeMap<PublicKeyBytes, ValidatorIndex>> {
    let head_state = controller.head_state().value;
    let (sender, receiver) = futures::channel::oneshot::channel();

    ApiToValidator::RegisteredValidators(sender).send(&api_to_validator_tx);

    let validator_indices = receiver
        .await?
        .into_iter()
        .filter_map(|pubkey| {
            let validator_index = accessors::index_of_public_key(&head_state, pubkey)?;
            Some((pubkey, validator_index))
        })
        .collect();

    Ok(validator_indices)
}

fn previous_epoch_proposal_assignments(
    state: &BeaconState<impl Preset>,
) -> Result<HashMap<ValidatorIndex, SlotVec>> {
    if accessors::get_current_epoch(state) == GENESIS_EPOCH {
        return Ok(HashMap::new());
    }

    proposal_assignments(state, accessors::get_previous_epoch(state))
}

fn proposal_assignments<P: Preset>(
    state: &BeaconState<P>,
    epoch: Epoch,
) -> Result<HashMap<ValidatorIndex, SlotVec>> {
    let mut proposal_assignments = HashMap::<_, SlotVec>::with_capacity(P::SlotsPerEpoch::USIZE);

    for slot in misc::slots_in_epoch::<P>(epoch) {
        let proposer_index = accessors::get_beacon_proposer_index_at_slot(state, slot)?;

        proposal_assignments
            .entry(proposer_index)
            .or_default()
            .push(slot);
    }

    Ok(proposal_assignments)
}

// Doing the same for the current epoch would require `state` to be in the last slot of the epoch
// and would require using `accessors::latest_block_root` for the last block.
fn previous_epoch_block_roots<P: Preset>(state: &BeaconState<P>) -> Result<HashMap<Slot, H256>> {
    if accessors::get_current_epoch(state) == GENESIS_EPOCH {
        return Ok(HashMap::new());
    }

    let slots_in_previous_epoch = misc::slots_in_epoch::<P>(accessors::get_previous_epoch(state));

    itertools::process_results(
        slots_in_previous_epoch
            .clone()
            .map(|slot| accessors::get_block_root_at_slot(state, slot)),
        |block_roots| {
            core::iter::once(H256::zero())
                .chain(block_roots)
                .tuple_windows()
                .map(|(previous, current)| (previous != current).then_some(current))
                .zip(slots_in_previous_epoch)
                .filter_map(|(block_root, slot)| Some((slot, block_root?)))
                .collect::<HashMap<_, _>>()
        },
    )
}

fn previous_epoch_attestation_assignments<P: Preset>(
    state: &BeaconState<P>,
) -> Result<HashMap<ValidatorIndex, AttestationAssignment>> {
    if accessors::get_current_epoch(state) == GENESIS_EPOCH {
        return Ok(HashMap::new());
    }

    let active_validator_count =
        accessors::active_validator_count_usize(state, RelativeEpoch::Previous);

    let mut attestation_assignments = HashMap::with_capacity(active_validator_count);

    for slot in misc::slots_in_epoch::<P>(accessors::get_previous_epoch(state)) {
        let committees = accessors::beacon_committees(state, slot)?;

        for (committee_index, committee) in (0..).zip(committees) {
            let attestation_assignment = AttestationAssignment {
                slot,
                committee_index,
            };

            attestation_assignments.extend(
                committee
                    .into_iter()
                    .zip(core::iter::repeat(attestation_assignment)),
            );
        }
    }

    Ok(attestation_assignments)
}

// A function that does the same for the previous epoch may be impossible.
// The Altair Honest Validator specification states:
// > *Note*: The data required to compute a given committee is not cached in the `BeaconState` after
// > committees are calculated at the period boundaries.
fn current_epoch_sync_committee_assignments<P: Preset>(
    state: &BeaconState<P>,
) -> HashMap<ValidatorIndex, SyncCommitteeAssignment> {
    let Some(state) = state.post_altair() else {
        return HashMap::new();
    };

    let mut sync_committee_assignments =
        HashMap::<_, SyncCommitteeAssignment>::with_capacity(P::SyncCommitteeSize::USIZE);

    for (position, pubkey) in state.current_sync_committee().pubkeys.iter().enumerate() {
        let validator_index = accessors::index_of_public_key(state, pubkey.to_bytes())
            .expect("public keys in state.current_sync_committee are taken from state.validators");

        sync_committee_assignments
            .entry(validator_index)
            .or_default()
            .positions
            .push(position);
    }

    sync_committee_assignments
}

fn sync_aggregate_with_root<P: Preset>(
    block: &SignedBeaconBlock<P>,
) -> Option<(SyncAggregate<P>, H256)> {
    let sync_aggregate = block.message().body().post_altair()?.sync_aggregate();
    let parent_root = block.message().parent_root();
    Some((sync_aggregate, parent_root))
}

fn sync_committee_performance(
    assignment: &Option<SyncCommitteeAssignment>,
    sync_aggregates_with_roots: &HashMap<Slot, (SyncAggregate<impl Preset>, H256)>,
) -> BTreeMap<Slot, SyncCommitteePerformance> {
    assignment
        .iter()
        .flat_map(|assignment| {
            sync_aggregates_with_roots.iter().map(
                move |(slot, (sync_aggregate, beacon_block_root))| {
                    let positions = assignment
                        .positions
                        .iter()
                        .copied()
                        .map(|position| (position, sync_aggregate.sync_committee_bits[position]))
                        .collect();

                    let performance = SyncCommitteePerformance {
                        positions,
                        beacon_block_root: *beacon_block_root,
                    };

                    (*slot, performance)
                },
            )
        })
        .collect()
}

fn slot_deltas(
    validator_index: ValidatorIndex,
    proposal_assignments: &[Slot],
    slot_reports: &SlotReports,
) -> BTreeMap<Slot, IndividualSlotDeltas> {
    let mut slot_deltas = BTreeMap::<_, IndividualSlotDeltas>::new();

    for (slot, slot_report) in slot_reports {
        if proposal_assignments.contains(slot) {
            for reward in slot_report.slashing_rewards.values().flatten().copied() {
                slot_deltas
                    .entry(*slot)
                    .or_default()
                    .slashing_rewards
                    .push(reward);
            }

            for proposer_reward in slot_report.attestation_rewards.iter().copied() {
                slot_deltas
                    .entry(*slot)
                    .or_default()
                    .attestation_rewards
                    .push(proposer_reward);
            }

            if let Some(proposer_rewards) = slot_report.sync_aggregate_rewards {
                slot_deltas
                    .entry(*slot)
                    .or_default()
                    .sync_aggregate_rewards
                    .replace(proposer_rewards)
                    .unwrap_none();
            }
        }

        if let Some(penalty) = slot_report
            .slashing_penalties
            .get(&validator_index)
            .copied()
        {
            slot_deltas
                .entry(*slot)
                .or_default()
                .slashing_penalty
                .replace(penalty)
                .unwrap_none();
        }

        if let Some(rewards) = slot_report.whistleblowing_rewards.get(&validator_index) {
            slot_deltas
                .entry(*slot)
                .or_default()
                .whistleblowing_rewards
                .clone_from(rewards);
        }

        if let Some(amounts) = slot_report.deposits.get(&validator_index) {
            slot_deltas
                .entry(*slot)
                .or_default()
                .deposits
                .clone_from(amounts);
        }

        if let Some(delta) = slot_report
            .sync_committee_deltas
            .get(&validator_index)
            .copied()
        {
            slot_deltas
                .entry(*slot)
                .or_default()
                .sync_committee_delta
                .replace(delta)
                .unwrap_none();
        }
    }

    slot_deltas
}

#[cfg(test)]
mod tests {
    use helper_functions::mutators;
    use types::{config::Config, preset::Minimal};

    use super::*;

    #[test]
    fn previous_epoch_proposal_assignments_works_when_active_validators_change() -> Result<()> {
        let config = Config::minimal();

        let (mut state, _) = factory::min_genesis_state::<Minimal>(&config)?;

        // Change the set of active validators to trigger a bug that was present in
        // `get_beacon_proposer_index_at_slot`. Building blocks for testing is tedious,
        // so we hack around it by calling `initiate_validator_exit` directly.
        let exiting_validator_index = 0;

        mutators::initiate_validator_exit(&config, &mut state, exiting_validator_index)?;

        let exit_epoch = state.validators().get(exiting_validator_index)?.exit_epoch;
        let start_slot = misc::compute_start_slot_at_epoch::<Minimal>(exit_epoch);

        combined::process_slots(&config, state.make_mut(), start_slot - 1)?;

        let proposal_assignments_before_exit = current_epoch_proposal_assignments(&state)?;

        combined::process_slots(&config, state.make_mut(), start_slot)?;

        let proposal_assignments_after_exit = previous_epoch_proposal_assignments(&state)?;

        assert_eq!(
            proposal_assignments_before_exit,
            proposal_assignments_after_exit,
        );

        Ok(())
    }

    fn current_epoch_proposal_assignments(
        state: &BeaconState<impl Preset>,
    ) -> Result<HashMap<ValidatorIndex, SlotVec>> {
        proposal_assignments(state, accessors::get_current_epoch(state))
    }
}
