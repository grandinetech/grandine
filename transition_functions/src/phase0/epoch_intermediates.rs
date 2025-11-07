use core::num::NonZeroU64;

use anyhow::Result;
use helper_functions::{
    accessors::{
        get_block_root, get_block_root_at_slot, get_current_epoch, get_finality_delay,
        get_previous_epoch,
    },
    misc::vec_of_default,
    mutators::clamp_balance,
    phase0::get_attesting_indices,
    predicates::{is_active_validator, is_eligible_for_penalties, is_in_inactivity_leak},
};
use itertools::{Itertools as _, izip};
use num_integer::Roots as _;
use serde::Serialize;
#[cfg(target_arch = "x86_64")]
use static_assertions::assert_eq_size;
use types::{
    nonstandard::{AttestationEpoch, AttestationOutcome, Outcome},
    phase0::{
        beacon_state::BeaconState,
        consts::BASE_REWARDS_PER_EPOCH,
        containers::{PendingAttestation, Validator},
        primitives::{Epoch, Gwei, H256, ValidatorIndex},
    },
    preset::Preset,
};

use crate::unphased::{EpochDeltas, ValidatorSummary};

pub trait Statistics: Copy + Default {
    type Performance: Performance;
    type Outcome: Outcome;

    fn previous_epoch_head_attesting_balance(self) -> Gwei;
    fn previous_epoch_source_attesting_balance(self) -> Gwei;
    fn previous_epoch_target_attesting_balance(self) -> Gwei;
    fn current_epoch_active_balance(self) -> Gwei;
    fn current_epoch_target_attesting_balance(self) -> Gwei;

    fn accumulate_validator(&mut self, active_in_current_epoch: bool, validator: &Validator);

    fn accumulate_previous_epoch_attestation(
        &mut self,
        performance: &mut Self::Performance,
        attestation: &PendingAttestation<impl Preset>,
        target: Self::Outcome,
        head: Self::Outcome,
        effective_balance: Gwei,
    );

    fn accumulate_current_epoch_attestation(
        &mut self,
        performance: &mut Self::Performance,
        matching_target: bool,
        effective_balance: Gwei,
    );

    fn clamp_balances<P: Preset>(&mut self);
}

pub trait Performance: Copy + Default {
    fn previous_epoch_matching_source(self) -> bool;
    fn previous_epoch_matching_target(self) -> bool;
    fn previous_epoch_matching_head(self) -> bool;
    fn previous_epoch_fastest_inclusion(self) -> Option<Inclusion>;
}

pub trait Phase0EpochDeltas: Copy + Default {
    fn add_source_reward(&mut self, value: Gwei);
    fn add_source_penalty(&mut self, value: Gwei);
    fn add_target_reward(&mut self, value: Gwei);
    fn add_target_penalty(&mut self, value: Gwei);
    fn add_head_reward(&mut self, value: Gwei);
    fn add_head_penalty(&mut self, value: Gwei);
    fn add_proposer_reward(&mut self, value: Gwei);
    fn add_inclusion_delay_reward(&mut self, value: Gwei);
    fn add_canceling_penalty(&mut self, value: Gwei);
    fn add_inactivity_penalty(&mut self, value: Gwei);
}

#[derive(Clone, Copy, Debug, Serialize)]
#[cfg_attr(test, derive(Default))]
pub struct Phase0ValidatorSummary {
    pub effective_balance: Gwei,
    pub slashed: bool,
    pub withdrawable_epoch: Epoch,
    pub eligible_for_penalties: bool,
}

#[cfg(target_arch = "x86_64")]
assert_eq_size!(Phase0ValidatorSummary, [u64; 3]);

impl ValidatorSummary for Phase0ValidatorSummary {
    // This does not update derived fields because `process_slashings` does not use them.
    fn update_from(&mut self, validator: &Validator) {
        self.effective_balance = validator.effective_balance;
        self.slashed = validator.slashed;
        self.withdrawable_epoch = validator.withdrawable_epoch;
    }
}

#[expect(clippy::struct_field_names)]
#[derive(Clone, Copy, Default)]
pub struct StatisticsForTransition {
    previous_epoch_source_attesting_balance: Gwei,
    previous_epoch_target_attesting_balance: Gwei,
    previous_epoch_head_attesting_balance: Gwei,
    current_epoch_active_balance: Gwei,
    current_epoch_target_attesting_balance: Gwei,
}

impl Statistics for StatisticsForTransition {
    type Performance = PerformanceForTransition;
    type Outcome = bool;

    fn previous_epoch_head_attesting_balance(self) -> Gwei {
        self.previous_epoch_head_attesting_balance
    }

    fn previous_epoch_source_attesting_balance(self) -> Gwei {
        self.previous_epoch_source_attesting_balance
    }

    fn previous_epoch_target_attesting_balance(self) -> Gwei {
        self.previous_epoch_target_attesting_balance
    }

    fn current_epoch_active_balance(self) -> Gwei {
        self.current_epoch_active_balance
    }

    fn current_epoch_target_attesting_balance(self) -> Gwei {
        self.current_epoch_target_attesting_balance
    }

    fn accumulate_validator(&mut self, active_in_current_epoch: bool, validator: &Validator) {
        if active_in_current_epoch {
            self.current_epoch_active_balance += validator.effective_balance;
        }
    }

    // Explicitly inlining these speeds up epoch processing by a few percent.
    #[inline]
    fn accumulate_previous_epoch_attestation(
        &mut self,
        performance: &mut Self::Performance,
        attestation: &PendingAttestation<impl Preset>,
        target: Self::Outcome,
        head: Self::Outcome,
        effective_balance: Gwei,
    ) {
        if !performance.previous_epoch_matching_source() {
            self.previous_epoch_source_attesting_balance += effective_balance;
            performance.previous_epoch_match = Match::Source;
        }

        if !performance.previous_epoch_matching_target() && target {
            self.previous_epoch_target_attesting_balance += effective_balance;
            performance.previous_epoch_match = Match::Target;
        }

        if !performance.previous_epoch_matching_head() && target && head {
            self.previous_epoch_head_attesting_balance += effective_balance;
            performance.previous_epoch_match = Match::Head;
        }

        let PendingAttestation {
            inclusion_delay,
            proposer_index,
            ..
        } = *attestation;

        let delay = inclusion_delay
            .try_into()
            .expect("MIN_ATTESTATION_INCLUSION_DELAY is at least 1 in all presets");

        let inclusion = Inclusion {
            delay,
            proposer_index,
        };

        let current = performance
            .previous_epoch_fastest_inclusion
            .get_or_insert(inclusion);

        // The `random` test cases (only `randomized_0` as of `consensus-specs` 1.1.9) contain
        // pre-states with impossible inclusion delays (529 - 525 = 7). This check should never be
        // needed in normal operation because attestations are processed in order of inclusion.
        if inclusion_delay < current.delay.get() {
            *current = inclusion;
        }
    }

    #[inline]
    fn accumulate_current_epoch_attestation(
        &mut self,
        performance: &mut Self::Performance,
        matching_target: bool,
        effective_balance: Gwei,
    ) {
        if !performance.current_epoch_matching_target && matching_target {
            self.current_epoch_target_attesting_balance += effective_balance;
            performance.current_epoch_matching_target = true;
        }
    }

    fn clamp_balances<P: Preset>(&mut self) {
        clamp_balance::<P>(&mut self.previous_epoch_source_attesting_balance);
        clamp_balance::<P>(&mut self.previous_epoch_target_attesting_balance);
        clamp_balance::<P>(&mut self.previous_epoch_head_attesting_balance);
        clamp_balance::<P>(&mut self.current_epoch_active_balance);
        clamp_balance::<P>(&mut self.current_epoch_target_attesting_balance);
    }
}

#[expect(clippy::struct_field_names)]
#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct StatisticsForReport {
    pub previous_epoch_source_attesting_balance: Gwei,
    pub previous_epoch_target_attesting_balance: Gwei,
    pub previous_epoch_head_attesting_balance: Gwei,
    pub current_epoch_active_balance: Gwei,
    pub current_epoch_target_attesting_balance: Gwei,
}

impl Statistics for StatisticsForReport {
    type Performance = PerformanceForReport;
    type Outcome = AttestationOutcome;

    fn previous_epoch_head_attesting_balance(self) -> Gwei {
        self.previous_epoch_head_attesting_balance
    }

    fn previous_epoch_source_attesting_balance(self) -> Gwei {
        self.previous_epoch_source_attesting_balance
    }

    fn previous_epoch_target_attesting_balance(self) -> Gwei {
        self.previous_epoch_target_attesting_balance
    }

    fn current_epoch_active_balance(self) -> Gwei {
        self.current_epoch_active_balance
    }

    fn current_epoch_target_attesting_balance(self) -> Gwei {
        self.current_epoch_target_attesting_balance
    }

    fn accumulate_validator(&mut self, active_in_current_epoch: bool, validator: &Validator) {
        if active_in_current_epoch {
            self.current_epoch_active_balance += validator.effective_balance;
        }
    }

    #[inline]
    fn accumulate_previous_epoch_attestation(
        &mut self,
        performance: &mut Self::Performance,
        attestation: &PendingAttestation<impl Preset>,
        target: Self::Outcome,
        head: Self::Outcome,
        effective_balance: Gwei,
    ) {
        if !performance.previous_epoch_matching_source() {
            self.previous_epoch_source_attesting_balance += effective_balance;
            performance.previous_epoch_source = Some(attestation.data.source.root);
        }

        if !performance.previous_epoch_matching_target() {
            if target.is_match() {
                self.previous_epoch_target_attesting_balance += effective_balance;
            }
            performance.previous_epoch_target = Some(target);
        }

        if !performance.previous_epoch_matching_head() {
            if target.is_match() && head.is_match() {
                self.previous_epoch_head_attesting_balance += effective_balance;
            }
            performance.previous_epoch_head = Some(head);
        }

        let PendingAttestation {
            inclusion_delay,
            proposer_index,
            ..
        } = *attestation;

        let delay = inclusion_delay
            .try_into()
            .expect("MIN_ATTESTATION_INCLUSION_DELAY is at least 1 in all presets");

        let inclusion = Inclusion {
            delay,
            proposer_index,
        };

        let current = performance
            .previous_epoch_fastest_inclusion
            .get_or_insert(inclusion);

        // The `random` test cases (only `randomized_0` as of `consensus-specs` 1.1.9) contain
        // pre-states with impossible inclusion delays (529 - 525 = 7). This check should never be
        // needed in normal operation because attestations are processed in order of inclusion.
        if inclusion_delay < current.delay.get() {
            *current = inclusion;
        }
    }

    #[inline]
    fn accumulate_current_epoch_attestation(
        &mut self,
        performance: &mut Self::Performance,
        matching_target: bool,
        effective_balance: Gwei,
    ) {
        if !performance.current_epoch_matching_target && matching_target {
            self.current_epoch_target_attesting_balance += effective_balance;
            performance.current_epoch_matching_target = true;
        }
    }

    fn clamp_balances<P: Preset>(&mut self) {
        clamp_balance::<P>(&mut self.previous_epoch_source_attesting_balance);
        clamp_balance::<P>(&mut self.previous_epoch_target_attesting_balance);
        clamp_balance::<P>(&mut self.previous_epoch_head_attesting_balance);
        clamp_balance::<P>(&mut self.current_epoch_active_balance);
        clamp_balance::<P>(&mut self.current_epoch_target_attesting_balance);
    }
}

#[derive(Clone, Copy, Default)]
pub struct PerformanceForTransition {
    previous_epoch_match: Match,
    previous_epoch_fastest_inclusion: Option<Inclusion>,
    current_epoch_matching_target: bool,
}

impl Performance for PerformanceForTransition {
    #[inline]
    fn previous_epoch_matching_source(self) -> bool {
        Match::Source <= self.previous_epoch_match
    }

    #[inline]
    fn previous_epoch_matching_target(self) -> bool {
        Match::Target <= self.previous_epoch_match
    }

    #[inline]
    fn previous_epoch_matching_head(self) -> bool {
        Match::Head <= self.previous_epoch_match
    }

    fn previous_epoch_fastest_inclusion(self) -> Option<Inclusion> {
        self.previous_epoch_fastest_inclusion
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct PerformanceForReport {
    // Source mismatches are not possible because the attestation wouldn't get included at all.
    previous_epoch_source: Option<H256>,
    // The state may contain multiple different attestations by the same validator.
    // If any of them have matching roots, the corresponding field will contain an
    // `AttestationOutcome::Match`. Otherwise, the field will contain an
    // `AttestationOutcome::Mismatch` with the root taken from the last attestation.
    previous_epoch_target: Option<AttestationOutcome>,
    previous_epoch_head: Option<AttestationOutcome>,
    previous_epoch_fastest_inclusion: Option<Inclusion>,
    current_epoch_matching_target: bool,
}

impl Performance for PerformanceForReport {
    #[inline]
    fn previous_epoch_matching_source(self) -> bool {
        self.previous_epoch_source.is_some()
    }

    #[inline]
    fn previous_epoch_matching_target(self) -> bool {
        self.previous_epoch_matching_source()
            && self
                .previous_epoch_target
                .is_some_and(AttestationOutcome::is_match)
    }

    #[inline]
    fn previous_epoch_matching_head(self) -> bool {
        self.previous_epoch_matching_target()
            && self
                .previous_epoch_head
                .is_some_and(AttestationOutcome::is_match)
    }

    fn previous_epoch_fastest_inclusion(self) -> Option<Inclusion> {
        self.previous_epoch_fastest_inclusion
    }
}

// As suggested by `clippy::struct_excessive_bools`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
enum Match {
    #[default]
    None,
    Source,
    Target,
    Head,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Inclusion {
    pub delay: NonZeroU64,
    pub proposer_index: ValidatorIndex,
}

#[derive(Clone, Copy, Default)]
pub struct EpochDeltasForTransition {
    reward: Gwei,
    penalty: Gwei,
}

impl EpochDeltas for EpochDeltasForTransition {
    fn combined_reward(self) -> Gwei {
        self.reward
    }

    fn combined_penalty(self) -> Gwei {
        self.penalty
    }
}

impl Phase0EpochDeltas for EpochDeltasForTransition {
    fn add_source_reward(&mut self, value: Gwei) {
        self.reward += value;
    }

    fn add_source_penalty(&mut self, value: Gwei) {
        self.penalty += value;
    }

    fn add_target_reward(&mut self, value: Gwei) {
        self.reward += value;
    }

    fn add_target_penalty(&mut self, value: Gwei) {
        self.penalty += value;
    }

    fn add_head_reward(&mut self, value: Gwei) {
        self.reward += value;
    }

    fn add_head_penalty(&mut self, value: Gwei) {
        self.penalty += value;
    }

    fn add_proposer_reward(&mut self, value: Gwei) {
        self.reward += value;
    }

    fn add_inclusion_delay_reward(&mut self, value: Gwei) {
        self.reward += value;
    }

    fn add_canceling_penalty(&mut self, value: Gwei) {
        self.penalty += value;
    }

    fn add_inactivity_penalty(&mut self, value: Gwei) {
        self.penalty += value;
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct EpochDeltasForReport {
    source_reward: Gwei,
    source_penalty: Gwei,
    target_reward: Gwei,
    target_penalty: Gwei,
    head_reward: Gwei,
    head_penalty: Gwei,
    proposer_reward: Gwei,
    inclusion_delay_reward: Gwei,
    canceling_penalty: Gwei,
    inactivity_penalty: Gwei,
}

impl EpochDeltas for EpochDeltasForReport {
    fn combined_reward(self) -> Gwei {
        self.source_reward
            + self.target_reward
            + self.head_reward
            + self.proposer_reward
            + self.inclusion_delay_reward
    }

    fn combined_penalty(self) -> Gwei {
        self.source_penalty
            + self.target_penalty
            + self.head_penalty
            + self.canceling_penalty
            + self.inactivity_penalty
    }
}

impl Phase0EpochDeltas for EpochDeltasForReport {
    fn add_source_reward(&mut self, value: Gwei) {
        self.source_reward += value;
    }

    fn add_source_penalty(&mut self, value: Gwei) {
        self.source_penalty += value;
    }

    fn add_target_reward(&mut self, value: Gwei) {
        self.target_reward += value;
    }

    fn add_target_penalty(&mut self, value: Gwei) {
        self.target_penalty += value;
    }

    fn add_head_reward(&mut self, value: Gwei) {
        self.head_reward += value;
    }

    fn add_head_penalty(&mut self, value: Gwei) {
        self.head_penalty += value;
    }

    fn add_proposer_reward(&mut self, value: Gwei) {
        self.proposer_reward += value;
    }

    fn add_inclusion_delay_reward(&mut self, value: Gwei) {
        self.inclusion_delay_reward += value;
    }

    fn add_canceling_penalty(&mut self, value: Gwei) {
        self.canceling_penalty += value;
    }

    fn add_inactivity_penalty(&mut self, value: Gwei) {
        self.inactivity_penalty += value;
    }
}

pub fn statistics<P: Preset, S: Statistics>(
    state: &BeaconState<P>,
) -> Result<(S, Vec<Phase0ValidatorSummary>, Vec<S::Performance>)> {
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);

    let mut statistics = S::default();

    let summaries = state
        .validators
        .into_iter()
        .map(|validator| {
            let Validator {
                effective_balance,
                slashed,
                withdrawable_epoch,
                ..
            } = *validator;

            let active_in_current_epoch = is_active_validator(validator, current_epoch);
            let eligible_for_penalties = is_eligible_for_penalties(validator, previous_epoch);

            statistics.accumulate_validator(active_in_current_epoch, validator);

            Phase0ValidatorSummary {
                effective_balance,
                slashed,
                withdrawable_epoch,
                eligible_for_penalties,
            }
        })
        .collect_vec();

    let mut performance = vec_of_default(state);

    // `get_block_root` can fail during the first slot of an epoch. However, `consensus-spec-tests`
    // requires calculating rewards and penalties for states in the genesis slot.
    //
    // Starting with `consensus-specs` version 1.3.0-rc.4, it is incorrect to return early if
    // `get_block_root(state, AttestationEpoch::Current)` fails. Returning early causes
    // `compute_pulled_up_tip` from the Fork Choice specification to compute unrealized checkpoints
    // incorrectly. That happens because `compute_pulled_up_tip` does not call `process_slots`.
    if let Ok(previous_epoch_target_block_root) = get_block_root(state, AttestationEpoch::Previous)
    {
        for attestation in &state.previous_epoch_attestations {
            let expected_target = previous_epoch_target_block_root;
            let expected_head = get_block_root_at_slot(state, attestation.data.slot)
                .expect("attestations are only added to beacon state when they are valid");

            let actual_target = attestation.data.target.root;
            let actual_head = attestation.data.beacon_block_root;

            let target_outcome = S::Outcome::compare(actual_target, expected_target);
            let head_outcome = S::Outcome::compare(actual_head, expected_head);

            for validator_index in
                get_attesting_indices(state, attestation.data, &attestation.aggregation_bits)
                    .expect("attestations are only added to beacon state when they are valid")
            {
                let index = usize::try_from(validator_index)?;
                let summary = summaries[index];

                if summary.slashed {
                    continue;
                }

                // The `Inclusion` constructed in `accumulate_previous_epoch_attestation` is the
                // same for all participants of the attestation, but hoisting it out of the loop and
                // passing it as a parameter does not improve performance.
                statistics.accumulate_previous_epoch_attestation(
                    &mut performance[index],
                    attestation,
                    target_outcome,
                    head_outcome,
                    summary.effective_balance,
                );
            }
        }
    }

    if let Ok(current_epoch_target_block_root) = get_block_root(state, AttestationEpoch::Current) {
        for attestation in &state.current_epoch_attestations {
            let matching_target = attestation.data.target.root == current_epoch_target_block_root;

            if !matching_target {
                continue;
            }

            for validator_index in
                get_attesting_indices(state, attestation.data, &attestation.aggregation_bits)
                    .expect("attestations are only added to beacon state when they are valid")
            {
                let index = usize::try_from(validator_index)?;
                let summary = summaries[index];

                if summary.slashed {
                    continue;
                }

                statistics.accumulate_current_epoch_attestation(
                    &mut performance[index],
                    matching_target,
                    summary.effective_balance,
                );
            }
        }
    }

    statistics.clamp_balances::<P>();

    Ok((statistics, summaries, performance))
}

pub fn epoch_deltas<P: Preset, S: Statistics, D: Phase0EpochDeltas>(
    state: &BeaconState<P>,
    statistics: S,
    summaries: impl IntoIterator<Item = Phase0ValidatorSummary>,
    performance: impl IntoIterator<Item = S::Performance>,
) -> Result<Vec<D>> {
    let finality_delay = get_finality_delay(state);
    let in_inactivity_leak = is_in_inactivity_leak(state);
    let total_active_balance_sqrt = statistics.current_epoch_active_balance().sqrt();

    let mut deltas: Vec<D> = vec_of_default(state);

    for (index, summary, performance) in izip!(0.., summaries, performance) {
        let Phase0ValidatorSummary {
            effective_balance,
            eligible_for_penalties,
            ..
        } = summary;

        let base_reward = effective_balance * P::BASE_REWARD_FACTOR
            / total_active_balance_sqrt
            / BASE_REWARDS_PER_EPOCH;

        let attestation_component_reward = |attesting_balance| {
            // > Factored out from balance totals to avoid uint64 overflow
            let increment = P::EFFECTIVE_BALANCE_INCREMENT;

            if in_inactivity_leak {
                // > Since full base reward will be canceled out by inactivity penalty deltas,
                // > optimal participation receives full base reward compensation here.
                base_reward
            } else {
                let reward_numerator = base_reward * (attesting_balance / increment);
                let reward_denominator = statistics.current_epoch_active_balance() / increment;
                reward_numerator / reward_denominator
            }
        };

        let proposer_reward = base_reward / P::PROPOSER_REWARD_QUOTIENT;

        if eligible_for_penalties {
            let deltas = &mut deltas[index];

            // The conditionals here do not check if the validator is slashed because `Performance`
            // already accounts for that. This is not the case with `Participation` in Altair.

            if performance.previous_epoch_matching_source() {
                deltas.add_source_reward(attestation_component_reward(
                    statistics.previous_epoch_source_attesting_balance(),
                ));
            } else {
                deltas.add_source_penalty(base_reward);
            }

            if performance.previous_epoch_matching_target() {
                deltas.add_target_reward(attestation_component_reward(
                    statistics.previous_epoch_target_attesting_balance(),
                ));
            } else {
                deltas.add_target_penalty(base_reward);
            }

            if performance.previous_epoch_matching_head() {
                deltas.add_head_reward(attestation_component_reward(
                    statistics.previous_epoch_head_attesting_balance(),
                ));
            } else {
                deltas.add_head_penalty(base_reward);
            }

            if in_inactivity_leak {
                // > If validator is performing optimally this cancels all rewards for a neutral
                // > balance
                deltas.add_canceling_penalty(
                    BASE_REWARDS_PER_EPOCH.get() * base_reward - proposer_reward,
                );

                if !performance.previous_epoch_matching_target() {
                    deltas.add_inactivity_penalty(
                        effective_balance * finality_delay / P::INACTIVITY_PENALTY_QUOTIENT,
                    );
                }

                // > No rewards associated with inactivity penalties
            }
        }

        if let Some(inclusion) = performance.previous_epoch_fastest_inclusion() {
            let Inclusion {
                delay,
                proposer_index,
            } = inclusion;

            let proposer_index = usize::try_from(proposer_index)?;
            let max_attester_reward = base_reward - proposer_reward;

            deltas[proposer_index].add_proposer_reward(proposer_reward);
            deltas[index].add_inclusion_delay_reward(max_attester_reward / delay);

            // > No penalties associated with inclusion delay
        }
    }

    Ok(deltas)
}

#[cfg(test)]
mod spec_tests {
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::preset::{Mainnet, Minimal};

    use crate::unphased::TestDeltas;

    use super::*;

    #[test_resources("consensus-spec-tests/tests/mainnet/phase0/rewards/*/*/*")]
    fn mainnet(case: Case) {
        run_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/phase0/rewards/*/*/*")]
    fn minimal(case: Case) {
        run_case::<Minimal>(case);
    }

    fn run_case<P: Preset>(case: Case) {
        let state = case.ssz_default("pre");

        let (statistics, summaries, performance) = statistics::<P, StatisticsForReport>(&state)
            .expect("every rewards test should calculate statistics successfully");

        let deltas: Vec<EpochDeltasForReport> =
            epoch_deltas(&state, statistics, summaries, performance)
                .expect("every rewards test should calculate deltas successfully");

        TestDeltas::assert_equal(
            deltas.iter().map(|deltas| deltas.source_reward),
            deltas.iter().map(|deltas| deltas.source_penalty),
            case.ssz_default("source_deltas"),
        );

        TestDeltas::assert_equal(
            deltas.iter().map(|deltas| deltas.target_reward),
            deltas.iter().map(|deltas| deltas.target_penalty),
            case.ssz_default("target_deltas"),
        );

        TestDeltas::assert_equal(
            deltas.iter().map(|deltas| deltas.head_reward),
            deltas.iter().map(|deltas| deltas.head_penalty),
            case.ssz_default("head_deltas"),
        );

        TestDeltas::assert_equal(
            deltas
                .iter()
                .map(|deltas| deltas.proposer_reward + deltas.inclusion_delay_reward),
            core::iter::repeat_n(0, deltas.len()),
            case.ssz_default("inclusion_delay_deltas"),
        );

        TestDeltas::assert_equal(
            core::iter::repeat_n(0, deltas.len()),
            deltas
                .iter()
                .map(|deltas| deltas.canceling_penalty + deltas.inactivity_penalty),
            case.ssz_default("inactivity_penalty_deltas"),
        );
    }
}
