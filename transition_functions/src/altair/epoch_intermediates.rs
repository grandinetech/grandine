use helper_functions::{
    accessors::{
        combined_participation, compute_base_reward, get_base_reward_per_increment,
        get_current_epoch, get_previous_epoch, total_active_balance,
    },
    mutators::clamp_balance,
    predicates::{is_active_validator, is_eligible_for_penalties, is_in_inactivity_leak},
};
use itertools::izip;
use serde::Serialize;
use static_assertions::assert_eq_size;
use types::{
    altair::{
        beacon_state::BeaconState,
        consts::{
            TIMELY_HEAD_WEIGHT, TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_WEIGHT, WEIGHT_DENOMINATOR,
        },
    },
    config::Config,
    nonstandard::Participation,
    phase0::{
        containers::Validator,
        primitives::{Epoch, Gwei},
    },
    preset::Preset,
    traits::PostAltairBeaconState,
};

use crate::unphased::{EpochDeltas, ValidatorSummary};

pub trait AltairEpochDeltas: Default {
    fn add_source_reward(&mut self, value: Gwei);
    fn add_source_penalty(&mut self, value: Gwei);
    fn add_target_reward(&mut self, value: Gwei);
    fn add_target_penalty(&mut self, value: Gwei);
    fn add_head_reward(&mut self, value: Gwei);
    fn add_inactivity_penalty(&mut self, value: Gwei);
}

#[derive(Clone, Copy, Debug, Serialize)]
#[cfg_attr(test, derive(Default))]
pub struct AltairValidatorSummary {
    pub effective_balance: Gwei,
    pub slashed: bool,
    pub withdrawable_epoch: Epoch,
    // Storing `activation_epoch` and `exit_epoch` is more general but caused a measurable slowdown
    // in Phase 0 and requires duplicating the implementation of `is_active_validator`.
    pub active_in_previous_epoch: bool,
    pub eligible_for_penalties: bool,
}

assert_eq_size!(AltairValidatorSummary, [u64; 3]);

impl ValidatorSummary for AltairValidatorSummary {
    // This does not update derived fields because `process_slashings` does not use them.
    fn update_from(&mut self, validator: &Validator) {
        self.effective_balance = validator.effective_balance;
        self.slashed = validator.slashed;
        self.withdrawable_epoch = validator.withdrawable_epoch;
    }
}

// This has no field for the active balance in the current epoch because during most epoch
// transitions it should already be calculated and cached in `Cache.total_active_balance`.
#[expect(clippy::struct_field_names)]
#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct Statistics {
    pub previous_epoch_source_participating_balance: Gwei,
    pub previous_epoch_target_participating_balance: Gwei,
    pub previous_epoch_head_participating_balance: Gwei,
    pub current_epoch_target_participating_balance: Gwei,
}

impl Statistics {
    fn clamp_balances<P: Preset>(&mut self) {
        clamp_balance::<P>(&mut self.previous_epoch_source_participating_balance);
        clamp_balance::<P>(&mut self.previous_epoch_target_participating_balance);
        clamp_balance::<P>(&mut self.previous_epoch_head_participating_balance);
        clamp_balance::<P>(&mut self.current_epoch_target_participating_balance);
    }
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

impl AltairEpochDeltas for EpochDeltasForTransition {
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

    fn add_inactivity_penalty(&mut self, value: Gwei) {
        self.penalty += value;
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct EpochDeltasForReport {
    pub source_reward: Gwei,
    pub source_penalty: Gwei,
    pub target_reward: Gwei,
    pub target_penalty: Gwei,
    pub head_reward: Gwei,
    pub inactivity_penalty: Gwei,
}

impl EpochDeltas for EpochDeltasForReport {
    fn combined_reward(self) -> Gwei {
        self.source_reward + self.target_reward + self.head_reward
    }

    fn combined_penalty(self) -> Gwei {
        self.source_penalty + self.target_penalty + self.inactivity_penalty
    }
}

impl AltairEpochDeltas for EpochDeltasForReport {
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

    fn add_inactivity_penalty(&mut self, value: Gwei) {
        self.inactivity_penalty += value;
    }
}

pub fn statistics<P: Preset, S: PostAltairBeaconState<P>>(
    state: &S,
) -> (Statistics, Vec<AltairValidatorSummary>, Vec<Participation>) {
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);
    let participation = combined_participation(state);

    let mut statistics = Statistics::default();

    let summaries = state
        .validators()
        .into_iter()
        .zip(participation.iter().copied())
        .map(|(validator, participation)| {
            let Validator {
                effective_balance,
                slashed,
                withdrawable_epoch,
                ..
            } = *validator;

            let active_in_previous_epoch = is_active_validator(validator, previous_epoch);
            let active_in_current_epoch = is_active_validator(validator, current_epoch);
            let eligible_for_penalties = is_eligible_for_penalties(validator, previous_epoch);

            if !slashed {
                // Unlike `get_unslashed_attesting_indices` in Phase 0,
                // `get_unslashed_participating_indices` in Altair checks if validators were active.
                // There doesn't seem to be a way for a validator that's not active to attest in
                // normal operation, but some test cases in `consensus-spec-tests` cover the check.

                if active_in_previous_epoch {
                    if participation.previous_epoch_matching_source() {
                        statistics.previous_epoch_source_participating_balance += effective_balance;
                    }

                    if participation.previous_epoch_matching_target() {
                        statistics.previous_epoch_target_participating_balance += effective_balance;
                    }

                    if participation.previous_epoch_matching_head() {
                        statistics.previous_epoch_head_participating_balance += effective_balance;
                    }
                }

                if active_in_current_epoch && participation.current_epoch_matching_target() {
                    statistics.current_epoch_target_participating_balance += effective_balance;
                }
            }

            AltairValidatorSummary {
                effective_balance,
                slashed,
                withdrawable_epoch,
                active_in_previous_epoch,
                eligible_for_penalties,
            }
        })
        .collect();

    statistics.clamp_balances::<P>();

    (statistics, summaries, participation)
}

pub fn epoch_deltas<P: Preset, D: AltairEpochDeltas>(
    config: &Config,
    state: &BeaconState<P>,
    statistics: Statistics,
    summaries: impl IntoIterator<Item = AltairValidatorSummary>,
    participation: impl IntoIterator<Item = Participation>,
) -> Vec<D> {
    let in_inactivity_leak = is_in_inactivity_leak(state);
    let base_reward_per_increment = get_base_reward_per_increment(state);

    let increment = P::EFFECTIVE_BALANCE_INCREMENT;
    let source_increments = statistics.previous_epoch_source_participating_balance / increment;
    let target_increments = statistics.previous_epoch_target_participating_balance / increment;
    let head_increments = statistics.previous_epoch_head_participating_balance / increment;
    let active_increments = total_active_balance(state) / increment;

    izip!(summaries, participation, &state.inactivity_scores)
        .map(|(summary, participation, inactivity_score)| {
            let mut deltas = D::default();

            let AltairValidatorSummary {
                effective_balance,
                slashed,
                eligible_for_penalties,
                ..
            } = summary;

            if !eligible_for_penalties {
                return deltas;
            }

            let base_reward =
                compute_base_reward::<P>(effective_balance, base_reward_per_increment);

            let participation_component_reward = |weight, unslashed_participating_increments| {
                let reward_numerator = base_reward * weight * unslashed_participating_increments;
                let reward_denominator = active_increments * WEIGHT_DENOMINATOR.get();
                reward_numerator / reward_denominator
            };

            let participation_component_penalty =
                |weight| base_reward * weight / WEIGHT_DENOMINATOR;

            if !slashed && participation.previous_epoch_matching_source() {
                if !in_inactivity_leak {
                    deltas.add_source_reward(participation_component_reward(
                        TIMELY_SOURCE_WEIGHT,
                        source_increments,
                    ));
                }
            } else {
                deltas.add_source_penalty(participation_component_penalty(TIMELY_SOURCE_WEIGHT));
            }

            if !slashed && participation.previous_epoch_matching_target() {
                if !in_inactivity_leak {
                    deltas.add_target_reward(participation_component_reward(
                        TIMELY_TARGET_WEIGHT,
                        target_increments,
                    ));
                }
            } else {
                deltas.add_target_penalty(participation_component_penalty(TIMELY_TARGET_WEIGHT));

                let penalty_numerator = effective_balance * inactivity_score;
                let penalty_denominator = config.inactivity_score_bias.get()
                    * P::INACTIVITY_PENALTY_QUOTIENT_ALTAIR.get();

                deltas.add_inactivity_penalty(penalty_numerator / penalty_denominator);
            }

            if !slashed && participation.previous_epoch_matching_head() && !in_inactivity_leak {
                deltas.add_head_reward(participation_component_reward(
                    TIMELY_HEAD_WEIGHT,
                    head_increments,
                ));
            }

            deltas
        })
        .collect()
}

#[cfg(test)]
mod spec_tests {
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::{
        altair::beacon_state::BeaconState,
        preset::{Mainnet, Minimal},
    };

    use crate::unphased::TestDeltas;

    use super::*;

    #[test_resources("consensus-spec-tests/tests/mainnet/altair/rewards/*/*/*")]
    fn mainnet(case: Case) {
        run_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/altair/rewards/*/*/*")]
    fn minimal(case: Case) {
        run_case::<Minimal>(case);
    }

    fn run_case<P: Preset>(case: Case) {
        let state = case.ssz_default::<BeaconState<P>>("pre");

        let (statistics, summaries, participation) = statistics(&state);

        let epoch_deltas: Vec<EpochDeltasForReport> = epoch_deltas(
            &P::default_config(),
            &state,
            statistics,
            summaries,
            participation,
        );

        TestDeltas::assert_equal(
            epoch_deltas.iter().map(|deltas| deltas.source_reward),
            epoch_deltas.iter().map(|deltas| deltas.source_penalty),
            case.ssz_default("source_deltas"),
        );

        TestDeltas::assert_equal(
            epoch_deltas.iter().map(|deltas| deltas.target_reward),
            epoch_deltas.iter().map(|deltas| deltas.target_penalty),
            case.ssz_default("target_deltas"),
        );

        TestDeltas::assert_equal(
            epoch_deltas.iter().map(|deltas| deltas.head_reward),
            core::iter::repeat_n(0, epoch_deltas.len()),
            case.ssz_default("head_deltas"),
        );

        TestDeltas::assert_equal(
            core::iter::repeat_n(0, epoch_deltas.len()),
            epoch_deltas.iter().map(|deltas| deltas.inactivity_penalty),
            case.ssz_default("inactivity_penalty_deltas"),
        );
    }
}
