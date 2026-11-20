use core::num::NonZeroU64;

use anyhow::{Error, Result};
use arithmetic::{NonZeroU64Ext as _, U64Ext as _};
use bit_field::BitField as _;
use helper_functions::{
    accessors::{
        combined_participation, compute_base_reward, compute_base_reward_per_increment,
        get_current_epoch, get_previous_epoch, total_active_balance,
    },
    mutators::clamp_balance,
    predicates::{is_active_validator, is_eligible_for_penalties, is_in_inactivity_leak},
};
use itertools::izip;
use serde::Serialize;
use types::{
    altair::{
        consts::{
            TIMELY_HEAD_FLAG_INDEX, TIMELY_HEAD_WEIGHT, TIMELY_SOURCE_FLAG_INDEX,
            TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_FLAG_INDEX, TIMELY_TARGET_WEIGHT,
            WEIGHT_DENOMINATOR,
        },
        primitives::ParticipationFlags,
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

#[cfg(target_arch = "x86_64")]
use static_assertions::assert_eq_size;

pub trait AltairEpochDeltas: Default {
    fn add_source_reward(&mut self, value: Gwei) -> Result<()>;
    fn add_source_penalty(&mut self, value: Gwei) -> Result<()>;
    fn add_target_reward(&mut self, value: Gwei) -> Result<()>;
    fn add_target_penalty(&mut self, value: Gwei) -> Result<()>;
    fn add_head_reward(&mut self, value: Gwei) -> Result<()>;
    fn add_inactivity_penalty(&mut self, value: Gwei) -> Result<()>;
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

#[cfg(target_arch = "x86_64")]
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
    fn combined_reward(self) -> Result<Gwei> {
        Ok(self.reward)
    }

    fn combined_penalty(self) -> Result<Gwei> {
        Ok(self.penalty)
    }
}

impl AltairEpochDeltas for EpochDeltasForTransition {
    fn add_source_reward(&mut self, value: Gwei) -> Result<()> {
        self.reward = self.reward.try_add(value)?;
        Ok(())
    }

    fn add_source_penalty(&mut self, value: Gwei) -> Result<()> {
        self.penalty = self.penalty.try_add(value)?;
        Ok(())
    }

    fn add_target_reward(&mut self, value: Gwei) -> Result<()> {
        self.reward = self.reward.try_add(value)?;
        Ok(())
    }

    fn add_target_penalty(&mut self, value: Gwei) -> Result<()> {
        self.penalty = self.penalty.try_add(value)?;
        Ok(())
    }

    fn add_head_reward(&mut self, value: Gwei) -> Result<()> {
        self.reward = self.reward.try_add(value)?;
        Ok(())
    }

    fn add_inactivity_penalty(&mut self, value: Gwei) -> Result<()> {
        self.penalty = self.penalty.try_add(value)?;
        Ok(())
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
    fn combined_reward(self) -> Result<Gwei> {
        self.source_reward
            .try_add(self.target_reward)?
            .try_add(self.head_reward)
            .map_err(Into::into)
    }

    fn combined_penalty(self) -> Result<Gwei> {
        self.source_penalty
            .try_add(self.target_penalty)?
            .try_add(self.inactivity_penalty)
            .map_err(Into::into)
    }
}

impl AltairEpochDeltas for EpochDeltasForReport {
    fn add_source_reward(&mut self, value: Gwei) -> Result<()> {
        self.source_reward = self.source_reward.try_add(value)?;
        Ok(())
    }

    fn add_source_penalty(&mut self, value: Gwei) -> Result<()> {
        self.source_penalty = self.source_penalty.try_add(value)?;
        Ok(())
    }

    fn add_target_reward(&mut self, value: Gwei) -> Result<()> {
        self.target_reward = self.target_reward.try_add(value)?;
        Ok(())
    }

    fn add_target_penalty(&mut self, value: Gwei) -> Result<()> {
        self.target_penalty = self.target_penalty.try_add(value)?;
        Ok(())
    }

    fn add_head_reward(&mut self, value: Gwei) -> Result<()> {
        self.head_reward = self.head_reward.try_add(value)?;
        Ok(())
    }

    fn add_inactivity_penalty(&mut self, value: Gwei) -> Result<()> {
        self.inactivity_penalty = self.inactivity_penalty.try_add(value)?;
        Ok(())
    }
}

pub fn statistics_and_summaries<P: Preset, S: PostAltairBeaconState<P>>(
    state: &S,
) -> Result<(Statistics, Vec<AltairValidatorSummary>, Vec<Participation>)> {
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);
    let participation = combined_participation(state);

    let mut statistics = Statistics::default();

    let summaries = izip!(
        state.validators().partial_validators(),
        state.validators().effective_balances().copied(),
        participation.iter().copied(),
    )
    .map(
        |(validator, effective_balance, participation)| -> Result<AltairValidatorSummary> {
            let slashed = validator.slashed;
            let withdrawable_epoch = validator.withdrawable_epoch;

            let active_in_previous_epoch = is_active_validator(validator, previous_epoch);
            let active_in_current_epoch = is_active_validator(validator, current_epoch);
            let eligible_for_penalties = is_eligible_for_penalties(validator, previous_epoch)?;

            if !slashed {
                // Unlike `get_unslashed_attesting_indices` in Phase 0,
                // `get_unslashed_participating_indices` in Altair checks if validators were active.
                // There doesn't seem to be a way for a validator that's not active to attest in
                // normal operation, but some test cases in `consensus-spec-tests` cover the check.

                if active_in_previous_epoch {
                    if participation.previous_epoch_matching_source() {
                        statistics.previous_epoch_source_participating_balance = statistics
                            .previous_epoch_source_participating_balance
                            .try_add(effective_balance)?;
                    }

                    if participation.previous_epoch_matching_target() {
                        statistics.previous_epoch_target_participating_balance = statistics
                            .previous_epoch_target_participating_balance
                            .try_add(effective_balance)?;
                    }

                    if participation.previous_epoch_matching_head() {
                        statistics.previous_epoch_head_participating_balance = statistics
                            .previous_epoch_head_participating_balance
                            .try_add(effective_balance)?;
                    }
                }

                if active_in_current_epoch && participation.current_epoch_matching_target() {
                    statistics.current_epoch_target_participating_balance = statistics
                        .current_epoch_target_participating_balance
                        .try_add(effective_balance)?;
                }
            }

            Ok(AltairValidatorSummary {
                effective_balance,
                slashed,
                withdrawable_epoch,
                active_in_previous_epoch,
                eligible_for_penalties,
            })
        },
    )
    .collect::<Result<Vec<_>>>()?;

    statistics.clamp_balances::<P>();

    Ok((statistics, summaries, participation))
}

pub fn statistics<P: Preset, S: PostAltairBeaconState<P>>(state: &S) -> Result<Statistics> {
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);

    let mut statistics = Statistics::default();

    izip!(
        state.validators().partial_validators(),
        state.validators().effective_balances().copied(),
        state.previous_epoch_participation(),
        state.current_epoch_participation(),
    )
    .filter(|(validator, _, _, _)| !validator.slashed)
    .try_for_each(
        |(
            validator,
            effective_balance,
            previous_epoch_participation,
            current_epoch_participation,
        )| {
            let active_in_previous_epoch = is_active_validator(validator, previous_epoch);
            let active_in_current_epoch = is_active_validator(validator, current_epoch);

            if active_in_previous_epoch {
                if previous_epoch_participation.get_bit(TIMELY_SOURCE_FLAG_INDEX) {
                    statistics.previous_epoch_source_participating_balance = statistics
                        .previous_epoch_source_participating_balance
                        .try_add(effective_balance)?;
                }

                if previous_epoch_participation.get_bit(TIMELY_TARGET_FLAG_INDEX) {
                    statistics.previous_epoch_target_participating_balance = statistics
                        .previous_epoch_target_participating_balance
                        .try_add(effective_balance)?;
                }

                if previous_epoch_participation.get_bit(TIMELY_HEAD_FLAG_INDEX) {
                    statistics.previous_epoch_head_participating_balance = statistics
                        .previous_epoch_head_participating_balance
                        .try_add(effective_balance)?;
                }
            }

            if active_in_current_epoch
                && current_epoch_participation.get_bit(TIMELY_TARGET_FLAG_INDEX)
            {
                statistics.current_epoch_target_participating_balance = statistics
                    .current_epoch_target_participating_balance
                    .try_add(effective_balance)?;
            }

            Ok::<(), Error>(())
        },
    )?;

    statistics.clamp_balances::<P>();

    Ok(statistics)
}

pub trait RewardSummary: Copy {
    fn effective_balance(self) -> Gwei;
    fn slashed(self) -> bool;
    fn eligible_for_penalties(self) -> bool;
}

impl RewardSummary for AltairValidatorSummary {
    fn effective_balance(self) -> Gwei {
        self.effective_balance
    }

    fn slashed(self) -> bool {
        self.slashed
    }

    fn eligible_for_penalties(self) -> bool {
        self.eligible_for_penalties
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EpochRewardScalars {
    pub in_inactivity_leak: bool,
    pub total_active_balance: Gwei,
    pub source_balance: Gwei,
    pub target_balance: Gwei,
    pub head_balance: Gwei,
}

impl EpochRewardScalars {
    pub fn new<P: Preset>(
        state: &impl PostAltairBeaconState<P>,
        statistics: Statistics,
    ) -> Result<Self> {
        Ok(Self {
            in_inactivity_leak: is_in_inactivity_leak(state)?,
            total_active_balance: total_active_balance(state),
            source_balance: statistics.previous_epoch_source_participating_balance,
            target_balance: statistics.previous_epoch_target_participating_balance,
            head_balance: statistics.previous_epoch_head_participating_balance,
        })
    }
}

pub fn epoch_deltas<P: Preset, D: AltairEpochDeltas>(
    config: &Config,
    inactivity_penalty_quotient: NonZeroU64,
    scalars: EpochRewardScalars,
    summaries: impl IntoIterator<Item = impl RewardSummary>,
    participation: impl IntoIterator<Item = ParticipationFlags>,
    inactivity_scores: impl IntoIterator<Item = u64>,
) -> Result<Vec<D>> {
    let EpochRewardScalars {
        in_inactivity_leak,
        total_active_balance,
        source_balance,
        target_balance,
        head_balance,
    } = scalars;

    let base_reward_per_increment = compute_base_reward_per_increment::<P>(total_active_balance)?;

    let increment = P::EFFECTIVE_BALANCE_INCREMENT;
    let source_increments = source_balance / increment;
    let target_increments = target_balance / increment;
    let head_increments = head_balance / increment;
    let active_increments = total_active_balance / increment;

    izip!(summaries, participation, inactivity_scores)
        .map(|(summary, participation, inactivity_score)| -> Result<D> {
            let mut deltas = D::default();

            let effective_balance = summary.effective_balance();
            let slashed = summary.slashed();

            if !summary.eligible_for_penalties() {
                return Ok(deltas);
            }

            let base_reward =
                compute_base_reward::<P>(effective_balance, base_reward_per_increment)?;

            let participation_component_reward =
                |weight, unslashed_participating_increments| -> Result<u64> {
                    let reward_numerator = base_reward
                        .try_mul(weight)?
                        .try_mul(unslashed_participating_increments)?;

                    let reward_denominator = active_increments.try_mul(WEIGHT_DENOMINATOR.get())?;

                    reward_numerator
                        .try_div(reward_denominator)
                        .map_err(Into::into)
                };

            let participation_component_penalty =
                |weight| -> Result<Gwei> { Ok(base_reward.try_mul(weight)? / WEIGHT_DENOMINATOR) };

            if !slashed && participation.get_bit(TIMELY_SOURCE_FLAG_INDEX) {
                if !in_inactivity_leak {
                    deltas.add_source_reward(participation_component_reward(
                        TIMELY_SOURCE_WEIGHT,
                        source_increments,
                    )?)?;
                }
            } else {
                deltas
                    .add_source_penalty(participation_component_penalty(TIMELY_SOURCE_WEIGHT)?)?;
            }

            if !slashed && participation.get_bit(TIMELY_TARGET_FLAG_INDEX) {
                if !in_inactivity_leak {
                    deltas.add_target_reward(participation_component_reward(
                        TIMELY_TARGET_WEIGHT,
                        target_increments,
                    )?)?;
                }
            } else {
                deltas
                    .add_target_penalty(participation_component_penalty(TIMELY_TARGET_WEIGHT)?)?;

                let penalty_numerator = effective_balance.try_mul(inactivity_score)?;
                let penalty_denominator = config
                    .inactivity_score_bias
                    .try_mul(inactivity_penalty_quotient)?;

                deltas.add_inactivity_penalty(penalty_numerator / penalty_denominator)?;
            }

            if !slashed && participation.get_bit(TIMELY_HEAD_FLAG_INDEX) && !in_inactivity_leak {
                deltas.add_head_reward(participation_component_reward(
                    TIMELY_HEAD_WEIGHT,
                    head_increments,
                )?)?;
            }

            Ok(deltas)
        })
        .collect()
}

#[cfg(test)]
mod spec_tests {
    use duplicate::duplicate_item;
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::preset::{Mainnet, Minimal};

    use crate::unphased::TestDeltas;

    use super::*;

    #[duplicate_item(
        glob                                                           function_name       preset    state_type                                             quotient;
        ["consensus-spec-tests/tests/mainnet/altair/rewards/*/*/*"]    [altair_mainnet]    [Mainnet] [types::altair::beacon_state::BeaconState<Mainnet>]    [INACTIVITY_PENALTY_QUOTIENT_ALTAIR];
        ["consensus-spec-tests/tests/minimal/altair/rewards/*/*/*"]    [altair_minimal]    [Minimal] [types::altair::beacon_state::BeaconState<Minimal>]    [INACTIVITY_PENALTY_QUOTIENT_ALTAIR];
        ["consensus-spec-tests/tests/mainnet/bellatrix/rewards/*/*/*"] [bellatrix_mainnet] [Mainnet] [types::bellatrix::beacon_state::BeaconState<Mainnet>] [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/minimal/bellatrix/rewards/*/*/*"] [bellatrix_minimal] [Minimal] [types::bellatrix::beacon_state::BeaconState<Minimal>] [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/mainnet/capella/rewards/*/*/*"]   [capella_mainnet]   [Mainnet] [types::capella::beacon_state::BeaconState<Mainnet>]   [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/minimal/capella/rewards/*/*/*"]   [capella_minimal]   [Minimal] [types::capella::beacon_state::BeaconState<Minimal>]   [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/mainnet/deneb/rewards/*/*/*"]     [deneb_mainnet]     [Mainnet] [types::deneb::beacon_state::BeaconState<Mainnet>]     [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/minimal/deneb/rewards/*/*/*"]     [deneb_minimal]     [Minimal] [types::deneb::beacon_state::BeaconState<Minimal>]     [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/mainnet/electra/rewards/*/*/*"]   [electra_mainnet]   [Mainnet] [types::electra::beacon_state::BeaconState<Mainnet>]   [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/minimal/electra/rewards/*/*/*"]   [electra_minimal]   [Minimal] [types::electra::beacon_state::BeaconState<Minimal>]   [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/mainnet/fulu/rewards/*/*/*"]      [fulu_mainnet]      [Mainnet] [types::fulu::beacon_state::BeaconState<Mainnet>]      [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/minimal/fulu/rewards/*/*/*"]      [fulu_minimal]      [Minimal] [types::fulu::beacon_state::BeaconState<Minimal>]      [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/mainnet/gloas/rewards/*/*/*"]     [gloas_mainnet]     [Mainnet] [types::gloas::beacon_state::BeaconState<Mainnet>]     [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
        ["consensus-spec-tests/tests/minimal/gloas/rewards/*/*/*"]     [gloas_minimal]     [Minimal] [types::gloas::beacon_state::BeaconState<Minimal>]     [INACTIVITY_PENALTY_QUOTIENT_BELLATRIX];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        let state = case.ssz_default::<state_type>("pre");

        run_case::<preset>(case, &state, preset::quotient)
            .expect("rewards test should not return an error")
    }

    fn run_case<P: Preset>(
        case: Case,
        state: &impl PostAltairBeaconState<P>,
        inactivity_penalty_quotient: NonZeroU64,
    ) -> Result<()> {
        let (statistics, summaries, participation) = statistics_and_summaries(state)?;

        let epoch_deltas: Vec<EpochDeltasForReport> = epoch_deltas::<P, _>(
            &P::default_config(),
            inactivity_penalty_quotient,
            EpochRewardScalars::new(state, statistics)?,
            summaries,
            participation
                .iter()
                .map(|participation| participation.previous),
            state.inactivity_scores().into_iter().copied(),
        )?;

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

        Ok(())
    }
}
