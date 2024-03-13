use helper_functions::{
    accessors::{compute_base_reward, get_base_reward_per_increment, total_active_balance},
    predicates::is_in_inactivity_leak,
};
use itertools::izip;
use types::{
    altair::consts::{
        TIMELY_HEAD_WEIGHT, TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_WEIGHT, WEIGHT_DENOMINATOR,
    },
    config::Config,
    deneb::beacon_state::BeaconState,
    nonstandard::Participation,
    preset::Preset,
};

use crate::altair::{EpochDeltas, Statistics, ValidatorSummary};

pub fn epoch_deltas<P: Preset, D: EpochDeltas>(
    config: &Config,
    state: &BeaconState<P>,
    statistics: Statistics,
    summaries: impl IntoIterator<Item = ValidatorSummary>,
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

            let ValidatorSummary {
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
                    * P::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX.get();

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
    use types::preset::{Mainnet, Minimal};

    use crate::{
        altair::{self, EpochDeltasForReport},
        unphased::TestDeltas,
    };

    use super::*;

    #[test_resources("consensus-spec-tests/tests/mainnet/deneb/rewards/*/*/*")]
    fn mainnet(case: Case) {
        run_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/deneb/rewards/*/*/*")]
    fn minimal(case: Case) {
        run_case::<Minimal>(case);
    }

    fn run_case<P: Preset>(case: Case) {
        let state = case.ssz_default::<BeaconState<P>>("pre");

        let (statistics, summaries, participation) = altair::statistics(&state);

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
            itertools::repeat_n(0, epoch_deltas.len()),
            case.ssz_default("head_deltas"),
        );

        TestDeltas::assert_equal(
            itertools::repeat_n(0, epoch_deltas.len()),
            epoch_deltas.iter().map(|deltas| deltas.inactivity_penalty),
            case.ssz_default("inactivity_penalty_deltas"),
        );
    }
}
