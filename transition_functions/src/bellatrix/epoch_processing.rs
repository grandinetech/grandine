use core::cell::LazyCell;

use anyhow::Result;
use arithmetic::{ArithmeticError, U64Ext as _};
use helper_functions::{
    accessors::{get_current_epoch, total_active_balance},
    misc::vec_of_default,
    mutators::decrease_balance,
};
use pubkey_cache::PubkeyCache;
use ssz::SszListMut as _;
use typenum::Unsigned as _;
use types::{
    bellatrix::beacon_state::BeaconState as BellatrixBeaconState, config::Config,
    phase0::primitives::Gwei, preset::Preset, traits::BeaconState,
};

use super::epoch_intermediates;
use crate::{
    altair::{self, EpochDeltasForTransition, EpochReport, ValidatorSummary},
    unphased::{self, SlashingPenalties},
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

pub fn process_epoch(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut BellatrixBeaconState<impl Preset>,
) -> Result<()> {
    #[cfg(feature = "metrics")]
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.epoch_processing_times.start_timer());

    // TODO(Grandine Team): Some parts of epoch processing could be done in parallel.
    let (statistics, mut summaries, participation) = altair::statistics_and_summaries(state)?;

    altair::process_justification_and_finalization(state, statistics)?;

    altair::process_inactivity_updates(
        config,
        state,
        summaries.iter().copied(),
        participation.iter().copied(),
    )?;

    // Epoch deltas must be computed after `process_justification_and_finalization` and
    // `process_inactivity_updates` because they depend on updated values of
    // `CapellaBeaconState.finalized_checkpoint` and `CapellaBeaconState.inactivity_scores`.
    //
    // Using `vec_of_default` in the genesis epoch does not improve performance.
    let epoch_deltas: Vec<EpochDeltasForTransition> = epoch_intermediates::epoch_deltas(
        config,
        state,
        statistics,
        summaries.iter().copied(),
        participation,
    )?;

    unphased::process_rewards_and_penalties(state, epoch_deltas)?;
    unphased::process_registry_updates(config, state, summaries.as_mut_slice())?;
    process_slashings::<_, ()>(state, summaries)?;
    unphased::process_eth1_data_reset(state)?;
    unphased::process_effective_balance_updates(state)?;
    unphased::process_slashings_reset(state)?;
    unphased::process_randao_mixes_reset(state)?;
    unphased::process_historical_roots_update(state)?;
    altair::process_participation_flag_updates(state);
    altair::process_sync_committee_updates(pubkey_cache, state)?;

    state.cache.advance_epoch();

    Ok(())
}

pub fn epoch_report<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut BellatrixBeaconState<P>,
) -> Result<EpochReport> {
    let (statistics, mut summaries, participation) = altair::statistics_and_summaries(state)?;

    altair::process_justification_and_finalization(state, statistics)?;

    altair::process_inactivity_updates(
        config,
        state,
        summaries.iter().copied(),
        participation.iter().copied(),
    )?;

    // Rewards and penalties are not applied in the genesis epoch. Return zero deltas for states in
    // the genesis epoch to avoid making misleading reports. The check cannot be done inside
    // `epoch_deltas` because some `rewards` test cases compute deltas in the genesis epoch.
    let epoch_deltas = if unphased::should_process_rewards_and_penalties(state) {
        epoch_intermediates::epoch_deltas(
            config,
            state,
            statistics,
            summaries.iter().copied(),
            participation,
        )?
    } else {
        vec_of_default(state)
    };

    unphased::process_rewards_and_penalties(state, epoch_deltas.iter().copied())?;
    unphased::process_registry_updates(config, state, summaries.as_mut_slice())?;

    let slashing_penalties = process_slashings(state, summaries.iter().copied())?;
    let post_balances = state.balances.into_iter().copied().collect();

    // Do the rest of epoch processing to leave the state valid for further transitions.
    // This way it can be used to calculate statistics for multiple epochs in a row.
    unphased::process_eth1_data_reset(state)?;
    unphased::process_effective_balance_updates(state)?;
    unphased::process_slashings_reset(state)?;
    unphased::process_randao_mixes_reset(state)?;
    unphased::process_historical_roots_update(state)?;
    altair::process_participation_flag_updates(state);
    altair::process_sync_committee_updates(pubkey_cache, state)?;

    state.cache.advance_epoch();

    Ok(EpochReport {
        statistics,
        summaries,
        epoch_deltas,
        slashing_penalties,
        post_balances,
    })
}

pub fn process_slashings<P: Preset, S: SlashingPenalties>(
    state: &mut impl BeaconState<P>,
    summaries: impl IntoIterator<Item = ValidatorSummary>,
) -> Result<S> {
    let current_epoch = get_current_epoch(state);
    let total_active_balance = total_active_balance(state);

    let (balances, slashings) = state.balances_mut_with_slashings();

    // Calculating this lazily saves 30-40 μs in typical networks.
    let adjusted_total_slashing_balance = LazyCell::new(|| -> Result<Gwei, ArithmeticError> {
        slashings
            .into_iter()
            .sum::<Gwei>()
            .try_mul(P::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX)
            .map(|balance| balance.min(total_active_balance))
    });

    let mut summaries = (0..).zip(summaries);
    let mut slashing_penalties = S::default();
    let mut update_result: Result<()> = Ok(());

    let mut apply_slashing = |balance: &mut Gwei| -> Result<()> {
        let (validator_index, summary) = summaries
            .next()
            .expect("list of validators and list of balances should have the same length");

        let ValidatorSummary {
            effective_balance,
            slashed,
            withdrawable_epoch,
            ..
        } = summary;

        if !slashed {
            return Ok(());
        }

        if current_epoch.try_add(P::EpochsPerSlashingsVector::U64 / 2)? != withdrawable_epoch {
            return Ok(());
        }

        // > Factored out from penalty numerator to avoid uint64 overflow
        let increment = P::EFFECTIVE_BALANCE_INCREMENT;
        let adjusted = (*adjusted_total_slashing_balance)?;
        let penalty_numerator = (effective_balance / increment).try_mul(adjusted)?;

        let penalty = penalty_numerator
            .try_div(total_active_balance)?
            .try_mul(increment.get())?;

        decrease_balance(balance, penalty);
        slashing_penalties.add(validator_index, penalty);

        Ok(())
    };

    balances.update(&mut |balance| {
        if update_result.is_err() {
            return;
        }

        update_result = apply_slashing(balance);
    });

    update_result?;

    Ok(slashing_penalties)
}

#[cfg(test)]
mod spec_tests {
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::preset::{Mainnet, Minimal};

    use super::*;

    // We do not honor `bls_setting` in epoch processing tests because none of them customize it.

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/justification_and_finalization/*/*"
    )]
    fn mainnet_justification_and_finalization(case: Case) {
        run_justification_and_finalization_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/justification_and_finalization/*/*"
    )]
    fn minimal_justification_and_finalization(case: Case) {
        run_justification_and_finalization_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/inactivity_updates/*/*"
    )]
    fn mainnet_inactivity_updates_updates(case: Case) {
        run_inactivity_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/inactivity_updates/*/*"
    )]
    fn minimal_inactivity_updates_updates(case: Case) {
        run_inactivity_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/rewards_and_penalties/*/*"
    )]
    fn mainnet_rewards_and_penalties(case: Case) {
        run_rewards_and_penalties_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/rewards_and_penalties/*/*"
    )]
    fn minimal_rewards_and_penalties(case: Case) {
        run_rewards_and_penalties_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/registry_updates/*/*"
    )]
    fn mainnet_registry_updates(case: Case) {
        run_registry_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/registry_updates/*/*"
    )]
    fn minimal_registry_updates(case: Case) {
        run_registry_updates_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/slashings/*/*")]
    fn mainnet_slashings(case: Case) {
        run_slashings_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/slashings/*/*")]
    fn minimal_slashings(case: Case) {
        run_slashings_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/eth1_data_reset/*/*"
    )]
    fn mainnet_eth1_data_reset(case: Case) {
        run_eth1_data_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/eth1_data_reset/*/*"
    )]
    fn minimal_eth1_data_reset(case: Case) {
        run_eth1_data_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/effective_balance_updates/*/*"
    )]
    fn mainnet_effective_balance_updates(case: Case) {
        run_effective_balance_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/effective_balance_updates/*/*"
    )]
    fn minimal_effective_balance_updates(case: Case) {
        run_effective_balance_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/slashings_reset/*/*"
    )]
    fn mainnet_slashings_reset(case: Case) {
        run_slashings_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/slashings_reset/*/*"
    )]
    fn minimal_slashings_reset(case: Case) {
        run_slashings_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/randao_mixes_reset/*/*"
    )]
    fn mainnet_randao_mixes_reset(case: Case) {
        run_randao_mixes_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/randao_mixes_reset/*/*"
    )]
    fn minimal_randao_mixes_reset(case: Case) {
        run_randao_mixes_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/historical_roots_update/*/*"
    )]
    fn mainnet_historical_roots_update(case: Case) {
        run_historical_roots_update_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/historical_roots_update/*/*"
    )]
    fn minimal_historical_roots_update(case: Case) {
        run_historical_roots_update_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/participation_flag_updates/*/*"
    )]
    fn mainnet_participation_flag_updates(case: Case) {
        run_participation_flag_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/participation_flag_updates/*/*"
    )]
    fn minimal_participation_flag_updates(case: Case) {
        run_participation_flag_updates_case::<Minimal>(case);
    }

    // There are no mainnet test cases for the `sync_committee_updates` sub-transition.
    #[test_resources(
        "consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/sync_committee_updates/*/*"
    )]
    fn minimal_sync_committee_updates(case: Case) {
        run_sync_committee_updates_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/bellatrix/epoch_processing/*/*/*")]
    fn mainnet_epoch_processing(case: Case) {
        run_epoch_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/bellatrix/epoch_processing/*/*/*")]
    fn minimal_epoch_processing(case: Case) {
        run_epoch_case::<Minimal>(case);
    }

    fn run_justification_and_finalization_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            let (statistics, _, _) = altair::statistics_and_summaries(state)?;

            altair::process_justification_and_finalization(state, statistics)
        });

        run_case::<P>(case, |_, state| {
            let statistics = altair::statistics(state)?;

            altair::process_justification_and_finalization(state, statistics)
        });
    }

    fn run_inactivity_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            let (_, summaries, participation) = altair::statistics_and_summaries(state)?;

            altair::process_inactivity_updates(
                &P::default_config(),
                state,
                summaries,
                participation,
            )
        });
    }

    fn run_rewards_and_penalties_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            let (statistics, summaries, participation) = altair::statistics_and_summaries(state)?;

            let deltas: Vec<EpochDeltasForTransition> = epoch_intermediates::epoch_deltas(
                &P::default_config(),
                state,
                statistics,
                summaries,
                participation,
            )?;

            unphased::process_rewards_and_penalties(state, deltas)
        });
    }

    fn run_registry_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            let mut summaries: Vec<ValidatorSummary> = vec_of_default(state);

            unphased::process_registry_updates(
                &P::default_config(),
                state,
                summaries.as_mut_slice(),
            )
        });
    }

    fn run_slashings_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            let (_, summaries, _) = altair::statistics_and_summaries(state)?;

            process_slashings::<_, ()>(state, summaries)
        });
    }

    fn run_eth1_data_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| unphased::process_eth1_data_reset(state));
    }

    fn run_effective_balance_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            unphased::process_effective_balance_updates(state)
        });
    }

    fn run_slashings_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| unphased::process_slashings_reset(state));
    }

    fn run_randao_mixes_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| unphased::process_randao_mixes_reset(state));
    }

    fn run_historical_roots_update_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            unphased::process_historical_roots_update(state)
        });
    }

    fn run_participation_flag_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            altair::process_participation_flag_updates(state);

            Ok(())
        });
    }

    fn run_sync_committee_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, altair::process_sync_committee_updates);
    }

    fn run_case<P: Preset>(
        case: Case,
        sub_transition: impl FnOnce(&PubkeyCache, &mut BellatrixBeaconState<P>) -> Result<()>,
    ) {
        let pubkey_cache = PubkeyCache::default();
        let mut state = case.ssz_default("pre");
        let post_option = case.try_ssz_default("post");

        let result = sub_transition(&pubkey_cache, &mut state).map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("epoch processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("epoch processing should fail");
        }
    }

    fn run_epoch_case<P: Preset>(case: Case) {
        let pubkey_cache = PubkeyCache::default();
        // Some sub-transition test cases (e.g. `effective_balance_updates/effective_balance_hysteresis`,
        // `slashings/{minimal_penalty,scaled_penalties}`) don't ship `pre_epoch`/`post_epoch` SSZ files
        // because they aren't valid full-epoch transitions. Skip them.
        let Some(mut state) = case.try_ssz_default::<BellatrixBeaconState<P>>("pre_epoch") else {
            return;
        };
        let post_option: Option<BellatrixBeaconState<P>> = case.try_ssz_default("post_epoch");

        let result = process_epoch(&P::default_config(), &pubkey_cache, &mut state).map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("epoch processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("epoch processing should fail");
        }
    }
}
