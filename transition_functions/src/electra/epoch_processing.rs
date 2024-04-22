use anyhow::Result;
use arithmetic::{NonZeroExt as _, U64Ext as _};
use helper_functions::{
    accessors::{
        get_activation_exit_churn_limit, get_active_balance, get_current_epoch, get_next_epoch,
    },
    electra::{initiate_validator_exit, is_eligible_for_activation_queue},
    misc::{compute_activation_exit_epoch, vec_of_default},
    mutators::{balance, decrease_balance, increase_balance, switch_to_compounding_validator},
    predicates::{
        has_compounding_withdrawal_credential, is_active_validator, is_eligible_for_activation,
    },
};
use prometheus_metrics::METRICS;
use ssz::{PersistentList, SszHash as _};
use try_from_iterator::TryFromIterator as _;
use types::{
    capella::containers::HistoricalSummary,
    config::Config,
    electra::beacon_state::BeaconState,
    preset::Preset,
    traits::{BeaconState as _, PostElectraBeaconState},
};

use super::epoch_intermediates;
use crate::{
    altair::{self, EpochDeltasForTransition, EpochReport},
    bellatrix, unphased,
    unphased::ValidatorSummary,
};

pub fn process_epoch(config: &Config, state: &mut BeaconState<impl Preset>) -> Result<()> {
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.epoch_processing_times.start_timer());

    // TODO(Grandine Team): Some parts of epoch processing could be done in parallel.

    let (statistics, mut summaries, participation) = altair::statistics(state);

    altair::process_justification_and_finalization(state, statistics);

    altair::process_inactivity_updates(
        config,
        state,
        summaries.iter().copied(),
        participation.iter().copied(),
    );

    // Epoch deltas must be computed after `process_justification_and_finalization` and
    // `process_inactivity_updates` because they depend on updated values of
    // `BeaconState.finalized_checkpoint` and `BeaconState.inactivity_scores`.
    //
    // Using `vec_of_default` in the genesis epoch does not improve performance.
    let epoch_deltas: Vec<EpochDeltasForTransition> = epoch_intermediates::epoch_deltas(
        config,
        state,
        statistics,
        summaries.iter().copied(),
        participation,
    );

    unphased::process_rewards_and_penalties(state, epoch_deltas);
    process_registry_updates(config, state, summaries.as_mut_slice())?;
    bellatrix::process_slashings::<_, ()>(state, summaries);
    unphased::process_eth1_data_reset(state);
    process_pending_balance_deposits(config, state)?;
    process_pending_consolidations(state)?;
    process_effective_balance_updates(state);
    unphased::process_slashings_reset(state);
    unphased::process_randao_mixes_reset(state);

    // > [Modified in Capella]
    process_historical_summaries_update(state)?;

    altair::process_participation_flag_updates(state);
    altair::process_sync_committee_updates(state)?;

    state.cache.advance_epoch();

    Ok(())
}

pub fn epoch_report<P: Preset>(config: &Config, state: &mut BeaconState<P>) -> Result<EpochReport> {
    let (statistics, mut summaries, participation) = altair::statistics(state);

    altair::process_justification_and_finalization(state, statistics);

    altair::process_inactivity_updates(
        config,
        state,
        summaries.iter().copied(),
        participation.iter().copied(),
    );

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
        )
    } else {
        vec_of_default(state)
    };

    unphased::process_rewards_and_penalties(state, epoch_deltas.iter().copied());
    process_registry_updates(config, state, summaries.as_mut_slice())?;

    let slashing_penalties = bellatrix::process_slashings(state, summaries.iter().copied());
    let post_balances = state.balances.into_iter().copied().collect();

    // Do the rest of epoch processing to leave the state valid for further transitions.
    // This way it can be used to calculate statistics for multiple epochs in a row.
    unphased::process_eth1_data_reset(state);
    process_effective_balance_updates(state);
    unphased::process_slashings_reset(state);
    unphased::process_randao_mixes_reset(state);
    unphased::process_historical_roots_update(state)?;
    altair::process_participation_flag_updates(state);
    altair::process_sync_committee_updates(state)?;

    state.cache.advance_epoch();

    Ok(EpochReport {
        statistics,
        summaries,
        epoch_deltas,
        slashing_penalties,
        post_balances,
    })
}

fn process_registry_updates<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    summaries: &mut [impl ValidatorSummary],
) -> Result<()> {
    let current_epoch = get_current_epoch(state);
    let next_epoch = get_next_epoch(state);

    // The indices collected in these do not overlap.
    // See <https://github.com/protolambda/eth2-docs/tree/de65f38857f1e27ffb6f25107d61e795cf1a5ad7#registry-updates>
    //
    // These could be computed in `epoch_intermediates::statistics`, but doing so causes a slowdown.
    let mut eligible_for_activation_queue = vec![];
    let mut ejections = vec![];
    let mut activation_queue = vec![];

    for (validator, validator_index) in state.validators().into_iter().zip(0..) {
        if is_eligible_for_activation_queue::<P>(validator) {
            eligible_for_activation_queue.push(validator_index);
        }

        if is_active_validator(validator, current_epoch)
            && validator.effective_balance <= config.ejection_balance
        {
            ejections.push(validator_index);
        }

        if is_eligible_for_activation(state, validator) {
            activation_queue.push((validator_index, validator.activation_eligibility_epoch));
        }
    }

    // > Process activation eligibility and ejections
    for validator_index in eligible_for_activation_queue {
        state
            .validators_mut()
            .get_mut(validator_index)?
            .activation_eligibility_epoch = next_epoch;
    }

    for validator_index in ejections {
        let index = usize::try_from(validator_index)?;

        initiate_validator_exit(config, state, validator_index)?;

        // `process_slashings` depends on `Validator.withdrawable_epoch`,
        // which may have been modified by `initiate_validator_exit`.
        // However, no test cases in `consensus-spec-tests` fail if this is absent.
        summaries[index].update_from(state.validators().get(validator_index)?);
    }

    // > Activate all eligible validators
    let activation_exit_epoch = compute_activation_exit_epoch::<P>(current_epoch);

    for validator_index in activation_queue
        .into_iter()
        .map(|(validator_index, _)| validator_index)
    {
        state
            .validators_mut()
            .get_mut(validator_index)?
            .activation_epoch = activation_exit_epoch;
    }

    Ok(())
}

fn process_pending_balance_deposits<P: Preset>(
    config: &Config,
    state: &mut impl PostElectraBeaconState<P>,
) -> Result<()> {
    let available_for_processing =
        state.deposit_balance_to_consume() + get_activation_exit_churn_limit(config, state);

    let mut processed_amount = 0;
    let mut next_deposit_index = 0;

    for deposit in &state.pending_balance_deposits().clone() {
        if processed_amount + deposit.amount > available_for_processing {
            break;
        }

        increase_balance(balance(state, deposit.index)?, deposit.amount);

        processed_amount += deposit.amount;
        next_deposit_index += 1;
    }

    *state.pending_balance_deposits_mut() = PersistentList::try_from_iter(
        state
            .pending_balance_deposits()
            .into_iter()
            .copied()
            .skip(next_deposit_index),
    )?;

    if state.pending_balance_deposits().len_usize() == 0 {
        *state.deposit_balance_to_consume_mut() = 0;
    } else {
        *state.deposit_balance_to_consume_mut() = available_for_processing - processed_amount;
    }

    Ok(())
}

fn process_pending_consolidations<P: Preset>(
    state: &mut impl PostElectraBeaconState<P>,
) -> Result<()> {
    let current_epoch = get_current_epoch(state);
    let mut next_pending_consolidation = 0;

    for pending_consolidation in &state.pending_consolidations().clone() {
        let source_validator = state.validators().get(pending_consolidation.source_index)?;

        if source_validator.slashed {
            next_pending_consolidation += 1;
            continue;
        }

        if source_validator.withdrawable_epoch > current_epoch {
            break;
        }

        switch_to_compounding_validator(state, pending_consolidation.target_index)?;

        let active_balance = get_active_balance(state, pending_consolidation.source_index)?;

        decrease_balance(
            balance(state, pending_consolidation.source_index)?,
            active_balance,
        );
        increase_balance(
            balance(state, pending_consolidation.target_index)?,
            active_balance,
        );

        next_pending_consolidation += 1;
    }

    *state.pending_consolidations_mut() = PersistentList::try_from_iter(
        state
            .pending_consolidations()
            .into_iter()
            .copied()
            .skip(next_pending_consolidation),
    )?;

    Ok(())
}

pub fn process_effective_balance_updates<P: Preset>(state: &mut impl PostElectraBeaconState<P>) {
    let hysteresis_increment = P::EFFECTIVE_BALANCE_INCREMENT.get() / P::HYSTERESIS_QUOTIENT;
    let downward_threshold = hysteresis_increment * P::HYSTERESIS_DOWNWARD_MULTIPLIER;
    let upward_threshold = hysteresis_increment * P::HYSTERESIS_UPWARD_MULTIPLIER;

    let (validators, balances) = state.validators_mut_with_balances();

    // These could be collected into a vector in `process_slashings`. Doing so speeds up this
    // function by around ~160 μs in Goerli, but may result in a slowdown in `process_slashings`.
    // The reason why the speedup is so small is likely because values in the balance tree are
    // packed into bundles of 8.
    let mut balances = balances.into_iter().copied();

    // > Update effective balances with hysteresis
    validators.update(|validator| {
        let effective_balance_limit = if has_compounding_withdrawal_credential(validator) {
            P::MAX_EFFECTIVE_BALANCE_ELECTRA
        } else {
            P::MIN_ACTIVATION_BALANCE
        };

        let balance = balances
            .next()
            .expect("list of validators and list of balances should have the same length");

        let below = balance + downward_threshold < validator.effective_balance;
        let above = validator.effective_balance + upward_threshold < balance;

        if below || above {
            validator.effective_balance = balance
                .prev_multiple_of(P::EFFECTIVE_BALANCE_INCREMENT)
                .min(effective_balance_limit);
        }
    });
}

fn process_historical_summaries_update<P: Preset>(state: &mut BeaconState<P>) -> Result<()> {
    let next_epoch = get_next_epoch(state);

    // > Set historical block root accumulator.
    if next_epoch.is_multiple_of(P::EpochsPerHistoricalRoot::non_zero()) {
        let historical_summary = HistoricalSummary {
            block_summary_root: state.block_roots().hash_tree_root(),
            state_summary_root: state.state_roots().hash_tree_root(),
        };

        state.historical_summaries.push(historical_summary)?;
    }

    Ok(())
}

#[cfg(test)]
mod spec_tests {
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::preset::{Mainnet, Minimal};

    use crate::altair::ValidatorSummary;

    use super::*;

    // We do not honor `bls_setting` in epoch processing tests because none of them customize it.

    #[test_resources("consensus-spec-tests/tests/mainnet/electra/epoch_processing/justification_and_finalization/*/*")]
    fn mainnet_justification_and_finalization(case: Case) {
        run_justification_and_finalization_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/electra/epoch_processing/justification_and_finalization/*/*")]
    fn minimal_justification_and_finalization(case: Case) {
        run_justification_and_finalization_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/inactivity_updates/*/*"
    )]
    fn mainnet_inactivity_updates_updates(case: Case) {
        run_inactivity_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/inactivity_updates/*/*"
    )]
    fn minimal_inactivity_updates_updates(case: Case) {
        run_inactivity_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/rewards_and_penalties/*/*"
    )]
    fn mainnet_rewards_and_penalties(case: Case) {
        run_rewards_and_penalties_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/rewards_and_penalties/*/*"
    )]
    fn minimal_rewards_and_penalties(case: Case) {
        run_rewards_and_penalties_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/registry_updates/*/*"
    )]
    fn mainnet_registry_updates(case: Case) {
        run_registry_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/registry_updates/*/*"
    )]
    fn minimal_registry_updates(case: Case) {
        run_registry_updates_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/electra/epoch_processing/slashings/*/*")]
    fn mainnet_slashings(case: Case) {
        run_slashings_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/electra/epoch_processing/slashings/*/*")]
    fn minimal_slashings(case: Case) {
        run_slashings_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/eth1_data_reset/*/*"
    )]
    fn mainnet_eth1_data_reset(case: Case) {
        run_eth1_data_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/eth1_data_reset/*/*"
    )]
    fn minimal_eth1_data_reset(case: Case) {
        run_eth1_data_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/effective_balance_updates/*/*"
    )]
    fn mainnet_effective_balance_updates(case: Case) {
        run_effective_balance_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/effective_balance_updates/*/*"
    )]
    fn minimal_effective_balance_updates(case: Case) {
        run_effective_balance_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/slashings_reset/*/*"
    )]
    fn mainnet_slashings_reset(case: Case) {
        run_slashings_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/slashings_reset/*/*"
    )]
    fn minimal_slashings_reset(case: Case) {
        run_slashings_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/randao_mixes_reset/*/*"
    )]
    fn mainnet_randao_mixes_reset(case: Case) {
        run_randao_mixes_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/randao_mixes_reset/*/*"
    )]
    fn minimal_randao_mixes_reset(case: Case) {
        run_randao_mixes_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/historical_summaries_update/*/*"
    )]
    fn mainnet_historical_summaries_update(case: Case) {
        run_historical_summaries_update_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/historical_summaries_update/*/*"
    )]
    fn minimal_historical_summaries_update(case: Case) {
        run_historical_summaries_update_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/participation_flag_updates/*/*"
    )]
    fn mainnet_participation_flag_updates(case: Case) {
        run_participation_flag_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/participation_flag_updates/*/*"
    )]
    fn minimal_participation_flag_updates(case: Case) {
        run_participation_flag_updates_case::<Minimal>(case);
    }

    // There are no mainnet test cases for the `sync_committee_updates` sub-transition.
    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/sync_committee_updates/*/*"
    )]
    fn minimal_sync_committee_updates(case: Case) {
        run_sync_committee_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/pending_balance_deposits/*/*"
    )]
    fn mainnet_pending_balance_deposits(case: Case) {
        run_pending_balance_deposits_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/pending_balance_deposits/*/*"
    )]
    fn minimal_pending_balance_deposits(case: Case) {
        run_pending_balance_deposits_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/electra/epoch_processing/pending_consolidations/*/*"
    )]
    fn mainnet_pending_consolidations(case: Case) {
        run_pending_consolidations_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/electra/epoch_processing/pending_consolidations/*/*"
    )]
    fn minimal_pending_consolidations(case: Case) {
        run_pending_consolidations_case::<Minimal>(case);
    }

    fn run_justification_and_finalization_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            let (statistics, _, _) = altair::statistics(state);

            altair::process_justification_and_finalization(state, statistics);

            Ok(())
        });
    }

    fn run_inactivity_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            let (_, summaries, participation) = altair::statistics(state);

            altair::process_inactivity_updates(
                &P::default_config(),
                state,
                summaries,
                participation,
            );

            Ok(())
        });
    }

    fn run_rewards_and_penalties_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            let (statistics, summaries, participation) = altair::statistics(state);

            let deltas: Vec<EpochDeltasForTransition> = epoch_intermediates::epoch_deltas(
                &P::default_config(),
                state,
                statistics,
                summaries,
                participation,
            );

            unphased::process_rewards_and_penalties(state, deltas);

            Ok(())
        });
    }

    fn run_registry_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            let mut summaries: Vec<ValidatorSummary> = vec_of_default(state);

            process_registry_updates(&P::default_config(), state, summaries.as_mut_slice())
        });
    }

    fn run_slashings_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            let (_, summaries, _) = altair::statistics(state);

            bellatrix::process_slashings::<_, ()>(state, summaries);

            Ok(())
        });
    }

    fn run_eth1_data_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            unphased::process_eth1_data_reset(state);

            Ok(())
        });
    }

    fn run_effective_balance_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            process_effective_balance_updates(state);

            Ok(())
        });
    }

    fn run_slashings_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            unphased::process_slashings_reset(state);

            Ok(())
        });
    }

    fn run_randao_mixes_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            unphased::process_randao_mixes_reset(state);

            Ok(())
        });
    }

    fn run_historical_summaries_update_case<P: Preset>(case: Case) {
        run_case::<P>(case, process_historical_summaries_update);
    }

    fn run_participation_flag_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            altair::process_participation_flag_updates(state);

            Ok(())
        });
    }

    fn run_sync_committee_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, altair::process_sync_committee_updates);
    }

    fn run_pending_balance_deposits_case<P: Preset>(case: Case) {
        run_case::<P>(case, |state| {
            process_pending_balance_deposits(&P::default_config(), state)
        });
    }

    fn run_pending_consolidations_case<P: Preset>(case: Case) {
        run_case::<P>(case, process_pending_consolidations)
    }

    fn run_case<P: Preset>(
        case: Case,
        sub_transition: impl FnOnce(&mut BeaconState<P>) -> Result<()>,
    ) {
        let mut state = case.ssz_default("pre");
        let post_option = case.try_ssz_default("post");

        let result = sub_transition(&mut state).map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("epoch processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("epoch processing should fail");
        }
    }
}
