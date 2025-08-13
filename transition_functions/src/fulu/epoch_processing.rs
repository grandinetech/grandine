use anyhow::Result;
use arithmetic::NonZeroExt as _;
use helper_functions::{
    accessors::{get_beacon_proposer_indices, get_current_epoch, get_next_epoch},
    electra::{initiate_validator_exit, is_eligible_for_activation_queue},
    misc::{compute_activation_exit_epoch, vec_of_default},
    predicates::{is_active_validator, is_eligible_for_activation},
};
use pubkey_cache::PubkeyCache;
use ssz::{PersistentVector, SszHash as _};
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    capella::containers::HistoricalSummary, config::Config,
    fulu::beacon_state::BeaconState as FuluBeaconState, preset::Preset, traits::BeaconState,
};

use super::epoch_intermediates;
use crate::{
    altair::{self, EpochDeltasForTransition, EpochReport},
    bellatrix, electra, unphased,
    unphased::ValidatorSummary,
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

pub fn process_epoch(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut FuluBeaconState<impl Preset>,
) -> Result<()> {
    #[cfg(feature = "metrics")]
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
    electra::process_pending_deposits(config, pubkey_cache, state)?;
    electra::process_pending_consolidations(state)?;
    electra::process_effective_balance_updates(state);
    unphased::process_slashings_reset(state);
    unphased::process_randao_mixes_reset(state);

    // > [Modified in Capella]
    process_historical_summaries_update(state)?;

    altair::process_participation_flag_updates(state);
    altair::process_sync_committee_updates(pubkey_cache, state)?;

    // > [New in Fulu:EIP7917]
    process_proposer_lookahead(config, state)?;

    state.cache.advance_epoch();

    Ok(())
}

fn process_historical_summaries_update<P: Preset>(state: &mut FuluBeaconState<P>) -> Result<()> {
    let next_epoch = get_next_epoch(state);

    // > Set historical block root accumulator.
    if next_epoch.is_multiple_of(P::EpochsPerHistoricalRoot::non_zero().into()) {
        let historical_summary = HistoricalSummary {
            block_summary_root: state.block_roots().hash_tree_root(),
            state_summary_root: state.state_roots().hash_tree_root(),
        };

        state.historical_summaries.push(historical_summary)?;
    }

    Ok(())
}

pub fn epoch_report<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut FuluBeaconState<P>,
) -> Result<EpochReport> {
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

    let slashing_penalties = electra::process_slashings(state, summaries.iter().copied());
    let post_balances = state.balances.into_iter().copied().collect();

    // Do the rest of epoch processing to leave the state valid for further transitions.
    // This way it can be used to calculate statistics for multiple epochs in a row.
    unphased::process_eth1_data_reset(state);
    electra::process_effective_balance_updates(state);
    unphased::process_slashings_reset(state);
    unphased::process_randao_mixes_reset(state);
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

fn process_registry_updates<P: Preset>(
    config: &Config,
    state: &mut FuluBeaconState<P>,
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

fn process_proposer_lookahead<P: Preset>(
    config: &Config,
    state: &mut FuluBeaconState<P>,
) -> Result<()> {
    let mut proposer_lookahead = state.proposer_lookahead.into_iter().collect::<Vec<_>>();

    let last_epoch_start = proposer_lookahead
        .len()
        .saturating_sub(P::SlotsPerEpoch::USIZE);
    proposer_lookahead.copy_within(P::SlotsPerEpoch::USIZE.., 0);

    let target_epoch = get_current_epoch(state).saturating_add(P::MinSeedLookahead::U64 + 1);
    let last_proposers_indices = get_beacon_proposer_indices(config, state, target_epoch)?;
    let refs = last_proposers_indices.iter().collect::<Vec<&_>>();
    proposer_lookahead[last_epoch_start..].copy_from_slice(&refs);

    state.proposer_lookahead =
        PersistentVector::try_from_iter(proposer_lookahead.into_iter().copied())?;

    Ok(())
}

#[cfg(test)]
mod spec_tests {
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::preset::{Mainnet, Minimal};

    use crate::{altair::ValidatorSummary, electra};

    use super::*;

    // We do not honor `bls_setting` in epoch processing tests because none of them customize it.

    #[test_resources("consensus-spec-tests/tests/mainnet/fulu/epoch_processing/justification_and_finalization/*/*")]
    fn mainnet_justification_and_finalization(case: Case) {
        run_justification_and_finalization_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/fulu/epoch_processing/justification_and_finalization/*/*")]
    fn minimal_justification_and_finalization(case: Case) {
        run_justification_and_finalization_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/inactivity_updates/*/*"
    )]
    fn mainnet_inactivity_updates_updates(case: Case) {
        run_inactivity_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/inactivity_updates/*/*"
    )]
    fn minimal_inactivity_updates_updates(case: Case) {
        run_inactivity_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/rewards_and_penalties/*/*"
    )]
    fn mainnet_rewards_and_penalties(case: Case) {
        run_rewards_and_penalties_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/rewards_and_penalties/*/*"
    )]
    fn minimal_rewards_and_penalties(case: Case) {
        run_rewards_and_penalties_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/registry_updates/*/*"
    )]
    fn mainnet_registry_updates(case: Case) {
        run_registry_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/registry_updates/*/*"
    )]
    fn minimal_registry_updates(case: Case) {
        run_registry_updates_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/fulu/epoch_processing/slashings/*/*")]
    fn mainnet_slashings(case: Case) {
        run_slashings_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/fulu/epoch_processing/slashings/*/*")]
    fn minimal_slashings(case: Case) {
        run_slashings_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/eth1_data_reset/*/*"
    )]
    fn mainnet_eth1_data_reset(case: Case) {
        run_eth1_data_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/eth1_data_reset/*/*"
    )]
    fn minimal_eth1_data_reset(case: Case) {
        run_eth1_data_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/effective_balance_updates/*/*"
    )]
    fn mainnet_effective_balance_updates(case: Case) {
        run_effective_balance_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/effective_balance_updates/*/*"
    )]
    fn minimal_effective_balance_updates(case: Case) {
        run_effective_balance_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/slashings_reset/*/*"
    )]
    fn mainnet_slashings_reset(case: Case) {
        run_slashings_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/slashings_reset/*/*"
    )]
    fn minimal_slashings_reset(case: Case) {
        run_slashings_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/randao_mixes_reset/*/*"
    )]
    fn mainnet_randao_mixes_reset(case: Case) {
        run_randao_mixes_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/randao_mixes_reset/*/*"
    )]
    fn minimal_randao_mixes_reset(case: Case) {
        run_randao_mixes_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/historical_summaries_update/*/*"
    )]
    fn mainnet_historical_summaries_update(case: Case) {
        run_historical_summaries_update_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/historical_summaries_update/*/*"
    )]
    fn minimal_historical_summaries_update(case: Case) {
        run_historical_summaries_update_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/participation_flag_updates/*/*"
    )]
    fn mainnet_participation_flag_updates(case: Case) {
        run_participation_flag_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/participation_flag_updates/*/*"
    )]
    fn minimal_participation_flag_updates(case: Case) {
        run_participation_flag_updates_case::<Minimal>(case);
    }

    // There are no mainnet test cases for the `sync_committee_updates` sub-transition.
    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/sync_committee_updates/*/*"
    )]
    fn minimal_sync_committee_updates(case: Case) {
        run_sync_committee_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/pending_deposits/*/*"
    )]
    fn mainnet_pending_deposits(case: Case) {
        run_pending_deposits_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/pending_deposits/*/*"
    )]
    fn minimal_pending_deposits(case: Case) {
        run_pending_deposits_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/pending_consolidations/*/*"
    )]
    fn mainnet_pending_consolidations(case: Case) {
        run_pending_consolidations_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/pending_consolidations/*/*"
    )]
    fn minimal_pending_consolidations(case: Case) {
        run_pending_consolidations_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/fulu/epoch_processing/proposer_lookahead/*/*"
    )]
    fn mainnet_process_look(case: Case) {
        run_process_look_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/fulu/epoch_processing/proposer_lookahead/*/*"
    )]
    fn minimal_process_look(case: Case) {
        run_process_look_case::<Minimal>(case);
    }

    fn run_justification_and_finalization_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            let (statistics, _, _) = altair::statistics(state);

            altair::process_justification_and_finalization(state, statistics);

            Ok(())
        });
    }

    fn run_inactivity_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
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
        run_case::<P>(case, |_, state| {
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
        run_case::<P>(case, |_, state| {
            let mut summaries: Vec<ValidatorSummary> = vec_of_default(state);

            process_registry_updates(&P::default_config(), state, summaries.as_mut_slice())
        });
    }

    fn run_slashings_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            let (_, summaries, _) = altair::statistics(state);

            electra::process_slashings::<_, ()>(state, summaries);

            Ok(())
        });
    }

    fn run_eth1_data_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            unphased::process_eth1_data_reset(state);

            Ok(())
        });
    }

    fn run_effective_balance_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            electra::process_effective_balance_updates(state);

            Ok(())
        });
    }

    fn run_slashings_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            unphased::process_slashings_reset(state);

            Ok(())
        });
    }

    fn run_randao_mixes_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            unphased::process_randao_mixes_reset(state);

            Ok(())
        });
    }

    fn run_historical_summaries_update_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| process_historical_summaries_update(state));
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

    fn run_pending_deposits_case<P: Preset>(case: Case) {
        run_case::<P>(case, |pubkey_cache, state| {
            electra::process_pending_deposits(&P::default_config(), pubkey_cache, state)
        });
    }

    fn run_pending_consolidations_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            electra::process_pending_consolidations(state)
        })
    }

    fn run_process_look_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            process_proposer_lookahead(&P::default_config(), state)
        })
    }

    fn run_case<P: Preset>(
        case: Case,
        sub_transition: impl FnOnce(&PubkeyCache, &mut FuluBeaconState<P>) -> Result<()>,
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
}
