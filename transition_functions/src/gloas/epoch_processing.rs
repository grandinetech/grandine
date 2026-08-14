use anyhow::Result;
use arithmetic::{NonZeroExt as _, U64Ext as _, UsizeExt as _};
use helper_functions::{
    accessors::{
        get_activation_churn_limit, get_builder_payment_quorum_threshold, get_current_epoch,
        get_next_epoch, index_of_public_key, ptc_for_slot_for_epoch_processing,
    },
    misc,
};
use itertools::Itertools as _;
use pubkey_cache::PubkeyCache;
use ssz::{PersistentVector, SszHash as _, SszListMut as _};
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    PtcWindow,
    capella::containers::HistoricalSummary,
    config::Config,
    gloas::{beacon_state::BeaconState, containers::BuilderPendingPayment},
    phase0::consts::FAR_FUTURE_EPOCH,
    preset::{BuilderPendingPaymentsLength, Preset},
    traits::{BeaconState as _, PostElectraBeaconState, PostGloasBeaconState},
};

use super::epoch_intermediates;
use crate::{
    altair::{self, EpochDeltasForTransition},
    electra::{self, apply_pending_deposit},
    fulu, unphased,
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

pub fn process_epoch(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut BeaconState<impl Preset>,
    trust_all_signatures: bool,
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
    // `BeaconState.finalized_checkpoint` and `BeaconState.inactivity_scores`.
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
    electra::process_registry_updates(config, state, summaries.as_mut_slice())?;
    electra::process_slashings::<_, ()>(state, summaries)?;
    unphased::process_eth1_data_reset(state)?;
    process_pending_deposits(config, pubkey_cache, state, trust_all_signatures)?;
    electra::process_pending_consolidations(state)?;

    process_builder_pending_payments(state)?;
    electra::process_effective_balance_updates(state)?;
    unphased::process_slashings_reset(state)?;
    unphased::process_randao_mixes_reset(state)?;

    // > [Modified in Capella]
    process_historical_summaries_update(state)?;

    altair::process_participation_flag_updates(state);
    altair::process_sync_committee_updates(pubkey_cache, state)?;

    fulu::process_proposer_lookahead(config, state)?;

    // > [New in Gloas:EIP7732]
    process_ptc_window(state)?;

    state.cache.advance_epoch();

    Ok(())
}

#[expect(
    clippy::useless_let_if_seq,
    reason = "assignments with multiple variables are more readable with conditional affectation"
)]
fn process_pending_deposits<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostElectraBeaconState<P>,
    trust_all_signatures: bool,
) -> Result<()> {
    let next_epoch = get_current_epoch(state).try_add(1)?;
    let available_for_processing = state
        .deposit_balance_to_consume()
        .try_add(get_activation_churn_limit(config, state))?;

    let mut processed_amount: u64 = 0;
    let mut next_deposit_index: u64 = 0;
    let mut deposits_to_postpone = vec![];
    let mut is_churn_limit_reached = false;
    let finalized_slot = misc::compute_start_slot_at_epoch::<P>(state.finalized_checkpoint().epoch);

    for deposit in &*state.pending_deposits().clone_boxed() {
        // > Check if deposit has been finalized, otherwise, stop processing.
        if deposit.slot > finalized_slot {
            break;
        }

        // > Check if number of processed deposits has not reached the limit, otherwise, stop processing.
        if next_deposit_index >= P::MAX_PENDING_DEPOSITS_PER_EPOCH {
            break;
        }

        let mut is_validator_exited = false;
        let mut is_validator_withdrawn = false;

        if let Some(validator_index) = index_of_public_key(state, &deposit.pubkey) {
            let validator = state.validators().get(validator_index)?;

            is_validator_exited = validator.exit_epoch < FAR_FUTURE_EPOCH;
            is_validator_withdrawn = validator.withdrawable_epoch < next_epoch;
        }

        if is_validator_withdrawn {
            // > Deposited balance will never become active. Increase balance but do not consume churn
            apply_pending_deposit(config, pubkey_cache, state, deposit, trust_all_signatures)?;
        } else if is_validator_exited {
            // > Validator is exiting, postpone the deposit until after withdrawable epoch
            deposits_to_postpone.push(*deposit);
        } else {
            // > Check if deposit fits in the churn, otherwise, do no more deposit processing in this epoch.
            is_churn_limit_reached =
                processed_amount.try_add(deposit.amount)? > available_for_processing;

            if is_churn_limit_reached {
                break;
            }

            processed_amount = processed_amount.try_add(deposit.amount)?;
            apply_pending_deposit(config, pubkey_cache, state, deposit, trust_all_signatures)?;
        }

        next_deposit_index = next_deposit_index.try_add(1)?;
    }

    let pending_deposits = state.pending_deposits().clone_boxed();

    state.pending_deposits_mut().try_assign_from_iter(
        &mut pending_deposits
            .iter()
            .copied()
            .skip(next_deposit_index.try_into()?)
            .chain(deposits_to_postpone),
    )?;

    if is_churn_limit_reached {
        *state.deposit_balance_to_consume_mut() =
            available_for_processing.try_sub(processed_amount)?;
    } else {
        *state.deposit_balance_to_consume_mut() = 0;
    }

    Ok(())
}

fn process_ptc_window<P: Preset>(state: &mut impl PostGloasBeaconState<P>) -> Result<()> {
    let mut ptc_window = state.ptc_window().into_iter().collect::<Vec<_>>();
    let last_epoch_start = ptc_window.len().try_sub(P::SlotsPerEpoch::USIZE)?;

    ptc_window.copy_within(P::SlotsPerEpoch::USIZE.., 0);

    let target_epoch = get_current_epoch(state).try_add(P::MinSeedLookahead::U64.try_add(1)?)?;

    let start_slot = misc::compute_start_slot_at_epoch::<P>(target_epoch);

    let ptcs = (start_slot..start_slot.try_add(P::SlotsPerEpoch::U64)?)
        .map(|slot| ptc_for_slot_for_epoch_processing(state, slot))
        .collect::<Result<Vec<_>>>()?;

    let refs = ptcs.iter().collect::<Vec<_>>();
    ptc_window[last_epoch_start..].copy_from_slice(&refs);

    *state.ptc_window_mut() = PtcWindow::<P>::try_from_iter(ptc_window.into_iter().cloned())?;

    Ok(())
}

fn process_builder_pending_payments<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
) -> Result<()> {
    let quorum = get_builder_payment_quorum_threshold(state)?;
    let payments = state
        .builder_pending_payments()
        .into_iter()
        .copied()
        .collect_vec();

    for payment in payments.iter().take(P::SlotsPerEpoch::USIZE) {
        if payment.weight >= quorum {
            state
                .builder_pending_withdrawals_mut()
                .push(payment.withdrawal)?;
        }
    }

    *state.builder_pending_payments_mut() = PersistentVector::try_from_iter(
        payments
            .into_iter()
            .skip(P::SlotsPerEpoch::USIZE)
            .chain(core::iter::repeat_n(
                BuilderPendingPayment::default(),
                P::SlotsPerEpoch::USIZE,
            ))
            .take(BuilderPendingPaymentsLength::<P>::USIZE),
    )?;

    Ok(())
}

fn process_historical_summaries_update<P: Preset>(state: &mut BeaconState<P>) -> Result<()> {
    let next_epoch = get_next_epoch(state)?;

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

#[cfg(test)]
mod spec_tests {
    use helper_functions::misc::vec_of_default;
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::preset::{Mainnet, Minimal};

    use super::*;

    use crate::altair::ValidatorSummary;

    // We do not honor `bls_setting` in epoch processing tests because none of them customize it.

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/justification_and_finalization/*/*"
    )]
    fn mainnet_justification_and_finalization(case: Case) {
        run_justification_and_finalization_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/justification_and_finalization/*/*"
    )]
    fn minimal_justification_and_finalization(case: Case) {
        run_justification_and_finalization_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/inactivity_updates/*/*"
    )]
    fn mainnet_inactivity_updates_updates(case: Case) {
        run_inactivity_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/inactivity_updates/*/*"
    )]
    fn minimal_inactivity_updates_updates(case: Case) {
        run_inactivity_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/rewards_and_penalties/*/*"
    )]
    fn mainnet_rewards_and_penalties(case: Case) {
        run_rewards_and_penalties_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/rewards_and_penalties/*/*"
    )]
    fn minimal_rewards_and_penalties(case: Case) {
        run_rewards_and_penalties_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/registry_updates/*/*"
    )]
    fn mainnet_registry_updates(case: Case) {
        run_registry_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/registry_updates/*/*"
    )]
    fn minimal_registry_updates(case: Case) {
        run_registry_updates_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/gloas/epoch_processing/slashings/*/*")]
    fn mainnet_slashings(case: Case) {
        run_slashings_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/gloas/epoch_processing/slashings/*/*")]
    fn minimal_slashings(case: Case) {
        run_slashings_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/eth1_data_reset/*/*"
    )]
    fn mainnet_eth1_data_reset(case: Case) {
        run_eth1_data_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/eth1_data_reset/*/*"
    )]
    fn minimal_eth1_data_reset(case: Case) {
        run_eth1_data_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/effective_balance_updates/*/*"
    )]
    fn mainnet_effective_balance_updates(case: Case) {
        run_effective_balance_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/effective_balance_updates/*/*"
    )]
    fn minimal_effective_balance_updates(case: Case) {
        run_effective_balance_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/slashings_reset/*/*"
    )]
    fn mainnet_slashings_reset(case: Case) {
        run_slashings_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/slashings_reset/*/*"
    )]
    fn minimal_slashings_reset(case: Case) {
        run_slashings_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/randao_mixes_reset/*/*"
    )]
    fn mainnet_randao_mixes_reset(case: Case) {
        run_randao_mixes_reset_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/randao_mixes_reset/*/*"
    )]
    fn minimal_randao_mixes_reset(case: Case) {
        run_randao_mixes_reset_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/historical_summaries_update/*/*"
    )]
    fn mainnet_historical_summaries_update(case: Case) {
        run_historical_summaries_update_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/historical_summaries_update/*/*"
    )]
    fn minimal_historical_summaries_update(case: Case) {
        run_historical_summaries_update_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/participation_flag_updates/*/*"
    )]
    fn mainnet_participation_flag_updates(case: Case) {
        run_participation_flag_updates_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/participation_flag_updates/*/*"
    )]
    fn minimal_participation_flag_updates(case: Case) {
        run_participation_flag_updates_case::<Minimal>(case);
    }

    // There are no mainnet test cases for the `sync_committee_updates` sub-transition.
    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/sync_committee_updates/*/*"
    )]
    fn minimal_sync_committee_updates(case: Case) {
        run_sync_committee_updates_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/pending_deposits/*/*"
    )]
    fn mainnet_pending_deposits(case: Case) {
        run_pending_deposits_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/pending_deposits_churn/*/*"
    )]
    fn mainnet_pending_deposits_churn(case: Case) {
        run_pending_deposits_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/pending_deposits/*/*"
    )]
    fn minimal_pending_deposits(case: Case) {
        run_pending_deposits_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/pending_deposits_churn/*/*"
    )]
    fn minimal_pending_deposits_churn(case: Case) {
        run_pending_deposits_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/pending_consolidations/*/*"
    )]
    fn mainnet_pending_consolidations(case: Case) {
        run_pending_consolidations_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/pending_consolidations/*/*"
    )]
    fn minimal_pending_consolidations(case: Case) {
        run_pending_consolidations_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/proposer_lookahead/*/*"
    )]
    fn mainnet_process_look(case: Case) {
        run_process_look_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/proposer_lookahead/*/*"
    )]
    fn minimal_process_look(case: Case) {
        run_process_look_case::<Minimal>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/mainnet/gloas/epoch_processing/builder_pending_payments/*/*"
    )]
    fn mainnet_process_builder_pending_payments(case: Case) {
        run_process_builder_pending_payments_case::<Mainnet>(case);
    }

    #[test_resources(
        "consensus-spec-tests/tests/minimal/gloas/epoch_processing/builder_pending_payments/*/*"
    )]
    fn minimal_process_builder_pending_payments(case: Case) {
        run_process_builder_pending_payments_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/gloas/epoch_processing/ptc_window/*/*")]
    fn mainnet_process_ptc_window(case: Case) {
        run_case::<Mainnet>(case, |_, state| process_ptc_window(state))
    }

    #[test_resources("consensus-spec-tests/tests/minimal/gloas/epoch_processing/ptc_window/*/*")]
    fn minimal_process_ptc_window(case: Case) {
        run_case::<Minimal>(case, |_, state| process_ptc_window(state))
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/gloas/epoch_processing/*/*/*")]
    fn mainnet_epoch_processing(case: Case) {
        run_epoch_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/gloas/epoch_processing/*/*/*")]
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

            electra::process_registry_updates(&P::default_config(), state, summaries.as_mut_slice())
        });
    }

    fn run_slashings_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            let (_, summaries, _) = altair::statistics_and_summaries(state)?;

            electra::process_slashings::<_, ()>(state, summaries)
        });
    }

    fn run_eth1_data_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| unphased::process_eth1_data_reset(state));
    }

    fn run_effective_balance_updates_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            electra::process_effective_balance_updates(state)?;

            Ok(())
        });
    }

    fn run_slashings_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| unphased::process_slashings_reset(state));
    }

    fn run_randao_mixes_reset_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| unphased::process_randao_mixes_reset(state));
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
            process_pending_deposits(&P::default_config(), pubkey_cache, state, false)
        });
    }

    fn run_pending_consolidations_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            electra::process_pending_consolidations(state)
        })
    }

    fn run_process_look_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| {
            fulu::process_proposer_lookahead(&P::default_config(), state)
        })
    }

    fn run_process_builder_pending_payments_case<P: Preset>(case: Case) {
        run_case::<P>(case, |_, state| process_builder_pending_payments(state))
    }

    fn run_case<P: Preset>(
        case: Case,
        sub_transition: impl FnOnce(&PubkeyCache, &mut BeaconState<P>) -> Result<()>,
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
        // Some sub-transition test cases (e.g. `effective_balance_updates/effective_balance_hysteresis*`,
        // `slashings/{minimal_penalty,scaled_penalties}`, `pending_deposits/process_pending_deposits_withdrawable_validator_not_churned`)
        // don't ship `pre_epoch`/`post_epoch` SSZ files because they aren't valid full-epoch transitions. Skip them.
        let Some(mut state) = case.try_ssz_default::<BeaconState<P>>("pre_epoch") else {
            return;
        };
        let post_option: Option<BeaconState<P>> = case.try_ssz_default("post_epoch");

        let result =
            process_epoch(&P::default_config(), &pubkey_cache, &mut state, false).map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("epoch processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("epoch processing should fail");
        }
    }
}
