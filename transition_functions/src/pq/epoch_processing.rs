use std::sync::Arc;

use anyhow::Result;
use arithmetic::{NonZeroExt as _, U64Ext as _};
use helper_functions::{
    accessors::{
        get_activation_churn_limit, get_current_epoch, get_next_epoch, index_of_public_key,
    },
    misc,
    pq::{compute_aggregation_committees_for_epoch, compute_deposit_pubkey, is_legacy_pubkey},
};
use pubkey_cache::PubkeyCache;
use ssz::{ContiguousVector, Hc, SszHash as _, SszListMut as _};
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    capella::containers::HistoricalSummary,
    config::Config,
    nonstandard::RelativeEpoch,
    phase0::consts::FAR_FUTURE_EPOCH,
    pq::{
        beacon_state::BeaconState, primitives::AggregationCommittees, validator_list::padded_pubkey,
    },
    preset::Preset,
    traits::SszValidatorList as _,
};

use crate::{
    altair::{self, EpochDeltasForTransition},
    electra, fulu, gloas,
    pq::execution_requests::{apply_pending_deposit, process_preregistration_expiry},
    unphased,
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

/// [`process_epoch`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_epoch)
pub fn process_epoch<P: Preset>(
    config: &Config,
    _pubkey_cache: &PubkeyCache,
    state: &mut BeaconState<P>,
) -> Result<()> {
    #[cfg(feature = "metrics")]
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.epoch_processing_times.start_timer());

    let (statistics, mut summaries, participation) = altair::statistics_and_summaries(state)?;

    altair::process_justification_and_finalization(state, statistics)?;

    altair::process_inactivity_updates(
        config,
        state,
        summaries.iter().copied(),
        participation.iter().copied(),
    )?;

    let epoch_deltas: Vec<EpochDeltasForTransition> = altair::epoch_deltas::<P, _>(
        config,
        P::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
        altair::EpochRewardScalars::new(state, statistics)?,
        summaries.iter().copied(),
        participation
            .iter()
            .map(|participation| participation.previous),
        state.inactivity_scores.into_iter().copied(),
    )?;

    unphased::process_rewards_and_penalties(state, epoch_deltas)?;
    electra::process_registry_updates(config, state, summaries.as_mut_slice())?;
    electra::process_slashings::<_, ()>(state, summaries)?;
    unphased::process_eth1_data_reset(state)?;
    process_pending_deposits(config, state)?;
    electra::process_pending_consolidations(state)?;
    gloas::process_builder_pending_payments(state)?;
    electra::process_effective_balance_updates(state)?;
    unphased::process_slashings_reset(state)?;
    unphased::process_randao_mixes_reset(state)?;
    process_historical_summaries_update(state)?;
    altair::process_participation_flag_updates(state);

    // > [Modified in PQ] Removed `process_sync_committee_updates`

    fulu::process_proposer_lookahead(config, state)?;

    let (ordered, shuffled) = gloas::process_ptc_window(state)?;

    // > [New in PQ]
    process_aggregation_committee_window(state)?;

    // > [New in PQ:EIP8205]
    process_preregistration_expiry(state)?;

    state.cache.advance_epoch();

    if P::MinSeedLookahead::U64 == 1 {
        state.cache.active_validator_indices_ordered[RelativeEpoch::Next] = ordered.into();
        state.cache.active_validator_indices_shuffled[RelativeEpoch::Next] = shuffled.into();
    }

    Ok(())
}

/// [`process_pending_deposits`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_pending_deposits)
pub(super) fn process_pending_deposits<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
) -> Result<()> {
    let next_epoch = get_current_epoch(state).try_add(1)?;
    let available_for_processing = state
        .deposit_balance_to_consume
        .try_add(get_activation_churn_limit(config, state))?;

    let mut processed_amount: u64 = 0;
    let mut next_deposit_index: u64 = 0;
    let mut deposits_to_postpone = vec![];
    let mut is_churn_limit_reached = false;
    let finalized_slot = misc::compute_start_slot_at_epoch::<P>(state.finalized_checkpoint.epoch);

    for deposit in &state.pending_deposits.clone() {
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

        // > [Modified in PQ]
        let pubkey = padded_pubkey(compute_deposit_pubkey(&deposit.pubkey));

        if let Some(validator_index) = index_of_public_key(state, &pubkey) {
            let validator = state.validators.partial_validator(validator_index)?;

            is_validator_exited = validator.exit_epoch < FAR_FUTURE_EPOCH;
            is_validator_withdrawn = validator.withdrawable_epoch < next_epoch;
        }

        // > [Modified in PQ]
        if is_validator_withdrawn || is_legacy_pubkey(&deposit.pubkey) {
            // > Deposited balance will never become active. Increase balance but do not consume churn
            apply_pending_deposit(config, state, deposit)?;
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
            apply_pending_deposit(config, state, deposit)?;
        }

        next_deposit_index = next_deposit_index.try_add(1)?;
    }

    let pending_deposits = state.pending_deposits.clone();

    state.pending_deposits.try_assign_from_iter(
        &mut pending_deposits
            .into_iter()
            .copied()
            .skip(next_deposit_index.try_into()?)
            .chain(deposits_to_postpone),
    )?;

    if is_churn_limit_reached {
        state.deposit_balance_to_consume = available_for_processing.try_sub(processed_amount)?;
    } else {
        state.deposit_balance_to_consume = 0;
    }

    Ok(())
}

pub(super) fn process_historical_summaries_update<P: Preset>(
    state: &mut BeaconState<P>,
) -> Result<()> {
    let next_epoch = get_next_epoch(state)?;

    // > Set historical block root accumulator.
    if next_epoch.is_multiple_of(P::EpochsPerHistoricalRoot::non_zero().into()) {
        let historical_summary = HistoricalSummary {
            block_summary_root: state.block_roots.hash_tree_root(),
            state_summary_root: state.state_roots.hash_tree_root(),
        };

        state.historical_summaries.push(historical_summary)?;
    }

    Ok(())
}

/// [`process_aggregation_committee_window`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-process_aggregation_committee_window)
pub(super) fn process_aggregation_committee_window<P: Preset>(
    state: &mut BeaconState<P>,
) -> Result<()> {
    // > Fill in the last epoch
    let next_epoch = get_current_epoch(state).try_add(P::MinSeedLookahead::U64.try_add(1)?)?;
    let last_epoch = compute_aggregation_committees_for_epoch(state, next_epoch)?;

    // > Shift all epochs forward by one
    let window = state
        .aggregation_committee_window
        .iter()
        .skip(P::SlotsPerEpoch::USIZE)
        .cloned()
        .chain(last_epoch);

    state.aggregation_committee_window =
        Arc::new(Hc::from(ContiguousVector::try_from_iter(window)?));

    Ok(())
}

/// [`initialize_aggregation_committee_window`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/fork.md#new-initialize_aggregation_committee_window)
pub fn initialize_aggregation_committee_window<P: Preset>(
    state: &mut BeaconState<P>,
) -> Result<()> {
    let current_epoch = get_current_epoch(state);
    let mut window = vec![AggregationCommittees::default(); P::SlotsPerEpoch::USIZE];

    for epoch in current_epoch..=current_epoch.try_add(P::MinSeedLookahead::U64)? {
        window.extend(compute_aggregation_committees_for_epoch(state, epoch)?);
    }

    state.aggregation_committee_window =
        Arc::new(Hc::from(ContiguousVector::try_from_iter(window)?));

    Ok(())
}
