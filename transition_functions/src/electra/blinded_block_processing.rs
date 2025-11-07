use core::ops::{Add as _, Rem as _};

use anyhow::{Result, ensure};
use helper_functions::{
    accessors, misc,
    mutators::{balance, decrease_balance},
    slot_report::SlotReport,
    verifier::Verifier,
};
use pubkey_cache::PubkeyCache;
use ssz::{ContiguousList, PersistentList, SszHash as _};
use tap::TryConv as _;
use try_from_iterator::TryFromIterator as _;
use typenum::{NonZero, Unsigned as _};
use types::{
    capella::containers::Withdrawal,
    config::Config,
    electra::{
        beacon_state::BeaconState,
        containers::{BlindedBeaconBlock, BlindedBeaconBlockBody},
    },
    preset::Preset,
    traits::{PostCapellaExecutionPayloadHeader, PostElectraBeaconState},
};

use super::block_processing;
use crate::{
    altair,
    unphased::{self, Error},
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

pub fn custom_process_blinded_block<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut BeaconState<P>,
    block: &BlindedBeaconBlock<P>,
    mut verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    #[cfg(feature = "metrics")]
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.blinded_block_transition_times.start_timer());

    debug_assert_eq!(state.slot, block.slot);

    unphased::process_block_header(config, state, block)?;

    // > [New in Capella]
    process_withdrawals_root(state, &block.body.execution_payload_header)?;

    // > [Modified in Capella]
    process_execution_payload(config, state, &block.body)?;

    unphased::process_randao(config, pubkey_cache, state, &block.body, &mut verifier)?;
    unphased::process_eth1_data(state, &block.body)?;

    block_processing::process_operations(
        config,
        pubkey_cache,
        state,
        &block.body,
        &mut verifier,
        &mut slot_report,
    )?;

    // > [New in Electra:EIP6110]
    for deposit_request in &block.body.execution_requests.deposits {
        block_processing::process_deposit_request(state, *deposit_request)?;
    }

    // > [New in Electra:EIP7002:EIP7251]
    for withdrawal_request in &block.body.execution_requests.withdrawals {
        block_processing::process_withdrawal_request(config, state, *withdrawal_request)?;
    }

    // > [New in Electra:EIP7251]
    for consolidation_request in &block.body.execution_requests.consolidations {
        block_processing::process_consolidation_request(config, state, *consolidation_request)?;
    }

    altair::process_sync_aggregate(
        config,
        pubkey_cache,
        state,
        block.body.sync_aggregate,
        verifier,
        slot_report,
    )
}

fn process_execution_payload<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    body: &BlindedBeaconBlockBody<P>,
) -> Result<()> {
    let payload_header = &body.execution_payload_header;

    let in_state = state.latest_execution_payload_header.block_hash;
    let in_block = payload_header.parent_hash;

    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadParentHashMismatch { in_state, in_block },
    );

    let in_state = accessors::get_randao_mix(state, accessors::get_current_epoch(state));
    let in_block = payload_header.prev_randao;

    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadPrevRandaoMismatch { in_state, in_block },
    );

    let computed = misc::compute_timestamp_at_slot(config, state, state.slot);
    let in_block = payload_header.timestamp;

    ensure!(
        computed == in_block,
        Error::<P>::ExecutionPayloadTimestampMismatch { computed, in_block },
    );

    state.latest_execution_payload_header = payload_header.clone();

    Ok(())
}

pub fn process_withdrawals_root<P: Preset>(
    state: &mut impl PostElectraBeaconState<P>,
    payload_header: &impl PostCapellaExecutionPayloadHeader<P>,
) -> Result<()>
where
    P::MaxWithdrawalsPerPayload: NonZero,
{
    let (expected_withdrawals, processed_partial_withdrawals_count) =
        block_processing::get_expected_withdrawals(state)?;
    let expected_withdrawals =
        expected_withdrawals.try_conv::<ContiguousList<_, P::MaxWithdrawalsPerPayload>>()?;

    let computed = expected_withdrawals.hash_tree_root();
    let in_block = payload_header.withdrawals_root();

    ensure!(
        computed == in_block,
        Error::<P>::WithdrawalRootMismatch { computed, in_block },
    );

    for withdrawal in expected_withdrawals.iter().copied() {
        let Withdrawal {
            amount,
            validator_index,
            ..
        } = withdrawal;

        decrease_balance(balance(state, validator_index)?, amount);
    }

    // > Update pending partial withdrawals [New in Electra:EIP7251]
    *state.pending_partial_withdrawals_mut() = PersistentList::try_from_iter(
        state
            .pending_partial_withdrawals()
            .into_iter()
            .copied()
            .skip(processed_partial_withdrawals_count),
    )?;

    // > Update the next withdrawal index if this block contained withdrawals
    if let Some(latest_withdrawal) = expected_withdrawals.last() {
        *state.next_withdrawal_index_mut() = latest_withdrawal.index + 1;
    }

    // > Update the next validator index to start the next withdrawal sweep
    if expected_withdrawals.len() == P::MaxWithdrawalsPerPayload::USIZE {
        // > Next sweep starts after the latest withdrawal's validator index
        let next_validator_index = expected_withdrawals
            .last()
            .expect(
                "the NonZero bound on P::MaxWithdrawalsPerPayload \
                 ensures that expected_withdrawals is not empty",
            )
            .validator_index
            .add(1)
            .rem(state.validators().len_u64());

        *state.next_withdrawal_validator_index_mut() = next_validator_index;
    } else {
        // > Advance sweep by the max length of the sweep if there was not a full set of withdrawals
        let next_index =
            state.next_withdrawal_validator_index() + P::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP;

        let next_validator_index = next_index % state.validators().len_u64();

        *state.next_withdrawal_validator_index_mut() = next_validator_index;
    }

    Ok(())
}
