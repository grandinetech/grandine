use core::ops::{Add as _, Rem as _};

use anyhow::{ensure, Result};
use helper_functions::{accessors, misc, slot_report::SlotReport, verifier::Verifier, mutators::{balance, decrease_balance},};
use prometheus_metrics::METRICS;
use ssz::{ContiguousList, SszHash as _};
use tap::TryConv as _;
use typenum::{NonZero, Unsigned as _};
use types::{
    capella::containers::Withdrawal,
    config::Config,
    electra::{
        beacon_state::BeaconState,
        containers::{BlindedBeaconBlock, BlindedBeaconBlockBody},
    },
    preset::Preset,
    traits::{PostElectraBeaconState, PostElectraExecutionPayloadHeader},
};

use super::block_processing;
use crate::{
    altair, 
    unphased::{self, Error},
};

pub fn custom_process_blinded_block<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    block: &BlindedBeaconBlock<P>,
    mut verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.blinded_block_transition_times.start_timer());

    debug_assert_eq!(state.slot, block.slot);

    unphased::process_block_header(state, block)?;

    // > [Modified in Electra:EIP7251]
    process_withdrawals_root(state, &block.body.execution_payload_header)?;

    // > [Modified in Capella]
    process_execution_payload(config, state, &block.body)?;

    unphased::process_randao(config, state, &block.body, &mut verifier)?;
    unphased::process_eth1_data(state, &block.body)?;

    block_processing::process_operations(
        config,
        state,
        &block.body,
        &mut verifier,
        &mut slot_report,
    )?;

    // TODO: process_deposit_requests_root()
    // TODO: process_withdrawal_requests_root()
    // TODO: process_consolidation_requests_root()

    altair::process_sync_aggregate(
        config,
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
    payload_header: &impl PostElectraExecutionPayloadHeader<P>,
) -> Result<()>
where
    P::MaxWithdrawalsPerPayload: NonZero,
{
    let expected_withdrawals = block_processing::get_expected_withdrawals(state)?.0
        .try_conv::<ContiguousList<_, P::MaxWithdrawalsPerPayload>>()?;

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
            *state.next_withdrawal_validator_index_mut() + P::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP;

        let next_validator_index = next_index % state.validators().len_u64();

        *state.next_withdrawal_validator_index_mut() = next_validator_index;
    }

    Ok(())
}