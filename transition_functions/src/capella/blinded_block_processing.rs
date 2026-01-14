use anyhow::{ensure, Result};
use helper_functions::{
    accessors, misc,
    mutators::{balance, decrease_balance},
    slot_report::SlotReport,
    verifier::Verifier,
};
use pubkey_cache::PubkeyCache;
use ssz::{ContiguousList, SszHash as _};
use tap::TryConv as _;
use typenum::NonZero;
use types::{
    capella::{
        beacon_state::BeaconState,
        containers::{BlindedBeaconBlock, BlindedBeaconBlockBody, Withdrawal},
    },
    config::Config,
    preset::Preset,
    traits::{PostCapellaBeaconState, PostCapellaExecutionPayloadHeader},
};

use crate::{
    altair,
    capella::{self, get_expected_withdrawals, update_next_withdrawal_validator_index},
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

    // > [Modified in Capella] Removed `is_execution_enabled` check in Capella
    //
    // > [New in Capella]
    process_withdrawals_root(state, &block.body.execution_payload_header)?;

    // > [Modified in Capella]
    process_execution_payload(config, state, &block.body)?;

    unphased::process_randao(config, pubkey_cache, state, &block.body, &mut verifier)?;
    unphased::process_eth1_data(state, &block.body)?;

    // > [Modified in Capella]
    capella::process_operations(
        config,
        pubkey_cache,
        state,
        &block.body,
        &mut verifier,
        &mut slot_report,
    )?;

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

    // > [Modified in Capella] Removed `is_merge_transition_complete` check in Capella
    // > Verify consistency of the parent hash with respect to the previous execution payload header
    let in_state = state.latest_execution_payload_header.block_hash;
    let in_block = payload_header.parent_hash;

    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadParentHashMismatch { in_state, in_block },
    );

    // > Verify prev_randao
    let in_state = accessors::get_randao_mix(state, accessors::get_current_epoch(state));
    let in_block = payload_header.prev_randao;

    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadPrevRandaoMismatch { in_state, in_block },
    );

    // > Verify timestamp
    let computed = misc::compute_timestamp_at_slot(config, state, state.slot);
    let in_block = payload_header.timestamp;

    ensure!(
        computed == in_block,
        Error::<P>::ExecutionPayloadTimestampMismatch { computed, in_block },
    );

    // > Cache execution payload header
    state.latest_execution_payload_header = payload_header.clone();

    Ok(())
}

pub fn process_withdrawals_root<P: Preset>(
    state: &mut impl PostCapellaBeaconState<P>,
    payload_header: &impl PostCapellaExecutionPayloadHeader<P>,
) -> Result<()>
where
    P::MaxWithdrawalsPerPayload: NonZero,
{
    let expected_withdrawals = get_expected_withdrawals(state)?
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
    update_next_withdrawal_validator_index(state, expected_withdrawals.as_ref());

    Ok(())
}
