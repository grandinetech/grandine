use anyhow::{ensure, Result};
use helper_functions::{accessors, misc, slot_report::SlotReport, verifier::Verifier};
use pubkey_cache::PubkeyCache;
use types::{
    config::Config,
    fulu::{
        beacon_state::BeaconState,
        containers::{BlindedBeaconBlock, BlindedBeaconBlockBody},
    },
    preset::Preset,
};

use crate::{
    altair, electra,
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

    // > [Modified in Electra]
    electra::process_withdrawals_root(state, &block.body.execution_payload_header)?;

    // > [Modified in Capella]
    process_execution_payload(config, state, &block.body)?;

    unphased::process_randao(config, pubkey_cache, state, &block.body, &mut verifier)?;
    unphased::process_eth1_data(state, &block.body)?;

    electra::process_operations(
        config,
        pubkey_cache,
        state,
        &block.body,
        &mut verifier,
        &mut slot_report,
    )?;

    // > [New in Electra:EIP6110]
    for deposit_request in &block.body.execution_requests.deposits {
        electra::process_deposit_request(state, *deposit_request)?;
    }

    // > [New in Electra:EIP7002:EIP7251]
    for withdrawal_request in &block.body.execution_requests.withdrawals {
        electra::process_withdrawal_request(config, state, *withdrawal_request)?;
    }

    // > [New in Electra:EIP7251]
    for consolidation_request in &block.body.execution_requests.consolidations {
        electra::process_consolidation_request(config, state, *consolidation_request)?;
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
