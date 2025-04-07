use anyhow::{ensure, Result};
use helper_functions::{accessors, misc, slot_report::SlotReport, verifier::Verifier};
use types::{
    config::Config,
    deneb::{
        beacon_state::BeaconState,
        containers::{BlindedBeaconBlock, BlindedBeaconBlockBody},
    },
    preset::Preset,
};

use super::block_processing;
use crate::{
    altair, capella,
    unphased::{self, Error},
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

pub fn custom_process_blinded_block<P: Preset>(
    config: &Config,
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
    capella::process_withdrawals_root(state, &block.body.execution_payload_header)?;

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
