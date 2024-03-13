use anyhow::{ensure, Result};
use helper_functions::{accessors, misc, predicates, slot_report::SlotReport, verifier::Verifier};

use types::{
    bellatrix::{
        beacon_state::BeaconState,
        containers::{BlindedBeaconBlock, BlindedBeaconBlockBody},
    },
    config::Config,
    preset::Preset,
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
    debug_assert_eq!(state.slot, block.slot);

    unphased::process_block_header(state, block)?;

    // > [New in Bellatrix]
    //
    // We call `process_execution_payload` unconditionally even in Bellatrix.
    // This way we don't have to check if the payload header corresponds to the default payload.
    // This is less general but probably safe because all blinded blocks should be post-Merge.
    // See <https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#responsibilities-during-the-merge-transition>.
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

    // > Verify consistency of the parent hash with respect to the previous execution payload header
    if predicates::is_merge_transition_complete(state) {
        let in_state = state.latest_execution_payload_header.block_hash;
        let in_block = payload_header.parent_hash;

        ensure!(
            in_state == in_block,
            Error::<P>::ExecutionPayloadParentHashMismatch { in_state, in_block },
        );
    }

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
