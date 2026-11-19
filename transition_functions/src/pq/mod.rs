//! The PQ state transition (`specs/_features/pq/beacon-chain.md`).
//!
//! XMSS signatures and STARK proofs are checked by [`verify_signatures`] in parallel with block
//! processing, like BLS signatures in earlier phases. Proofs are verified with
//! [`pq_prover::block_backend`].

use core::ops::Not as _;

use anyhow::{Result, ensure};
use arithmetic::U64Ext as _;
use helper_functions::{
    misc, par_utils,
    slot_report::SlotReport,
    verifier::{NullVerifier, Verifier, VerifierOption},
};
use pubkey_cache::PubkeyCache;
use ssz::Hc;
use types::{
    config::Config,
    phase0::primitives::Slot,
    pq::{beacon_state::BeaconState, containers::SignedBeaconBlock},
    preset::Preset,
};

pub use block_processing::{
    apply_parent_execution_payload, process_parent_execution_payload, validate_attester_slashing,
    verify_execution_payload_bid_signature, verify_execution_requests_limits,
};
pub use epoch_processing::initialize_aggregation_committee_window;

pub(crate) use block_processing::{process_block, process_block_for_gossip};
pub(crate) use epoch_processing::process_epoch;

use crate::{
    gloas,
    unphased::{Error, ProcessSlots, StateRootPolicy},
};

mod block_processing;
mod epoch_processing;
mod execution_requests;

#[cfg(test)]
mod spec_tests;

#[expect(clippy::too_many_arguments)]
pub fn state_transition<P: Preset, V: Verifier + Send>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut Hc<BeaconState<P>>,
    signed_block: &SignedBeaconBlock<P>,
    process_slots: ProcessSlots,
    state_root_policy: StateRootPolicy,
    verifier: V,
    slot_report: impl SlotReport + Send,
) -> Result<()> {
    let block = &signed_block.message;

    // > Process slots (including those with no blocks) since block
    if process_slots.should_process(state, block) {
        self::process_slots(config, pubkey_cache, state, block.slot)?;
    }

    let verify_signatures = V::IS_NULL.not().then(|| {
        let state = state.clone();

        // > Verify signature
        move || verify_signatures(config, pubkey_cache, &state, signed_block, &verifier)
    });

    let process_block = || {
        // > Process block
        block_processing::custom_process_block(
            config,
            state,
            &signed_block.message,
            &NullVerifier,
            slot_report,
        )?;

        // > Verify state root
        state_root_policy.verify(state, block)?;

        Ok(())
    };

    if let Some(verify_signatures) = verify_signatures {
        let (block_result, signature_result) = par_utils::join(process_block, verify_signatures);
        signature_result.and(block_result)
    } else {
        process_block()
    }
}

pub fn verify_signatures<P: Preset>(
    config: &Config,
    _pubkey_cache: &PubkeyCache,
    state: &BeaconState<P>,
    block: &SignedBeaconBlock<P>,
    verifier: &impl Verifier,
) -> Result<()> {
    if !verifier.has_option(VerifierOption::SkipBlockBaseSignatures)
        && !verifier.has_option(VerifierOption::SkipBlockRootSignature)
    {
        block_processing::verify_block_signature(config, state, block)?;
    }

    block_processing::verify_body_signatures(config, state, &block.message)
}

pub fn process_slots<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut Hc<BeaconState<P>>,
    slot: Slot,
) -> Result<()> {
    ensure!(
        state.slot < slot,
        Error::<P>::SlotNotLater {
            current: state.slot,
            target: slot,
        },
    );

    while state.slot < slot {
        gloas::process_slot(state)?;

        // > Process epoch on the start slot of the next epoch
        if misc::is_epoch_start::<P>(state.slot.try_add(1)?) {
            process_epoch(config, pubkey_cache, state)?;
        }

        state.slot = state.slot.try_add(1)?;
    }

    Ok(())
}
