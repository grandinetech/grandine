use anyhow::{ensure, Result};
use helper_functions::misc;
use pubkey_cache::PubkeyCache;
use ssz::{Hc, SszHash as _};
use typenum::Unsigned as _;
use types::{
    config::Config,
    gloas::beacon_state::BeaconState,
    phase0::primitives::Slot,
    preset::{Preset, SlotsPerHistoricalRoot},
    traits::PostGloasBeaconState,
};

use super::epoch_processing;
use crate::unphased::Error;

pub fn process_slot<P: Preset>(state: &mut impl PostGloasBeaconState<P>) -> Result<()> {
    let slot = state.slot();

    // > Cache state root
    let previous_state_root = state.hash_tree_root();
    *state.state_roots_mut().mod_index_mut(slot) = previous_state_root;

    // > Cache latest block header state root
    if state.latest_block_header().state_root.is_zero() {
        state.latest_block_header_mut().state_root = previous_state_root;
    }

    // > Cache block root
    let previous_block_root = state.latest_block_header().hash_tree_root();
    *state.block_roots_mut().mod_index_mut(slot) = previous_block_root;

    // > Unset the next payload availability
    let slot_usize: usize = slot.try_into()?;
    state
        .execution_payload_availability_mut()
        .set((slot_usize + 1) % SlotsPerHistoricalRoot::<P>::USIZE, false);

    state.cache_mut().advance_slot();

    Ok(())
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
        process_slot(state)?;

        // > Process epoch on the start slot of the next epoch
        if misc::is_epoch_start::<P>(state.slot + 1) {
            epoch_processing::process_epoch(config, pubkey_cache, state)?;
        }

        state.slot += 1;
    }

    Ok(())
}
