use anyhow::{Result, ensure};
use arithmetic::U64Ext as _;
use helper_functions::misc;
use pubkey_cache::PubkeyCache;
use ssz::Hc;
use types::{
    bellatrix::beacon_state::BeaconState, config::Config, phase0::primitives::Slot, preset::Preset,
};

use super::epoch_processing;
use crate::unphased::{self, Error};

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
        unphased::process_slot(state);

        // > Process epoch on the start slot of the next epoch
        if misc::is_epoch_start::<P>(state.slot.try_add(1)?) {
            epoch_processing::process_epoch(config, pubkey_cache, state)?;
        }

        state.slot = state.slot.try_add(1)?;
    }

    Ok(())
}
