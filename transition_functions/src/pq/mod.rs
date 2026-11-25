// TODO(PQ): Implement the PQ state transition (`specs/_features/pq/beacon-chain.md`).

use anyhow::{Result, bail};
use helper_functions::{slot_report::SlotReport, verifier::Verifier};
use pubkey_cache::PubkeyCache;
use ssz::Hc;
use types::{
    config::Config,
    phase0::primitives::Slot,
    pq::{
        beacon_state::BeaconState,
        containers::{BeaconBlock, SignedBeaconBlock},
    },
    preset::Preset,
};

use crate::unphased::{ProcessSlots, StateRootPolicy};

fn unimplemented() -> Result<()> {
    bail!("the PQ state transition is not implemented yet")
}

#[expect(clippy::too_many_arguments)]
pub fn state_transition<P: Preset>(
    _config: &Config,
    _pubkey_cache: &PubkeyCache,
    _state: &mut Hc<BeaconState<P>>,
    _signed_block: &SignedBeaconBlock<P>,
    _process_slots: ProcessSlots,
    _state_root_policy: StateRootPolicy,
    _verifier: impl Verifier,
    _slot_report: impl SlotReport,
) -> Result<()> {
    unimplemented()
}

pub fn verify_signatures<P: Preset>(
    _config: &Config,
    _pubkey_cache: &PubkeyCache,
    _state: &BeaconState<P>,
    _block: &SignedBeaconBlock<P>,
    _verifier: impl Verifier,
) -> Result<()> {
    unimplemented()
}

pub fn process_slots<P: Preset>(
    _config: &Config,
    _pubkey_cache: &PubkeyCache,
    _state: &mut Hc<BeaconState<P>>,
    _slot: Slot,
) -> Result<()> {
    unimplemented()
}

pub fn process_epoch<P: Preset>(
    _config: &Config,
    _pubkey_cache: &PubkeyCache,
    _state: &mut BeaconState<P>,
) -> Result<()> {
    unimplemented()
}

pub fn process_block<P: Preset>(
    _config: &Config,
    _pubkey_cache: &PubkeyCache,
    _state: &mut BeaconState<P>,
    _block: &BeaconBlock<P>,
    _verifier: impl Verifier,
    _slot_report: impl SlotReport,
) -> Result<()> {
    unimplemented()
}

pub fn process_block_for_gossip<P: Preset>(
    _config: &Config,
    _pubkey_cache: &PubkeyCache,
    _state: &BeaconState<P>,
    _block: &SignedBeaconBlock<P>,
) -> Result<()> {
    unimplemented()
}
