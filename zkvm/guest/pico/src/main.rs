#![no_main]

use anyhow::Result;
use pico_sdk::io::{commit, read_as, read_vec};
use pubkey_cache::PubkeyCache;
use ssz::{SszHash as _, SszRead as _};
use transition_functions::combined::untrusted_state_transition as state_transition;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    nonstandard::Phase,
    preset::{Mainnet, Preset},
};

pico_sdk::entrypoint!(main);

pub fn main() {
    println!("Loading block and state...");
    let (config, block, mut state, cache) = read_block_and_state::<Mainnet>()
        .expect("zkvm-guest-pico: read_block_and_state should succeed");

    println!("Performing state transition...");
    state_transition(&config, &cache, &mut state, &block)
        .expect("zkvm-guest-pico: state_transtion should not fail");

    commit(&state.hash_tree_root().0);
}

fn read_block_and_state<P: Preset>()
-> Result<(Config, SignedBeaconBlock<P>, BeaconState<P>, PubkeyCache)> {
    let config_kind: u8 = read_as::<u8>();
    let config = match config_kind {
        0 => Config::mainnet(),
        1 => Config::pectra_devnet_6(),
        v => panic!("unknown config kind {v}"),
    };

    let state_ssz = read_vec();
    let block_ssz = read_vec();
    let cache_ssz = read_vec();
    let phase_bytes = read_vec();

    let phase = enum_iterator::all::<Phase>()
        .zip(0_u8..)
        .find(|(_, index)| phase_bytes.get(0) == Some(&index))
        .map(|(phase, _)| phase);

    println!("Parsing SignedBeaconBlock...");
    let block = match phase {
        Some(phase) => SignedBeaconBlock::<P>::from_ssz_at_phase(phase, &block_ssz)?,
        None => SignedBeaconBlock::<P>::from_ssz(&config, &block_ssz)?,
    };

    println!("Parsing BeaconState...");
    let state = match phase {
        Some(phase) => BeaconState::<P>::from_ssz_at_phase(phase, &state_ssz)?,
        None => BeaconState::<P>::from_ssz(&config, &state_ssz)?,
    };

    let cache = PubkeyCache::from_ssz(&config, &cache_ssz)?;

    Ok((config, block, state, cache))
}
