#![no_main]

use anyhow::Result;
use pico_sdk::io::{commit, read_vec, read_as};
use pubkey_cache::PubkeyCache;
use ssz::{SszRead as _, SszHash as _};
use transition_functions::combined::untrusted_state_transition as state_transition;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    nonstandard::Phase,
    preset::{Mainnet, Preset},
};

pico_sdk::entrypoint!(main);

pub fn main() {
    println!("loading block and state...");

    let (config, block, mut state, cache) = read_block_and_state::<Mainnet>()
        .expect("zkvm-guest-pico: read_block_and_state should succeed");

    println!("loaded block and state");

    println!("performing state transition...");

    state_transition(&config, &cache, &mut state, &block)
        .expect("zkvm-guest-pico: state_transtion should not fail");

    println!("performed state transition");

    commit(&state.hash_tree_root().0);

    println!("committed output");
}

fn read_block_and_state<P: Preset>() -> Result<(Config, SignedBeaconBlock<P>, BeaconState<P>, PubkeyCache)> {
    let config_kind: u8 = read_as::<u8>();
    let config = match config_kind {
        0 => Config::mainnet(),
        1 => Config::pectra_devnet_6(),
        v => panic!("unknown config kind {v}"),
    };

    let state_ssz = read_vec();
    println!("state_ssz len: {}", state_ssz.len());

    let block_ssz = read_vec();
    println!("block_ssz len: {}", block_ssz.len());

    let cache_ssz = read_vec();
    println!("cache_ssz len: {}", cache_ssz.len());

    let phase_bytes = read_vec();
    println!("phase_bytes len: {}", phase_bytes.len());

    let phase = enum_iterator::all::<Phase>()
        .zip(0_u8..)
        .find(|(_, index)| phase_bytes.get(0) == Some(&index))
        .map(|(phase, _)| phase);

    println!("parsing SignedBeaconBlock starts");
    let block = match phase {
        Some(phase) => SignedBeaconBlock::<P>::from_ssz_at_phase(phase, &block_ssz)?,
        None => SignedBeaconBlock::<P>::from_ssz(&config, &block_ssz)?,
    };
    println!("parsing SignedBeaconBlock ends");

    println!("parsing BeaconState starts");
    let state = match phase {
        Some(phase) => BeaconState::<P>::from_ssz_at_phase(phase, &state_ssz)?,
        None => BeaconState::<P>::from_ssz(&config, &state_ssz)?,
    };
    println!("parsing BeaconState ends");

    let cache = PubkeyCache::from_ssz(&config, &cache_ssz)?;

    Ok((config, block, state, cache))
}
