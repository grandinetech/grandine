#![no_main]

use anyhow::Result;
use pico_sdk::io::{commit, read_vec};
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
    // use Config::pectra_devnet_4() for Pectra devnet-4;
    let config = Config::pectra_devnet_6();

    let (block, mut state, cache) = read_block_and_state::<Mainnet>(&config)
        .expect("zkvm-guest-pico: read_block_and_state should succeed");

    eprintln!("zkvm-guest-pico: state transition starts");
    state_transition(&config, &cache, &mut state, &block)
        .expect("zkvm-guest-pico: state_transtion should not fail");
    eprintln!("zkvm-guest-pico: state transition ends");

    commit(&state.hash_tree_root().0);
}

fn read_block_and_state<P: Preset>(config: &Config) -> Result<(SignedBeaconBlock<P>, BeaconState<P>, PubkeyCache)> {

    let state_ssz = read_vec();
    eprintln!("zkvm-guest-pico: state_ssz len: {}", state_ssz.len());

    let block_ssz = read_vec();
    eprintln!("zkvm-guest-pico: block_ssz len: {}", block_ssz.len());

    let cache_ssz = read_vec();
    eprintln!("zkvm-guest-pico: cache_ssz len: {}", cache_ssz.len());

    let phase_bytes = read_vec();
    eprintln!("zkvm-guest-pico: phase_bytes len: {}", phase_bytes.len());

    let phase = enum_iterator::all::<Phase>()
        .zip(0_u8..)
        .find(|(_, index)| phase_bytes.get(0) == Some(&index))
        .map(|(phase, _)| phase);

    eprintln!("zkvm-guest-pico: parsing SignedBeaconBlock starts");
    let block = match phase {
        Some(phase) => SignedBeaconBlock::<P>::from_ssz_at_phase(phase, &block_ssz)?,
        None => SignedBeaconBlock::<P>::from_ssz(config, &block_ssz)?,
    };
    eprintln!("zkvm-guest-pico: parsing SignedBeaconBlock ends");

    eprintln!("zkvm-guest-pico: parsing BeaconState starts");
    let state = match phase {
        Some(phase) => BeaconState::<P>::from_ssz_at_phase(phase, &state_ssz)?,
        None => BeaconState::<P>::from_ssz(config, &state_ssz)?,
    };
    eprintln!("zkvm-guest-pico: parsing BeaconState ends");

    let cache = PubkeyCache::from_ssz(config, &cache_ssz)?;

    Ok((block, state, cache))
}
