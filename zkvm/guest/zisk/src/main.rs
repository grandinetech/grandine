#![no_main]
ziskos::entrypoint!(main);

use anyhow::Result;
use byteorder::ByteOrder;
use pubkey_cache::PubkeyCache;
use serde::{Deserialize, Serialize};
use ssz::{SszHash as _, SszRead as _};
use transition_functions::combined::untrusted_state_transition as state_transition;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    nonstandard::Phase,
    preset::{Mainnet, Preset},
};
use ziskos::{read_input, set_output};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VMGuestInput {
    config: u8,
    state_ssz: Vec<u8>,
    block_ssz: Vec<u8>,
    cache_ssz: Vec<u8>,
    phase_bytes: Vec<u8>,
}

fn main() {
    println!("loading block and state...");

    let input = read_input();
    let (config, block, mut state, cache) = read_block_and_state::<Mainnet>(&input)
        .expect("zkvm-guest-zisk: read_block_and_state should succeed");

    println!("loaded block and state");

    println!("performing state transition...");

    state_transition(&config, &cache, &mut state, &block)
        .expect("zkvm-guest-zisk: state_transtion should not fail");

    println!("performed state transition");

    let mut root = state.hash_tree_root().0;

    // Write the resulting state root to the output, 4 bytes at a time.
    for i in 0..8 {
        let word = byteorder::BigEndian::read_u32(&mut root[i * 4..i * 4 + 4]);
        set_output(i, word);
    }
}

/// Deserializes the input data and parses the SSZ components
fn read_block_and_state<P: Preset>(
    input: &[u8],
) -> Result<(Config, SignedBeaconBlock<P>, BeaconState<P>, PubkeyCache)> {
    // Deserialize the input using bincode
    let VMGuestInput {
        config,
        state_ssz,
        block_ssz,
        cache_ssz,
        phase_bytes,
    } = bincode::deserialize(input).unwrap();

    let config = match config {
        0 => Config::mainnet(),
        1 => Config::pectra_devnet_6(),
        v => panic!("unknown config kind {v}"),
    };

    // Convert phase byte to Phase enum
    let phase = enum_iterator::all::<Phase>()
        .zip(0_u8..)
        .find(|(_, index)| *index == phase_bytes[0])
        .map(|(phase, _)| phase);

    // Parse the block from SSZ
    let block = match phase {
        Some(phase) => SignedBeaconBlock::<P>::from_ssz_at_phase(phase, &block_ssz)?,
        None => SignedBeaconBlock::<P>::from_ssz(&config, &block_ssz)?,
    };

    // Parse the state from SSZ
    let state = match phase {
        Some(phase) => BeaconState::<P>::from_ssz_at_phase(phase, &state_ssz)?,
        None => BeaconState::<P>::from_ssz(&config, &state_ssz)?,
    };

    // Parse the cache from SSZ
    let cache = PubkeyCache::from_ssz(&config, &cache_ssz)?;

    Ok((config, block, state, cache))
}
