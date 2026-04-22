#![no_main]
ziskos::entrypoint!(main);

use anyhow::{Result, anyhow, ensure};
use byteorder::ByteOrder;
use pubkey_cache::PubkeyCache;
use ssz::{SszHash as _, SszRead as _};
use transition_functions::combined::untrusted_state_transition as state_transition;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    nonstandard::Phase,
    preset::{Mainnet, Preset},
};
use ziskos::{read_input_slice, set_output};

fn main() {
    println!("loading block and state...");

    let input = read_input_slice();
    let (config, block, mut state, cache) = read_block_and_state::<Mainnet>(input)
        .expect("zkvm-guest-zisk: read_block_and_state should succeed");

    println!("loaded block and state");

    println!("performing state transition...");

    state_transition(&config, &cache, &mut state, &block)
        .expect("zkvm-guest-zisk: state_transtion should not fail");

    println!("performed state transition");

    let mut root = state.hash_tree_root().0;

    // Write the resulting state root to the output, 4 bytes at a time.
    for i in 0..8 {
        let word = byteorder::LittleEndian::read_u32(&mut root[i * 4..i * 4 + 4]);
        set_output(i, word);
    }
}

/// Deserializes the input data and parses the SSZ components
fn read_block_and_state<P: Preset>(
    mut input: &[u8],
) -> Result<(Config, SignedBeaconBlock<P>, BeaconState<P>, PubkeyCache)> {
    // reading config
    let config = take_bytes(&mut input, 1)?[0];

    // reading state_ssz
    let state_ssz_len = read_len(&mut input)?;
    let state_ssz = take_bytes(&mut input, state_ssz_len)?;

    // reading block_ssz
    let block_ssz_len = read_len(&mut input)?;
    let block_ssz = take_bytes(&mut input, block_ssz_len)?;

    // reading cache_ssz
    let cache_ssz_len = read_len(&mut input)?;
    let cache_ssz = take_bytes(&mut input, cache_ssz_len)?;

    // reading phase_bytes
    let phase_bytes_len = read_len(&mut input)?;
    let phase_bytes = take_bytes(&mut input, phase_bytes_len)?;

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

fn read_len(input: &mut &[u8]) -> Result<usize> {
    let bytes = take_bytes(input, size_of::<usize>())?;
    let bytes: [u8; size_of::<usize>()] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid length field"))?;

    Ok(usize::from_be_bytes(bytes))
}

fn take_bytes<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    ensure!(input.len() >= len, "input ended early");

    let (prefix, suffix) = input.split_at(len);
    *input = suffix;

    Ok(prefix)
}
