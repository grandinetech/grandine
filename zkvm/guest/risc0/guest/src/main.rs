use risc0_zkvm::guest::env;

use anyhow::Result;
use ssz::{SszRead as _, SszHash as _};
use transition_functions::combined::untrusted_state_transition as state_transition;
use pubkey_cache::PubkeyCache;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    nonstandard::Phase,
    preset::{Mainnet, Preset},
};

fn read_block_and_state<P: Preset>() -> Result<(Config, SignedBeaconBlock<P>, BeaconState<P>, PubkeyCache)> {
    let config_kind: u8 = env::read();
    let config = match config_kind {
        0 => Config::mainnet(),
        1 => Config::pectra_devnet_6(),
        v => panic!("unknown config kind {v}"),
    };

    let state_ssz_len: usize = env::read();
    let block_ssz_len: usize = env::read();
    let cache_ssz_len: usize = env::read();
    let phase_bytes_len: usize = env::read();

    let mut block_ssz = vec![0_u8; block_ssz_len];
    let mut state_ssz = vec![0_u8; state_ssz_len];
    let mut cache_ssz = vec![0_u8; cache_ssz_len];
    let mut phase_bytes = vec![0_u8; phase_bytes_len];

    env::read_slice(&mut state_ssz);
    env::read_slice(&mut block_ssz);
    env::read_slice(&mut cache_ssz);
    env::read_slice(&mut phase_bytes);

    let phase = enum_iterator::all::<Phase>()
        .zip(0_u8..)
        .find(|(_, index)| phase_bytes.get(0) == Some(&index))
        .map(|(phase, _)| phase);

    let block = match phase {
        Some(phase) => SignedBeaconBlock::<P>::from_ssz_at_phase(phase, &block_ssz)?,
        None => SignedBeaconBlock::<P>::from_ssz(&config, &block_ssz)?,
    };

    let state = match phase {
        Some(phase) => BeaconState::<P>::from_ssz_at_phase(phase, &state_ssz)?,
        None => BeaconState::<P>::from_ssz(&config, &state_ssz)?,
    };

    let cache = PubkeyCache::from_ssz(&config, &cache_ssz)?;

    Ok((config, block, state, cache))
}

fn main() -> Result<()> {
    // ----------------

    let start = env::cycle_count();

    let (config, block, mut state, cache) = read_block_and_state::<Mainnet>()?;

    eprintln!("read input: {}", env::cycle_count() - start);

    // ----------------

    let start = env::cycle_count();

    state_transition(&config, &cache, &mut state, &block)?;

    eprintln!("state transition: {}", env::cycle_count() - start);

    // ----------------

    let start = env::cycle_count();

    env::commit_slice(&state.hash_tree_root().0);

    eprintln!("write output: {}", env::cycle_count() - start);

    Ok(())
}
