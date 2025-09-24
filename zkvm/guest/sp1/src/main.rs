// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use anyhow::Result;
use pubkey_cache::PubkeyCache;
use ssz::{SszHash as _, SszRead as _};
use transition_functions::combined::untrusted_state_transition as state_transition;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    nonstandard::Phase,
    preset::{Mainnet, Preset},
};

fn read_block_and_state<P: Preset>(
) -> Result<(Config, SignedBeaconBlock<P>, BeaconState<P>, PubkeyCache)> {
    let config_kind: u8 = sp1_zkvm::io::read();
    let config = match config_kind {
        0 => Config::mainnet(),
        1 => Config::pectra_devnet_6(),
        v => panic!("unknown config kind {v}"),
    };

    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let state_ssz = sp1_zkvm::io::read_vec();
    let block_ssz = sp1_zkvm::io::read_vec();
    let cache_ssz = sp1_zkvm::io::read_vec();
    let phase_bytes = sp1_zkvm::io::read_vec();

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

pub fn main() {
    println!("loading block and state...");

    let (config, block, mut state, cache) = read_block_and_state::<Mainnet>().unwrap();

    println!("loaded block and state");

    println!("performing state transition...");

    state_transition(&config, &cache, &mut state, &block).unwrap();

    println!("performed state transition");

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&state.hash_tree_root().0);

    println!("committed output");
}
