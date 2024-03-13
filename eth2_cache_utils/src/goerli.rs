use core::ops::RangeInclusive;
use std::sync::Arc;

use spec_test_utils::Case;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    phase0::{
        consts::GENESIS_SLOT,
        containers::Attestation,
        primitives::{Epoch, Slot},
    },
    preset::Mainnet,
};

use crate::generic::{self, LazyBeaconBlocks, LazyBeaconState};

const CASE: Case = Case {
    case_path_relative_to_workspace_root: "eth2-cache/prater",
};

pub static GENESIS_BEACON_STATE: LazyBeaconState<Mainnet> =
    LazyBeaconState::new(|| beacon_state(GENESIS_SLOT, 6));

pub static BEACON_BLOCKS_UP_TO_SLOT_128: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(104, || beacon_blocks(GENESIS_SLOT..=128, 6));

pub static BEACON_BLOCKS_UP_TO_SLOT_1024: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(938, || beacon_blocks(GENESIS_SLOT..=1024, 6));

pub static BEACON_BLOCKS_UP_TO_SLOT_2048: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(1925, || beacon_blocks(GENESIS_SLOT..=2048, 6));

pub static BEACON_BLOCKS_UP_TO_SLOT_8192: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(7874, || beacon_blocks(GENESIS_SLOT..=8192, 6));

#[must_use]
pub fn beacon_blocks(
    slots: RangeInclusive<Slot>,
    width: usize,
) -> Vec<Arc<SignedBeaconBlock<Mainnet>>> {
    generic::beacon_blocks(&Config::goerli(), CASE, slots, width)
}

#[must_use]
pub fn beacon_state(slot: Slot, width: usize) -> Arc<BeaconState<Mainnet>> {
    generic::beacon_state(&Config::goerli(), CASE, slot, width)
}

#[must_use]
pub fn attestations(directory: &str, epoch: Epoch) -> Vec<Attestation<Mainnet>> {
    let pattern = format!("attestations/epoch_{epoch:06}/{directory}/*.ssz");

    CASE.glob(pattern)
        .map(|path| CASE.ssz_uncompressed_default(path))
        .collect()
}
