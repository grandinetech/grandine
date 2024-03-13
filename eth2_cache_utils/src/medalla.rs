use core::ops::RangeInclusive;
use std::sync::Arc;

use spec_test_utils::Case;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    phase0::{consts::GENESIS_SLOT, primitives::Slot},
    preset::Medalla,
};

use crate::generic::{self, LazyBeaconBlock, LazyBeaconBlocks, LazyBeaconState};

const ROUGHTIME_START: Slot = 73248;
const ROUGHTIME_END: Slot = 74272;

const CASE: Case = Case {
    case_path_relative_to_workspace_root: "eth2-cache/medalla",
};

pub static GENESIS_BEACON_STATE: LazyBeaconState<Medalla> =
    LazyBeaconState::new(|| beacon_state(GENESIS_SLOT, 4));

pub static BEACON_STATE_DURING_ROUGHTIME: LazyBeaconState<Medalla> =
    LazyBeaconState::new(|| beacon_state(ROUGHTIME_START, 5));

pub static GENESIS_BEACON_BLOCK: LazyBeaconBlock<Medalla> =
    LazyBeaconBlock::new(|| generic::beacon_block(&Config::medalla(), CASE, GENESIS_SLOT, 4));

pub static BEACON_BLOCKS_UP_TO_SLOT_128: LazyBeaconBlocks<Medalla> =
    LazyBeaconBlocks::new(81, || beacon_blocks(GENESIS_SLOT..=128, 4));

pub static BEACON_BLOCKS_UP_TO_SLOT_1024: LazyBeaconBlocks<Medalla> =
    LazyBeaconBlocks::new(742, || beacon_blocks(GENESIS_SLOT..=1024, 4));

pub static BEACON_BLOCKS_DURING_ROUGHTIME: LazyBeaconBlocks<Medalla> =
    LazyBeaconBlocks::new(362, || beacon_blocks(ROUGHTIME_START..=ROUGHTIME_END, 5));

#[must_use]
pub fn beacon_blocks(
    slots: RangeInclusive<Slot>,
    width: usize,
) -> Vec<Arc<SignedBeaconBlock<Medalla>>> {
    generic::beacon_blocks(&Config::medalla(), CASE, slots, width)
}

#[must_use]
pub fn beacon_state(slot: Slot, width: usize) -> Arc<BeaconState<Medalla>> {
    generic::beacon_state(&Config::medalla(), CASE, slot, width)
}
