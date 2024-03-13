use core::ops::RangeInclusive;
use std::sync::Arc;

use spec_test_utils::Case;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    phase0::{consts::GENESIS_SLOT, primitives::Slot},
    preset::Mainnet,
};

use crate::generic::{self, LazyBeaconBlock, LazyBeaconState};

const CASE: Case = Case {
    case_path_relative_to_workspace_root: "eth2-cache/withdrawals_devnet_3",
};

pub static GENESIS_BEACON_STATE: LazyBeaconState<Mainnet> =
    LazyBeaconState::new(|| beacon_state(GENESIS_SLOT, 6));

pub static GENESIS_BEACON_BLOCK: LazyBeaconBlock<Mainnet> =
    LazyBeaconBlock::new(|| generic::beacon_block(&Config::withdrawal_devnet_3(), CASE, 0, 6));

#[must_use]
pub fn beacon_blocks(
    slots: RangeInclusive<Slot>,
    width: usize,
) -> Vec<Arc<SignedBeaconBlock<Mainnet>>> {
    generic::beacon_blocks(&Config::withdrawal_devnet_3(), CASE, slots, width)
}

#[must_use]
pub fn beacon_state(slot: Slot, width: usize) -> Arc<BeaconState<Mainnet>> {
    generic::beacon_state(&Config::withdrawal_devnet_3(), CASE, slot, width)
}
