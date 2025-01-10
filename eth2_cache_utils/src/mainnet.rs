use core::ops::RangeInclusive;
use std::{collections::BTreeMap, sync::Arc};

use spec_test_utils::Case;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    deneb::containers::BlobSidecar,
    phase0::{consts::GENESIS_SLOT, primitives::Slot},
    preset::Mainnet,
};

use crate::generic::{self, LazyBeaconBlock, LazyBeaconBlocks, LazyBeaconState, LazyBlobSidecars};

const CASE: Case = Case {
    case_path_relative_to_workspace_root: "eth2-cache/mainnet",
};

pub static GENESIS_BEACON_STATE: LazyBeaconState<Mainnet> =
    LazyBeaconState::new(|| beacon_state(GENESIS_SLOT, 6));

pub static BEACON_STATE_AT_SLOT_8192: LazyBeaconState<Mainnet> =
    LazyBeaconState::new(|| beacon_state(8192, 6));

pub static ALTAIR_BEACON_STATE: LazyBeaconState<Mainnet> =
    LazyBeaconState::new(|| beacon_state(3_078_848, 7));

pub static CAPELLA_BEACON_STATE: LazyBeaconState<Mainnet> =
    LazyBeaconState::new(|| beacon_state(7_834_112, 7));

pub static ALTAIR_BEACON_BLOCK: LazyBeaconBlock<Mainnet> =
    LazyBeaconBlock::new(|| generic::beacon_block(&Config::mainnet(), CASE, 3_078_848, 7));

pub static CAPELLA_BEACON_BLOCK: LazyBeaconBlock<Mainnet> =
    LazyBeaconBlock::new(|| generic::beacon_block(&Config::mainnet(), CASE, 7_834_112, 7));

pub static BEACON_BLOCKS_UP_TO_SLOT_128: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(106, || beacon_blocks(GENESIS_SLOT..=128, 6));

pub static BEACON_BLOCKS_UP_TO_SLOT_1024: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(876, || beacon_blocks(GENESIS_SLOT..=1024, 6));

pub static BEACON_BLOCKS_UP_TO_SLOT_2048: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(1829, || beacon_blocks(GENESIS_SLOT..=2048, 6));

pub static BEACON_BLOCKS_UP_TO_SLOT_8192: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(7716, || beacon_blocks(GENESIS_SLOT..=8192, 6));

pub static ALTAIR_BEACON_BLOCKS_FROM_32_SLOTS: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(33, || beacon_blocks(3_078_848..=3_078_880, 7));

pub static ALTAIR_BEACON_BLOCKS_FROM_128_SLOTS: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(128, || beacon_blocks(3_078_848..=3_078_976, 7));

pub static ALTAIR_BEACON_BLOCKS_FROM_1024_SLOTS: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(1017, || beacon_blocks(3_078_848..=3_079_872, 7));

pub static ALTAIR_BEACON_BLOCKS_FROM_2048_SLOTS: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(2038, || beacon_blocks(3_078_848..=3_080_896, 7));

pub static ALTAIR_BEACON_BLOCKS_FROM_8192_SLOTS: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(8101, || beacon_blocks(3_078_848..=3_087_040, 7));

pub static CAPELLA_BEACON_BLOCKS_FROM_244816_SLOTS: LazyBeaconBlocks<Mainnet> =
    LazyBeaconBlocks::new(127, || beacon_blocks(7_834_112..=7_834_240, 7));

pub static DENEB_BLOB_SIDECARS_FROM_32_SLOTS: LazyBlobSidecars<Mainnet> =
    LazyBlobSidecars::new(129, || {
        blob_sidecars(9_481_344..=9_481_393, 7)
            .into_values()
            .flatten()
            .collect()
    });

#[must_use]
pub fn beacon_blocks(
    slots: RangeInclusive<Slot>,
    width: usize,
) -> Vec<Arc<SignedBeaconBlock<Mainnet>>> {
    generic::beacon_blocks(&Config::mainnet(), CASE, slots, width)
}

#[must_use]
pub fn beacon_state(slot: Slot, width: usize) -> Arc<BeaconState<Mainnet>> {
    generic::beacon_state(&Config::mainnet(), CASE, slot, width)
}

#[must_use]
pub fn blob_sidecars(
    slots: RangeInclusive<Slot>,
    width: usize,
) -> BTreeMap<Slot, Vec<Arc<BlobSidecar<Mainnet>>>> {
    generic::blob_sidecars(&Config::mainnet(), CASE, slots, width)
}
