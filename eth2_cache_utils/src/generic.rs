use core::ops::RangeInclusive;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, LazyLock},
};

use itertools::Itertools as _;
use spec_test_utils::Case;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    deneb::containers::BlobSidecar,
    phase0::primitives::Slot,
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

// `LazyLock` implements `core::ops::Deref`, which is more confusing than useful.
// Explicit forcing is better.

pub struct LazyBeaconState<P: Preset> {
    state: LazyLock<Arc<BeaconState<P>>>,
}

impl<P: Preset> LazyBeaconState<P> {
    #[must_use]
    pub const fn new(thunk: fn() -> Arc<BeaconState<P>>) -> Self {
        let state = LazyLock::new(thunk);
        Self { state }
    }

    pub fn force(&self) -> &Arc<BeaconState<P>> {
        LazyLock::force(&self.state)
    }
}

pub struct LazyBeaconBlock<P: Preset> {
    block: LazyLock<Arc<SignedBeaconBlock<P>>>,
}

impl<P: Preset> LazyBeaconBlock<P> {
    #[must_use]
    pub(crate) const fn new(thunk: fn() -> Arc<SignedBeaconBlock<P>>) -> Self {
        let block = LazyLock::new(thunk);
        Self { block }
    }

    pub fn force(&self) -> &Arc<SignedBeaconBlock<P>> {
        LazyLock::force(&self.block)
    }
}

pub struct LazyBeaconBlocks<P: Preset> {
    expected_count: u64,
    blocks: LazyLock<Vec<Arc<SignedBeaconBlock<P>>>>,
}

impl<P: Preset> LazyBeaconBlocks<P> {
    #[must_use]
    pub(crate) const fn new(
        expected_count: u64,
        thunk: fn() -> Vec<Arc<SignedBeaconBlock<P>>>,
    ) -> Self {
        Self {
            expected_count,
            blocks: LazyLock::new(thunk),
        }
    }

    #[must_use]
    pub const fn count(&self) -> u64 {
        self.expected_count
    }

    pub fn force(&self) -> &[Arc<SignedBeaconBlock<P>>] {
        let blocks = LazyLock::force(&self.blocks);
        let actual_count = u64::try_from(blocks.len()).expect("block count should fit in u64");

        assert_eq!(actual_count, self.expected_count);

        blocks
    }
}

pub fn beacon_state<P: Preset>(
    config: &Config,
    case: Case,
    slot: Slot,
    width: usize,
) -> Arc<BeaconState<P>> {
    let path = case
        .glob(format!("beacon_state_slot_{slot:0width$}_*"))
        .exactly_one()
        .unwrap_or_else(|_| {
            panic!(
                "slot should unambiguously identify a BeaconState in {}",
                case.case_path_relative_to_workspace_root,
            )
        });

    case.ssz_uncompressed(config, path)
}

pub fn beacon_block<P: Preset>(
    config: &Config,
    case: Case,
    slot: Slot,
    width: usize,
) -> Arc<SignedBeaconBlock<P>> {
    beacon_blocks(config, case, slot..=slot, width)
        .into_iter()
        .exactly_one()
        .unwrap_or_else(|_| {
            panic!(
                "slot should unambiguously identify a SignedBeaconBlock in {}",
                case.case_path_relative_to_workspace_root,
            )
        })
}

pub fn beacon_blocks<P: Preset>(
    config: &Config,
    case: Case,
    slots: RangeInclusive<Slot>,
    width: usize,
) -> Vec<Arc<SignedBeaconBlock<P>>> {
    let pattern = format!("beacon_block_slot_{:?<width$}_*", "");
    let low = format!("beacon_block_slot_{:0width$}_*", slots.start());
    let high = format!("beacon_block_slot_{:0width$}_*", slots.end() + 1);

    let blocks = case
        .glob(pattern)
        .skip_while(|path| path < Path::new(low.as_str()))
        .take_while(|path| path < Path::new(high.as_str()))
        .map(|path| case.ssz_uncompressed(config, path))
        .collect::<Vec<Arc<SignedBeaconBlock<P>>>>();

    if let Some(first_block) = blocks.first() {
        assert_eq!(first_block.message().slot(), *slots.start());
    }

    if let Some(last_block) = blocks.last() {
        assert_eq!(last_block.message().slot(), *slots.end());
    }

    blocks
}

pub fn blob_sidecars<P: Preset>(
    config: &Config,
    case: Case,
    slots: RangeInclusive<Slot>,
    width: usize,
) -> BTreeMap<Slot, Vec<Arc<BlobSidecar<P>>>> {
    let pattern = format!("blob_sidecar_slot_{:?<width$}_*", "");
    let low = format!("blob_sidecar_slot_{:0width$}_*", slots.start());
    let high = format!("blob_sidecar_slot_{:0width$}_*", slots.end() + 1);

    let blobs = case
        .glob(pattern)
        .skip_while(|path| path < Path::new(low.as_str()))
        .take_while(|path| path < Path::new(high.as_str()))
        .map(|path| case.ssz_uncompressed::<_, Arc<BlobSidecar<P>>>(config, path))
        .chunk_by(|blob| blob.signed_block_header.message.slot)
        .into_iter()
        .map(|(slot, blobs)| (slot, blobs.collect_vec()))
        .collect::<BTreeMap<_, _>>();

    if let Some((first_slot, _)) = blobs.first_key_value() {
        assert_eq!(*first_slot, *slots.start());
    }

    if let Some((last_slot, _)) = blobs.last_key_value() {
        assert_eq!(*last_slot, *slots.end());
    }

    blobs
}
