use core::ops::RangeInclusive;
use std::{collections::BTreeMap, sync::Arc};

use helper_functions::misc;
use itertools::Itertools;
use spec_test_utils::Case;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    deneb::containers::BlobSidecar,
    phase0::{
        containers::Attestation,
        primitives::{Epoch, Slot},
    },
    preset::Mainnet,
};

use crate::generic::{self, LazyBeaconState};

const CASE: Case = Case {
    case_path_relative_to_workspace_root: "eth2-cache/holesky",
};

pub static CAPELLA_BEACON_STATE: LazyBeaconState<Mainnet> =
    LazyBeaconState::new(|| beacon_state(49920, 6));

#[must_use]
pub fn beacon_blocks(
    slots: RangeInclusive<Slot>,
    width: usize,
) -> Vec<Arc<SignedBeaconBlock<Mainnet>>> {
    generic::beacon_blocks(&Config::holesky(), CASE, slots, width)
}

#[must_use]
pub fn beacon_state(slot: Slot, width: usize) -> Arc<BeaconState<Mainnet>> {
    generic::beacon_state(&Config::holesky(), CASE, slot, width)
}

#[must_use]
pub fn blob_sidecars(
    slots: RangeInclusive<Slot>,
    width: usize,
) -> BTreeMap<Slot, Vec<Arc<BlobSidecar<Mainnet>>>> {
    generic::blob_sidecars(&Config::holesky(), CASE, slots, width)
}

#[must_use]
pub fn aggregate_attestations_by_epoch(epoch: Epoch) -> Vec<Attestation<Mainnet>> {
    let pattern = format!("attestations/epoch_{epoch:08}/aggregate_attestations/*.ssz");

    CASE.glob(pattern)
        .map(|path| CASE.ssz_uncompressed_default(path))
        .collect()
}

#[must_use]
pub fn aggregate_attestations_by_epoch_sorted_by_data(epoch: Epoch) -> Vec<Attestation<Mainnet>> {
    let pattern = format!("attestations/epoch_{epoch:08}/aggregate_attestations/*.ssz");

    CASE.glob(pattern)
        .map(|path| CASE.ssz_uncompressed_default::<Attestation<_>>(path))
        .sorted_by_key(|attestation| attestation.data)
        .collect()
}

#[must_use]
pub fn aggregate_attestations_by_slot(slot: Slot) -> Vec<Attestation<Mainnet>> {
    let epoch = misc::compute_epoch_at_slot::<Mainnet>(slot);
    let pattern = format!(
        "attestations/epoch_{epoch:08}/aggregate_attestations/attestation_slot_{slot:08}_*.ssz"
    );

    CASE.glob(pattern)
        .map(|path| CASE.ssz_uncompressed_default(path))
        .collect()
}
