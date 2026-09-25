use std::sync::Arc;

use diff::{BeaconStatePatch, Patch as _, PatchConfig};
use ssz::{SszReadDefault, SszWrite as _};
use types::{combined::BeaconState, preset::Mainnet};

use super::DiffEngine;

pub struct GrandineDiff;

impl DiffEngine for GrandineDiff {
    type Prepared = Arc<BeaconState<Mainnet>>;
    type Patch = Vec<u8>;

    fn prepare(&self, state: Arc<BeaconState<Mainnet>>) -> Self::Prepared {
        state
    }

    fn restore(&self, prepared: Self::Prepared) -> Arc<BeaconState<Mainnet>> {
        prepared
    }

    // Patches compress themselves field by field, so there is nothing to
    // compress here.
    fn diff(&self, base: &Self::Prepared, changed: &Self::Prepared) -> Self::Patch {
        BeaconStatePatch::<Mainnet>::diff(PatchConfig::default(), base, changed)
            .expect("should diff")
            .to_ssz()
            .expect("should serialize")
    }

    fn apply(&self, mut base: Self::Prepared, patch: Self::Patch) -> Self::Prepared {
        BeaconStatePatch::<Mainnet>::from_ssz_default(patch)
            .expect("should deserialize")
            .apply(&mut base)
            .expect("patch should apply");

        base
    }
}
