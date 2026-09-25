use std::sync::Arc;

use ssz::{SszRead, SszWrite as _};
use types::{combined::BeaconState, config::Config, preset::Mainnet};

use super::DiffEngine;

pub struct Xdelta3Diff;

impl DiffEngine for Xdelta3Diff {
    type Prepared = Vec<u8>;
    type Patch = Vec<u8>;

    fn prepare(&self, state: Arc<BeaconState<Mainnet>>) -> Self::Prepared {
        state.to_ssz().expect("should serialize")
    }

    fn restore(&self, prepared: Self::Prepared) -> Arc<BeaconState<Mainnet>> {
        SszRead::from_ssz(&Config::mainnet(), prepared).expect("should deserialize")
    }

    fn diff(&self, base: &Self::Prepared, changed: &Self::Prepared) -> Self::Patch {
        ::xdelta3::encode(changed, base).expect("diffing should succeed")
    }

    fn apply(&self, base: Self::Prepared, patch: Self::Patch) -> Self::Prepared {
        ::xdelta3::decode(&patch, &base).expect("patch must apply")
    }
}
