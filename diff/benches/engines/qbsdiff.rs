use std::{io, sync::Arc};

use qbsdiff::{Bsdiff, Bspatch};
use ssz::{SszRead, SszWrite as _};
use types::{combined::BeaconState, config::Config, preset::Mainnet};

use super::DiffEngine;

pub struct QbsDiff;

impl DiffEngine for QbsDiff {
    type Prepared = Vec<u8>;
    type Patch = Vec<u8>;

    fn prepare(&self, state: Arc<BeaconState<Mainnet>>) -> Self::Prepared {
        state.to_ssz().expect("should serialize")
    }

    fn restore(&self, prepared: Self::Prepared) -> Arc<BeaconState<Mainnet>> {
        SszRead::from_ssz(&Config::mainnet(), prepared).expect("should deserialize")
    }

    fn diff(&self, base: &Self::Prepared, changed: &Self::Prepared) -> Self::Patch {
        let mut patch = Vec::new();

        Bsdiff::new(base, changed)
            .compare(io::Cursor::new(&mut patch))
            .expect("diffing should success");

        patch
    }

    fn apply(&self, base: Self::Prepared, patch: Self::Patch) -> Self::Prepared {
        let patcher = Bspatch::new(patch.as_slice()).expect("must be valid patch");

        let mut target = Vec::new();

        patcher
            .apply(&base, io::Cursor::new(&mut target))
            .expect("patch must apply");

        target
    }
}
