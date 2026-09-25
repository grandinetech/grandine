// Dev-dependencies of the `comparison` and `beacon_state` benchmarks, which are separate targets.
#[cfg(test)]
use {
    bytesize as _, criterion as _, eth_state_diff as _, fs_err as _, qbsdiff as _, reqwest as _,
    rkyv as _, std_ext as _, tabled as _, xdelta3 as _,
};

mod beacon_state;
mod compress;
mod error;
mod list;
mod patch;
mod replace;

pub use crate::{
    beacon_state::BeaconStatePatch,
    error::Error,
    patch::{Patch, PatchConfig},
};
