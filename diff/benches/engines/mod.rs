pub mod eth_state_diff;
pub mod grandine;
pub mod qbsdiff;
pub mod xdelta3;

use std::sync::Arc;

use types::{combined::BeaconState, preset::Mainnet};

pub trait PatchSize {
    fn size(&self) -> usize;
}

impl PatchSize for Vec<u8> {
    fn size(&self) -> usize {
        self.len()
    }
}

pub trait DiffEngine {
    /// Type holding a beacon state prepared for diffing.
    ///
    /// This allows an engine to serialize or otherwise prepare a state before
    /// diffing it, moving that work out of the hot path and allowing it to be
    /// cached.
    type Prepared: Clone;

    /// Patch type representing a serialized patch ready to be written to disk.
    /// Unlike states, patches do not have a prepared form because deserialized
    /// patches should not be kept in memory.
    type Patch: PatchSize + Clone;

    fn prepare(&self, state: Arc<BeaconState<Mainnet>>) -> Self::Prepared;

    fn restore(&self, prepared: Self::Prepared) -> Arc<BeaconState<Mainnet>>;

    fn diff(&self, base: &Self::Prepared, changed: &Self::Prepared) -> Self::Patch;

    fn apply(&self, base: Self::Prepared, patch: Self::Patch) -> Self::Prepared;
}
