mod bundles;
mod gwei_deltas;
mod position_set;
mod positional;
mod queue;
mod vector;

use typenum::U10000000000000000000;

pub use gwei_deltas::GweiDeltas;
pub use position_set::PositionSet;
pub use positional::{EditAccumulator, PositionalEdit, PositionalPatch};
pub use queue::QueuePatch;
pub use vector::VectorPatch;

/// A large value, used as "unlimited" value for containers.
pub type Unlimited = U10000000000000000000;
