mod balances;
mod builders;
mod gwei_deltas;
mod participation;
mod position_set;
mod positional;
mod ptc;
mod queue;
mod validators;
mod vector;

use typenum::U10000000000000000000;

pub use balances::BalancesPatch;
pub use builders::BuilderListPatch;
pub use participation::ParticipationPatch;
pub use positional::PositionalPatch;
pub use ptc::PtcPatch;
pub use queue::QueuePatch;
pub use validators::ValidatorListPatch;
pub use vector::VectorPatch;

/// A large value, used as "unlimited" value for containers.
#[expect(
    clippy::redundant_pub_crate,
    reason = "`list` being private already hides this, but `pub(crate)` states that it is never \
              meant to appear in the crate's public API"
)]
pub(crate) type Unlimited = U10000000000000000000;
