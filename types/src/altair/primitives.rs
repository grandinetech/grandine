use core::num::NonZeroU64;

pub type NonZeroGwei = NonZeroU64;
// TODO(Grandine Team): Consider using `bitflags` or `enumset` instead.
pub type ParticipationFlags = u8;
pub type SubcommitteeIndex = u64;
pub type SyncCommitteePeriod = u64;
