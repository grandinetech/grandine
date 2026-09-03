use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum Error {
    #[error("cross-phase diffs are not supported")]
    CrossPhaseDiff,

    #[error("patch phase does not match the base value")]
    PatchPhaseMismatch,

    #[error("patch index is out of bounds")]
    PatchIndexOutOfBounds,

    #[error("patch exceeds list limit")]
    PatchListLimitExceeded,

    #[error("patch result length does not match expected length")]
    PatchLengthMismatch,

    #[error("patch does not apply to a base of this length")]
    PatchBaseLengthMismatch,

    #[error("diff cannot be represented by this patch type")]
    UnsupportedDiff,

    #[error("patch encoding is invalid")]
    InvalidPatchEncoding,

    #[error("balance delta is invalid")]
    InvalidBalanceDelta,
}
