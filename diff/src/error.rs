use anyhow::Error as AnyhowError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
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

    #[error(transparent)]
    Custom(AnyhowError),
}
