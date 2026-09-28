use crate::error::Error;

/// Options controlling how patches are built.
#[derive(Clone, Copy, Debug)]
pub struct PatchConfig {
    /// zstd compression level used for compressed patch fields.
    pub compression_level: i32,
}

impl Default for PatchConfig {
    fn default() -> Self {
        Self {
            compression_level: zstd::DEFAULT_COMPRESSION_LEVEL,
        }
    }
}

pub trait Patch<T: ?Sized>: Sized {
    fn diff(config: PatchConfig, base: &T, changed: &T) -> Result<Self, Error>;

    /// Applies the patch to `base` in place.
    ///
    /// On `Err`, `base` is left in an unspecified state - fields may have been applied before the
    /// failing one - and must be discarded rather than reused.
    fn apply(self, base: &mut T) -> Result<(), Error>;
}
