use ssz::{Ssz, SszRead, SszWrite};

use crate::{
    compress::Compressed,
    error::Error,
    patch::{Patch, PatchConfig},
};

#[derive(Clone, Debug, Default, Ssz)]
#[ssz(
    transparent,
    derive_hash = false,
    bound = "T: SszWrite",
    bound_for_read = "T: SszRead<C> + SszWrite"
)]
pub struct ReplacePatch<T>(Option<T>);

impl<T: Clone + PartialEq> Patch<T> for ReplacePatch<T> {
    fn diff(_config: PatchConfig, base: &T, changed: &T) -> Result<Self, Error> {
        Ok(Self((base != changed).then(|| changed.clone())))
    }

    fn apply(self, base: &mut T) -> Result<(), Error> {
        if let Some(changed) = self.0 {
            *base = changed;
        }

        Ok(())
    }
}

/// `ReplacePatch<Compressed<T>>` is slightly smaller, than `Compressed<ReplacePatch<T>>`.
///
/// That is because the `ReplacePatch<T>` stores only 1 byte for unchanged values,
/// while `Compressed<T>` always includes zstd header, no matter what value size
/// is.
impl<T: Clone + PartialEq> Patch<T> for ReplacePatch<Compressed<T>> {
    fn diff(config: PatchConfig, base: &T, changed: &T) -> Result<Self, Error> {
        Ok(Self((base != changed).then(|| {
            Compressed::with_level(changed.clone(), config.compression_level)
        })))
    }

    fn apply(self, base: &mut T) -> Result<(), Error> {
        if let Some(changed) = self.0 {
            *base = changed.into_inner();
        }

        Ok(())
    }
}
