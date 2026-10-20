use ssz::Compressed;

use crate::{
    error::Error,
    patch::{Patch, PatchConfig},
};

impl<T: ?Sized, U: Patch<T>> Patch<T> for Compressed<U> {
    fn diff(config: PatchConfig, base: &T, changed: &T) -> Result<Self, Error> {
        U::diff(config, base, changed)
            .map(|inner| Self::with_level(inner, config.compression_level))
    }

    fn apply(self, base: &mut T) -> Result<(), Error> {
        self.into_inner().apply(base)
    }
}
