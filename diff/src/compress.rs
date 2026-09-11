use core::fmt::Debug;

use ssz::{ByteList, ReadError, Size, SszRead, SszSize, SszWrite, WriteError};
use typenum::U4294967296;

use crate::{
    error::Error,
    patch::{Patch, PatchConfig},
};

type CompressedSizeLimit = U4294967296;

/// Wrapper that stores the SSZ encoding of `T` zstd-compressed.
#[derive(Debug, Clone)]
pub struct Compressed<T> {
    inner: T,
    level: i32,
}

impl<T> Compressed<T> {
    pub const fn with_level(inner: T, level: i32) -> Self {
        Self { inner, level }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> SszSize for Compressed<T> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<T: SszWrite> SszWrite for Compressed<T> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        let serialized = self.inner.to_ssz()?;

        if !zstd::compression_level_range().contains(&self.level) {
            return Err(WriteError::Custom {
                message: "unspecified compression level",
            });
        }

        let compressed = zstd::encode_all(serialized.as_slice(), self.level).map_err(|_| {
            WriteError::Custom {
                message: "failed to compress patch field",
            }
        })?;

        ByteList::<CompressedSizeLimit>::try_from(compressed)
            .map_err(|_| WriteError::Custom {
                message: "compressed patch field exceeds the maximum size",
            })?
            .write_variable(bytes)
    }
}

impl<C, T: SszRead<C>> SszRead<C> for Compressed<T> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let compressed = ByteList::<CompressedSizeLimit>::from_ssz(context, bytes)?;

        let decompressed =
            zstd::decode_all(compressed.as_bytes()).map_err(|_| ReadError::Custom {
                message: "failed to decompress patch field",
            })?;

        T::from_ssz(context, decompressed).map(|inner| Self {
            inner,
            // We deliberately provide invalid compression level here - we do
            // not know desired compression level, so we want to fail instead of
            // silently succeeding. This should not be an issue, because we
            // usually don't want to serialize back recently deserialized patch.
            // Although if such functionality is ever needed, it is better to
            // provide compression level through the context parameter, rather
            // than trying to guess.
            level: i32::MIN,
        })
    }
}

impl<T: ?Sized, U: Patch<T>> Patch<T> for Compressed<U> {
    fn diff(config: PatchConfig, base: &T, changed: &T) -> Result<Self, Error> {
        U::diff(config, base, changed)
            .map(|inner| Self::with_level(inner, config.compression_level))
    }

    fn apply(self, base: &mut T) -> Result<(), Error> {
        self.inner.apply(base)
    }
}

#[cfg(test)]
mod tests {
    use ssz::{SszReadDefault, SszWrite as _, WriteError};

    use super::Compressed;

    #[test]
    fn re_serializing_a_decoded_value_is_rejected() {
        let value = Compressed::with_level(0u32, zstd::DEFAULT_COMPRESSION_LEVEL);
        let encoded = value.to_ssz().expect("must serialize");
        let decoded: Compressed<u32> =
            SszReadDefault::from_ssz_default(encoded).expect("must deserialize");

        assert_eq!(
            decoded.to_ssz(),
            Err(WriteError::Custom {
                message: "unspecified compression level"
            })
        );
    }
}
