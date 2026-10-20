use typenum::U4294967296;

use crate::{
    byte_list::ByteList,
    error::{ReadError, WriteError},
    porcelain::{SszRead, SszSize, SszWrite},
    size::Size,
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

        // Unlike a streaming encoder, this records the size of the field in the zstd frame
        // header, so that reading it back allocates the output once.
        let compressed =
            zstd::bulk::compress(&serialized, self.level).map_err(|_| WriteError::Custom {
                message: "failed to compress field",
            })?;

        ByteList::<CompressedSizeLimit>::try_from(compressed)
            .map_err(|_| WriteError::Custom {
                message: "compressed field exceeds the maximum size",
            })?
            .write_variable(bytes)
    }
}

impl<C, T: SszRead<C>> SszRead<C> for Compressed<T> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let compressed = ByteList::<CompressedSizeLimit>::from_ssz(context, bytes)?;
        let compressed = compressed.as_bytes();

        let decompressed = match zstd::zstd_safe::get_frame_content_size(compressed) {
            Ok(Some(size)) => usize::try_from(size)
                .ok()
                .and_then(|size| zstd::bulk::decompress(compressed, size).ok()),
            // Fields written by older releases leave the size out of the frame header.
            Ok(None) | Err(_) => zstd::decode_all(compressed).ok(),
        }
        .ok_or(ReadError::Custom {
            message: "failed to decompress field",
        })?;

        T::from_ssz(context, decompressed).map(|inner| Self {
            inner,
            // We deliberately provide invalid compression level here - we do
            // not know desired compression level, so we want to fail instead of
            // silently succeeding. This should not be an issue, because we
            // usually don't want to serialize back a recently deserialized
            // value. Although if such functionality is ever needed, it is
            // better to provide compression level through the context
            // parameter, rather than trying to guess.
            level: i32::MIN,
        })
    }
}

#[cfg(test)]
mod tests {
    use typenum::U16;

    use crate::{
        contiguous_list::ContiguousList,
        error::WriteError,
        porcelain::{SszReadDefault, SszWrite as _},
    };

    use super::Compressed;

    #[test]
    fn decompressing_restores_the_compressed_value() {
        let values = ContiguousList::<u64, U16>::try_from(vec![7; 16]).expect("fits in the limit");

        let encoded = Compressed::with_level(values.clone(), zstd::DEFAULT_COMPRESSION_LEVEL)
            .to_ssz()
            .expect("must serialize");

        let decoded: Compressed<ContiguousList<u64, U16>> =
            SszReadDefault::from_ssz_default(encoded).expect("must deserialize");

        assert_eq!(decoded.into_inner(), values);
    }

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
