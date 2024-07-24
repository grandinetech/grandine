use core::fmt::{Debug, Formatter, Result as FmtResult};

use derivative::Derivative;
use derive_more::From;
use ethereum_types::H256;
use generic_array::ArrayLength;
use serde::{Deserialize, Deserializer, Serialize};
use typenum::{NonZero, U1};

use crate::{
    contiguous_vector::ContiguousVector,
    error::ReadError,
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    size::Size,
    type_level::{ArrayLengthCopy, ContiguousVectorElements, MerkleElements},
};

#[derive(From, Derivative, Serialize)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = "N: ArrayLengthCopy<u8>"),
    PartialEq(bound = ""),
    Eq(bound = ""),
    Default(bound = "")
)]
#[serde(transparent)]
pub struct ByteVector<N: ArrayLength<u8>> {
    #[serde(with = "serde_utils::prefixed_hex_or_bytes_slice")]
    bytes: ContiguousVector<u8, N>,
}

// This sort of code arguably belongs in an impl of `core::fmt::LowerHex` rather than `Debug`,
// but we don't ever format byte vectors directly and we need a `Debug` impl anyway.
impl<N: ArrayLength<u8>> Debug for ByteVector<N> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("0x")?;

        for byte in &self.bytes {
            write!(formatter, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl<'de, N: ArrayLength<u8>> Deserialize<'de> for ByteVector<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_utils::prefixed_hex_or_bytes_generic_array::deserialize(deserializer)
            .map(Into::into)
            .map(|bytes| Self { bytes })
    }
}

impl<N: ContiguousVectorElements<u8>> SszSize for ByteVector<N> {
    const SIZE: Size = Size::Fixed { size: N::USIZE };
}

impl<C, N: ContiguousVectorElements<u8> + NonZero> SszRead<C> for ByteVector<N> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        ContiguousVector::from_ssz_unchecked(context, bytes).map(Into::into)
    }
}

impl<N: ContiguousVectorElements<u8> + NonZero> SszWrite for ByteVector<N> {
    fn write_fixed(&self, bytes: &mut [u8]) {
        self.bytes.write_fixed(bytes)
    }
}

impl<N: ContiguousVectorElements<u8> + MerkleElements<u8>> SszHash for ByteVector<N> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        self.bytes.hash_tree_root()
    }
}

impl<N: ArrayLength<u8>> ByteVector<N> {
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
