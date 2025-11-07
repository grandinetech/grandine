use core::fmt::{Debug, Formatter, Result as FmtResult};

use derivative::Derivative;
use derive_more::From;
use ethereum_types::H256;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use typenum::{U1, Unsigned};

use crate::{
    contiguous_list::ContiguousList,
    error::{ReadError, WriteError},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    size::Size,
    type_level::MerkleElements,
};

#[derive(From, Derivative, Serialize)]
#[derivative(
    Clone(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = ""),
    Default(bound = "")
)]
#[serde(transparent)]
pub struct ByteList<N> {
    #[serde(with = "serde_utils::prefixed_hex_or_bytes_slice")]
    bytes: ContiguousList<u8, N>,
}

// This sort of code arguably belongs in an impl of `core::fmt::LowerHex` rather than `Debug`,
// but we don't ever format byte lists directly and we need a `Debug` impl anyway.
impl<N> Debug for ByteList<N> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("0x")?;

        for byte in &self.bytes {
            write!(formatter, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl<'de, N: Unsigned> Deserialize<'de> for ByteList<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_utils::prefixed_hex_or_bytes_cow::deserialize(deserializer)?
            .into_owned()
            .try_into()
            .map(ContiguousList::into)
            .map_err(D::Error::custom)
    }
}

impl<N> SszSize for ByteList<N> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<C, N: Unsigned> SszRead<C> for ByteList<N> {
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        // Do not forward to `ContiguousList::from_ssz_unchecked`.
        // The specialized implementation here is much faster.
        // The difference is most noticeable when decoding transactions in execution payloads.
        ContiguousList::<u8, N>::validate_length(bytes.len())?;
        let bytes = ContiguousList::new_unchecked(bytes.into());
        Ok(Self { bytes })
    }
}

impl<N> SszWrite for ByteList<N> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.bytes.write_variable(bytes)
    }
}

impl<N: MerkleElements<u8>> SszHash for ByteList<N> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        self.bytes.hash_tree_root()
    }
}
