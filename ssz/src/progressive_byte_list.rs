use core::fmt::{Debug, Formatter, Result as FmtResult};

use derivative::Derivative;
use derive_more::From;
use ethereum_types::H256;
use serde::{Deserialize, Deserializer, Serialize};
use typenum::{U1, Unsigned};

use crate::{
    byte_list::ByteList,
    error::{ReadError, WriteError},
    merkle_tree::{self, ProgressiveMerkleTree},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    size::Size,
};

// TODO(gloas): in spec, ProgressiveByteList is an unbounded container, and its
// limits are enforced in user-site. This would require careful refactoring, so
// for easier transition, limits are kept as-is for now.
//
// Serialization is identical to `ByteList`. Only merkleization differs:
// the packed byte chunks are hashed with a progressive Merkle tree (EIP-7916)
// instead of a fixed-depth binary tree.
#[derive(From, Derivative, Serialize)]
#[derivative(
    Clone(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = ""),
    Default(bound = "")
)]
#[serde(bound = "", transparent)]
pub struct ProgressiveByteList<N>(ByteList<N>);

impl<N> ProgressiveByteList<N> {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<N: Unsigned> TryFrom<Vec<u8>> for ProgressiveByteList<N> {
    type Error = ReadError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, ReadError> {
        ByteList::try_from(bytes).map(Self)
    }
}

impl<N> Debug for ProgressiveByteList<N> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        self.0.fmt(formatter)
    }
}

impl<'de, N: Unsigned> Deserialize<'de> for ProgressiveByteList<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ByteList::deserialize(deserializer).map(Self)
    }
}

impl<N> SszSize for ProgressiveByteList<N> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<C, N: Unsigned> SszRead<C> for ProgressiveByteList<N> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        ByteList::from_ssz_unchecked(context, bytes).map(Self)
    }
}

impl<N> SszWrite for ProgressiveByteList<N> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.0.write_variable(bytes)
    }
}

impl<N> SszHash for ProgressiveByteList<N> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = ProgressiveMerkleTree::merkleize_bytes(self.as_bytes());
        merkle_tree::mix_in_length(root, self.as_bytes().len())
    }
}
