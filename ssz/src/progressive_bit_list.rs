use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use ethereum_types::H256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use typenum::{U1, Unsigned};

use crate::{
    BitList, MerkleBits, ReadError, Size, SszHash, SszRead, SszSize, SszWrite, WriteError,
    list::SszBitList,
    merkle_tree::{self, ProgressiveMerkleTree},
};

#[derive(Deref, DerefMut, Derivative)]
#[derivative(
    Clone(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = ""),
    Default(bound = ""),
    Debug(bound = "", transparent = "true")
)]
pub struct ProgressiveBitList<N>(
    #[deref]
    #[deref_mut]
    BitList<N>,
);

impl<N> From<BitList<N>> for ProgressiveBitList<N> {
    fn from(bit_list: BitList<N>) -> Self {
        Self(bit_list)
    }
}

impl<N> From<ProgressiveBitList<N>> for BitList<N> {
    fn from(bit_list: ProgressiveBitList<N>) -> Self {
        bit_list.0
    }
}

impl<'de, N: Unsigned> Deserialize<'de> for ProgressiveBitList<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        BitList::deserialize(deserializer).map(Self)
    }
}

impl<N> Serialize for ProgressiveBitList<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<N> SszSize for ProgressiveBitList<N> {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl<C, N: Unsigned> SszRead<C> for ProgressiveBitList<N> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        BitList::from_ssz_unchecked(context, bytes).map(Self)
    }
}

impl<N> SszWrite for ProgressiveBitList<N> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.0.write_variable(bytes)
    }
}

impl<N: MerkleBits> SszHash for ProgressiveBitList<N> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = ProgressiveMerkleTree::merkleize_bytes(self.0.as_raw_slice());
        merkle_tree::mix_in_length(root, self.len())
    }
}

impl<N: MerkleBits + Send + Sync> SszBitList for ProgressiveBitList<N> {
    fn len_usize(&self) -> usize {
        self.0.len_usize()
    }

    fn len_u64(&self) -> u64 {
        self.0.len_u64()
    }

    fn get_bit(&self, index: usize) -> Option<bool> {
        self.0.get_bit(index)
    }

    fn count_ones(&self) -> usize {
        self.0.count_ones()
    }

    fn iter_bits<'a>(&'a self) -> Box<dyn ExactSizeIterator<Item = bool> + 'a> {
        self.0.iter_bits()
    }
}
