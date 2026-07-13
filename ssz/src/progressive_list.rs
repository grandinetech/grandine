use core::{fmt::Debug, hash::Hash};

use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use ethereum_types::H256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use try_from_iterator::TryFromIterator;
use typenum::{U1, Unsigned};

use crate::{
    ContiguousList, MerkleElements, ReadError, Size, SszHash, SszList, SszRead, SszSize, SszWrite,
    WriteError,
    merkle_tree::{self, ProgressiveMerkleTree},
};

// TODO(gloas): in spec, ProgressiveList is unbounded container, and its limits
// are enforced in user-site. This would require careful refactoring, so for
// easier transition, limits are kept as-is for now.
#[derive(Deref, DerefMut, Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    Hash(bound = "T: Hash"),
    Default(bound = ""),
    Debug(bound = "T: Debug", transparent = "true")
)]
pub struct ProgressiveList<T, N>(ContiguousList<T, N>);

impl<T, N> ProgressiveList<T, N> {
    #[must_use]
    pub fn full(element: T) -> Self
    where
        T: Clone,
        N: Unsigned,
    {
        Self(ContiguousList::full(element))
    }

    #[must_use]
    pub fn map<U>(self, function: impl FnMut(T) -> U) -> ProgressiveList<U, N> {
        ProgressiveList(self.0.map(function))
    }

    #[must_use]
    pub fn into_inner(self) -> ContiguousList<T, N> {
        self.0
    }
}

impl<T, N> From<ContiguousList<T, N>> for ProgressiveList<T, N> {
    fn from(list: ContiguousList<T, N>) -> Self {
        Self(list)
    }
}

impl<T, N> From<ProgressiveList<T, N>> for ContiguousList<T, N> {
    fn from(list: ProgressiveList<T, N>) -> Self {
        list.0
    }
}

impl<T, N> AsRef<[T]> for ProgressiveList<T, N> {
    fn as_ref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<T, N: Unsigned> TryFrom<Vec<T>> for ProgressiveList<T, N> {
    type Error = ReadError;

    fn try_from(vec: Vec<T>) -> Result<Self, Self::Error> {
        ContiguousList::try_from(vec).map(Self)
    }
}

impl<T, N: Unsigned, const SIZE: usize> TryFrom<[T; SIZE]> for ProgressiveList<T, N> {
    type Error = ReadError;

    fn try_from(array: [T; SIZE]) -> Result<Self, Self::Error> {
        ContiguousList::try_from(array).map(Self)
    }
}

impl<T, N> IntoIterator for ProgressiveList<T, N> {
    type Item = T;
    type IntoIter = <ContiguousList<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'list, T, N> IntoIterator for &'list ProgressiveList<T, N> {
    type Item = &'list T;
    type IntoIter = <&'list ContiguousList<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.0).into_iter()
    }
}

impl<T, N: Unsigned> TryFromIterator<T> for ProgressiveList<T, N> {
    type Error = ReadError;

    fn try_from_iter(elements: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        ContiguousList::try_from_iter(elements).map(Self)
    }
}

impl<T: Serialize, N> Serialize for ProgressiveList<T, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, N: Unsigned> Deserialize<'de> for ProgressiveList<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ContiguousList::deserialize(deserializer).map(Self)
    }
}

impl<T: SszSize, N> SszSize for ProgressiveList<T, N> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<C, T: SszRead<C>, N: Unsigned> SszRead<C> for ProgressiveList<T, N> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        ContiguousList::from_ssz_unchecked(context, bytes).map(Self)
    }
}

impl<T: SszWrite, N> SszWrite for ProgressiveList<T, N> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.0.write_variable(bytes)
    }
}

impl<T, N> SszHash for ProgressiveList<T, N>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
    N: MerkleElements<T> + Send + Sync,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = if T::PackingFactor::USIZE == 1 {
            let chunks = self.0.as_ref().iter().map(SszHash::hash_tree_root);
            ProgressiveMerkleTree::merkleize_progressive(chunks)
        } else {
            ProgressiveMerkleTree::merkleize_packed(&self.0)
        };
        merkle_tree::mix_in_length(root, self.len_usize())
    }
}

impl<T, N> SszList<T> for ProgressiveList<T, N>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
    N: MerkleElements<T> + Send + Sync,
{
    fn len_usize(&self) -> usize {
        self.0.len_usize()
    }

    fn len_u64(&self) -> u64 {
        self.0.len_u64()
    }

    fn get(&self, index: u64) -> Result<&T, crate::IndexError> {
        self.0.get(index)
    }

    fn iter<'a>(&'a self) -> Box<dyn ExactSizeIterator<Item = &'a T> + 'a> {
        self.0.iter()
    }

    fn clone_boxed(&self) -> Box<dyn SszList<T>>
    where
        T: Clone + 'static,
    {
        Box::new(self.clone())
    }
}
