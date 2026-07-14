use core::{fmt::Debug, hash::Hash};

use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use ethereum_types::H256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use try_from_iterator::TryFromIterator;
use typenum::{U1, Unsigned};

use crate::{
    ContiguousList, ReadError, Size, SszHash, SszList, SszRead, SszSize, SszWrite, WriteError,
    merkle_tree::{self, ProgressiveMerkleTree},
};

type PrettyBigU = typenum::U1048576;

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
pub struct ProgressiveList<T>(ContiguousList<T, PrettyBigU>);

impl<T> ProgressiveList<T> {
    #[must_use]
    pub fn full(element: T) -> Self
    where
        T: Clone,
    {
        Self(ContiguousList::full(element))
    }

    #[must_use]
    pub fn map<U>(self, function: impl FnMut(T) -> U) -> ProgressiveList<U> {
        ProgressiveList(self.0.map(function))
    }

    #[must_use]
    pub fn into_inner(self) -> ContiguousList<T, PrettyBigU> {
        self.0
    }
}

impl<T, N: Unsigned> From<ContiguousList<T, N>> for ProgressiveList<T> {
    fn from(list: ContiguousList<T, N>) -> Self {
        Self(ContiguousList::try_from_iter(list).expect("list should fit in ProgressiveList"))
    }
}

impl<T, N: Unsigned> From<ProgressiveList<T>> for ContiguousList<T, N> {
    fn from(list: ProgressiveList<T>) -> Self {
        Self::try_from_iter(list).expect("list should fit in target ContiguousList")
    }
}

impl<T> AsRef<[T]> for ProgressiveList<T> {
    fn as_ref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<T> TryFrom<Vec<T>> for ProgressiveList<T> {
    type Error = ReadError;

    fn try_from(vec: Vec<T>) -> Result<Self, Self::Error> {
        ContiguousList::try_from(vec).map(Self)
    }
}

impl<T, const SIZE: usize> TryFrom<[T; SIZE]> for ProgressiveList<T> {
    type Error = ReadError;

    fn try_from(array: [T; SIZE]) -> Result<Self, Self::Error> {
        ContiguousList::try_from(array).map(Self)
    }
}

impl<T> IntoIterator for ProgressiveList<T> {
    type Item = T;
    type IntoIter = <ContiguousList<T, PrettyBigU> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'list, T> IntoIterator for &'list ProgressiveList<T> {
    type Item = &'list T;
    type IntoIter = <&'list ContiguousList<T, PrettyBigU> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.0).into_iter()
    }
}

impl<T> TryFromIterator<T> for ProgressiveList<T> {
    type Error = ReadError;

    fn try_from_iter(elements: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        ContiguousList::try_from_iter(elements).map(Self)
    }
}

impl<T: Serialize> Serialize for ProgressiveList<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ProgressiveList<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ContiguousList::deserialize(deserializer).map(Self)
    }
}

impl<T: SszSize> SszSize for ProgressiveList<T> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<C, T: SszRead<C>> SszRead<C> for ProgressiveList<T> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        ContiguousList::from_ssz_unchecked(context, bytes).map(Self)
    }
}

impl<T: SszWrite> SszWrite for ProgressiveList<T> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.0.write_variable(bytes)
    }
}

impl<T> SszHash for ProgressiveList<T>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
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

impl<T> SszList<T> for ProgressiveList<T>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
{
    fn len_usize(&self) -> usize {
        self.0.as_ref().len()
    }

    fn len_u64(&self) -> u64 {
        u64::try_from(self.0.as_ref().len()).expect("list length fits in u64")
    }

    fn get(&self, index: u64) -> Result<&T, crate::IndexError> {
        let index =
            usize::try_from(index).map_err(|_| crate::IndexError::DoesNotFitInUsize { index })?;
        let length = self.0.as_ref().len();

        self.0
            .as_ref()
            .get(index)
            .ok_or(crate::IndexError::OutOfBounds { length, index })
    }

    fn iter<'a>(&'a self) -> Box<dyn ExactSizeIterator<Item = &'a T> + 'a> {
        Box::new(self.0.as_ref().iter())
    }

    fn clone_boxed(&self) -> Box<dyn SszList<T>>
    where
        T: Clone + 'static,
    {
        Box::new(self.clone())
    }
}
