use core::{fmt::Debug, hash::Hash, marker::PhantomData};

use derivative::Derivative;
use derive_more::{AsRef, Deref, DerefMut};
use ethereum_types::H256;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use try_from_iterator::TryFromIterator;
use typenum::{Unsigned, U1};

use crate::{
    error::{ReadError, WriteError},
    merkle_tree::{self, MerkleTree},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    shared,
    size::Size,
    type_level::MerkleElements,
};

#[derive(Deref, DerefMut, Derivative, Serialize)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    Hash(bound = "T: Hash"),
    Default(bound = ""),
    Debug(bound = "T: Debug", transparent = "true")
)]
#[serde(transparent)]
pub struct ContiguousList<T, N> {
    #[deref]
    #[deref_mut]
    elements: Box<[T]>,
    #[derivative(Debug = "ignore")]
    phantom: PhantomData<N>,
}

impl<T, N> AsRef<[T]> for ContiguousList<T, N> {
    fn as_ref(&self) -> &[T] {
        self.elements.as_ref()
    }
}

impl<T, N: Unsigned> TryFrom<Vec<T>> for ContiguousList<T, N> {
    type Error = ReadError;

    fn try_from(vec: Vec<T>) -> Result<Self, Self::Error> {
        Self::validate_length(vec.len())?;
        Ok(Self::new_unchecked(vec.into()))
    }
}

// This could be a `From` impl if feature `generic_const_exprs` were stable.
// See <https://internals.rust-lang.org/t/const-generics-where-restrictions/12742/6>.
impl<T, N: Unsigned, const SIZE: usize> TryFrom<[T; SIZE]> for ContiguousList<T, N> {
    type Error = ReadError;

    fn try_from(array: [T; SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_iter(array)
    }
}

impl<T, N> IntoIterator for ContiguousList<T, N> {
    type Item = T;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        // `Box::into_iter` cannot be called like a method until Rust 2024.
        // See <https://github.com/rust-lang/rust/pull/124097/>.
        Box::into_iter(self.elements)
    }
}

impl<'list, T, N> IntoIterator for &'list ContiguousList<T, N> {
    type Item = &'list T;
    type IntoIter = <&'list [T] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T, N: Unsigned> TryFromIterator<T> for ContiguousList<T, N> {
    type Error = ReadError;

    fn try_from_iter(elements: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        let elements = Box::from_iter(elements);
        Self::validate_length(elements.len())?;
        Ok(Self::new_unchecked(elements))
    }
}

impl<'de, T: Deserialize<'de>, N: Unsigned> Deserialize<'de> for ContiguousList<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let elements = Vec::deserialize(deserializer)?;
        elements.try_into().map_err(D::Error::custom)
    }
}

impl<T: SszSize, N> SszSize for ContiguousList<T, N> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<C, T: SszRead<C>, N: Unsigned> SszRead<C> for ContiguousList<T, N> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let results = shared::read_list(context, bytes)?;
        itertools::process_results(results, |elements| Self::try_from_iter(elements))?
    }
}

impl<T: SszWrite, N> SszWrite for ContiguousList<T, N> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        shared::write_list(bytes, self)
    }
}

impl<T: SszHash + SszWrite, N: MerkleElements<T>> SszHash for ContiguousList<T, N> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = if T::PackingFactor::USIZE == 1 {
            let chunks = self.iter().map(SszHash::hash_tree_root);
            MerkleTree::<N::UnpackedMerkleTreeDepth>::merkleize_chunks(chunks)
        } else {
            MerkleTree::<N::PackedMerkleTreeDepth>::merkleize_packed(self)
        };
        merkle_tree::mix_in_length(root, self.len())
    }
}

impl<T, N> ContiguousList<T, N> {
    #[must_use]
    pub fn full(element: T) -> Self
    where
        T: Clone,
        N: Unsigned,
    {
        Self::new_unchecked(vec![element; N::USIZE].into())
    }

    #[must_use]
    pub fn map<U>(self, function: impl FnMut(T) -> U) -> ContiguousList<U, N> {
        ContiguousList::new_unchecked(self.into_iter().map(function).collect())
    }

    const fn validate_length(actual: usize) -> Result<(), ReadError>
    where
        N: Unsigned,
    {
        let maximum = N::USIZE;

        if actual > maximum {
            return Err(ReadError::ListTooLong { maximum, actual });
        }

        Ok(())
    }

    fn new_unchecked(elements: Box<[T]>) -> Self {
        Self {
            elements,
            phantom: PhantomData,
        }
    }
}
