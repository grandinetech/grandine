#![expect(
    clippy::allow_attributes,
    reason = "clippy::allow_attributes lint triggers from some derive macros. \
              See <https://github.com/rust-lang/rust-clippy/issues/13349>."
)]
use core::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
};

use derivative::Derivative;
use derive_more::{AsRef, Deref, DerefMut};
use ethereum_types::H256;
use generic_array::{ArrayLength, GenericArray};
use serde::{
    de::{Error as _, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use try_from_iterator::TryFromIterator;
use typenum::{Unsigned as _, U1};

use crate::{
    error::{ReadError, WriteError},
    merkle_tree::MerkleTree,
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    shared,
    size::Size,
    type_level::{ContiguousVectorElements, MerkleElements},
};

#[derive(Deref, DerefMut, AsRef, Derivative, Serialize)]
#[as_ref(forward)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    Default(bound = "T: Default"),
    Debug(bound = "T: Debug", transparent = "true")
)]
#[serde(bound(serialize = "T: Serialize"), transparent)]
pub struct ContiguousVector<T, N: ArrayLength<T>> {
    elements: GenericArray<T, N>,
}

impl<T: Copy, N: ArrayLength<T, ArrayType: Copy>> Copy for ContiguousVector<T, N> {}

impl<T, N: ArrayLength<T>, A: Into<GenericArray<T, N>>> From<A> for ContiguousVector<T, N> {
    fn from(array: A) -> Self {
        let elements = array.into();
        Self { elements }
    }
}

impl<T, N: ArrayLength<T>> IntoIterator for ContiguousVector<T, N> {
    type Item = T;
    type IntoIter = <GenericArray<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<'vector, T, N: ArrayLength<T>> IntoIterator for &'vector ContiguousVector<T, N> {
    type Item = &'vector T;
    type IntoIter = <&'vector [T] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T, N: ArrayLength<T>> TryFromIterator<T> for ContiguousVector<T, N> {
    type Error = ReadError;

    fn try_from_iter(elements: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        let expected = N::USIZE;

        let mut actual = 0;
        let mut counting_iterator = elements.into_iter().inspect(|_| actual += 1);

        let Some(elements) = GenericArray::from_exact_iter(counting_iterator.by_ref()) else {
            counting_iterator.count();
            return Err(ReadError::VectorSizeMismatch { expected, actual });
        };

        Ok(Self { elements })
    }
}

// The `Deserialize` impl for `GenericArray` requires `T` to implement `Default` even though it's
// completely avoidable.
impl<'de, T: Deserialize<'de>, N: ArrayLength<T>> Deserialize<'de> for ContiguousVector<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ContiguousVectorVisitor<T, N>(PhantomData<(T, N)>);

        impl<'de, T, N> Visitor<'de> for ContiguousVectorVisitor<T, N>
        where
            T: Deserialize<'de>,
            N: ArrayLength<T>,
        {
            type Value = ContiguousVector<T, N>;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                write!(formatter, "a vector of length {}", N::USIZE)
            }

            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                itertools::process_results(
                    core::iter::from_fn(|| seq.next_element().transpose()),
                    |elements| ContiguousVector::try_from_iter(elements).map_err(S::Error::custom),
                )?
            }
        }

        deserializer.deserialize_tuple(N::USIZE, ContiguousVectorVisitor(PhantomData))
    }
}

impl<T: SszSize, N: ContiguousVectorElements<T>> SszSize for ContiguousVector<T, N> {
    const SIZE: Size = T::SIZE.mul(N::USIZE);
}

impl<C, T: SszRead<C>, N: ContiguousVectorElements<T>> SszRead<C> for ContiguousVector<T, N> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let results = shared::read_vector::<_, _, N>(context, bytes)?;
        itertools::process_results(results, |elements| Self::try_from_iter(elements))?
    }
}

impl<T: SszWrite, N: ContiguousVectorElements<T>> SszWrite for ContiguousVector<T, N> {
    fn write_fixed(&self, bytes: &mut [u8]) {
        shared::write_fixed_vector(bytes, self)
    }

    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        shared::write_variable_vector::<N>(bytes, self)
    }
}

impl<T, N> SszHash for ContiguousVector<T, N>
where
    T: SszHash + SszWrite,
    N: ContiguousVectorElements<T> + MerkleElements<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        if T::PackingFactor::USIZE == 1 {
            let chunks = self.iter().map(SszHash::hash_tree_root);
            MerkleTree::<N::UnpackedMerkleTreeDepth>::merkleize_chunks(chunks)
        } else {
            MerkleTree::<N::PackedMerkleTreeDepth>::merkleize_packed(self)
        }
    }
}

impl<T, N: ArrayLength<T>> ContiguousVector<T, N> {
    pub(crate) fn repeat_element(element: T) -> Self
    where
        T: Clone,
    {
        Self::try_from_iter(core::iter::repeat_n(element, N::USIZE))
            .expect("length of iterator matches type parameter")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_iter_reports_length_correctly_on_failure() {
        type N = U1;

        let input = [5, 5, 5, 5, 5];

        assert_eq!(
            ContiguousVector::<u64, N>::try_from_iter(input),
            Err(ReadError::VectorSizeMismatch {
                expected: N::USIZE,
                actual: input.len(),
            }),
        );
    }
}
