use core::fmt::Debug;

use derivative::Derivative;
use derive_more::{AsRef, Deref};

use crate::{
    error::{ReadError, WriteError},
    porcelain::{SszRead, SszSize, SszWrite},
    shared,
    size::Size,
    SszReadDefault,
};

#[derive(Deref, Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    Default(bound = ""),
    Debug(bound = "T: Debug", transparent = "true")
)]
pub struct DynamicList<T> {
    #[deref]
    elements: Box<[T]>,
}

impl<T> AsRef<[T]> for DynamicList<T> {
    fn as_ref(&self) -> &[T] {
        self.elements.as_ref()
    }
}

impl<T> IntoIterator for DynamicList<T> {
    type Item = T;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        // `Box::into_iter` cannot be called like a method until Rust 2024.
        // See <https://github.com/rust-lang/rust/pull/124097/>.
        Box::into_iter(self.elements)
    }
}

impl<'list, T> IntoIterator for &'list DynamicList<T> {
    type Item = &'list T;
    type IntoIter = <&'list [T] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: SszSize> SszSize for DynamicList<T> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<T: SszReadDefault> SszRead<usize> for DynamicList<T> {
    fn from_ssz_unchecked(maximum: &usize, bytes: &[u8]) -> Result<Self, ReadError> {
        let results = shared::read_list(&(), bytes)?;

        itertools::process_results(results, |elements| {
            Self::try_from_iter_with_maximum(elements, *maximum)
        })?
    }
}

impl<T: SszWrite> SszWrite for DynamicList<T> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        shared::write_list(bytes, self)
    }
}

impl<T> DynamicList<T> {
    #[must_use]
    pub fn empty() -> Self
    where
        T: Clone,
    {
        Self::new_unchecked(vec![].into())
    }

    #[must_use]
    pub fn single(element: T) -> Self
    where
        T: Clone,
    {
        Self::new_unchecked(vec![element].into())
    }

    #[must_use]
    pub fn full(element: T, maximum: usize) -> Self
    where
        T: Clone,
    {
        Self::new_unchecked(vec![element; maximum].into())
    }

    pub fn from_iter_with_maximum(elements: impl IntoIterator<Item = T>, maximum: usize) -> Self {
        let elements = elements.into_iter().take(maximum).collect::<Box<_>>();
        Self::new_unchecked(elements)
    }

    pub fn try_from_iter_with_maximum(
        elements: impl IntoIterator<Item = T>,
        maximum: usize,
    ) -> Result<Self, ReadError> {
        let elements = Box::from_iter(elements);

        Self::validate_length(elements.len(), maximum)?;
        Ok(Self::new_unchecked(elements))
    }

    const fn validate_length(actual: usize, maximum: usize) -> Result<(), ReadError> {
        if actual > maximum {
            return Err(ReadError::ListTooLong { maximum, actual });
        }

        Ok(())
    }

    const fn new_unchecked(elements: Box<[T]>) -> Self {
        Self { elements }
    }
}
