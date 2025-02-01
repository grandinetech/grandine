use core::convert::Infallible;

/// Fallible equivalent of [`FromIterator`].
///
/// SSZ collections have a fixed or maximum length,
/// so they cannot be successfully constructed from an arbitrary iterator.
///
/// [`FromIterator`] or [`TryFrom`] cannot be used for this due to coherence rules.
pub trait TryFromIterator<T>: Sized {
    type Error;

    fn try_from_iter(items: impl IntoIterator<Item = T>) -> Result<Self, Self::Error>;
}

impl<T> TryFromIterator<T> for Box<[T]> {
    type Error = Infallible;

    fn try_from_iter(items: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        Ok(Self::from_iter(items))
    }
}

impl<T> TryFromIterator<T> for Vec<T> {
    type Error = Infallible;

    fn try_from_iter(items: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        Ok(Self::from_iter(items))
    }
}
