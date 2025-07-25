// Possible future improvements:
// - Use `anyhow::Error` as the error type instead of `ReadError` and `WriteError`.
// - Implement `SszWrite` and `SszHash` for mutable references.
// - Make `SszRead` mutate an existing object instead of creating a new one.
//   Use that to implement `SszRead` for `mutable references.
// - Make `SszRead::from_ssz_unchecked` accept `&GenericArray<u8, _>` or `&[u8; _]`.
// - Make `SszWrite::write_fixed` accept `&mut GenericArray<u8, _>` or `&mut [u8; _]`.
// - Make the traits operate on implementors of `std::io::Read` and `std::io::Write`.
//   This would make the code significantly more complicated with no clear benefit.

use easy_ext::ext;
use ethereum_types::H256;
use typenum::{Logarithm2, NonZero, Unsigned};

use crate::{
    error::{ReadError, WriteError},
    size::Size,
};

pub trait SszSize {
    const SIZE: Size;
}

pub trait SszRead<C>: SszSize + Sized {
    /// Attempts to deserialize `bytes` into `Self` without checking the length of `bytes`.
    ///
    /// This is safe in the Rust sense of the word but may panic if called directly.
    /// This should only be called as an optimization inside [`SszRead`] impls for fixed-size types.
    /// For variable-size types [`SszRead::from_ssz`] is equivalent and should be used instead.
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError>;

    /// Attempts to deserialize `bytes` into `Self` with full validation.
    ///
    /// This should be used in favor of [`SszRead::from_ssz_unchecked`] outside [`SszRead`] impls.
    fn from_ssz(context: &C, bytes: impl AsRef<[u8]>) -> Result<Self, ReadError> {
        let bytes = bytes.as_ref();

        if let Size::Fixed { size: expected } = Self::SIZE {
            let actual = bytes.len();

            if actual != expected {
                return Err(ReadError::FixedSizeMismatch { expected, actual });
            }
        }

        Self::from_ssz_unchecked(context, bytes)
    }
}

/// Extension trait for types that can be deserialized without a context.
#[ext(SszReadDefault)]
pub impl<T: SszRead<()>> T {
    fn from_ssz_default(bytes: impl AsRef<[u8]>) -> Result<Self, ReadError> {
        Self::from_ssz(&(), bytes)
    }
}

pub trait SszWrite: SszSize {
    // The panics could be avoided with some type-level programming, but it's not worth the trouble.
    fn write_fixed(&self, _bytes: &mut [u8]) {
        panic!("SszWrite::write_fixed must be implemented for fixed-size types");
    }

    fn write_variable(&self, _bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        panic!("SszWrite::write_variable must be implemented for variable-size types");
    }

    fn to_ssz(&self) -> Result<Vec<u8>, WriteError> {
        match Self::SIZE {
            Size::Fixed { size } => {
                let mut bytes = vec![0; size];
                self.write_fixed(bytes.as_mut_slice());
                Ok(bytes)
            }
            Size::Variable { minimum_size } => {
                let mut bytes = Vec::with_capacity(minimum_size);
                self.write_variable(&mut bytes)?;
                Ok(bytes)
            }
        }
    }
}

pub trait SszHash {
    type PackingFactor: Unsigned + NonZero + Logarithm2;

    fn hash_tree_root(&self) -> H256;
}

pub trait SszUnify {
    /// Modifies `self` to share structure with `other`.
    ///
    /// Returns `true` if `self` and `other` are equal regardless of whether `self` was modified.
    ///
    /// Comparison and unification are conceptually separate but done by the same method to avoid
    /// traversing data structures multiple times.
    fn unify(&mut self, other: &Self) -> bool;
}
