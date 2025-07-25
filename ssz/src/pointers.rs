use std::sync::Arc as StdArc;

use ethereum_types::H256;
use std_ext::ArcExt as _;
use triomphe::Arc as TriompheArc;

use crate::{
    error::{ReadError, WriteError},
    porcelain::{SszHash, SszRead, SszSize, SszUnify, SszWrite},
    size::Size,
};

impl<T: SszSize> SszSize for &T {
    const SIZE: Size = T::SIZE;
}

impl<T: SszWrite> SszWrite for &T {
    fn write_fixed(&self, bytes: &mut [u8]) {
        (*self).write_fixed(bytes);
    }

    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        (*self).write_variable(bytes)
    }
}

impl<T: SszHash> SszHash for &T {
    type PackingFactor = T::PackingFactor;

    fn hash_tree_root(&self) -> H256 {
        (*self).hash_tree_root()
    }
}

impl<T: PartialEq + ?Sized> SszUnify for &T {
    fn unify(&mut self, other: &Self) -> bool {
        let equal = self == other;

        if equal {
            *self = other;
        }

        equal
    }
}

impl<T: SszSize> SszSize for Box<T> {
    const SIZE: Size = T::SIZE;
}

impl<C, T: SszRead<C>> SszRead<C> for Box<T> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        T::from_ssz_unchecked(context, bytes).map(Self::new)
    }
}

impl<T: SszWrite> SszWrite for Box<T> {
    fn write_fixed(&self, bytes: &mut [u8]) {
        self.as_ref().write_fixed(bytes);
    }

    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.as_ref().write_variable(bytes)
    }
}

impl<T: SszHash> SszHash for Box<T> {
    type PackingFactor = T::PackingFactor;

    fn hash_tree_root(&self) -> H256 {
        self.as_ref().hash_tree_root()
    }
}

impl<T: SszUnify + ?Sized> SszUnify for Box<T> {
    fn unify(&mut self, other: &Self) -> bool {
        self.as_mut().unify(other)
    }
}

impl<T: SszSize> SszSize for StdArc<T> {
    const SIZE: Size = T::SIZE;
}

impl<C, T: SszRead<C>> SszRead<C> for StdArc<T> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        T::from_ssz_unchecked(context, bytes).map(Self::new)
    }
}

impl<T: SszWrite> SszWrite for StdArc<T> {
    fn write_fixed(&self, bytes: &mut [u8]) {
        self.as_ref().write_fixed(bytes);
    }

    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.as_ref().write_variable(bytes)
    }
}

impl<T: SszHash> SszHash for StdArc<T> {
    type PackingFactor = T::PackingFactor;

    fn hash_tree_root(&self) -> H256 {
        self.as_ref().hash_tree_root()
    }
}

impl<T: SszUnify + Clone> SszUnify for StdArc<T> {
    fn unify(&mut self, other: &Self) -> bool {
        let equal = self.make_mut().unify(other);

        if equal {
            *self = other.clone_arc();
        }

        equal
    }
}

impl<T: SszSize> SszSize for TriompheArc<T> {
    const SIZE: Size = T::SIZE;
}

impl<C, T: SszRead<C>> SszRead<C> for TriompheArc<T> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        T::from_ssz_unchecked(context, bytes).map(Self::new)
    }
}

impl<T: SszWrite> SszWrite for TriompheArc<T> {
    fn write_fixed(&self, bytes: &mut [u8]) {
        self.as_ref().write_fixed(bytes);
    }

    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.as_ref().write_variable(bytes)
    }
}

impl<T: SszHash> SszHash for TriompheArc<T> {
    type PackingFactor = T::PackingFactor;

    fn hash_tree_root(&self) -> H256 {
        self.as_ref().hash_tree_root()
    }
}

impl<T: SszUnify + Clone> SszUnify for TriompheArc<T> {
    fn unify(&mut self, other: &Self) -> bool {
        let equal = self.make_mut().unify(other);

        if equal {
            *self = other.clone_arc();
        }

        equal
    }
}
