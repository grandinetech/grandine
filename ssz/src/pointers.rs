use std::sync::Arc;

use ethereum_types::H256;

use crate::{
    error::{ReadError, WriteError},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
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

impl<T: SszSize> SszSize for Arc<T> {
    const SIZE: Size = T::SIZE;
}

impl<C, T: SszRead<C>> SszRead<C> for Arc<T> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        T::from_ssz_unchecked(context, bytes).map(Self::new)
    }
}

impl<T: SszWrite> SszWrite for Arc<T> {
    fn write_fixed(&self, bytes: &mut [u8]) {
        self.as_ref().write_fixed(bytes);
    }

    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.as_ref().write_variable(bytes)
    }
}

impl<T: SszHash> SszHash for Arc<T> {
    type PackingFactor = T::PackingFactor;

    fn hash_tree_root(&self) -> H256 {
        self.as_ref().hash_tree_root()
    }
}
