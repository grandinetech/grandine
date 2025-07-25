// This contains impls for types that correspond to the `BytesN` types from the SSZ specification.
// They are not basic types, so they are not packed.

use ethereum_types::{H160, H256, H32};
use primitive_types::H384;
use typenum::{U1, U48};

use crate::{
    error::ReadError,
    porcelain::{SszHash, SszRead, SszSize, SszUnify, SszWrite},
    size::Size,
    BytesToDepth, MerkleTree,
};

impl SszSize for H32 {
    const SIZE: Size = Size::Fixed {
        size: Self::len_bytes(),
    };
}

impl<C> SszRead<C> for H32 {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Self::from_slice(bytes))
    }
}

impl SszWrite for H32 {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.as_bytes());
    }
}

impl SszHash for H32 {
    type PackingFactor = U1;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        let mut hash = H256::zero();
        hash[..Self::len_bytes()].copy_from_slice(self.as_bytes());
        hash
    }
}

impl SszUnify for H32 {
    #[inline]
    fn unify(&mut self, other: &Self) -> bool {
        self == other
    }
}

impl SszSize for H160 {
    const SIZE: Size = Size::Fixed {
        size: Self::len_bytes(),
    };
}

impl<C> SszRead<C> for H160 {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Self::from_slice(bytes))
    }
}

impl SszWrite for H160 {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.as_bytes());
    }
}

impl SszHash for H160 {
    type PackingFactor = U1;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        let mut hash = H256::zero();
        hash[..Self::len_bytes()].copy_from_slice(self.as_bytes());
        hash
    }
}

impl SszUnify for H160 {
    #[inline]
    fn unify(&mut self, other: &Self) -> bool {
        self == other
    }
}

impl SszSize for H256 {
    const SIZE: Size = Size::Fixed {
        size: Self::len_bytes(),
    };
}

impl<C> SszRead<C> for H256 {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Self::from_slice(bytes))
    }
}

impl SszWrite for H256 {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.as_bytes());
    }
}

impl SszHash for H256 {
    type PackingFactor = U1;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        *self
    }
}

impl SszUnify for H256 {
    #[inline]
    fn unify(&mut self, other: &Self) -> bool {
        self == other
    }
}

impl SszSize for H384 {
    const SIZE: Size = Size::Fixed {
        size: Self::len_bytes(),
    };
}

impl<C> SszRead<C> for H384 {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Self::from_slice(bytes))
    }
}

impl SszWrite for H384 {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.as_bytes());
    }
}

impl SszHash for H384 {
    type PackingFactor = U1;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        MerkleTree::<BytesToDepth<U48>>::merkleize_bytes(self)
    }
}

impl SszUnify for H384 {
    #[inline]
    fn unify(&mut self, other: &Self) -> bool {
        self == other
    }
}
