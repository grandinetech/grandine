use byteorder::ByteOrder as _;
use ethereum_types::H256;
use typenum::{U2, U32, U4, U8};

use crate::{
    consts::Endianness,
    error::ReadError,
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    size::Size,
};

#[cfg(test)]
use typenum::U16;

impl SszSize for bool {
    const SIZE: Size = Size::Fixed {
        size: size_of::<Self>(),
    };
}

impl<C> SszRead<C> for bool {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        match bytes[0] {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(ReadError::BooleanInvalid { value }),
        }
    }
}

impl SszWrite for bool {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes[0] = (*self).into();
    }
}

impl SszHash for bool {
    type PackingFactor = U32;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        let mut hash = H256::zero();
        hash.as_mut()[0] = (*self).into();
        hash
    }
}

impl SszSize for u8 {
    const SIZE: Size = Size::Fixed {
        size: size_of::<Self>(),
    };
}

impl<C> SszRead<C> for u8 {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(bytes[0])
    }
}

impl SszWrite for u8 {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes[0] = *self
    }
}

impl SszHash for u8 {
    type PackingFactor = U32;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        let mut hash = H256::zero();
        hash.as_mut()[0] = *self;
        hash
    }
}

#[cfg(test)]
impl SszSize for u16 {
    const SIZE: Size = Size::Fixed {
        size: size_of::<Self>(),
    };
}

#[cfg(test)]
impl<C> SszRead<C> for u16 {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Endianness::read_u16(bytes))
    }
}

#[cfg(test)]
impl SszWrite for u16 {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        Endianness::write_u16(bytes, *self);
    }
}

#[cfg(test)]
impl SszHash for u16 {
    type PackingFactor = U16;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        let mut hash = H256::zero();
        self.write_fixed(hash.as_bytes_mut());
        hash
    }
}

impl SszSize for u32 {
    const SIZE: Size = Size::Fixed {
        size: size_of::<Self>(),
    };
}

impl<C> SszRead<C> for u32 {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Endianness::read_u32(bytes))
    }
}

impl SszWrite for u32 {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        Endianness::write_u32(bytes, *self);
    }
}

impl SszHash for u32 {
    type PackingFactor = U8;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        let mut hash = H256::zero();
        self.write_fixed(hash.as_bytes_mut());
        hash
    }
}

impl SszSize for u64 {
    const SIZE: Size = Size::Fixed {
        size: size_of::<Self>(),
    };
}

impl<C> SszRead<C> for u64 {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Endianness::read_u64(bytes))
    }
}

impl SszWrite for u64 {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        Endianness::write_u64(bytes, *self);
    }
}

impl SszHash for u64 {
    type PackingFactor = U4;

    // Note that this is not the same as `H256::from_low_u64_le`. `H256::from_low_u64_le(1)`
    // produces the hash `0x0000000000000000000000000000000000000000000000000100000000000000`.
    #[inline]
    fn hash_tree_root(&self) -> H256 {
        let mut hash = H256::zero();
        self.write_fixed(hash.as_bytes_mut());
        hash
    }
}

impl SszSize for u128 {
    const SIZE: Size = Size::Fixed {
        size: size_of::<Self>(),
    };
}

impl<C> SszRead<C> for u128 {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Endianness::read_u128(bytes))
    }
}

impl SszWrite for u128 {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        Endianness::write_u128(bytes, *self);
    }
}

impl SszHash for u128 {
    type PackingFactor = U2;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        let mut hash = H256::zero();
        self.write_fixed(hash.as_bytes_mut());
        hash
    }
}
