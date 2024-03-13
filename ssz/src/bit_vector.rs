use core::{
    fmt::{Debug, Formatter, Result as FmtResult},
    iter::FusedIterator,
    ops::{Index, Range},
};

use bit_field::BitArray as _;
use bitvec::{order::Lsb0, view::BitView as _};
use educe::Educe;
use ethereum_types::H256;
use generic_array::GenericArray;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use tap::TryConv as _;
use typenum::{NonZero, Unsigned as _, U1};

use crate::{
    consts::BITS_PER_BYTE,
    error::ReadError,
    merkle_tree::MerkleTree,
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    size::Size,
    type_level::{BitVectorBits, MerkleBits},
};

#[derive(Educe, Serialize)]
#[educe(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[serde(transparent)]
pub struct BitVector<N: BitVectorBits> {
    // There's maybe a dozen crates that implement bit arrays, but none of them have what we need.
    // Most notably:
    // - `bitvec::array::BitArray` requires a length for the primitive array backing it, but type
    //   parameters cannot be used in `const` expressions yet.
    // - `typenum_bitset::BitSet` does not implement `Shl` or even `Copy`.
    #[serde(with = "serde_utils::prefixed_hex_or_bytes_slice")]
    bytes: GenericArray<u8, N::Bytes>,
}

// Indices could be checked statically like in `sized-vec` and `type-vec`, but that would only
// add useless boilerplate.
impl<N: BitVectorBits> Index<usize> for BitVector<N> {
    type Output = bool;

    fn index(&self, index: usize) -> &Self::Output {
        let bit = self.get(index).unwrap_or_else(|| {
            panic!("index out of bounds (length: {}, index: {index})", N::USIZE)
        });

        if bit {
            &true
        } else {
            &false
        }
    }
}

impl<N: BitVectorBits> Index<Range<usize>> for BitVector<N> {
    type Output = bool;

    fn index(&self, mut range: Range<usize>) -> &Self::Output {
        if range.all(|index| self[index]) {
            &true
        } else {
            &false
        }
    }
}

impl<N: BitVectorBits> IntoIterator for BitVector<N> {
    type Item = bool;
    type IntoIter = Bits<N>;

    fn into_iter(self) -> Self::IntoIter {
        Bits {
            bit_vector: self,
            index: 0,
        }
    }
}

// This sort of code arguably belongs in an impl of `core::fmt::Binary` rather than `Debug`,
// but we don't ever format bit vectors directly and we need a `Debug` impl anyway.
impl<N: BitVectorBits> Debug for BitVector<N> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("0b")?;

        for bit in *self {
            formatter.write_str(if bit { "1" } else { "0" })?;
        }

        Ok(())
    }
}

impl<'de, N: BitVectorBits> Deserialize<'de> for BitVector<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_utils::prefixed_hex_or_bytes_generic_array::deserialize(deserializer)?;
        Self::validate_length(bytes.as_slice()).map_err(D::Error::custom)?;
        Ok(Self { bytes })
    }
}

impl<N: BitVectorBits + NonZero> SszSize for BitVector<N> {
    const SIZE: Size = Size::Fixed {
        size: N::Bytes::USIZE,
    };
}

impl<C, N: BitVectorBits + NonZero> SszRead<C> for BitVector<N> {
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Self::validate_length(bytes)?;
        let bytes = GenericArray::clone_from_slice(bytes);
        Ok(Self { bytes })
    }
}

impl<N: BitVectorBits + NonZero> SszWrite for BitVector<N> {
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.bytes.as_slice());
    }
}

impl<N: BitVectorBits + MerkleBits> SszHash for BitVector<N> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        MerkleTree::<N::MerkleTreeDepth>::merkleize_bytes(self.bytes)
    }
}

impl<N: BitVectorBits> BitVector<N> {
    #[must_use]
    pub fn new(value: bool) -> Self {
        let mut bytes = GenericArray::default();
        bytes.view_bits_mut::<Lsb0>()[..N::USIZE].fill(value);
        Self { bytes }
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<bool> {
        (index < N::USIZE).then(|| self.bytes.get_bit(index))
    }

    #[must_use]
    pub fn any(&self) -> bool {
        self.bytes.into_iter().any(|byte| byte > 0)
    }

    #[must_use]
    pub fn none(&self) -> bool {
        self.bytes.into_iter().all(|byte| byte == 0)
    }

    #[must_use]
    pub fn count_ones(&self) -> usize {
        self.bytes.view_bits::<Lsb0>().count_ones()
    }

    #[must_use]
    pub fn last_one(&self) -> Option<usize> {
        self.bytes.view_bits::<Lsb0>().last_one()
    }

    // Indices could be checked statically like in `sized-vec` and `type-vec`, but that would only
    // add useless boilerplate.
    pub fn set(&mut self, index: usize, value: bool) {
        assert!(index < N::USIZE);

        self.bytes.set_bit(index, value)
    }

    // This is all `consensus-specs` needs.
    // Shifting by more than 8 bits is harder to implement correctly.
    pub fn shift_up_by_1(&mut self) {
        let offset = 1;
        let last_byte_index = N::Bytes::USIZE - 1;
        let last_byte_mask = !0 >> (N::USIZE % BITS_PER_BYTE);

        let mut carry = 0;

        for index in 0..last_byte_index {
            let old = self.bytes[index];
            self.bytes[index] = (old << offset) | carry;
            carry = old >> (BITS_PER_BYTE - offset);
        }

        let old = self.bytes[last_byte_index];
        self.bytes[last_byte_index] = ((old << offset) | carry) & last_byte_mask;
    }

    fn validate_length(bytes: &[u8]) -> Result<(), ReadError> {
        let leading_zeros_in_last_byte = bytes
            .last()
            .expect("BitVector::validate_length is only called with nonempty slices")
            .leading_zeros()
            .try_conv::<usize>()
            .expect("number of bits in a byte should fit in usize");

        let bits_in_last_byte_lower_bound = BITS_PER_BYTE - leading_zeros_in_last_byte;
        let expected = N::USIZE;
        let actual = (bytes.len() - 1) * BITS_PER_BYTE + bits_in_last_byte_lower_bound;

        if actual > expected {
            return Err(ReadError::BitVectorTooLong { expected, actual });
        }

        Ok(())
    }
}

pub struct Bits<N: BitVectorBits> {
    bit_vector: BitVector<N>,
    index: usize,
}

impl<N: BitVectorBits> Iterator for Bits<N> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        (self.index < N::USIZE).then(|| {
            let bit = self.bit_vector.bytes.get_bit(self.index);
            self.index += 1;
            bit
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = N::USIZE - self.index;
        (length, Some(length))
    }

    fn count(self) -> usize {
        self.len()
    }

    fn last(mut self) -> Option<Self::Item> {
        let last_index = N::USIZE.checked_sub(1)?;
        self.index = self.index.max(last_index);
        self.next()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.index = self.index.saturating_add(n).min(N::USIZE);
        self.next()
    }
}

impl<N: BitVectorBits> ExactSizeIterator for Bits<N> {}

impl<N: BitVectorBits> FusedIterator for Bits<N> {}
