use core::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
    ops::BitOrAssign,
};

use bit_field::BitArray as _;
use bitvec::{bitbox, boxed::BitBox, vec::BitVec};
use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use ethereum_types::H256;
use serde::{de::Error as _, ser::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use static_assertions::assert_eq_size;
use typenum::{Unsigned, U1, U2048};

use crate::{
    consts::BITS_PER_BYTE,
    error::{ReadError, WriteError},
    merkle_tree::{self, MerkleTree},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    size::Size,
    type_level::MerkleBits,
};

#[derive(Deref, DerefMut, Derivative)]
#[derivative(
    Clone(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = ""),
    PartialOrd(bound = ""),
    Ord(bound = ""),
    Default(bound = "")
)]
pub struct BitList<N> {
    // `bitvec` has a rather complicated API, some of which is slow due to being overly general.
    // The only reason we use `BitBox` instead of `Box<[u8]>` is because `Box<[u8]>` would
    // necessitate storing the length in bits in a separate field, making this struct 1 word bigger.
    //
    // Small lists could be stored entirely in the pointer, making the heap allocation unnecessary.
    // However, there doesn't seem to be any crate that implements such an optimization.
    // On top of that, with the mainnet preset it would be useless on most machines even with the
    // minimal number of validators.
    //
    // We rely on `bitvec::order::Lsb0` being the default bit ordering to implement SSZ correctly.
    #[deref]
    #[deref_mut]
    bits: BitBox<u8>,
    #[derivative(PartialEq = "ignore", PartialOrd = "ignore", Ord = "ignore")]
    phantom: PhantomData<N>,
}

// The `U2048` is in reference to `MaxValidatorsPerCommittee`.
// `BitList`s with different maximum lengths should have the same size.
assert_eq_size!(BitList<U2048>, [usize; 2]);

impl<N> From<BitList<N>> for Vec<u8> {
    fn from(bit_list: BitList<N>) -> Self {
        let length = bit_list.len();
        let mut bytes = bit_list.bits.into_bitvec().into_vec();
        bytes.resize(bytes_with_delimiting_bit(length), 0);
        bytes.set_bit(length, true);
        bytes
    }
}

impl<N: Unsigned> TryFrom<Vec<u8>> for BitList<N> {
    type Error = ReadError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let length = Self::measure_length(bytes.as_slice())?;
        Ok(Self::from_vec_with_length(bytes, length))
    }
}

// This could be a `From` impl if feature `generic_const_exprs` were stable.
// See <https://internals.rust-lang.org/t/const-generics-where-restrictions/12742/6>.
#[cfg(test)]
impl<N: Unsigned, const SIZE: usize> TryFrom<[bool; SIZE]> for BitList<N> {
    type Error = ReadError;

    fn try_from(bits: [bool; SIZE]) -> Result<Self, Self::Error> {
        Self::validate_length(SIZE)?;

        let mut bit_list = Self::with_length(SIZE);

        for (index, bit) in bits.into_iter().enumerate() {
            bit_list.bits.set(index, bit);
        }

        Ok(bit_list)
    }
}

impl<N> BitOrAssign<&Self> for BitList<N> {
    fn bitor_assign(&mut self, other: &Self) {
        assert_eq!(self.len(), other.len());

        // Starting with `bitvec` 1.0.0, bitwise assignment operators should be just as fast as
        // batched updates using `BitBox::as_raw_slice` and `BitBox::as_raw_mut_slice`.
        self.bits |= &other.bits;
    }
}

// The Binary` impl for `bitvec::slice::BitSlice` is close to what we want but not quite it.
//
// This sort of code arguably belongs in an impl of `core::fmt::Binary` rather than `Debug`,
// but we don't ever format bit lists directly and we need a `Debug` impl anyway.
impl<N> Debug for BitList<N> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("0b")?;

        for bit in self.iter().by_vals() {
            formatter.write_str(if bit { "1" } else { "0" })?;
        }

        Ok(())
    }
}

// `BitBox` deserializes itself as a struct with multiple fields.
impl<'de, N: Unsigned> Deserialize<'de> for BitList<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_utils::prefixed_hex_or_bytes_cow::deserialize(deserializer)?
            .into_owned()
            .try_into()
            .map_err(D::Error::custom)
    }
}

// `BitBox` serializes itself as a struct with multiple fields.
impl<N> Serialize for BitList<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut ssz_bytes = vec![];
        self.write_variable(&mut ssz_bytes)
            .map_err(S::Error::custom)?;
        serde_utils::prefixed_hex_or_bytes_slice::serialize(ssz_bytes, serializer)
    }
}

impl<N> SszSize for BitList<N> {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl<C, N: Unsigned> SszRead<C> for BitList<N> {
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let length = Self::measure_length(bytes)?;
        let bytes = bytes[..bytes_without_delimiting_bit(length)].to_vec();
        Ok(Self::from_vec_with_length(bytes, length))
    }
}

impl<N> SszWrite for BitList<N> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        let length_before = bytes.len();
        let length_after = length_before + bytes_with_delimiting_bit(self.len());

        bytes.resize(length_after, 0);

        let new_bytes = &mut bytes[length_before..];

        new_bytes[..bytes_without_delimiting_bit(self.len())].copy_from_slice(self.as_raw_slice());
        new_bytes.set_bit(self.len(), true);

        Ok(())
    }
}

impl<N: MerkleBits> SszHash for BitList<N> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = MerkleTree::<N::MerkleTreeDepth>::merkleize_bytes(self.as_raw_slice());
        merkle_tree::mix_in_length(root, self.len())
    }
}

impl<N> BitList<N> {
    #[must_use]
    pub fn full(value: bool) -> Self
    where
        N: Unsigned,
    {
        Self::new(value, N::USIZE)
    }

    #[must_use]
    pub fn with_length(length: usize) -> Self
    where
        N: Unsigned,
    {
        Self::new(false, length)
    }

    #[must_use]
    pub fn new(value: bool, length: usize) -> Self
    where
        N: Unsigned,
    {
        assert!(length <= N::USIZE);

        Self::from_bit_box(bitbox![_, _; u8::from(value); length])
    }

    pub fn concatenate<'lists>(
        bit_lists: impl IntoIterator<Item = &'lists Self>,
    ) -> Result<Self, ReadError>
    where
        N: Unsigned,
    {
        let mut bits = BitVec::new();

        for bit_list in bit_lists {
            bits.extend_from_bitslice(bit_list);
        }

        let maximum = N::USIZE;
        let actual = bits.len();

        if actual > maximum {
            return Err(ReadError::BitListTooLong { maximum, actual });
        }

        Ok(Self::from_bit_box(bits.into_boxed_bitslice()))
    }

    #[must_use]
    pub fn any_not_in(&self, other: &Self) -> bool {
        assert_eq!(self.len(), other.len());

        core::iter::zip(self.as_raw_slice(), other.as_raw_slice())
            .any(|(byte, other_byte)| byte & !other_byte > 0)
    }

    #[must_use]
    pub fn any_in_common(&self, other: &Self) -> bool {
        assert_eq!(self.len(), other.len());

        core::iter::zip(self.as_raw_slice(), other.as_raw_slice())
            .any(|(byte, other_byte)| (byte & other_byte) > 0)
    }

    #[must_use]
    pub fn count_not_in(&self, other: &Self) -> usize {
        assert_eq!(self.len(), other.len());

        core::iter::zip(self.as_raw_slice(), other.as_raw_slice())
            .map(|(byte, other_byte)| (byte & !other_byte).count_ones())
            .map(usize::try_from)
            .map(|result| result.expect("number of bits in a byte should fit in usize"))
            .sum()
    }

    fn measure_length(bytes: &[u8]) -> Result<usize, ReadError>
    where
        N: Unsigned,
    {
        let leading_zeros_in_last_byte = bytes
            .last()
            .ok_or(ReadError::BitListEmptySlice)?
            .leading_zeros()
            .try_into()
            .expect("number of bits in a byte should fit in usize");

        let data_bits_in_last_byte = (BITS_PER_BYTE - 1)
            .checked_sub(leading_zeros_in_last_byte)
            .ok_or(ReadError::BitListNoDelimitingBit)?;

        let maximum = N::USIZE;
        let actual = (bytes.len() - 1) * BITS_PER_BYTE + data_bits_in_last_byte;

        if actual > maximum {
            return Err(ReadError::BitListTooLong { maximum, actual });
        }

        Ok(actual)
    }

    fn from_vec_with_length(bytes: Vec<u8>, length: usize) -> Self {
        let mut bits = BitVec::from_vec(bytes);
        bits.truncate(length);
        Self::from_bit_box(bits.into_boxed_bitslice())
    }

    fn from_bit_box(mut bits: BitBox<u8>) -> Self {
        bits.fill_uninitialized(false);

        Self {
            bits,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
impl<N> BitList<N> {
    const fn validate_length(actual: usize) -> Result<(), ReadError>
    where
        N: Unsigned,
    {
        let maximum = N::USIZE;

        if actual > maximum {
            return Err(ReadError::BitListTooLong { maximum, actual });
        }

        Ok(())
    }
}

const fn bytes_without_delimiting_bit(length: usize) -> usize {
    length.div_ceil(BITS_PER_BYTE)
}

const fn bytes_with_delimiting_bit(length: usize) -> usize {
    length.saturating_add(1).div_ceil(BITS_PER_BYTE)
}

#[cfg(test)]
mod tests {
    use typenum::U2;

    use super::*;

    // `BitVec::repeat` sets all bits in its buffer (including unused ones) to the same value.
    // The documentation for `BitBox::fill_uninitialized` does imply it could do that.
    // Remove the call to `BitBox::fill_uninitialized` in `BitList::from_bit_box` to see this fail.
    #[test]
    fn bit_list_new_with_true_clears_unused_bits() {
        assert_eq!(BitList::<U1>::new(true, 1).bits.as_raw_slice(), [1]);
    }

    // `BitVec::repeat` could technically set unused bits to `true` even in this scenario.
    #[test]
    fn bit_list_new_with_false_clears_unused_bits() {
        assert_eq!(BitList::<U1>::new(false, 1).bits.as_raw_slice(), [0]);
    }

    #[test]
    fn can_concatenate_bit_lists_of_max_length_1() -> Result<(), ReadError> {
        type N = U1;

        fn bit_list<const SIZE: usize>(bits: [bool; SIZE]) -> Result<BitList<N>, ReadError> {
            bits.try_into()
        }

        #[allow(clippy::needless_pass_by_value)]
        fn concatenate<const SIZE: usize>(
            bit_lists: [BitList<N>; SIZE],
        ) -> Result<BitList<N>, ReadError> {
            BitList::concatenate(bit_lists.iter())
        }

        assert_eq!(concatenate([]), bit_list([]));
        assert_eq!(concatenate([bit_list([])?]), bit_list([]));
        assert_eq!(concatenate([bit_list([])?, bit_list([])?]), bit_list([]));

        assert_eq!(concatenate([bit_list([false])?]), bit_list([false]));
        assert_eq!(concatenate([bit_list([true])?]), bit_list([true]));

        assert_eq!(
            concatenate([bit_list([true])?, bit_list([true])?]),
            Err(ReadError::BitListTooLong {
                maximum: 1,
                actual: 2,
            }),
        );

        Ok(())
    }

    #[test]
    fn can_concatenate_bit_lists_of_max_length_2() -> Result<(), ReadError> {
        type N = U2;

        fn bit_list<const SIZE: usize>(bits: [bool; SIZE]) -> Result<BitList<N>, ReadError> {
            bits.try_into()
        }

        #[allow(clippy::needless_pass_by_value)]
        fn concatenate<const SIZE: usize>(
            bit_lists: [BitList<N>; SIZE],
        ) -> Result<BitList<N>, ReadError> {
            BitList::concatenate(bit_lists.iter())
        }

        assert_eq!(
            concatenate([bit_list([false])?, bit_list([false])?]),
            bit_list([false, false]),
        );

        assert_eq!(
            concatenate([bit_list([false])?, bit_list([true])?]),
            bit_list([false, true]),
        );

        assert_eq!(
            concatenate([bit_list([true])?, bit_list([false])?]),
            bit_list([true, false]),
        );

        assert_eq!(
            concatenate([bit_list([true])?, bit_list([true])?]),
            bit_list([true, true]),
        );

        assert_eq!(
            concatenate([bit_list([false, false])?, bit_list([])?]),
            bit_list([false, false]),
        );

        assert_eq!(
            concatenate([bit_list([])?, bit_list([false, false])?]),
            bit_list([false, false]),
        );

        assert_eq!(
            concatenate([bit_list([true, true])?, bit_list([])?]),
            bit_list([true, true]),
        );

        assert_eq!(
            concatenate([bit_list([])?, bit_list([true, true])?]),
            bit_list([true, true]),
        );

        assert_eq!(
            concatenate([bit_list([true, true])?, bit_list([true])?]),
            Err(ReadError::BitListTooLong {
                maximum: 2,
                actual: 3,
            }),
        );

        assert_eq!(
            concatenate([bit_list([true])?, bit_list([true, true])?]),
            Err(ReadError::BitListTooLong {
                maximum: 2,
                actual: 3,
            }),
        );

        assert_eq!(
            concatenate([bit_list([true, true])?, bit_list([true, true])?]),
            Err(ReadError::BitListTooLong {
                maximum: 2,
                actual: 4,
            }),
        );

        Ok(())
    }
}
