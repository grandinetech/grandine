// TODO(Grandine Team): Consider shortening the name to `U256`.
//                      The main reason not to is the risk of confusing it with `typenum::U256`.
//                      `consensus-specs` calls it `uint256`, but `U256` would match Rust primitives.

use core::{
    fmt::{Formatter, Result as FmtResult},
    num::NonZeroU64,
    ops::{Div, Rem},
    str::FromStr,
};

use byteorder::ByteOrder as _;
use derive_more::{Add, DebugCustom, Display, From, Into, LowerHex, Mul, Shr, Sub};
use ethereum_types::{FromDecStrErr, FromStrRadixErr, H256, U256 as RawUint256};
use num_traits::{Num, One, Zero};
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use typenum::U1;

use crate::{
    consts::Endianness,
    error::{ConversionError, ReadError},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    size::Size,
};

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    From,
    Into,
    Add,
    Sub,
    Mul,
    Shr,
    DebugCustom,
    Display,
    LowerHex,
)]
#[mul(forward)]
#[debug(fmt = "{_0}")]
pub struct Uint256(RawUint256);

impl TryFrom<Uint256> for u64 {
    type Error = ConversionError;

    fn try_from(value: Uint256) -> Result<Self, Self::Error> {
        value
            .into_raw()
            .try_into()
            .map_err(|_| ConversionError::Uint256DoesNotFitInU64 { value })
    }
}

impl FromStr for Uint256 {
    type Err = FromDecStrErr;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        RawUint256::from_dec_str(string).map(Self)
    }
}

impl Div for Uint256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        Self(self.into_raw().div(rhs.into_raw()))
    }
}

impl Div<NonZeroU64> for Uint256 {
    type Output = Self;

    fn div(self, rhs: NonZeroU64) -> Self::Output {
        Self(self.into_raw().div(rhs.get()))
    }
}

impl Rem for Uint256 {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self(self.into_raw().div(rhs.into_raw()))
    }
}

impl Rem<NonZeroU64> for Uint256 {
    type Output = Self;

    fn rem(self, rhs: NonZeroU64) -> Self::Output {
        Self(self.into_raw().rem(rhs.get()))
    }
}

impl Zero for Uint256 {
    fn zero() -> Self {
        Self::ZERO
    }

    fn is_zero(&self) -> bool {
        self.into_raw().is_zero()
    }
}

impl One for Uint256 {
    fn one() -> Self {
        Self(RawUint256::one())
    }
}

impl Num for Uint256 {
    type FromStrRadixErr = FromStrRadixErr;

    fn from_str_radix(string: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        RawUint256::from_str_radix(string, radix).map(Self)
    }
}

impl<'de> Deserialize<'de> for Uint256 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Uint256Visitor;

        impl<'de> Visitor<'de> for Uint256Visitor {
            type Value = Uint256;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                formatter.write_str("a 256-bit unsigned integer")
            }

            fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                let expected = size_of::<Uint256>();
                let actual = bytes.len();

                if actual != expected {
                    return Err(E::custom(format!(
                        "expected {expected} bytes, found {actual}",
                    )));
                }

                Ok(Uint256(RawUint256::from_little_endian(bytes)))
            }

            fn visit_str<E: Error>(self, string: &str) -> Result<Self::Value, E> {
                RawUint256::from_dec_str(string)
                    .map(Uint256)
                    .map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Uint256Visitor)
        } else {
            deserializer.deserialize_bytes(Uint256Visitor)
        }
    }
}

impl Serialize for Uint256 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            let mut bytes = [0; size_of::<Self>()];
            self.into_raw().to_little_endian(&mut bytes);
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl SszSize for Uint256 {
    const SIZE: Size = Size::Fixed {
        size: size_of::<Self>(),
    };
}

impl<C> SszRead<C> for Uint256 {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let mut raw = RawUint256::default();

        for (chunk, limb) in bytes.chunks_exact(size_of::<u64>()).zip(raw.0.iter_mut()) {
            *limb = Endianness::read_u64(chunk);
        }

        Ok(Self(raw))
    }
}

impl SszWrite for Uint256 {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        for (chunk, limb) in bytes
            .chunks_exact_mut(size_of::<u64>())
            .zip(self.into_raw().0)
        {
            Endianness::write_u64(chunk, limb);
        }
    }
}

impl SszHash for Uint256 {
    type PackingFactor = U1;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        let mut hash = H256::zero();
        self.write_fixed(hash.as_bytes_mut());
        hash
    }
}

impl Uint256 {
    pub const BITS: u16 = 256;
    pub const MAX: Self = Self(RawUint256::MAX);
    pub const ZERO: Self = Self(RawUint256::zero());

    // `<RawUint256 as From<u64>>::from` is not `const`.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        let mut raw = RawUint256::zero();
        raw.0[0] = value;
        Self(raw)
    }

    // `<RawUint256 as From<u128>>::from` is not `const`.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        #[rustfmt::skip]
        let [
            b0,  b1,  b2,  b3,  b4,  b5,  b6,  b7,
            b8,  b9,  b10, b11, b12, b13, b14, b15,
        ] = value.to_be_bytes();

        let mut raw = RawUint256::zero();
        raw.0[0] = u64::from_be_bytes([b8, b9, b10, b11, b12, b13, b14, b15]);
        raw.0[1] = u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]);
        Self(raw)
    }

    // `<RawUint256 as From<[u8; 32]>>::from` is not `const`.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; size_of::<Self>()]) -> Self {
        #[rustfmt::skip]
        let [
            b0,  b1,  b2,  b3,  b4,  b5,  b6,  b7,
            b8,  b9,  b10, b11, b12, b13, b14, b15,
            b16, b17, b18, b19, b20, b21, b22, b23,
            b24, b25, b26, b27, b28, b29, b30, b31,
        ] = bytes;

        Self(RawUint256([
            u64::from_be_bytes([b24, b25, b26, b27, b28, b29, b30, b31]),
            u64::from_be_bytes([b16, b17, b18, b19, b20, b21, b22, b23]),
            u64::from_be_bytes([b8, b9, b10, b11, b12, b13, b14, b15]),
            u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]),
        ]))
    }

    #[must_use]
    pub fn saturating_mul(self, rhs: Self) -> Self {
        Self(self.into_raw().saturating_mul(rhs.into_raw()))
    }

    const fn into_raw(self) -> RawUint256 {
        self.0
    }
}
