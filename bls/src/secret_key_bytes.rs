use core::{
    fmt::{Binary, Debug, Display, LowerExp, LowerHex, Octal, Pointer, UpperExp, UpperHex},
    ops::Deref,
};

use derive_more::{AsMut, AsRef, From};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use ssz::{ReadError, Size, SszHash, SszRead, SszSize, SszWrite};
use static_assertions::assert_not_impl_any;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SecretKey;

// Unlike public keys and signatures, secret keys are not compressed.
const SIZE: usize = size_of::<SecretKey>();

#[derive(Default, AsRef, AsMut, From, Zeroize, ZeroizeOnDrop, Deserialize)]
#[as_ref(forward)]
#[as_mut(forward)]
#[serde(transparent)]
pub struct SecretKeyBytes {
    #[serde(with = "serde_utils::prefixed_hex_or_bytes_array")]
    pub(crate) bytes: [u8; SIZE],
}

// Prevent `SecretKeyBytes` from implementing some traits to avoid leaking secret keys.
// This could also be done by wrapping it in `secrecy::Secret`.
assert_not_impl_any! {
    SecretKeyBytes:

    Clone,
    Copy,
    Deref,
    ToOwned,

    Debug,
    Binary,
    Display,
    LowerExp,
    LowerHex,
    Octal,
    Pointer,
    UpperExp,
    UpperHex,

    Serialize,
    SszHash,
}

impl FromHex for SecretKeyBytes {
    type Error = <[u8; SIZE] as FromHex>::Error;

    fn from_hex<T: AsRef<[u8]>>(digits: T) -> Result<Self, Self::Error> {
        let bytes = FromHex::from_hex(digits)?;
        Ok(Self { bytes })
    }
}

impl SszSize for SecretKeyBytes {
    const SIZE: Size = Size::Fixed { size: SIZE };
}

impl<C> SszRead<C> for SecretKeyBytes {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let mut secret_key = Self::default();
        secret_key.bytes.copy_from_slice(bytes);
        Ok(secret_key)
    }
}

impl SszWrite for SecretKeyBytes {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.bytes);
    }
}
