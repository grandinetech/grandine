use core::{
    fmt::{Binary, Display, LowerExp, LowerHex, Octal, Pointer, UpperExp, UpperHex},
    hash::{Hash, Hasher},
    ops::Deref,
};
use std::borrow::ToOwned;

use blst::min_pk::SecretKey as RawSecretKey;
use derive_more::Debug;
use serde::Serialize;
use ssz::{SszHash, SszWrite};
use static_assertions::assert_not_impl_any;

use crate::{consts::DOMAIN_SEPARATION_TAG, error::Error, traits::SecretKey as SecretKeyTrait};

use super::{
    public_key::PublicKey,
    secret_key_bytes::{SecretKeyBytes, SIZE},
    signature::Signature,
};

// `RawSecretKey` already implements `Zeroize` (with `zeroize(drop)`):
// <https://github.com/supranational/blst/blob/v0.3.10/bindings/rust/src/lib.rs#L458-L460>
#[derive(Debug)]
// Inspired by `DebugSecret` from the `secrecy` crate.
#[debug("[REDACTED]")]
pub struct SecretKey(RawSecretKey);

// Prevent `SecretKey` from implementing some traits to avoid leaking secret keys.
// This could also be done by wrapping it in `secrecy::Secret`.
assert_not_impl_any! {
    SecretKey:

    Clone,
    Copy,
    Deref,
    ToOwned,

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
    SszWrite,
}

impl PartialEq for SecretKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_raw().to_bytes() == other.as_raw().to_bytes()
    }
}

impl Eq for SecretKey {}

impl TryFrom<SecretKeyBytes> for SecretKey {
    type Error = Error;

    #[inline]
    fn try_from(secret_key_bytes: SecretKeyBytes) -> Result<Self, Self::Error> {
        RawSecretKey::from_bytes(secret_key_bytes.as_ref())
            .map(Self)
            .map_err(Into::into)
    }
}

impl Hash for SecretKey {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.as_raw().to_bytes().hash(hasher)
    }
}

impl SecretKeyTrait<SIZE> for SecretKey {
    type SecretKeyBytes = SecretKeyBytes;
    type PublicKey = PublicKey;
    type Signature = Signature;

    #[inline]
    #[must_use]
    fn to_public_key(&self) -> PublicKey {
        self.as_raw().sk_to_pk().into()
    }

    #[inline]
    #[must_use]
    fn sign(&self, message: impl AsRef<[u8]>) -> Signature {
        self.as_raw()
            .sign(message.as_ref(), DOMAIN_SEPARATION_TAG, &[])
            .into()
    }

    #[inline]
    #[must_use]
    fn to_bytes(&self) -> SecretKeyBytes {
        let bytes = self.as_raw().to_bytes();
        SecretKeyBytes { bytes }
    }
}

impl SecretKey {
    const fn as_raw(&self) -> &RawSecretKey {
        &self.0
    }
}
