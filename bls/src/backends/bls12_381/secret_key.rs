use core::ops::Deref;
use core::{
    fmt::{Binary, Display, LowerExp, LowerHex, Octal, Pointer, UpperExp, UpperHex},
    hash::{Hash, Hasher},
};
use std::borrow::ToOwned;

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Projective, G2Projective, Scalar,
};
use derive_more::Debug;
use serde::Serialize;
use sha2::Sha256;
use ssz::{SszHash, SszWrite};
use static_assertions::assert_not_impl_any;

use super::{
    public_key::PublicKey,
    secret_key_bytes::{SecretKeyBytes, SIZE},
    signature::Signature,
};
use crate::{consts::DOMAIN_SEPARATION_TAG, error::Error, traits::SecretKey as SecretKeyTrait};

#[derive(Debug)]
#[debug("[REDACTED]")]
pub struct SecretKey(Scalar);

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
        let scalar = match Option::from(Scalar::from_bytes(
            secret_key_bytes.as_ref().try_into().unwrap(),
        )) {
            Some(scalar) => scalar,
            None => {
                return Err(Error::InvalidSecretKey);
            }
        };
        Ok(Self(scalar))
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
        let point = G1Projective::generator() * self.as_raw();
        PublicKey::from(point)
    }

    #[inline]
    #[must_use]
    fn sign(&self, message: impl AsRef<[u8]>) -> Signature {
        let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            &[message.as_ref()],
            DOMAIN_SEPARATION_TAG,
        );
        let signature = h * self.0;

        Signature::from(signature)
    }

    #[inline]
    #[must_use]
    fn to_bytes(&self) -> SecretKeyBytes {
        let bytes = self.as_raw().to_bytes();
        SecretKeyBytes { bytes }
    }
}

impl SecretKey {
    const fn as_raw(&self) -> &Scalar {
        &self.0
    }
}
