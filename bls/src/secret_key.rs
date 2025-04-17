use core::{fmt::Debug, hash::Hash};

use crate::{
    backend::backend, public_key::{PublicKey, PublicKeyTrait}, secret_key_bytes::SecretKeyBytes, signature::{Signature, SignatureTrait}, Backend, Error
};

pub trait SecretKeyTrait<const N: usize>: Debug + PartialEq + Eq + Hash {
    type PublicKey: PublicKeyTrait;
    type Signature: SignatureTrait;

    fn to_public_key(&self) -> Self::PublicKey;
    fn sign(&self, message: impl AsRef<[u8]>) -> Self::Signature;
    fn to_bytes(&self) -> SecretKeyBytes;
}

#[derive(PartialEq, Eq, Hash, derive_more::Debug)]
pub enum SecretKey {
    #[cfg(feature = "blst")]
    #[debug("[REDACTED]")]
    Blst(blst::SecretKey),

    #[cfg(feature = "zkcrypto")]
    #[debug("[REDACTED]")]
    Zkcrypto(zkcrypto::SecretKey)
}

impl TryFrom<SecretKeyBytes> for SecretKey {
    type Error = Error;

    fn try_from(bytes: SecretKeyBytes) -> Result<Self, Self::Error> {
        match backend() {
            #[cfg(feature = "blst")]
            Backend::Blst => Ok(SecretKey::Blst(blst::SecretKey::try_from(bytes)?)),

            #[cfg(feature = "zkcrypto")]
            Backend::Zkcrypto => Ok(SecretKey::Zkcrypto(zkcrypto::SecretKey::try_from(bytes)?)),
        }
    }
}

impl SecretKeyTrait<32> for SecretKey {
    type PublicKey = PublicKey;
    
    type Signature = Signature;

    fn to_public_key(&self) -> PublicKey {
        match self {
            #[cfg(feature = "blst")]
            SecretKey::Blst(secret_key) => PublicKey::Blst(secret_key.to_public_key()),

            #[cfg(feature = "zkcrypto")]
            SecretKey::Zkcrypto(secret_key) => PublicKey::Zkcrypto(secret_key.to_public_key()),
        }
    }

    fn sign(&self, message: impl AsRef<[u8]>) -> Signature {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(secret_key) => Signature::Blst(secret_key.sign(message)),

            #[cfg(feature = "zkcrypto")]
            Self::Zkcrypto(secret_key) => Signature::Zkcrypto(secret_key.sign(message))
        }
    }

    fn to_bytes(&self) -> SecretKeyBytes {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(secret_key) => secret_key.to_bytes(),

            #[cfg(feature = "zkcrypto")]
            Self::Zkcrypto(secret_key) => secret_key.to_bytes(),
        }
    }
}

#[cfg(feature = "blst")]
pub(crate) mod blst {
    use blst::min_pk::SecretKey as RawSecretKey;

    use crate::{
        error::Error, public_key::blst::PublicKey, secret_key_bytes::SecretKeyBytes,
        signature::blst::Signature, DOMAIN_SEPARATION_TAG,
    };

    use super::SecretKeyTrait;

    #[derive(derive_more::Debug)]
    // Inspired by `DebugSecret` from the `secrecy` crate.
    #[debug("[REDACTED]")]
    pub struct SecretKey(RawSecretKey);

    impl PartialEq for SecretKey {
        #[inline]
        fn eq(&self, other: &Self) -> bool {
            self.as_raw().to_bytes() == other.as_raw().to_bytes()
        }
    }

    impl Eq for SecretKey {}

    impl core::hash::Hash for SecretKey {
        fn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {
            self.as_raw().to_bytes().hash(hasher)
        }
    }

    impl SecretKey {
        const fn as_raw(&self) -> &RawSecretKey {
            &self.0
        }
    }

    impl TryFrom<SecretKeyBytes> for SecretKey {
        type Error = Error;

        #[inline]
        fn try_from(secret_key_bytes: SecretKeyBytes) -> Result<Self, Self::Error> {
            RawSecretKey::from_bytes(secret_key_bytes.as_ref())
                .map(Self)
                .map_err(|_| Error::InvalidSecretKey)
        }
    }

    impl SecretKeyTrait<32> for SecretKey {
        type PublicKey = PublicKey;
        type Signature = Signature;

        #[inline]
        #[must_use]
        fn to_bytes(&self) -> SecretKeyBytes {
            SecretKeyBytes {
                bytes: self.as_raw().to_bytes(),
            }
        }

        #[inline]
        fn to_public_key(&self) -> PublicKey {
            self.as_raw().sk_to_pk().into()
        }

        #[inline]
        fn sign(&self, message: impl AsRef<[u8]>) -> Signature {
            self.as_raw()
                .sign(message.as_ref(), DOMAIN_SEPARATION_TAG, &[])
                .into()
        }
    }
}

#[cfg(feature = "zkcrypto")]
mod zkcrypto {
    use bls12_381::{hash_to_curve::{ExpandMsgXmd, HashToCurve}, G1Projective, G2Projective, Scalar};
    use sha2::Sha256;

    use crate::{public_key::zkcrypto::PublicKey, signature::zkcrypto::Signature, Error, SecretKeyBytes, DOMAIN_SEPARATION_TAG};

    use super::SecretKeyTrait;

    #[derive(derive_more::Debug)]
    #[debug("[REDACTED]")]
    pub struct SecretKey(Scalar);

    impl PartialEq for SecretKey {
        fn eq(&self, other: &Self) -> bool {
            self.as_raw().to_bytes() == other.as_raw().to_bytes()
        }
    }

    impl Eq for SecretKey {}

    impl core::hash::Hash for SecretKey {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.as_raw().to_bytes().hash(state);
        }
    }

    impl TryFrom<SecretKeyBytes> for SecretKey {
        type Error = Error;
    
        fn try_from(value: SecretKeyBytes) -> Result<Self, Self::Error> {
            if value.bytes.iter().all(|&b| b == 0) {
                return Err(Error::InvalidSecretKey);
            }

            let mut le_bytes = value.bytes;
            le_bytes.reverse();

            let scalar = match Option::from(Scalar::from_bytes(&le_bytes)) {
                Some(scalar) => scalar,
                None => return Err(Error::InvalidSecretKey),
            };

            Ok(Self(scalar))
        }
    }

    impl SecretKeyTrait<32> for SecretKey {
        type PublicKey = PublicKey;
    
        type Signature = Signature;
    
        fn to_public_key(&self) -> Self::PublicKey {
            let point = G1Projective::generator() * self.as_raw();
            PublicKey::from(point)
        }
    
        fn sign(&self, message: impl AsRef<[u8]>) -> Self::Signature {
            let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([message.as_ref()], DOMAIN_SEPARATION_TAG);
            let signature = h * self.as_raw();

            Signature::from(signature)
        }
    
        fn to_bytes(&self) -> crate::SecretKeyBytes {
            let mut bytes = self.as_raw().to_bytes();
            bytes.reverse();

            SecretKeyBytes { bytes }
        }
    }

    impl SecretKey {
        const fn as_raw(&self) -> &Scalar {
            &self.0
        }
    }
}