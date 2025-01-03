use crate::{
    consts::DOMAIN_SEPARATION_TAG, error::Error, impl_secret_key,
    traits::SecretKey as SecretKeyTrait,
};
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Projective, G2Projective, Scalar,
};
use sha2::Sha256;

use super::{
    public_key::PublicKey,
    secret_key_bytes::{SecretKeyBytes, SIZE},
    signature::Signature,
};

impl_secret_key!(
    SecretKeyTrait<SIZE>,
    SecretKey,
    Scalar,
    SecretKeyBytes,
    PublicKey,
    Signature
);

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

impl SecretKeyTrait<SIZE> for SecretKey {
    type SecretKeyBytes = SecretKeyBytes;
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
        let signature = h * self.as_raw();

        Signature::from(signature)
    }
}
