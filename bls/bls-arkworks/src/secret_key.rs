use ark_bls12_381::{g2, Fr, G1Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    short_weierstrass::Projective,
    PrimeGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use bls_core::{
    consts::DOMAIN_SEPARATION_TAG, error::Error, impl_secret_key,
    traits::SecretKey as SecretKeyTrait,
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
    Fr,
    SecretKeyBytes,
    PublicKey,
    Signature,
    |scalar: &Fr| scalar.into_bigint().to_bytes_le()
);

impl TryFrom<SecretKeyBytes> for SecretKey {
    type Error = Error;

    #[inline]
    fn try_from(secret_key_bytes: SecretKeyBytes) -> Result<Self, Self::Error> {
        if secret_key_bytes.bytes.iter().all(|&b| b == 0) {
            return Err(Error::InvalidSecretKey);
        }

        let scalar = match Option::from(Fr::from_be_bytes_mod_order(&secret_key_bytes.bytes)) {
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
        let mut bytes = [0u8; SIZE];
        self.as_raw().serialize_compressed(&mut bytes[..]).unwrap();
        SecretKeyBytes { bytes }
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
        let hasher = MapToCurveBasedHasher::<
            Projective<g2::Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<g2::Config>,
        >::new(DOMAIN_SEPARATION_TAG)
        .unwrap();
        let hash = hasher.hash(message.as_ref()).unwrap();
        let signature = hash * self.as_raw();

        Signature::from(signature)
    }
}
