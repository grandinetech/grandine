use ark_bls12_381::{G1Affine, G1Projective};
use ark_ec::AffineRepr;
use ark_serialize::CanonicalDeserialize;
use derive_more::From;

use bls_core::{error::Error, traits::PublicKey as PublicKeyTrait};

use super::public_key_bytes::PublicKeyBytes;

#[derive(Clone, Copy, PartialEq, Eq, Debug, From)]
pub struct PublicKey(G1Projective);

impl Default for PublicKey {
    #[inline]
    fn default() -> Self {
        Self(G1Projective::default())
    }
}

impl TryFrom<PublicKeyBytes> for PublicKey {
    type Error = Error;

    #[inline]
    fn try_from(bytes: PublicKeyBytes) -> Result<Self, Self::Error> {
        let point = G1Affine::deserialize_compressed::<&[u8]>(bytes.as_ref())
            .map_err(|_| Error::DecompressionFailed)?;

        if bool::from(point.is_zero()) {
            return Err(Error::InvalidPublicKey);
        }

        if !bool::from(point.is_on_curve()) {
            return Err(Error::DecompressionFailed);
        }

        Ok(Self(point.into()))
    }
}

impl PublicKeyTrait for PublicKey {
    type PublicKeyBytes = PublicKeyBytes;

    #[inline]
    fn aggregate_in_place(&mut self, other: Self) {
        self.0 = *self.as_raw() + other.as_raw();
    }
}

impl PublicKey {
    pub(crate) const fn as_raw(&self) -> &G1Projective {
        &self.0
    }
}
