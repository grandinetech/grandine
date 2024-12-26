use bls12_381::{G1Affine, G1Projective};
use derive_more::From;

use crate::{error::Error, traits::PublicKey as PublicKeyTrait};

use super::public_key_bytes::PublicKeyBytes;

#[derive(Clone, Copy, PartialEq, Eq, Debug, From)]
pub struct PublicKey(G1Projective);

impl Default for PublicKey {
    #[inline]
    fn default() -> Self {
        Self(G1Projective::identity())
    }
}

impl TryFrom<PublicKeyBytes> for PublicKey {
    type Error = Error;

    #[inline]
    fn try_from(bytes: PublicKeyBytes) -> Result<Self, Self::Error> {
        let point: G1Affine = Option::from(G1Affine::from_compressed(bytes.as_ref()))
            .ok_or(Error::DecompressionFailed)?;

        if !bool::from(point.is_torsion_free()) {
            return Err(Error::DecompressionFailed);
        }

        Ok(Self(point.into()))
    }
}

impl PublicKeyTrait for PublicKey {
    type PublicKeyBytes = PublicKeyBytes;

    #[inline]
    fn aggregate_in_place(&mut self, other: Self) {
        self.as_raw().add(other.as_raw());
    }
}

impl PublicKey {
    pub(crate) const fn as_raw(&self) -> &G1Projective {
        &self.0
    }
}
