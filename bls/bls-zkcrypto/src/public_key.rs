use bls12_381::{G1Affine, G1Projective};
use derive_more::From;

use bls_core::{error::Error, traits::PublicKey as PublicKeyTrait, DECOMPRESSED_SIZE};

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

        if bool::from(point.is_identity()) {
            return Err(Error::InvalidPublicKey);
        }

        if !bool::from(point.is_torsion_free()) {
            return Err(Error::DecompressionFailed);
        }

        Ok(Self(point.into()))
    }
}

impl PublicKeyTrait for PublicKey {
    type PublicKeyBytes = PublicKeyBytes;

    #[inline]
    fn aggregate_in_place(&mut self, other: &Self) {
        self.0 = self.as_raw().add(other.as_raw());
    }

    fn deserialize_from_decompressed_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(
            G1Affine::from_uncompressed(
                bytes.try_into().map_err(|_| Error::DeserializationFailed)?,
            )
            .into_option()
            .ok_or(Error::DeserializationFailed)?
            .into(),
        ))
    }

    fn serialize_to_decompressed_bytes(&self) -> [u8; DECOMPRESSED_SIZE] {
        G1Affine::from(self.as_raw()).to_uncompressed()
    }
}

impl PublicKey {
    pub(crate) const fn as_raw(&self) -> &G1Projective {
        &self.0
    }
}
