use blst::min_pk::{AggregatePublicKey as RawAggregatePublicKey, PublicKey as RawPublicKey};
use derive_more::From;

use bls_core::{error::Error, traits::PublicKey as PublicKeyTrait};

use super::public_key_bytes::PublicKeyBytes;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, From)]
pub struct PublicKey(RawPublicKey);

impl TryFrom<PublicKeyBytes> for PublicKey {
    type Error = Error;

    #[inline]
    fn try_from(bytes: PublicKeyBytes) -> Result<Self, Self::Error> {
        let raw =
            RawPublicKey::uncompress(bytes.as_bytes()).map_err(|_| Error::InvalidPublicKey)?;

        // This is needed to pass `fast_aggregate_verify` tests.
        // See the following for more information:
        // - <https://github.com/supranational/blst/issues/11>
        // - <https://github.com/ethereum/consensus-specs/releases/tag/v1.0.0>
        raw.validate().map_err(|_| Error::InvalidPublicKey)?;

        Ok(Self(raw))
    }
}

impl PublicKeyTrait for PublicKey {
    type PublicKeyBytes = PublicKeyBytes;

    #[inline]
    fn aggregate_in_place(&mut self, other: Self) {
        let mut self_aggregate = RawAggregatePublicKey::from_public_key(self.as_raw());
        let other_aggregate = RawAggregatePublicKey::from_public_key(other.as_raw());
        self_aggregate.add_aggregate(&other_aggregate);
        self.0 = self_aggregate.to_public_key();
    }
}

impl PublicKey {
    pub(crate) const fn as_raw(&self) -> &RawPublicKey {
        &self.0
    }
}
