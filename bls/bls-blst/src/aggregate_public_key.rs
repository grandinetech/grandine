use blst::min_pk::{AggregatePublicKey as RawAggregatePublicKey, PublicKey as RawPublicKey};

use bls_core::traits::AggregatePublicKey as AggregatePublicKeyTrait;

use super::public_key::PublicKey;

#[derive(Clone, Copy, Debug)]
pub struct AggregatePublicKey(RawAggregatePublicKey);

impl Default for AggregatePublicKey {
    #[inline]
    fn default() -> Self {
        Self(RawAggregatePublicKey::from_public_key(
            &RawPublicKey::default(),
        ))
    }
}

impl AggregatePublicKeyTrait for AggregatePublicKey {
    type PublicKey = PublicKey;

    #[inline]
    fn add_public_key(mut self, public_key: &PublicKey) -> Self {
        self.0
            .add_public_key(public_key.as_raw(), false)
            .expect("adding a public key without validating it cannot fail");
        self
    }

    #[inline]
    fn add_aggregate(mut self, other: &Self) -> Self {
        self.0.add_aggregate(&other.0);
        self
    }

    #[inline]
    fn to_public_key(&self) -> PublicKey {
        self.0.to_public_key().into()
    }
}
