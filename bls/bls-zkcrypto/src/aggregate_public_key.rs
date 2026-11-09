use bls12_381::G1Projective;

use bls_core::traits::AggregatePublicKey as AggregatePublicKeyTrait;

use super::public_key::PublicKey;

#[derive(Clone, Copy, Debug)]
pub struct AggregatePublicKey(G1Projective);

impl Default for AggregatePublicKey {
    #[inline]
    fn default() -> Self {
        Self(G1Projective::identity())
    }
}

impl AggregatePublicKeyTrait for AggregatePublicKey {
    type PublicKey = PublicKey;

    #[inline]
    fn add_public_key(self, public_key: &PublicKey) -> Self {
        Self(self.0.add(public_key.as_raw()))
    }

    #[inline]
    fn add_aggregate(self, other: &Self) -> Self {
        Self(self.0.add(&other.0))
    }

    #[inline]
    fn to_public_key(&self) -> PublicKey {
        self.0.into()
    }
}
