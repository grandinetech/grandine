use std::sync::Arc;

use crate::error::Error;

pub trait AggregatePublicKey: Default {
    type PublicKey;

    /// [`eth_aggregate_pubkeys`](https://github.com/ethereum/consensus-specs/blob/86fb82b221474cc89387fa6436806507b3849d88/specs/altair/bls.md#eth_aggregate_pubkeys)
    fn aggregate_nonempty(
        keys: impl IntoIterator<Item = Arc<Self::PublicKey>>,
    ) -> Result<Self::PublicKey, Error> {
        let mut iterator = keys.into_iter().peekable();

        if iterator.peek().is_none() {
            return Err(Error::NoPublicKeysToAggregate);
        }

        Ok(iterator
            .fold(Self::default(), |acc, item| acc.add_public_key(&item))
            .to_public_key())
    }

    #[must_use]
    fn add_public_key(self, public_key: &Self::PublicKey) -> Self;

    #[must_use]
    fn add_aggregate(self, other: &Self) -> Self;

    fn to_public_key(&self) -> Self::PublicKey;
}
