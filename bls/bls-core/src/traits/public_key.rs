use core::fmt::Debug;

use crate::error::Error;

use super::PublicKeyBytes as PublicKeyBytesTrait;

pub trait PublicKey:
    Clone + Copy + PartialEq + Eq + Default + Debug + TryFrom<Self::PublicKeyBytes>
{
    type PublicKeyBytes: PublicKeyBytesTrait;

    /// [`eth_aggregate_pubkeys`](https://github.com/ethereum/consensus-specs/blob/86fb82b221474cc89387fa6436806507b3849d88/specs/altair/bls.md#eth_aggregate_pubkeys)
    fn aggregate_nonempty(keys: impl IntoIterator<Item = Self>) -> Result<Self, Error> {
        keys.into_iter()
            .reduce(Self::aggregate)
            .ok_or(Error::NoPublicKeysToAggregate)
    }

    #[must_use]
    fn aggregate(mut self, other: Self) -> Self {
        self.aggregate_in_place(other);
        self
    }

    fn aggregate_in_place(&mut self, other: Self);
}
