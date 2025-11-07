use core::fmt::Debug;
use std::sync::Arc;

use crate::{DECOMPRESSED_SIZE, error::Error};

use super::PublicKeyBytes as PublicKeyBytesTrait;

pub trait PublicKey:
    Clone + Copy + PartialEq + Eq + Default + Debug + TryFrom<Self::PublicKeyBytes>
{
    type PublicKeyBytes: PublicKeyBytesTrait;

    /// [`eth_aggregate_pubkeys`](https://github.com/ethereum/consensus-specs/blob/86fb82b221474cc89387fa6436806507b3849d88/specs/altair/bls.md#eth_aggregate_pubkeys)
    fn aggregate_nonempty(keys: impl IntoIterator<Item = Arc<Self>>) -> Result<Self, Error> {
        let mut iterator = keys.into_iter();

        if let Some(first) = iterator.next() {
            return Ok(iterator.fold(*first, |acc, item| acc.aggregate(&item)));
        }

        Err(Error::NoPublicKeysToAggregate)
    }

    #[must_use]
    fn aggregate(mut self, other: &Self) -> Self {
        self.aggregate_in_place(other);
        self
    }

    fn aggregate_in_place(&mut self, other: &Self);

    fn deserialize_from_decompressed_bytes(bytes: &[u8]) -> Result<Self, Error>;

    fn serialize_to_decompressed_bytes(&self) -> [u8; DECOMPRESSED_SIZE];
}
