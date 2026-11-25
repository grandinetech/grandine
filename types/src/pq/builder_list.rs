use core::ops::{Deref, DerefMut};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{
    H256, ProgressiveList, ReadError, Size, SszHash, SszRead, SszSize, SszWrite, U1, WriteError,
    read_list, write_list,
};
use try_from_iterator::TryFromIterator as _;

use crate::{
    collections::Builders,
    gloas::containers::Builder as GloasBuilder,
    pq::{
        containers::Builder,
        validator_list::{padded_pubkey, unpadded_pubkey},
    },
};

impl From<&GloasBuilder> for Builder {
    fn from(builder: &GloasBuilder) -> Self {
        Self {
            pubkey: unpadded_pubkey(&builder.pubkey),
            version: builder.version,
            execution_address: builder.execution_address,
            balance: builder.balance,
            deposit_epoch: builder.deposit_epoch,
            withdrawable_epoch: builder.withdrawable_epoch,
        }
    }
}

impl From<Builder> for GloasBuilder {
    fn from(builder: Builder) -> Self {
        Self {
            pubkey: padded_pubkey(builder.pubkey),
            version: builder.version,
            execution_address: builder.execution_address,
            balance: builder.balance,
            deposit_epoch: builder.deposit_epoch,
            withdrawable_epoch: builder.withdrawable_epoch,
        }
    }
}

/// The PQ `builders` list.
///
/// Builders are kept as Gloas `Builder`s with padded public keys so that code shared with Gloas
/// works unchanged. The list is serialized and hashed as PQ `Builder`s, without caching.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct PqBuilders(pub(crate) Builders);

impl Deref for PqBuilders {
    type Target = Builders;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PqBuilders {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PqBuilders {
    fn to_pq(&self) -> Vec<Builder> {
        self.0.into_iter().map(Builder::from).collect()
    }

    fn from_pq(builders: impl IntoIterator<Item = Builder>) -> Self {
        Self(
            Builders::try_from_iter(builders.into_iter().map(GloasBuilder::from))
                .expect("progressive lists are unbounded in practice"),
        )
    }
}

impl Serialize for PqBuilders {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_pq().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PqBuilders {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<Builder>::deserialize(deserializer).map(Self::from_pq)
    }
}

impl SszSize for PqBuilders {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl SszWrite for PqBuilders {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        write_list(bytes, self.to_pq())
    }
}

impl<C> SszRead<C> for PqBuilders {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let builders: Vec<Builder> = read_list(usize::MAX, context, bytes)?;
        Ok(Self::from_pq(builders))
    }
}

impl SszHash for PqBuilders {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        ProgressiveList::<Builder>::try_from_iter(self.to_pq())
            .expect("progressive lists are unbounded in practice")
            .hash_tree_root()
    }
}
