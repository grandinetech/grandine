use core::fmt::Debug;

use derive_more::derive::From;

use crate::{backend::Backend, error::Error, public_key_bytes::PublicKeyBytes};

pub trait PublicKeyTrait:
    Clone + Copy + PartialEq + Eq + Default + Debug + TryFrom<PublicKeyBytes>
{
    fn aggregate_in_place(&mut self, other: Self);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, From)]
pub enum PublicKey {
    #[cfg(feature = "blst")]
    Blst(blst::PublicKey),
}

impl Into<PublicKeyBytes> for PublicKey {
    #[inline]
    fn into(self) -> PublicKeyBytes {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(v) => v.into(),
        }
    }
}

#[allow(irrefutable_let_patterns)]
impl PublicKey {
    pub fn default(backend: Backend) -> Self {
        match backend {
            #[cfg(feature = "blst")]
            Backend::Blst => PublicKey::Blst(blst::PublicKey::default()),
        }
    }

    #[inline]
    pub fn try_from_with_backend(bytes: PublicKeyBytes, backend: Backend) -> Result<Self, Error> {
        match backend {
            #[cfg(feature = "blst")]
            Backend::Blst => Ok(PublicKey::Blst(blst::PublicKey::try_from(bytes)?)),
        }
    }

    #[inline]
    pub fn aggregate_in_place(&mut self, other: Self) {
        match self {
            #[cfg(feature = "blst")]
            PublicKey::Blst(v) => {
                let PublicKey::Blst(other) = other else {
                    panic!("trying to mix backends - this should never happen");
                };
                v.aggregate_in_place(other);
            }
        }
    }

    /// [`eth_aggregate_pubkeys`](https://github.com/ethereum/consensus-specs/blob/86fb82b221474cc89387fa6436806507b3849d88/specs/altair/bls.md#eth_aggregate_pubkeys)
    pub fn aggregate_nonempty(keys: impl IntoIterator<Item = Self>) -> Result<Self, Error> {
        keys.into_iter()
            .reduce(Self::aggregate)
            .ok_or(Error::NoPublicKeysToAggregate)
    }

    #[must_use]
    pub fn aggregate(mut self, other: Self) -> Self {
        self.aggregate_in_place(other);
        self
    }
}

#[cfg(feature = "blst")]
pub(crate) mod blst {
    use blst::min_pk::{AggregatePublicKey as RawAggregatePublicKey, PublicKey as RawPublicKey};
    use derive_more::From;

    use super::PublicKeyTrait;
    use crate::{error::Error, PublicKeyBytes};

    #[derive(Clone, Copy, PartialEq, Eq, Default, Debug, From)]
    pub struct PublicKey(RawPublicKey);

    impl Into<PublicKeyBytes> for PublicKey {
        #[inline]
        fn into(self) -> PublicKeyBytes {
            PublicKeyBytes(self.as_raw().compress())
        }
    }

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
}
