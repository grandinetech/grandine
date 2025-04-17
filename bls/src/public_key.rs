use core::fmt::Debug;

use derive_more::derive::From;

use crate::{backend::{backend, Backend}, error::Error, public_key_bytes::PublicKeyBytes};

pub trait PublicKeyTrait:
    Clone + Copy + PartialEq + Eq + Default + Debug + TryFrom<PublicKeyBytes>
{
    fn aggregate_in_place(&mut self, other: Self);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, From)]
pub enum PublicKey {
    #[cfg(feature = "blst")]
    Blst(blst::PublicKey),

    #[cfg(feature = "zkcrypto")]
    Zkcrypto(zkcrypto::PublicKey)
}

impl Into<PublicKeyBytes> for PublicKey {
    #[inline]
    fn into(self) -> PublicKeyBytes {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(v) => v.into(),

            #[cfg(feature = "zkcrypto")]
            Self::Zkcrypto(v) => v.into(),
        }
    }
}

impl Default for PublicKey {
    #[inline]
    fn default() -> Self {
        match backend() {
            #[cfg(feature = "blst")]
            Backend::Blst => Self::Blst(blst::PublicKey::default()),

            #[cfg(feature = "zkcrypto")]
            Backend::Zkcrypto => Self::Zkcrypto(zkcrypto::PublicKey::default()),
        }
    }
}

impl TryFrom<PublicKeyBytes> for PublicKey {
    type Error = Error;

    #[inline]
    fn try_from(bytes: PublicKeyBytes) -> Result<Self, Self::Error> {
        match backend() {
            #[cfg(feature = "blst")]
            Backend::Blst => Ok(PublicKey::Blst(blst::PublicKey::try_from(bytes)?)),

            #[cfg(feature = "zkcrypto")]
            Backend::Zkcrypto => Ok(PublicKey::Zkcrypto(zkcrypto::PublicKey::try_from(bytes)?)),
        }
    }
}

#[allow(irrefutable_let_patterns)]
impl PublicKeyTrait for PublicKey {
    #[inline]
    fn aggregate_in_place(&mut self, other: Self) {
        match self {
            #[cfg(feature = "blst")]
            PublicKey::Blst(v) => v.aggregate_in_place(other.as_blst()),

            #[cfg(feature = "zkcrypto")]
            PublicKey::Zkcrypto(v) => v.aggregate_in_place(other.as_zkcrypto()),
        }
    }
}

impl PublicKey {
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

    #[cfg(feature = "blst")]
    pub(crate) fn as_blst(self) -> blst::PublicKey {
        *self.as_blst_ref()
    }

    #[cfg(feature = "blst")]
    pub(crate) fn as_blst_ref(&self) -> &blst::PublicKey {
        match self {
            Self::Blst(v) => v,

            _ => panic!("mixed backends"),
        }
    }

    #[cfg(feature = "zkcrypto")]
    pub(crate) fn as_zkcrypto(self) -> zkcrypto::PublicKey {
        *self.as_zkcrypto_ref()
    }
    
    #[cfg(feature = "zkcrypto")]
    pub(crate) fn as_zkcrypto_ref(&self) -> &zkcrypto::PublicKey {
        match self {
            Self::Zkcrypto(v) => v,
        
            _ => panic!("mixed backends"),
        }
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

#[cfg(feature = "zkcrypto")]
pub(crate) mod zkcrypto {
    use bls12_381::{G1Affine, G1Projective};
    use derive_more::From;

    use crate::{Error, PublicKeyBytes};

    use super::PublicKeyTrait;

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
        fn aggregate_in_place(&mut self, other: Self) {
            self.0 = self.as_raw().add(other.as_raw());
        }
    }

    impl PublicKey {
        pub(crate) const fn as_raw(&self) -> &G1Projective {
            &self.0
        }
    }

    impl Into<PublicKeyBytes> for PublicKey {
        fn into(self) -> PublicKeyBytes {
            let affine: G1Affine = self.as_raw().into();

            PublicKeyBytes(affine.to_compressed())
        }
    }
}