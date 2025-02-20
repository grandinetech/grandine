use core::fmt::Debug;
use serde::{Deserialize, Serialize};
use ssz::{SszHash, SszRead, SszSize, SszWrite};

use crate::error::Error;

use super::{PublicKey as PublicKeyTrait, PublicKeyBytes as PublicKeyBytesTrait};

#[expect(clippy::trait_duplication_in_bounds)]
pub trait CachedPublicKey<C = ()>:
    Default
    + Debug
    + Deserialize<'static>
    + Serialize
    + Clone
    + From<Self::PublicKeyBytes>
    + From<Self::PublicKey>
    + PartialEq
    + Eq
    + SszSize
    + SszRead<C>
    + SszWrite
    + SszHash
{
    type PublicKeyBytes: PublicKeyBytesTrait;
    type PublicKey: PublicKeyTrait;

    fn new(bytes: Self::PublicKeyBytes, public_key: Self::PublicKey) -> Self;
    fn as_bytes(&self) -> &Self::PublicKeyBytes;
    fn to_bytes(&self) -> Self::PublicKeyBytes;
    fn decompress(&self) -> Result<&Self::PublicKey, Error>;
}

#[expect(clippy::module_name_repetitions)]
#[macro_export]
macro_rules! impl_cached_public_key {
    ($trait:ty, $name:ident, $pkb:ty, $pk:ty) => {
        #[derive(Default, derivative::Derivative, serde::Deserialize, serde::Serialize)]
        #[derivative(PartialEq, Eq)]
        #[serde(transparent)]
        pub struct $name {
            bytes: $pkb,
            #[derivative(PartialEq = "ignore")]
            #[serde(skip)]
            decompressed: once_cell::race::OnceBox<$pk>,
        }

        // `OnceBox` does not implement `Clone`.
        impl Clone for $name {
            fn clone(&self) -> Self {
                let Self {
                    bytes,
                    ref decompressed,
                } = *self;
                match decompressed.get().copied() {
                    Some(public_key) => Self::new(bytes, public_key),
                    None => bytes.into(),
                }
            }
        }

        impl From<$pkb> for $name {
            #[inline]
            fn from(bytes: $pkb) -> Self {
                Self {
                    bytes,
                    decompressed: once_cell::race::OnceBox::new(),
                }
            }
        }

        impl From<$pk> for $name {
            #[inline]
            fn from(public_key: $pk) -> Self {
                Self::new(public_key.into(), public_key)
            }
        }

        impl ssz::SszSize for $name {
            const SIZE: ssz::Size = <$pkb>::SIZE;
        }

        impl<C> ssz::SszRead<C> for $name {
            #[inline]
            fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ssz::ReadError> {
                Ok(Self {
                    bytes: <$pkb as ssz::SszReadDefault>::from_ssz_default(bytes)?,
                    decompressed: once_cell::race::OnceBox::new(),
                })
            }
        }

        impl ssz::SszWrite for $name {
            #[inline]
            fn write_fixed(&self, bytes: &mut [u8]) {
                self.bytes.write_fixed(bytes);
            }
        }

        impl ssz::SszHash for $name {
            type PackingFactor = <$pkb as ssz::SszHash>::PackingFactor;

            #[inline]
            fn hash_tree_root(&self) -> ssz::H256 {
                self.bytes.hash_tree_root()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("CachedPublicKey")
                    .field("bytes", &self.bytes)
                    .finish()
            }
        }

        impl $trait for $name {
            type PublicKeyBytes = $pkb;
            type PublicKey = $pk;

            fn new(bytes: Self::PublicKeyBytes, public_key: Self::PublicKey) -> Self {
                let decompressed = once_cell::race::OnceBox::new();
                decompressed
                    .set(Box::new(public_key))
                    .expect("decompressed is empty because OnceBox::new returns an empty cell");

                Self {
                    bytes,
                    decompressed,
                }
            }

            #[inline]
            fn as_bytes(&self) -> &Self::PublicKeyBytes {
                &self.bytes
            }

            #[inline]
            fn to_bytes(&self) -> Self::PublicKeyBytes {
                self.bytes
            }

            #[inline]
            fn decompress(&self) -> Result<&Self::PublicKey, bls_core::error::Error> {
                self.decompressed
                    .get_or_try_init(|| self.bytes.try_into().map(Box::new))
            }
        }
    };
}
