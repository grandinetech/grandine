use core::{fmt::Debug, str::FromStr};
use hex::FromHex;
use ssz::{SszHash, SszRead, SszSize, SszUnify, SszWrite};

use super::PublicKey as PublicKeyTrait;

pub const COMPRESSED_SIZE: usize = 48;

// Both `zkcrypto` and `blst` use the same decompressed public key length,
// but other implementations may differ:
// https://github.com/lovesh/signature-schemes/issues/13#issue-518231751
// This should ideally be an associated constant in the `PublicKey` trait,
// but that requires `generic_const_exprs` to be stable.
pub const DECOMPRESSED_SIZE: usize = 96;

pub trait PublicKeyBytes<C = ()>:
    AsRef<[u8]>
    + AsMut<[u8]>
    + Copy
    + Clone
    + Send
    + Sync
    + Default
    + PartialEq
    + Eq
    + Debug
    + FromStr
    + FromHex
    + From<Self::PublicKey>
    + SszSize
    + SszRead<C>
    + SszWrite
    + SszHash
    + SszUnify
{
    type PublicKey: PublicKeyTrait;
}

#[expect(clippy::module_name_repetitions)]
#[macro_export]
macro_rules! impl_public_key_bytes {
    ($name:ident) => {
        impl hex::FromHex for $name {
            type Error = <[u8; $crate::traits::COMPRESSED_SIZE] as hex::FromHex>::Error;

            fn from_hex<T: AsRef<[u8]>>(digits: T) -> Result<Self, Self::Error> {
                hex::FromHex::from_hex(digits).map(Self)
            }
        }

        impl ssz::SszSize for $name {
            const SIZE: ssz::Size = ssz::Size::Fixed {
                size: $crate::traits::COMPRESSED_SIZE,
            };
        }

        impl<C> ssz::SszRead<C> for $name {
            #[inline]
            fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ssz::ReadError> {
                Ok(Self::from_slice(bytes))
            }
        }

        impl ssz::SszWrite for $name {
            #[inline]
            fn write_fixed(&self, bytes: &mut [u8]) {
                bytes.copy_from_slice(self.as_bytes());
            }
        }

        impl ssz::SszHash for $name {
            type PackingFactor = typenum::U1;

            #[inline]
            fn hash_tree_root(&self) -> ssz::H256 {
                ssz::MerkleTree::<ssz::BytesToDepth<typenum::U48>>::merkleize_bytes(self)
            }
        }

        impl $crate::ssz::SszUnify for $name {
            #[inline]
            fn unify(&mut self, other: &Self) -> bool {
                self == other
            }
        }

        impl $crate::traits::PublicKeyBytes for $name {
            type PublicKey = PublicKey;
        }
    };
}
