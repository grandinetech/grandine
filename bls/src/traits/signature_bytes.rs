use core::{fmt::Debug, str::FromStr};
use ssz::{SszHash, SszRead, SszSize, SszWrite};
use typenum::U96;

pub type CompressedSize = U96;

pub trait SignatureBytes<C = ()>:
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
    + SszSize
    + SszRead<C>
    + SszWrite
    + SszHash
{
    fn empty() -> Self;
    fn is_empty(self) -> bool;
}

#[expect(clippy::module_name_repetitions)]
#[macro_export]
macro_rules! impl_signature_bytes {
    ($trait:ident, $name:ident, $size:expr) => {
        construct_fixed_hash! {
            #[derive(derive_more::AsRef)]
            pub struct $name($size);
        }

        impl_fixed_hash_serde!($name, $size);

        impl ssz::SszSize for $name {
            const SIZE: ssz::Size = ssz::Size::Fixed { size: $size };
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
                ssz::MerkleTree::<ssz::BytesToDepth<typenum::U96>>::merkleize_bytes(self)
            }
        }

        impl $trait for $name {
            #[inline]
            fn empty() -> Self {
                let mut bytes = Self::zero();
                bytes.as_mut()[0] = 0xc0;
                bytes
            }

            #[inline]
            fn is_empty(self) -> bool {
                self == Self::empty()
            }
        }
    };
}
