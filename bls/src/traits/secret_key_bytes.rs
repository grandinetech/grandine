use hex::FromHex;
use serde::Deserialize;
use ssz::{SszRead, SszSize, SszWrite};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub trait SecretKeyBytes<const N: usize, C = ()>:
    Default
    + AsRef<[u8]>
    + AsMut<[u8]>
    + From<[u8; N]>
    + Zeroize
    + ZeroizeOnDrop
    + Deserialize<'static>
    + FromHex
    + SszSize
    + SszRead<C>
    + SszWrite
{
}

#[macro_export]
macro_rules! impl_secret_key_bytes {
    ($name:ident, $size:expr) => {
        #[derive(
            Default,
            derive_more::AsRef,
            derive_more::AsMut,
            derive_more::From,
            zeroize::Zeroize,
            zeroize::ZeroizeOnDrop,
            serde::Deserialize,
        )]
        #[as_ref(forward)]
        #[as_mut(forward)]
        #[serde(transparent)]
        pub struct $name {
            #[serde(with = "serde_utils::prefixed_hex_or_bytes_array")]
            pub(crate) bytes: [u8; $size],
        }

        static_assertions::assert_not_impl_any! {
            $name:
            Clone, Copy, std::ops::Deref, std::borrow::ToOwned,
            std::fmt::Debug, std::fmt::Binary, std::fmt::Display,
            std::fmt::LowerExp, std::fmt::LowerHex, std::fmt::Octal,
            std::fmt::Pointer, std::fmt::UpperExp, std::fmt::UpperHex,
            serde::Serialize, ssz::SszHash,
        }

        impl hex::FromHex for $name {
            type Error = <[u8; $size] as hex::FromHex>::Error;

            fn from_hex<T: AsRef<[u8]>>(digits: T) -> Result<Self, Self::Error> {
                let bytes = hex::FromHex::from_hex(digits)?;
                Ok(Self { bytes })
            }
        }

        impl ssz::SszSize for $name {
            const SIZE: ssz::Size = ssz::Size::Fixed { size: $size };
        }

        impl<C> ssz::SszRead<C> for $name {
            #[inline]
            fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ssz::ReadError> {
                let mut secret_key = Self::default();
                secret_key.bytes.copy_from_slice(bytes);
                Ok(secret_key)
            }
        }

        impl ssz::SszWrite for $name {
            #[inline]
            fn write_fixed(&self, bytes: &mut [u8]) {
                bytes.copy_from_slice(&self.bytes);
            }
        }

        impl $crate::traits::SecretKeyBytes<$size> for $name {}
    };
}
