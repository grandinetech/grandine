use core::{fmt::Debug, hash::Hash};

use super::{
    PublicKey as PublicKeyTrait, SecretKeyBytes as SecretKeyBytesTrait, Signature as SignatureTrait,
};

pub trait SecretKey<const N: usize>: Debug + PartialEq + Eq + Hash {
    type SecretKeyBytes: SecretKeyBytesTrait<N>;
    type PublicKey: PublicKeyTrait;
    type Signature: SignatureTrait;

    fn to_public_key(&self) -> Self::PublicKey;
    fn sign(&self, message: impl AsRef<[u8]>) -> Self::Signature;
    fn to_bytes(&self) -> Self::SecretKeyBytes;
}

#[expect(clippy::module_name_repetitions)]
#[macro_export]
macro_rules! impl_secret_key {
    ($trait:ty, $name:ident, $raw:ty, $skb:ty, $pk:ty, $sig:ty, $to_bytes:expr) => {
        #[derive(derive_more::Debug)]
        // Inspired by `DebugSecret` from the `secrecy` crate.
        #[debug("[REDACTED]")]
        pub struct $name($raw);


        // Prevent `SecretKey` from implementing some traits to avoid leaking secret keys.
        // This could also be done by wrapping it in `secrecy::Secret`.
        static_assertions::assert_not_impl_any! {
            $name:
            Clone, Copy, core::ops::Deref, ToOwned,
            core::fmt::Binary, core::fmt::Display, core::fmt::LowerExp, core::fmt::LowerHex, core::fmt::Octal,
            core::fmt::Pointer, core::fmt::UpperExp, core::fmt::UpperHex,
            serde::Serialize, ssz::SszHash, ssz::SszWrite,
        }

        impl PartialEq for $name {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                ($to_bytes)(self.as_raw()) == ($to_bytes)(other.as_raw())
            }
        }

        impl Eq for $name  {}

        impl core::hash::Hash for $name {
            fn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {
                ($to_bytes)(self.as_raw()).hash(hasher)
            }
        }

        impl $name {
            const fn as_raw(&self) -> &$raw {
                &self.0
            }
        }
    };
}
