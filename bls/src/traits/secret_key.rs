use core::{fmt::Debug, hash::Hash};

use super::{BlsPublicKey, BlsSecretKeyBytes, BlsSignature};

/// Secret key trait.
///
/// # Safety
/// Implementors MUST:
/// 1. NOT implement:
///    - Clone, Copy, Deref, ToOwned
///    - Display and other formatting traits
///    - Serialize, SszHash, SszWrite
///    Use `assert_not_impl_any!` macro to enforce this
///
/// 2. Implement Debug to only show "[REDACTED]":
///    ```rust
///    #[derive(Debug)]
///    #[debug("[REDACTED]")]
///    ```
pub trait BlsSecretKey<const N: usize>: Debug + PartialEq + Eq + Hash {
    type SecretKeyBytes: BlsSecretKeyBytes<N>;
    type PublicKey: BlsPublicKey;
    type Signature: BlsSignature;

    fn to_public_key(&self) -> Self::PublicKey;
    fn sign(&self, message: impl AsRef<[u8]>) -> Self::Signature;
    fn to_bytes(&self) -> Self::SecretKeyBytes;
}
