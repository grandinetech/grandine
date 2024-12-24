use core::{fmt::Debug, hash::Hash};

use super::{
    PublicKey as PublicKeyTrait, SecretKeyBytes as SecretKeyBytesTrait, Signature as SignatureTrait,
};

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
///    use core::fmt::Debug;
///
///    struct SecretKeyImpl;
///
///    impl Debug for SecretKeyImpl {
///        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///            write!(f, "[REDACTED]")
///        }
///    }
///    ```
pub trait SecretKey<const N: usize>: Debug + PartialEq + Eq + Hash {
    type SecretKeyBytes: SecretKeyBytesTrait<N>;
    type PublicKey: PublicKeyTrait;
    type Signature: SignatureTrait;

    fn to_public_key(&self) -> Self::PublicKey;
    fn sign(&self, message: impl AsRef<[u8]>) -> Self::Signature;
    fn to_bytes(&self) -> Self::SecretKeyBytes;
}
