use super::{
    PublicKey as PublicKeyTrait, PublicKeyBytes as PublicKeyBytesTrait, Signature as SignatureTrait,
};
use core::{fmt::Debug, hash::Hash};

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
pub trait SecretKey<C, const N: usize>: PartialEq + Eq + Hash + Debug {
    type PublicKeyBytes: PublicKeyBytesTrait<C>;
    type PublicKey: PublicKeyTrait<C>;
    type Signature: SignatureTrait<C, N>;

    fn to_public_key(&self) -> Self::PublicKey;
    fn sign(&self, message: impl AsRef<[u8]>) -> Self::Signature;
    fn to_bytes(&self) -> Self::PublicKeyBytes;
}
