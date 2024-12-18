use hex::FromHex;
use serde::Deserialize;
use ssz::{SszRead, SszSize, SszWrite};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret key bytes trait.
///
/// # Safety
/// Implementors MUST:
/// 1. NOT implement:
///    - Clone, Copy, Deref
///    - Debug, Display, Binary, Hex formatting traits
///    - Serialize, SszHash
///    Use `assert_not_impl_any!` macro to enforce this
///
/// 2. Use these derive macros:
///    - `#[as_ref(forward)]`
///    - `#[as_mut(forward)]`
///    - `#[serde(transparent)]`
///
pub trait SecretKeyBytes<C, const N: usize>:
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
