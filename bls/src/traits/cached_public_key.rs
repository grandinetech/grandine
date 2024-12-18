use core::fmt::Debug;
use serde::{Deserialize, Serialize};
use ssz::{SszHash, SszRead, SszSize, SszWrite};

use super::{PublicKey as PublicKeyTrait, PublicKeyBytes as PublicKeyBytesTrait};

pub trait CachedPublicKey<C>:
    Default
    + Debug
    + Clone
    + PartialEq
    + Eq
    + Deserialize<'static>
    + Serialize
    + SszSize
    + SszRead<C>
    + SszWrite
    + SszHash
{
    type PublicKeyBytes: PublicKeyBytesTrait<C>;
    type PublicKey: PublicKeyTrait<C>;

    fn from_bytes(bytes: Self::PublicKeyBytes) -> Self;
    fn from_public_key(public_key: Self::PublicKey) -> Self;
    fn as_bytes(&self) -> &Self::PublicKeyBytes;
    fn to_bytes(&self) -> Self::PublicKeyBytes;
    fn decompress(&self) -> Result<&Self::PublicKey, crate::Error>;
}
