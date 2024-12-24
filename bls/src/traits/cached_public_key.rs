use core::fmt::Debug;
use serde::{Deserialize, Serialize};
use ssz::{SszHash, SszRead, SszSize, SszWrite};

use crate::error::Error;

use super::{PublicKey as PublicKeyTrait, PublicKeyBytes as PublicKeyBytesTrait};

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
