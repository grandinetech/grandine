use core::{fmt::Debug, str::FromStr};
use hex::FromHex;
use ssz::{SszHash, SszRead, SszSize, SszWrite};

pub trait PublicKeyBytes<C>:
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
    + SszSize
    + SszRead<C>
    + SszWrite
    + SszHash
{
}
