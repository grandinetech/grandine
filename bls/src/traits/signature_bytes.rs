use core::{fmt::Debug, str::FromStr};
use hex::FromHex;
use ssz::{SszHash, SszRead, SszSize, SszWrite};

pub trait SignatureBytes<C, const N: usize>:
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
    fn empty() -> Self;
    fn is_empty(self) -> bool;
}
