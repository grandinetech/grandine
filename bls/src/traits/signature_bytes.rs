use core::{fmt::Debug, str::FromStr};
use ssz::{SszHash, SszRead, SszSize, SszWrite};

pub trait BlsSignatureBytes<C = ()>:
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
    + SszSize
    + SszRead<C>
    + SszWrite
    + SszHash
{
    fn empty() -> Self;
    fn is_empty(self) -> bool;
}
