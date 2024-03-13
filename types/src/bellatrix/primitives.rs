use ssz::{ByteList, Uint256};

use crate::preset::Preset;

pub type Difficulty = Uint256;
pub type Gas = u64;
pub type Transaction<P> = ByteList<<P as Preset>::MaxBytesPerTransaction>;
pub type Wei = Uint256;
