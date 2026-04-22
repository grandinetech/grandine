use ssz::ByteList;

use crate::preset::Preset;

pub type BuilderIndex = u64;
pub type PayloadStatus = u8;
pub type BlockAccessList<P> = ByteList<<P as Preset>::MaxBytesPerTransaction>;
