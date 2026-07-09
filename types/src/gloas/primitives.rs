use ssz::ProgressiveByteList;

use crate::preset::Preset;

pub type BuilderIndex = u64;
pub type PayloadStatus = u8;
pub type BlockAccessList<P> = ProgressiveByteList<<P as Preset>::MaxBytesPerTransaction>;
pub type Transaction<P> = ProgressiveByteList<<P as Preset>::MaxBytesPerTransaction>;
