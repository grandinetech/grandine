use core::num::NonZeroUsize;

use byteorder::LittleEndian;
use ethereum_types::H256;
use nonzero_ext::nonzero;

pub const BITS_PER_BYTE: NonZeroUsize = nonzero!(8_usize);
pub const BYTES_PER_CHUNK: usize = H256::len_bytes();
pub const BYTES_PER_LENGTH_OFFSET: NonZeroUsize = nonzero!(size_of::<Offset>());

pub type Endianness = LittleEndian;
pub type Offset = u32;
