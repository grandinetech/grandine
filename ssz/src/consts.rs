use byteorder::LittleEndian;
use ethereum_types::H256;

pub const BITS_PER_BYTE: usize = 8;
pub const BYTES_PER_CHUNK: usize = H256::len_bytes();
pub const BYTES_PER_LENGTH_OFFSET: usize = size_of::<Offset>();

pub type Endianness = LittleEndian;
pub type Offset = u32;
