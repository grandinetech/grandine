use thiserror::Error;

use crate::{
    consts::{Offset, BYTES_PER_LENGTH_OFFSET},
    uint256::Uint256,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum ReadError {
    #[error("expected fixed-size value of {expected} bytes, found {actual} bytes")]
    FixedSizeMismatch { expected: usize, actual: usize },
    #[error("offset {offset} does not fit in usize")]
    OffsetDoesNotFitInUsize { offset: Offset },
    #[error(
        "offsets {start} and {end} are not valid subslice bounds for slice of length {length}"
    )]
    OffsetsNotValidSubsliceBounds {
        start: usize,
        end: usize,
        length: usize,
    },
    #[error("expected boolean to be 0 or 1, found {value}")]
    BooleanInvalid { value: u8 },
    #[error(
        "expected vector of variable-size elements to have \
         {expected} as the first offset, found {actual}"
    )]
    VectorFirstOffsetMismatch { expected: usize, actual: usize },
    #[error("expected vector to have {expected} elements, found {actual} elements")]
    VectorSizeMismatch { expected: usize, actual: usize },
    #[error("first offset of list is not aligned")]
    ListFirstOffsetUnaligned { first_offset: usize },
    #[error("expected list to have no more than {maximum} elements, found {actual} elements")]
    ListTooLong { maximum: usize, actual: usize },
    #[error("expected bit vector to have no more than {expected} bits, found {actual} bits")]
    BitVectorTooLong { expected: usize, actual: usize },
    #[error("empty slice is not a valid bit list")]
    BitListEmptySlice,
    #[error("last byte of slice has no delimiting bit")]
    BitListNoDelimitingBit,
    #[error("expected bit list to have no more than {maximum} bits, found {actual} bits")]
    BitListTooLong { maximum: usize, actual: usize },
    #[error("expected container to have {expected} as the first offset, found {actual}")]
    ContainerFirstOffsetMismatch { expected: usize, actual: usize },
    // TODO(Grandine Team): Try replacing `ReadError::Custom` with something that can carry arbitrary
    //                      runtime data. An `Error` associated type in `SszRead` would be the most
    //                      flexible, but harder to use and would require a lot of changes. Using
    //                      `anyhow::Error` as the error type in SSZ traits would be easier, but may
    //                      worsen performance.
    #[error("{message}")]
    Custom { message: &'static str },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum WriteError {
    #[error("offset {offset} does not fit in {BYTES_PER_LENGTH_OFFSET} bytes")]
    OffsetTooBig { offset: usize },
}

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("index {index} does not fit in usize")]
    DoesNotFitInUsize { index: u64 },
    #[error("index {index} is out of bounds for collection of length {length}")]
    OutOfBounds { length: usize, index: usize },
}

#[derive(Debug, Error)]
pub enum PushError {
    #[error("list is full")]
    ListFull,
}

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("Uint256 {value} does not fit in u64")]
    Uint256DoesNotFitInU64 { value: Uint256 },
}
