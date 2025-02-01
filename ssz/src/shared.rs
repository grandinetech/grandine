// TODO(32-bit support): Review all uses of `typenum::Unsigned::USIZE`.

// <https://notes.ethereum.org/ruKvDXl6QOW3gnqVYb8ezA> describes some of the validations that SSZ
// decoders need to perform.
//
// The `#[inline]` attributes produce a measurable speedup.

use core::ops::Range;

use itertools::{Either, Itertools as _};
use try_from_iterator::TryFromIterator;
use typenum::Unsigned;

use crate::{
    consts::{Offset, BYTES_PER_LENGTH_OFFSET},
    error::{IndexError, ReadError, WriteError},
    iter::ExactSize,
    porcelain::{SszRead, SszReadDefault as _, SszWrite},
    size::Size,
};

// TODO(32-bit support): Rethink the new code.
//                       Try to avoid referring to `Unsigned::U64` or `Unsigned::U128`.
// The associated constants in `typenum::Unsigned` are computed using the `<<` operator,
// which silently discards set bits that are shifted out of range.
pub const fn saturating_usize<N: Unsigned>() -> usize {
    if N::U64 > usize::MAX as u64 {
        usize::MAX
    } else {
        N::USIZE
    }
}

#[inline]
pub fn subslice(bytes: &[u8], range: Range<usize>) -> Result<&[u8], ReadError> {
    let Range { start, end } = range;
    bytes
        .get(start..end)
        .ok_or(ReadError::OffsetsNotValidSubsliceBounds {
            start,
            end,
            length: bytes.len(),
        })
}

#[inline]
pub fn read_offset_unchecked(bytes: &[u8]) -> Result<usize, ReadError> {
    let offset = Offset::from_ssz_default(bytes)?;
    offset
        .try_into()
        .map_err(|_| ReadError::OffsetDoesNotFitInUsize { offset })
}

#[inline]
pub fn write_offset(bytes: &mut [u8], destination: usize, offset: usize) -> Result<(), WriteError> {
    let offset = Offset::try_from(offset).map_err(|_| WriteError::OffsetTooBig { offset })?;
    offset.write_fixed(&mut bytes[destination..destination + BYTES_PER_LENGTH_OFFSET]);
    Ok(())
}

// TODO(feature/optimize-ssz-decoding): Rewrite `read_vector` the same way as `read_list`.
#[inline]
pub fn read_vector<'all, C, T: SszRead<C> + 'all, N: Unsigned>(
    context: &'all C,
    bytes: &'all [u8],
) -> Result<impl Iterator<Item = Result<T, ReadError>> + 'all, ReadError> {
    if let Size::Fixed { size } = T::SIZE {
        let results = bytes
            .chunks(size)
            .map(|chunk| T::from_ssz_unchecked(context, chunk));

        Ok(Either::Left(results))
    } else {
        let first_offset_subslice = subslice(bytes, 0..BYTES_PER_LENGTH_OFFSET)?;
        let expected = N::USIZE * BYTES_PER_LENGTH_OFFSET;
        let actual = read_offset_unchecked(first_offset_subslice)?;

        if actual != expected {
            return Err(ReadError::VectorFirstOffsetMismatch { expected, actual });
        }

        let results = read_variable_elements(context, bytes, expected)?;

        Ok(Either::Right(results))
    }
}

#[inline]
pub fn write_fixed_vector<T: SszWrite>(bytes: &mut [u8], elements: impl IntoIterator<Item = T>) {
    let size = T::SIZE.fixed_part();

    for (element, subslice) in elements.into_iter().zip(bytes.chunks_exact_mut(size)) {
        element.write_fixed(subslice);
    }
}

#[inline]
pub fn write_variable_vector<N: Unsigned>(
    bytes: &mut Vec<u8>,
    elements: impl IntoIterator<Item = impl SszWrite>,
) -> Result<(), WriteError> {
    write_list(bytes, ExactSize::new(elements.into_iter(), N::USIZE))
}

#[inline]
pub fn read_list<C, T: SszRead<C>, L: TryFromIterator<T, Error: Into<ReadError>> + Default>(
    maximum: usize,
    context: &C,
    bytes: &[u8],
) -> Result<L, ReadError> {
    // TODO(feature/optimize-ssz-decoding): Is the early return needed for correctness?
    if bytes.is_empty() {
        return Ok(L::default());
    }

    if let Size::Fixed { size } = T::SIZE {
        if bytes.len() % size != 0 {
            return Err(ReadError::ListSizeNotMultiple {
                list: bytes.len(),
                element: size,
            });
        }

        // TODO(feature/optimize-ssz-decoding): Benchmark without the early validation if that makes sense.
        let actual = bytes.len() / size;

        if actual > maximum {
            return Err(ReadError::ListTooLong { maximum, actual });
        }

        bytes
            .chunks_exact(size)
            .map(|chunk| T::from_ssz_unchecked(context, chunk))
            .process_results(|elements| L::try_from_iter(elements))?
            .map_err(Into::into)
    } else {
        let first_offset_subslice = subslice(bytes, 0..BYTES_PER_LENGTH_OFFSET)?;
        let first_offset = read_offset_unchecked(first_offset_subslice)?;

        if first_offset % BYTES_PER_LENGTH_OFFSET != 0 {
            return Err(ReadError::ListFirstOffsetUnaligned { first_offset });
        }

        // TODO(feature/optimize-ssz-decoding): Benchmark without the early validation if that makes sense.
        let actual = first_offset / BYTES_PER_LENGTH_OFFSET;

        if actual > maximum {
            return Err(ReadError::ListTooLong { maximum, actual });
        }

        read_variable_elements(context, bytes, first_offset)?
            .process_results(|elements| L::try_from_iter(elements))?
            .map_err(Into::into)
    }
}

#[inline]
pub fn write_list<T: SszWrite>(
    bytes: &mut Vec<u8>,
    elements: impl IntoIterator<IntoIter = impl ExactSizeIterator<Item = T>>,
) -> Result<(), WriteError> {
    let elements = elements.into_iter();
    let element_count = elements.len();
    let length_before = bytes.len();

    if let Size::Fixed { size } = T::SIZE {
        let length_after = length_before + element_count * size;

        bytes.resize(length_after, 0);

        let new_bytes = &mut bytes[length_before..];

        for (element, subslice) in elements.zip(new_bytes.chunks_exact_mut(size)) {
            element.write_fixed(subslice);
        }
    } else {
        let length_with_offsets = length_before + element_count * BYTES_PER_LENGTH_OFFSET;

        bytes.resize(length_with_offsets, 0);

        for (index, element) in elements.enumerate() {
            let destination = length_before + index * BYTES_PER_LENGTH_OFFSET;
            let offset = bytes.len() - length_before;

            write_offset(bytes, destination, offset)?;

            element.write_variable(bytes)?;
        }
    }

    Ok(())
}

pub fn validate_index(length: usize, index: u64) -> Result<usize, IndexError> {
    // Converting `index` to `usize` is safe, but it makes elements past `u32::MAX` inaccessible on
    // 32 bit machines. Persistent collections may have more than that due to structural sharing.
    // Indexing with a `u64` directly would require some intrusive changes to the rest of the crate.
    let index = index
        .try_into()
        .map_err(|_| IndexError::DoesNotFitInUsize { index })?;

    if length <= index {
        return Err(IndexError::OutOfBounds { length, index });
    }

    Ok(index)
}

#[inline]
fn read_variable_elements<'all, C, T: SszRead<C>>(
    context: &'all C,
    bytes: &'all [u8],
    first_offset: usize,
) -> Result<impl Iterator<Item = Result<T, ReadError>> + 'all, ReadError> {
    let results = subslice(bytes, 0..first_offset)?
        .chunks_exact(BYTES_PER_LENGTH_OFFSET)
        .map(read_offset_unchecked)
        .chain(core::iter::once(Ok(bytes.len())))
        .tuple_windows()
        .map(move |(start_result, end_result)| {
            let start = start_result?;
            let end = end_result?;
            let subslice = subslice(bytes, start..end)?;
            T::from_ssz(context, subslice)
        });

    Ok(results)
}
