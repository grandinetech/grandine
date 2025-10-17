use arithmetic::{NonZeroExt as _, UsizeExt as _};
use bit_field::BitField as _;
use ethereum_types::H256;
use generic_array::ArrayLength;
use hashing::ZERO_HASHES;
use typenum::{IsGreaterOrEqual, NonZero, PowerOfTwo, True};

use crate::{porcelain::SszHash, type_level::MinimumBundleSize};

/// Trait for [type-level numbers] that may be used as a bundle size for persistent collections.
///
/// To save resources, values in persistent collections are stored in contiguous regions of memory
/// called bundles. The size of a bundle is the maximum number of values that fit in it.
///
/// To make hashing work correctly, a bundle must be exactly large enough to fill some power of 2 of
/// [`BYTES_PER_CHUNK`]-sized chunks without padding. The minimum size of a bundle for elements of
/// type `T` is equal to [`T::PackingFactor`] and may be looked up using [`MinimumBundleSize`].
///
/// Types whose chunks are not produced by hashing should be stored in bundles large enough to fill
/// at least 2 chunks to avoid wasting memory on redundant hashes. The minimum size of such a bundle
/// may be calculated using [`UnhashedBundleSize`].
///
/// Larger bundles may be used to lower memory usage at the cost of higher CPU usage.
///
/// Bundles were originally named "packs".
/// The new name was chosen to avoid confusion with SSZ packing.
///
/// [`BYTES_PER_CHUNK`]: crate::consts::BYTES_PER_CHUNK
/// [`UnhashedBundleSize`]: crate::type_level::UnhashedBundleSize
///
/// [type-level numbers]: typenum
/// [`T::PackingFactor`]: SszHash::PackingFactor
pub trait BundleSize<T>: ArrayLength<T> + NonZero {
    #[must_use]
    fn depth_of_length(length: usize) -> u8 {
        length.ilog2_ceil().saturating_sub(Self::ilog2())
    }

    #[must_use]
    fn index_of_bundle(index: usize) -> usize {
        index.get_bits(usize::from(Self::ilog2())..)
    }

    #[must_use]
    fn index_in_bundle(index: usize) -> usize {
        // `BitField::get_bits` panics if the range passed to it is empty.
        match Self::ilog2() {
            0 => 0,
            nonzero => index.get_bits(..usize::from(nonzero)),
        }
    }

    #[must_use]
    fn zero_hash(height: u8) -> H256
    where
        T: SszHash,
    {
        let chunk_height = height + Self::ilog2() - T::PackingFactor::ilog2();
        ZERO_HASHES[usize::from(chunk_height)]
    }
}

impl<T, B> BundleSize<T> for B
where
    T: SszHash,
    Self: ArrayLength<T>
        + NonZero
        + PowerOfTwo
        + IsGreaterOrEqual<MinimumBundleSize<T>, Output = True>,
{
}
