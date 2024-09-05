use core::{
    fmt::Debug,
    num::NonZeroU64,
    ops::{Index as _, Rem as _},
};

use anyhow::Result;
use bit_field::BitArray as _;
use itertools::izip;
use tap::TryConv as _;
use types::{phase0::primitives::H256, preset::Preset};

const BITS_PER_HASH: usize = H256::len_bytes() * 8;

// Originally based on:
// <https://github.com/protolambda/eth2-shuffle/tree/fd840f1036c1f8f6d7625ffe6ff4d9c60f942876>
// See the following for an explanation of the algorithm:
// - <https://github.com/protolambda/eth2-docs/tree/de65f38857f1e27ffb6f25107d61e795cf1a5ad7#shuffling>
// - <https://github.com/protolambda/eth2-impl-design/tree/782b1d2da088e4ebbbea227cfa0a8752399239fb#shuffling>
pub fn shuffle_slice<P: Preset, T>(slice: &mut [T], seed: H256) -> Result<()> {
    let Some(length) = slice.len().try_into().map(NonZeroU64::new)? else {
        return Ok(());
    };

    for round in (0..P::SHUFFLE_ROUND_COUNT).rev() {
        let pivot = compute_pivot(seed, round, length)
            .try_conv::<usize>()
            .expect("remainder of division by number that fits in usize also fits in usize");

        let midpoint = pivot + 1;
        let (low, high) = slice.split_at_mut(midpoint);

        // Naively parallelizing these with Rayon causes deadlocks due to the lock held in
        // `OnceCell::get_or_init` higher on the stack and the way Rayon runs tasks. See:
        // - <https://github.com/rayon-rs/rayon/issues/592>
        // - <https://github.com/rayon-rs/rayon/pull/765>
        // It could be worked around by spawning a scoped thread and submitting tasks to a
        // separate thread pool. A proper solution would require changes to Rayon and `once_cell`.
        swap_around_mirror(seed, round, low, 0);
        swap_around_mirror(seed, round, high, midpoint);
    }

    Ok(())
}

fn swap_around_mirror<T>(seed: H256, round: u8, slice: &mut [T], offset: usize) {
    // `[T]::chunks_exact_mut` and `[T]::rchunks_exact_mut` are needed for full performance.
    // `[T]::as_chunks_mut` and `[T]::as_rchunks_mut` could simplify this when stabilized.

    let mirror = slice.len() / 2;
    let offset_mirror = offset + mirror;
    let offset_length = offset + slice.len();
    let trailing = mirror.min(offset_length % BITS_PER_HASH);
    let leading = (mirror - trailing) % BITS_PER_HASH;

    let (low, mut high) = slice.split_at_mut(mirror);

    if low.len() < high.len() {
        high = &mut high[1..];
    }

    assert_eq!(low.len(), mirror);
    assert_eq!(high.len(), mirror);

    if trailing > 0 {
        let source = compute_source(seed, round, offset_length / BITS_PER_HASH);
        let bit_indices = (0..offset_length % BITS_PER_HASH).rev();
        let low_elements = low[..trailing].iter_mut();
        let high_elements = high[mirror - trailing..].iter_mut().rev();

        swap_using_source(source, bit_indices, low_elements, high_elements);
    }

    for (offset_chunk_index, low_chunk, high_chunk) in izip!(
        (0..offset_length / BITS_PER_HASH).rev(),
        low[trailing..].chunks_exact_mut(BITS_PER_HASH),
        high[..mirror - trailing].rchunks_exact_mut(BITS_PER_HASH),
    ) {
        let source = compute_source(seed, round, offset_chunk_index);
        let bit_indices = 0..BITS_PER_HASH;
        let low_elements = low_chunk.iter_mut().rev();
        let high_elements = high_chunk;

        swap_using_source(source, bit_indices, low_elements, high_elements);
    }

    if leading > 0 {
        let source = compute_source(seed, round, offset_mirror / BITS_PER_HASH);
        let bit_indices = (0..BITS_PER_HASH).rev();
        let low_elements = low[mirror - leading..].iter_mut();
        let high_elements = high[..leading].iter_mut().rev();

        swap_using_source(source, bit_indices, low_elements, high_elements);
    }
}

fn swap_using_source<'slice, T: 'slice>(
    source: H256,
    bit_indices: impl IntoIterator<Item = usize>,
    low: impl IntoIterator<Item = &'slice mut T>,
    high: impl IntoIterator<Item = &'slice mut T>,
) {
    for (bit_index, index, flip) in izip!(bit_indices, low, high) {
        let bit = source.as_bytes().get_bit(bit_index);

        if bit {
            core::mem::swap(index, flip);
        }
    }
}

#[must_use]
pub fn shuffle_single<P: Preset>(mut index: u64, index_count: NonZeroU64, seed: H256) -> u64 {
    assert!(index < index_count.get());

    for round in 0..P::SHUFFLE_ROUND_COUNT {
        let pivot = compute_pivot(seed, round, index_count);
        let flip = (pivot + index_count.get() - index) % index_count;
        let position = index.max(flip);
        let source = compute_source(seed, round, position / BITS_PER_HASH as u64);
        let bit_index = position.to_le_bytes()[0].into();
        let bit = source.as_bytes().get_bit(bit_index);

        if bit {
            index = flip;
        }
    }

    index
}

fn compute_pivot(seed: H256, round: u8, index_count: NonZeroU64) -> u64 {
    hashing::hash_256_8(seed, round)
        .index(..size_of::<u64>())
        .try_into()
        .map(u64::from_le_bytes)
        .expect("slice has the same size as u64")
        .rem(index_count)
}

fn compute_source(
    seed: H256,
    round: u8,
    position_window: impl TryInto<u64, Error = impl Debug>,
) -> H256 {
    // Truncate to match the behavior of `compute_shuffled_index` in `consensus-specs`.
    #[allow(clippy::cast_possible_truncation)]
    let position_window = position_window
        .try_into()
        .expect("position_window should fit in u64") as u32;

    hashing::hash_256_8_32(seed, round, position_window)
}

// The edge cases with 0 and 1 elements are covered by `consensus-spec-tests`.
// In fact, there are 30 test cases for each of them.
#[cfg(test)]
mod spec_tests {
    use itertools::Itertools as _;
    use serde::Deserialize;
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::preset::{Mainnet, Minimal};

    use super::*;

    #[allow(clippy::struct_field_names)]
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Mapping {
        seed: H256,
        count: u64,
        mapping: Vec<u64>,
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/phase0/shuffling/*/*/*")]
    fn mainnet(case: Case) {
        run_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/phase0/shuffling/*/*/*")]
    fn minimal(case: Case) {
        run_case::<Minimal>(case);
    }

    fn run_case<P: Preset>(case: Case) {
        let Mapping {
            seed,
            count,
            mapping,
        } = case.yaml("mapping");
        let mut actual_mapping = (0..count).collect_vec();

        shuffle_slice::<P, _>(&mut actual_mapping, seed)
            .expect("length of mapping fits in u64 because count is u64");

        assert_eq!(actual_mapping, mapping);
    }
}
