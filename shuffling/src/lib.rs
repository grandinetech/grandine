use core::{
    fmt::Debug,
    num::NonZeroU64,
    ops::{Index as _, Rem as _},
};
#[cfg(not(target_os = "zkvm"))]
use std::{num::NonZeroUsize, sync::LazyLock};

use anyhow::Result;
use bit_field::BitArray as _;
use itertools::izip;
use nonzero_ext::nonzero;
use tap::TryConv as _;
use types::{phase0::primitives::H256, preset::Preset};

const BITS_PER_HASH: usize = H256::len_bytes() * 8;

#[cfg(not(target_os = "zkvm"))]
const MIN_CHUNKS_PER_WORKER: usize = 8;

#[cfg(not(target_os = "zkvm"))]
const MIN_PARALLEL_LEN: usize = 1 << 16;

#[cfg(not(target_os = "zkvm"))]
static POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    rayon::ThreadPoolBuilder::new()
        .num_threads(shuffle_threadpool_size())
        .thread_name(|index| format!("shuffle-{index}"))
        .build()
        .expect("shuffle thread pool should build with default settings")
});

#[cfg(not(target_os = "zkvm"))]
fn shuffle_threadpool_size() -> usize {
    use std::thread::available_parallelism;

    static SIZE: LazyLock<usize> =
        LazyLock::new(|| available_parallelism().map_or(1, NonZeroUsize::get));

    *SIZE
}

// Originally based on:
// <https://github.com/protolambda/eth2-shuffle/tree/fd840f1036c1f8f6d7625ffe6ff4d9c60f942876>
// See the following for an explanation of the algorithm:
// - <https://github.com/protolambda/eth2-docs/tree/de65f38857f1e27ffb6f25107d61e795cf1a5ad7#shuffling>
// - <https://github.com/protolambda/eth2-impl-design/tree/782b1d2da088e4ebbbea227cfa0a8752399239fb#shuffling>
pub fn shuffle_slice<P: Preset, T: Send>(slice: &mut [T], seed: H256) -> Result<()> {
    let Some(length) = slice.len().try_into().map(NonZeroU64::new)? else {
        return Ok(());
    };

    #[cfg(not(target_os = "zkvm"))]
    if slice.len() >= MIN_PARALLEL_LEN {
        POOL.install(|| shuffle_rounds::<P, T>(slice, seed, length, true));

        return Ok(());
    }

    shuffle_rounds::<P, T>(slice, seed, length, false);

    Ok(())
}

fn shuffle_rounds<P: Preset, T: Send>(
    slice: &mut [T],
    seed: H256,
    length: NonZeroU64,
    parallel: bool,
) {
    let worker_count = parallel
        .then(|| {
            #[cfg(not(target_os = "zkvm"))]
            return shuffle_threadpool_size();

            #[cfg(target_os = "zkvm")]
            return 1;
        })
        .unwrap_or(1);

    for round in (0..P::SHUFFLE_ROUND_COUNT).rev() {
        let pivot = compute_pivot(seed, round, length)
            .try_conv::<usize>()
            .expect("remainder of division by number that fits in usize also fits in usize");

        let midpoint = pivot.saturating_add(1);
        let (low, high) = slice.split_at_mut(midpoint);

        swap_around_mirror(seed, round, low, 0, worker_count);
        swap_around_mirror(seed, round, high, midpoint, worker_count);
    }
}

fn swap_around_mirror<T: Send>(
    seed: H256,
    round: u8,
    slice: &mut [T],
    offset: usize,
    worker_count: usize,
) {
    // `[T]::chunks_exact_mut` and `[T]::rchunks_exact_mut` are needed for full performance.
    // `[T]::as_chunks_mut` and `[T]::as_rchunks_mut` could simplify this when stabilized.

    let mirror = slice.len() / 2;
    let offset_mirror = offset.saturating_add(mirror);
    let offset_length = offset.saturating_add(slice.len());
    let trailing = mirror.min(offset_length % BITS_PER_HASH);
    let leading = mirror.saturating_sub(trailing) % BITS_PER_HASH;

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
        let high_elements = high[mirror.saturating_sub(trailing)..].iter_mut().rev();

        swap_using_source(source, bit_indices, low_elements, high_elements);
    }

    if leading > 0 {
        let source = compute_source(seed, round, offset_mirror / BITS_PER_HASH);
        let bit_indices = (0..BITS_PER_HASH).rev();
        let low_elements = low[mirror.saturating_sub(leading)..].iter_mut();
        let high_elements = high[..leading].iter_mut().rev();

        swap_using_source(source, bit_indices, low_elements, high_elements);
    }

    let chunk_count = mirror.saturating_sub(trailing) / BITS_PER_HASH;

    if chunk_count == 0 {
        return;
    }

    let low = &mut low[trailing..mirror.saturating_sub(leading)];
    let high = &mut high[leading..mirror.saturating_sub(trailing)];

    #[cfg(not(target_os = "zkvm"))]
    if worker_count.min(chunk_count / MIN_CHUNKS_PER_WORKER) > 1 {
        let worker_count = worker_count.min(chunk_count / MIN_CHUNKS_PER_WORKER);
        let part_chunks = chunk_count.div_ceil(worker_count);
        let part_len = part_chunks.saturating_mul(BITS_PER_HASH);

        let pieces = izip!(
            (0..=offset_length).rev().step_by(part_len),
            low.chunks_mut(part_len),
            high.rchunks_mut(part_len)
        );

        rayon::scope(|scope| {
            for (part_offset, low_part, high_part) in pieces {
                scope.spawn(move |_| {
                    swap_chunk_range(seed, round, low_part, high_part, part_offset)
                });
            }
        });

        return;
    }

    swap_chunk_range(seed, round, low, high, offset_length);
}

fn swap_chunk_range<T>(seed: H256, round: u8, low: &mut [T], high: &mut [T], offset: usize) {
    for (offset_chunk_index, low_chunk, high_chunk) in izip!(
        (0..offset / BITS_PER_HASH).rev(),
        low.chunks_exact_mut(BITS_PER_HASH),
        high.rchunks_exact_mut(BITS_PER_HASH)
    ) {
        let source = compute_source(seed, round, offset_chunk_index);
        let bit_indices = 0..BITS_PER_HASH;
        let low_elements = low_chunk.iter_mut().rev();
        let high_elements = high_chunk;

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
        let flip = pivot
            .saturating_add(index_count.get())
            .saturating_sub(index)
            % index_count;

        let position = index.max(flip);
        let source = compute_source(seed, round, position / nonzero!(BITS_PER_HASH as u64));
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
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Truncate to match the behavior of `compute_shuffled_index` in `consensus-specs`."
    )]
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

    #[expect(clippy::struct_field_names)]
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

    #[test]
    fn large_parallel_shuffle() {
        let count: u64 = 100_000;
        let seed = H256::repeat_byte(0xab);
        let index_count = NonZeroU64::new(count).expect("count is non-zero");

        let mut shuffled = (0..count).collect_vec();
        shuffle_slice::<Mainnet, _>(&mut shuffled, seed).expect("count fits in u64");

        for index in 0..count {
            assert_eq!(
                shuffled[usize::try_from(index).expect("index fits in usize")],
                shuffle_single::<Mainnet>(index, index_count, seed),
                "mismatch at position {index}"
            )
        }
    }
}
