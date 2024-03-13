// The `unused_crate_dependencies` lint checks every crate in a package separately.
// See <https://github.com/rust-lang/rust/issues/57274>.
#![allow(unused_crate_dependencies)]

// Since the keys are `usize`, interpolation search could be used as well.
// We don't bother with it for a number of reasons: it's more complicated, has
// bad worst case complexity, requires division, and isn't implemented anywhere.
//
// Using unsafe indexing speeds up lookups in `Vec` significantly. Strangely, this is the case even
// with linear search (and more so than with binary search) despite it using an iterator otherwise.
//
// Binary search in `Vec` becomes faster than the average case of linear search at a length of
// around 10 elements. The breakpoint is higher for `VecDeque`.
//
// Search in `Vector` is slower than in `Vec` and `VecDeque` even with a small number of elements.
//
// Binary search is always faster than linear search in `Vector` with a small number of elements due
// to the need to create an `im::vector::Focus`.
//
// Lookups in `OrdMap` are comparable to binary search in `Vec` and `VecDeque`.
//
// Lookups in `OrdMap` are faster than in any other map type.

use allocator as _;
use std::collections::{BTreeMap, HashMap as StdHashMap, VecDeque};

use criterion::{
    measurement::Measurement, Bencher, BenchmarkGroup, BenchmarkId, Criterion, Throughput,
};
use easy_ext::ext;
use im::{HashMap as ImHashMap, OrdMap, Vector};

type Key = usize;

// This is a new type rather than an alias to make the output of `tynm::type_name` look better.
#[derive(Clone, Copy, Default)]
struct Small;

// This is a new type rather than an alias to make the output of `tynm::type_name` look better.
#[derive(Clone, Copy, Default)]
struct Large([usize; 8]);

// Criterion macros only add confusion.
fn main() {
    let mut criterion = Criterion::default().configure_from_args();

    criterion
        .benchmark_group("lookup in collection")
        .benchmark_all(0)
        .benchmark_all(1)
        .benchmark_all(4)
        .benchmark_all(16)
        .benchmark_all(64)
        .benchmark_all(256);

    criterion.final_summary();
}

#[ext]
impl<M: Measurement> BenchmarkGroup<'_, M> {
    fn benchmark_all(&mut self, length: usize) -> &mut Self {
        self.benchmark_sequence::<Vec<(Key, Small)>, Vec<(Key, Large)>>(length)
            .benchmark_sequence::<VecDeque<(Key, Small)>, VecDeque<(Key, Large)>>(length)
            .benchmark_sequence::<Vector<(Key, Small)>, Vector<(Key, Large)>>(length)
            .benchmark_map::<BTreeMap<Key, Small>, BTreeMap<Key, Large>>(length)
            .benchmark_map::<OrdMap<Key, Small>, OrdMap<Key, Large>>(length)
            .benchmark_map::<StdHashMap<Key, Small>, StdHashMap<Key, Large>>(length)
            .benchmark_map::<ImHashMap<Key, Small>, ImHashMap<Key, Large>>(length)
    }

    fn benchmark_sequence<S: Sequence, L: Sequence>(&mut self, length: usize) -> &mut Self {
        // Criterion uses the values passed to `throughput` for rendering line plots.
        self.throughput(Throughput::Elements(
            length
                .try_into()
                .expect("number of elements in collection should fit in u64"),
        ))
        .bench_function(
            BenchmarkId::new(
                format!("{} linear search best case", S::type_name()),
                length,
            ),
            |bencher| bencher.benchmark_linear_best::<S>(length),
        )
        .bench_function(
            BenchmarkId::new(
                format!("{} linear search worst case", S::type_name()),
                length,
            ),
            |bencher| bencher.benchmark_linear_worst::<S>(length),
        )
        .bench_function(
            BenchmarkId::new(
                format!("{} linear search best case", L::type_name()),
                length,
            ),
            |bencher| bencher.benchmark_linear_best::<L>(length),
        )
        .bench_function(
            BenchmarkId::new(
                format!("{} linear search worst case", L::type_name()),
                length,
            ),
            |bencher| bencher.benchmark_linear_worst::<L>(length),
        )
        .bench_function(
            BenchmarkId::new(
                format!("{} binary search best case", S::type_name()),
                length,
            ),
            |bencher| bencher.benchmark_binary_best::<S>(length),
        )
        .bench_function(
            BenchmarkId::new(
                format!("{} binary search worst case", S::type_name()),
                length,
            ),
            |bencher| bencher.benchmark_binary_worst::<S>(length),
        )
        .bench_function(
            BenchmarkId::new(
                format!("{} binary search best case", L::type_name()),
                length,
            ),
            |bencher| bencher.benchmark_binary_best::<L>(length),
        )
        .bench_function(
            BenchmarkId::new(
                format!("{} binary search worst case", L::type_name()),
                length,
            ),
            |bencher| bencher.benchmark_binary_worst::<L>(length),
        )
    }

    fn benchmark_map<S: Map, L: Map>(&mut self, length: usize) -> &mut Self {
        // Criterion uses the values passed to `throughput` for rendering line plots.
        self.throughput(Throughput::Elements(
            length
                .try_into()
                .expect("number of elements in collection should fit in u64"),
        ))
        .bench_function(BenchmarkId::new(S::type_name(), length), |bencher| {
            bencher.benchmark_map::<S>(length)
        })
        .bench_function(BenchmarkId::new(L::type_name(), length), |bencher| {
            bencher.benchmark_map::<L>(length)
        })
    }
}

#[ext]
impl<M: Measurement> Bencher<'_, M> {
    fn benchmark_linear_best<T: Sequence>(&mut self, length: usize) {
        let sequence = collect::<T::Item, T>(length);
        self.iter(|| sequence.linear_search(core::hint::black_box(0)))
    }

    fn benchmark_linear_worst<T: Sequence>(&mut self, length: usize) {
        let sequence = collect::<T::Item, T>(length);
        self.iter(|| sequence.linear_search(core::hint::black_box(length - 1)))
    }

    fn benchmark_binary_best<T: Sequence>(&mut self, length: usize) {
        let sequence = collect::<T::Item, T>(length);
        self.iter(|| sequence.binary_search(core::hint::black_box(length / 2)))
    }

    fn benchmark_binary_worst<T: Sequence>(&mut self, length: usize) {
        let sequence = collect::<T::Item, T>(length);
        self.iter(|| sequence.binary_search(core::hint::black_box(0)))
    }

    fn benchmark_map<T: Map>(&mut self, length: usize) {
        let map = collect::<T::Item, T>(length);
        self.iter(|| map.get(core::hint::black_box(length - 1)))
    }
}

fn collect<T: Default, C: FromIterator<(Key, T)>>(length: usize) -> C {
    core::hint::black_box(
        core::iter::repeat_with(T::default)
            .enumerate()
            .take(length)
            .collect(),
    )
}

trait Sequence: FromIterator<(Key, <Self as Sequence>::Item)> {
    type Item: Default;

    fn linear_search(&self, needle: Key) -> Option<&Self::Item>;

    fn binary_search(&self, needle: Key) -> Option<&Self::Item>;

    fn type_name() -> String {
        tynm::type_name::<Self>()
    }
}

impl<T: Default> Sequence for Vec<(Key, T)> {
    type Item = T;

    fn linear_search(&self, needle: Key) -> Option<&Self::Item> {
        // This is the code that was used to benchmark unsafe indexing.
        // For some reason it outperforms the version with `Iterator::find`.
        // ```
        // self.iter()
        //     .position(|(key, _)| *key == needle)
        //     .map(|index| unsafe { self.get_unchecked(index) })
        //     .map(|(_, value)| value)
        // ```

        self.iter()
            .find(|(key, _)| *key == needle)
            .map(|(_, value)| value)
    }

    fn binary_search(&self, needle: Key) -> Option<&Self::Item> {
        // This is the code that was used to benchmark unsafe indexing.
        // ```
        // self.binary_search_by_key(&needle, |(key, _)| *key)
        //     .ok()
        //     .map(|index| unsafe { self.get_unchecked(index) })
        //     .map(|(_, value)| value)
        // ```

        self.binary_search_by_key(&needle, |(key, _)| *key)
            .ok()
            .map(|index| &self[index])
            .map(|(_, value)| value)
    }
}

impl<T: Default> Sequence for VecDeque<(Key, T)> {
    type Item = T;

    fn linear_search(&self, needle: Key) -> Option<&Self::Item> {
        self.iter()
            .find(|(key, _)| *key == needle)
            .map(|(_, value)| value)
    }

    fn binary_search(&self, needle: Key) -> Option<&Self::Item> {
        self.binary_search_by_key(&needle, |(key, _)| *key)
            .ok()
            .map(|index| &self[index])
            .map(|(_, value)| value)
    }
}

impl<T: Clone + Default> Sequence for Vector<(Key, T)> {
    type Item = T;

    fn linear_search(&self, needle: Key) -> Option<&Self::Item> {
        self.iter()
            .find(|(key, _)| *key == needle)
            .map(|(_, value)| value)
    }

    fn binary_search(&self, needle: Key) -> Option<&Self::Item> {
        self.binary_search_by_key(&needle, |(key, _)| *key)
            .ok()
            .map(|index| &self[index])
            .map(|(_, value)| value)
    }
}

trait Map: FromIterator<(Key, <Self as Map>::Item)> {
    type Item: Default;

    fn get(&self, needle: Key) -> Option<&Self::Item>;

    fn type_name() -> String {
        tynm::type_name::<Self>()
    }
}

impl<T: Default> Map for BTreeMap<Key, T> {
    type Item = T;

    fn get(&self, needle: Key) -> Option<&Self::Item> {
        self.get(&needle)
    }
}

impl<T: Clone + Default> Map for OrdMap<Key, T> {
    type Item = T;

    fn get(&self, needle: Key) -> Option<&Self::Item> {
        self.get(&needle)
    }
}

impl<T: Default> Map for StdHashMap<Key, T> {
    type Item = T;

    fn get(&self, needle: Key) -> Option<&Self::Item> {
        self.get(&needle)
    }

    fn type_name() -> String {
        format!("std::collections::{}", tynm::type_name::<Self>())
    }
}

impl<T: Clone + Default> Map for ImHashMap<Key, T> {
    type Item = T;

    fn get(&self, needle: Key) -> Option<&Self::Item> {
        self.get(&needle)
    }

    fn type_name() -> String {
        format!("im::{}", tynm::type_name::<Self>())
    }
}
