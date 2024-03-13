// The `unused_crate_dependencies` lint checks every crate in a package separately.
// See <https://github.com/rust-lang/rust/issues/57274>.
#![allow(unused_crate_dependencies)]

use allocator as _;
use criterion::{BatchSize, Criterion, Throughput};
use easy_ext::ext;
use itertools::Itertools as _;
use types::{config::Config, phase0::primitives::H256, preset::Mainnet};

// Criterion macros only add confusion.
fn main() {
    Criterion::default()
        .configure_from_args()
        .benchmark_shuffle_slice(
            "shuffling::shuffle_slice with minimum number of validators in mainnet (2 ** 16)",
            Config::mainnet().min_genesis_active_validator_count.get(),
        )
        .benchmark_shuffle_slice(
            "shuffling::shuffle_slice with number of validators in Goerli at genesis (210000)",
            210_000,
        )
        .benchmark_shuffle_slice("shuffling::shuffle_slice with 2 ** 18 elements", 1 << 18)
        .benchmark_shuffle_slice(
            // See <https://github.com/ethereum/consensus-specs/issues/2137>.
            "shuffling::shuffle_slice with proposed cap for number of validators (2 ** 20)",
            1 << 20,
        )
        .final_summary();
}

#[ext]
impl Criterion {
    fn benchmark_shuffle_slice(&mut self, group_name: &str, length: u64) -> &mut Self {
        let seed = core::hint::black_box(H256::zero());

        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(1))
            .bench_function("elements of type ()", |bencher| {
                bencher.iter_batched_ref(
                    || (0..length).map(|_| ()).collect_vec(),
                    |slice| shuffling::shuffle_slice::<Mainnet, _>(slice, seed),
                    BatchSize::SmallInput,
                )
            })
            .bench_function("elements of type u64", |bencher| {
                bencher.iter_batched_ref(
                    || (0..length).collect_vec(),
                    |slice| shuffling::shuffle_slice::<Mainnet, _>(slice, seed),
                    BatchSize::SmallInput,
                )
            });

        self
    }
}
