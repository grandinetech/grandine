// The `unused_crate_dependencies` lint checks every crate in a package separately.
// See <https://github.com/rust-lang/rust/issues/57274>.
#![allow(unused_crate_dependencies)]

use core::cell::LazyCell;

use allocator as _;
use criterion::{Criterion, Throughput};
use easy_ext::ext;
use genesis::Incremental;
use itertools::Itertools as _;
use types::{config::Config, phase0::primitives::ExecutionBlockHash, preset::Mainnet};

const DEPOSIT_COUNT: u64 = 1024;

// Criterion macros only add confusion.
fn main() {
    Criterion::default()
        .configure_from_args()
        .benchmark_quick_start_beacon_state()
        .final_summary();
}

#[ext]
impl Criterion {
    fn benchmark_quick_start_beacon_state(&mut self) -> &mut Self {
        let config = Config::mainnet();

        let deposit_data = LazyCell::new(|| {
            (0..DEPOSIT_COUNT)
                .map(|validator_index| {
                    let secret_key = interop::secret_key(validator_index);
                    interop::quick_start_deposit_data::<Mainnet>(&config, &secret_key)
                })
                .collect_vec()
        });

        self.benchmark_group("quick start beacon state")
            .throughput(Throughput::Elements(DEPOSIT_COUNT))
            .bench_function(format!("with {DEPOSIT_COUNT} deposits"), |bencher| {
                let deposit_data = LazyCell::force(&deposit_data);

                bencher.iter_with_large_drop(|| {
                    let mut incremental = Incremental::<Mainnet>::new(&config);

                    for (data, index) in deposit_data.iter().copied().zip(0..) {
                        incremental
                            .add_deposit_data(data, index)
                            .expect("deposit data processing should succeed");
                    }

                    incremental
                        .finish(ExecutionBlockHash::default(), None)
                        .expect("genesis state should be constructed successfully")
                });
            });

        self
    }
}
