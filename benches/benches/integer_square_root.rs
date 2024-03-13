// The `unused_crate_dependencies` lint checks every crate in a package separately.
// See <https://github.com/rust-lang/rust/issues/57274>.
#![allow(unused_crate_dependencies)]

use allocator as _;
use criterion::{Criterion, Throughput};
use easy_ext::ext;
use integer_sqrt::IntegerSquareRoot;
use num_integer::Roots;
use types::{
    config::Config,
    preset::{Mainnet, Preset as _},
};

// Criterion macros only add confusion.
fn main() {
    Criterion::default()
        .configure_from_args()
        .benchmark_sqrt(
            "integer_sqrt::IntegerSquareRoot::integer_sqrt",
            IntegerSquareRoot::integer_sqrt,
        )
        .benchmark_sqrt("num_integer::Roots::sqrt", Roots::sqrt)
        .final_summary();
}

#[ext]
impl Criterion {
    fn benchmark_sqrt(
        &mut self,
        group_name: &str,
        mut function: impl FnMut(&u64) -> u64,
    ) -> &mut Self {
        let max_effective_balance = Mainnet::MAX_EFFECTIVE_BALANCE;

        let min_genesis_active_validator_count =
            Config::mainnet().min_genesis_active_validator_count.get();

        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(1))
            .bench_function("MAX_EFFECTIVE_BALANCE", |bencher| {
                bencher.iter(|| function(&core::hint::black_box(max_effective_balance)))
            })
            .bench_function(
                "MAX_EFFECTIVE_BALANCE * MIN_GENESIS_ACTIVE_VALIDATOR_COUNT",
                |bencher| {
                    let balance = max_effective_balance * min_genesis_active_validator_count;
                    bencher.iter(|| function(&core::hint::black_box(balance)))
                },
            );

        self
    }
}
