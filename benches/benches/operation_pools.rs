// The `unused_crate_dependencies` lint checks every crate in a package separately.
// See <https://github.com/rust-lang/rust/issues/57274>.
#![allow(unused_crate_dependencies)]

use std::sync::Arc;

use allocator as _;
use criterion::{Criterion, Throughput};
use easy_ext::ext;
use eth2_cache_utils::{goerli, holesky, LazyBeaconState};
use helper_functions::accessors;
use once_cell::unsync::Lazy;
use operation_pools::AttestationPacker;
use std_ext::ArcExt as _;
use types::{config::Config, phase0::containers::Attestation, preset::Preset};

// Criterion macros only add confusion.
fn main() {
    Criterion::default()
        .configure_from_args()
        .benchmark_greedy_attestation_packing(
            "greedy attestation packing in Goerli at slot 547813",
            LazyBeaconState::new(|| goerli::beacon_state(547_813, 6)),
            Lazy::new(|| goerli::attestations("aggregate_attestations", 17119 - 1)),
            Lazy::new(|| goerli::attestations("aggregate_attestations", 17119)),
        )
        .benchmark_dynamical_attestation_packing(
            "dynamical attestation packing in Goerli at slot 547813",
            LazyBeaconState::new(|| goerli::beacon_state(547_813, 6)),
            Lazy::new(|| goerli::attestations("aggregate_attestations", 17119 - 1)),
            Lazy::new(|| goerli::attestations("aggregate_attestations", 17119)),
        )
        .benchmark_greedy_attestation_packing(
            "greedy attestation packing in Holesky at slot 50015",
            LazyBeaconState::new(|| holesky::beacon_state(50_015, 8)),
            Lazy::new(|| holesky::attestations("aggregate_attestations", 1562 - 1)),
            Lazy::new(|| holesky::attestations("aggregate_attestations", 1562)),
        )
        .benchmark_dynamical_attestation_packing(
            "dynamical attestation packing in Holesky at slot 50015",
            LazyBeaconState::new(|| holesky::beacon_state(50_015, 8)),
            Lazy::new(|| holesky::attestations("aggregate_attestations", 1562 - 1)),
            Lazy::new(|| holesky::attestations("aggregate_attestations", 1562)),
        )
        .final_summary();
}

#[ext]
impl Criterion {
    fn benchmark_greedy_attestation_packing<P: Preset>(
        &mut self,
        group_name: &str,
        state: LazyBeaconState<P>,
        previous_aggregates: Lazy<Vec<Attestation<P>>>,
        current_aggregates: Lazy<Vec<Attestation<P>>>,
    ) -> &mut Self {
        let config = Arc::new(Config::mainnet());

        let packer = Lazy::new(|| {
            let state = state.force().clone_arc();
            let latest_block_root = accessors::latest_block_root(&state);

            AttestationPacker::new(config, latest_block_root, state, true)
                .expect("AttestationPacker should be constructed successfully")
        });

        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(1))
            .bench_function(
                "AttestationPacker::pack_proposable_attestations",
                |bencher| {
                    let packer = Lazy::force(&packer);
                    let previous_aggregates = Lazy::force(&previous_aggregates);
                    let current_aggregates = Lazy::force(&current_aggregates);

                    bencher.iter_with_large_drop(|| {
                        packer.pack_proposable_attestations_greedily(
                            previous_aggregates,
                            current_aggregates,
                        )
                    })
                },
            );

        self
    }

    fn benchmark_dynamical_attestation_packing<P: Preset>(
        &mut self,
        group_name: &str,
        state: LazyBeaconState<P>,
        previous_aggregates: Lazy<Vec<Attestation<P>>>,
        current_aggregates: Lazy<Vec<Attestation<P>>>,
    ) -> &mut Self {
        let config = Arc::new(Config::mainnet());

        let packer = Lazy::new(|| {
            let state = state.force().clone_arc();
            let latest_block_root = accessors::latest_block_root(&state);

            AttestationPacker::new(config, latest_block_root, state, true)
                .expect("AttestationPacker should be constructed successfully")
        });

        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(1))
            .bench_function(
                "AttestationPacker::pack_proposable_attestations_dynamically",
                |bencher| {
                    let packer = Lazy::force(&packer);
                    let previous_aggregates = Lazy::force(&previous_aggregates);
                    let current_aggregates = Lazy::force(&current_aggregates);

                    bencher.iter_with_large_drop(|| {
                        packer.pack_proposable_attestations_dynamically(
                            previous_aggregates,
                            current_aggregates,
                        )
                    })
                },
            );

        self
    }
}
