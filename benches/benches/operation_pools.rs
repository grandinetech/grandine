#![expect(
    unused_crate_dependencies,
    reason = "The `unused_crate_dependencies` lint checks every crate in a package separately. \
              See <https://github.com/rust-lang/rust/issues/57274>."
)]

use core::cell::LazyCell;
use std::sync::Arc;

use allocator as _;
use criterion::{Criterion, Throughput};
use easy_ext::ext;
use eth2_cache_utils::{LazyBeaconState, goerli, holesky};
use operation_pools::AttestationPacker;
use operation_pools::PoolAttestation;
use std_ext::ArcExt as _;
use types::{config::Config, phase0::containers::Attestation, preset::Preset};

// Criterion macros only add confusion.
fn main() {
    Criterion::default()
        .configure_from_args()
        .benchmark_greedy_attestation_packing(
            "greedy attestation packing in Goerli at slot 547813",
            LazyBeaconState::new(|| goerli::beacon_state(547_813, 6)),
            LazyCell::new(|| {
                goerli::attestations_sorted_by_data("aggregate_attestations", 17119 - 1)
            }),
            LazyCell::new(|| goerli::attestations_sorted_by_data("aggregate_attestations", 17119)),
        )
        .benchmark_greedy_attestation_packing(
            "greedy attestation packing in Holesky at slot 50015",
            LazyBeaconState::new(|| holesky::beacon_state(50_015, 8)),
            LazyCell::new(|| holesky::aggregate_attestations_by_epoch_sorted_by_data(1562 - 1)),
            LazyCell::new(|| holesky::aggregate_attestations_by_epoch_sorted_by_data(1562)),
        )
        .final_summary();
}

#[ext]
impl Criterion {
    fn benchmark_greedy_attestation_packing<P: Preset>(
        &mut self,
        group_name: &str,
        state: LazyBeaconState<P>,
        previous_aggregates: LazyCell<Vec<Attestation<P>>>,
        current_aggregates: LazyCell<Vec<Attestation<P>>>,
    ) -> &mut Self {
        let config = Arc::new(Config::mainnet());

        let packer = LazyCell::new(|| {
            let state = state.force().clone_arc();

            AttestationPacker::new(config, state, true)
                .expect("AttestationPacker should be constructed successfully")
        });

        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(1))
            .bench_function(
                "AttestationPacker::pack_proposable_attestations_greedily",
                |bencher| {
                    let packer = LazyCell::force(&packer);
                    let previous_aggregates = LazyCell::force(&previous_aggregates);
                    let current_aggregates = LazyCell::force(&current_aggregates);

                    let previous_pool = to_pool_attestations(previous_aggregates);
                    let current_pool = to_pool_attestations(current_aggregates);

                    bencher.iter_with_large_drop(|| {
                        packer.pack_proposable_attestations_greedily(&previous_pool, &current_pool)
                    })
                },
            );

        self
    }
}

fn to_pool_attestations<P: Preset>(attestations: &[Attestation<P>]) -> Vec<PoolAttestation<P>> {
    attestations
        .iter()
        .map(|a| PoolAttestation {
            aggregation_bits: a.aggregation_bits.clone(),
            data: a.data,
            committee_index: a.data.index,
            signature: a.signature,
        })
        .collect()
}
