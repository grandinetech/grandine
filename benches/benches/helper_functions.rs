#![expect(
    unused_crate_dependencies,
    reason = "The `unused_crate_dependencies` lint checks every crate in a package separately. \
              See <https://github.com/rust-lang/rust/issues/57274>."
)]

use std::sync::Arc;

use allocator as _;
use bls::traits::CachedPublicKey as _;
use criterion::{BatchSize, Criterion, Throughput};
use easy_ext::ext;
use eth2_cache_utils::{goerli, mainnet, medalla, LazyBeaconState};
use helper_functions::accessors;
use ssz::Hc;
use std_ext::ArcExt as _;
use types::{
    altair::containers::SyncCommittee, cache::Cache, combined::BeaconState,
    phase0::primitives::ValidatorIndex, preset::Preset, traits::BeaconState as _,
};

// Criterion macros only add confusion.
fn main() {
    Criterion::default()
        .configure_from_args()
        .benchmark_get_beacon_proposer_index(
            "accessors::get_beacon_proposer_index with mainnet genesis state",
            &mainnet::GENESIS_BEACON_STATE,
        )
        .benchmark_get_beacon_proposer_index(
            "accessors::get_beacon_proposer_index with Goerli genesis state",
            &goerli::GENESIS_BEACON_STATE,
        )
        .benchmark_get_beacon_proposer_index(
            "accessors::get_beacon_proposer_index with Medalla genesis state",
            &medalla::GENESIS_BEACON_STATE,
        )
        .benchmark_get_next_sync_committee(
            "accessors::get_next_sync_committee with mainnet Altair state",
            &mainnet::ALTAIR_BEACON_STATE,
        )
        .final_summary();
}

#[ext]
impl Criterion {
    fn benchmark_get_beacon_proposer_index(
        &mut self,
        group_name: &str,
        state: &LazyBeaconState<impl Preset>,
    ) -> &mut Self {
        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(1))
            .bench_function("cached", |bencher| {
                let state = state.force();

                get_beacon_proposer_index(state);

                bencher.iter(|| get_beacon_proposer_index(state))
            })
            .bench_function("not cached", |bencher| {
                bencher.iter_batched_ref(
                    || {
                        let mut state = state.force().clone_arc();
                        *state.make_mut().cache_mut() = Cache::default();
                        state
                    },
                    |state| get_beacon_proposer_index(state),
                    BatchSize::SmallInput,
                )
            });

        self
    }

    fn benchmark_get_next_sync_committee(
        &mut self,
        group_name: &str,
        state: &LazyBeaconState<impl Preset>,
    ) -> &mut Self {
        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(1))
            .bench_function("decompressed public keys cached", |bencher| {
                let state = state.force();

                for validator in state.validators() {
                    validator.pubkey.decompress().ok();
                }

                bencher.iter_with_large_drop(|| get_next_sync_committee(state))
            })
            .bench_function("decompressed public keys not cached", |bencher| {
                let mut state = state.force().clone_arc();

                // Clear decompressed keys. Doing this using `PersistentList::update` has no effect
                // because decompressed keys are ignored when comparing `CachedPublicKey`.
                for validator in state.validators_mut() {
                    validator.pubkey = validator.pubkey.to_bytes().into();
                }

                bencher.iter_with_large_drop(|| get_next_sync_committee(&state))
            });

        self
    }
}

fn get_beacon_proposer_index(state: &BeaconState<impl Preset>) -> ValidatorIndex {
    // Wrapping `state` in `core::hint::black_box` or `criterion::black_box` reduces throughput of
    // cached index benchmarks by 30-40% and 15-20% respectively. The states we use for benchmarking
    // are read from files at runtime, so it's unlikely that this is due to the functions preventing
    // some unrealistic optimization. The documentation for `criterion::black_box` does state it may
    // have overhead.
    accessors::get_beacon_proposer_index(state)
        .expect("proposer index should be computed successfully")
}

fn get_next_sync_committee<P: Preset>(state: &BeaconState<P>) -> Arc<Hc<SyncCommittee<P>>> {
    // `get_next_sync_committee` only computes the committee correctly when `state` is at a sync
    // committee period boundary, but it performs roughly the same amount of computation either way,
    // which is good enough for benchmarking.
    accessors::get_next_sync_committee(state)
        .expect("next sync committee should be computed successfully")
}
