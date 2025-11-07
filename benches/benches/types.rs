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
use eth2_cache_utils::{
    LazyBeaconBlocks, LazyBeaconState, LazyBlobSidecars, goerli, mainnet, medalla,
};
use itertools::Itertools as _;
use serde::{Deserialize, Serialize};
use ssz::{SszRead, SszWrite};
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    deneb::containers::BlobSidecar,
    preset::Preset,
};

// Criterion macros only add confusion.
fn main() {
    Criterion::default()
        .configure_from_args()
        .benchmark_state(
            "mainnet genesis state",
            &Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
        )
        .benchmark_state(
            "mainnet state at slot 8192",
            &Config::mainnet(),
            &mainnet::BEACON_STATE_AT_SLOT_8192,
        )
        .benchmark_state(
            "mainnet Altair state",
            &Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
        )
        .benchmark_state(
            "Goerli genesis state",
            &Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
        )
        .benchmark_state(
            "Medalla genesis state",
            &Config::medalla(),
            &medalla::GENESIS_BEACON_STATE,
        )
        .benchmark_state(
            "Medalla roughtime state",
            &Config::medalla(),
            &medalla::BEACON_STATE_DURING_ROUGHTIME,
        )
        .benchmark_blocks(
            "mainnet blocks up to slot 128",
            &Config::mainnet(),
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_128,
        )
        .benchmark_blocks(
            "mainnet Altair blocks from 128 slots",
            &Config::mainnet(),
            &mainnet::ALTAIR_BEACON_BLOCKS_FROM_128_SLOTS,
        )
        .benchmark_blocks(
            "Goerli blocks up to slot 128",
            &Config::goerli(),
            &goerli::BEACON_BLOCKS_UP_TO_SLOT_128,
        )
        .benchmark_blocks(
            "Medalla blocks up to slot 128",
            &Config::medalla(),
            &medalla::BEACON_BLOCKS_UP_TO_SLOT_128,
        )
        .benchmark_blob_sidecars(
            "mainnet Deneb blob sidecars from 32 slots",
            &mainnet::DENEB_BLOB_SIDECARS_FROM_32_SLOTS,
        )
        .final_summary();
}

#[ext]
impl Criterion {
    fn benchmark_state<P: Preset>(
        &mut self,
        group_name: &str,
        config: &Config,
        state: &LazyBeaconState<P>,
    ) -> &mut Self {
        let ssz_bytes = LazyCell::new(|| state_to_ssz(state.force()));

        // `BeaconState` is never deserialized from JSON. Deserializing the combined `BeaconState`
        // would require another use of `#[serde(untagged)]`, which is rarely a good idea.
        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(1))
            .bench_function("from SSZ", |bencher| {
                let ssz_bytes = ssz_bytes.as_slice();

                bencher.iter_with_large_drop(|| state_from_ssz::<P>(config, ssz_bytes))
            })
            .bench_function("to SSZ", |bencher| {
                let state = state.force();

                bencher.iter_with_large_drop(|| state_to_ssz(state))
            })
            .bench_function("to JSON directly", |bencher| {
                let state = state.force();

                bencher.iter_with_large_drop(|| state_to_json_directly(state))
            })
            .bench_function("to JSON via serde_utils::stringify", |bencher| {
                let state = state.force();

                bencher.iter_with_large_drop(|| state_to_json_via_stringify(state))
            });

        self
    }

    fn benchmark_blocks<P: Preset>(
        &mut self,
        group_name: &str,
        config: &Config,
        blocks: &LazyBeaconBlocks<P>,
    ) -> &mut Self {
        let ssz_bytes = LazyCell::new(|| slice_to_ssz(blocks.force()));
        let json_bytes = LazyCell::new(|| slice_to_json_directly(blocks.force()));

        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(blocks.count()))
            .bench_function("from SSZ", |bencher| {
                let ssz_bytes = ssz_bytes.iter().map(Vec::as_slice);

                bencher.iter_with_large_drop(|| {
                    vec_from_ssz::<Config, Arc<SignedBeaconBlock<P>>>(config, ssz_bytes.clone())
                })
            })
            .bench_function("to SSZ", |bencher| {
                let blocks = blocks.force();

                bencher.iter_with_large_drop(|| slice_to_ssz(blocks))
            })
            .bench_function("from JSON", |bencher| {
                let json_bytes = json_bytes.iter().map(Vec::as_slice);

                bencher.iter_with_large_drop(|| {
                    vec_from_json::<Arc<SignedBeaconBlock<P>>>(json_bytes.clone())
                })
            })
            .bench_function("to JSON directly", |bencher| {
                let blocks = blocks.force();

                bencher.iter_with_large_drop(|| slice_to_json_directly(blocks))
            })
            .bench_function("to JSON via serde_utils::stringify", |bencher| {
                let blocks = blocks.force();

                bencher.iter_with_large_drop(|| slice_to_json_via_stringify(blocks))
            });

        self
    }

    fn benchmark_blob_sidecars<P: Preset>(
        &mut self,
        group_name: &str,
        blob_sidecars: &LazyBlobSidecars<P>,
    ) -> &mut Self {
        let ssz_bytes = LazyCell::new(|| slice_to_ssz(blob_sidecars.force()));
        let json_bytes = LazyCell::new(|| slice_to_json_directly(blob_sidecars.force()));

        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(blob_sidecars.count()))
            .bench_function("from SSZ", |bencher| {
                let ssz_bytes = ssz_bytes.iter().map(Vec::as_slice);

                bencher.iter_with_large_drop(|| {
                    vec_from_ssz::<(), Arc<BlobSidecar<P>>>(&(), ssz_bytes.clone())
                })
            })
            .bench_function("to SSZ", |bencher| {
                let blob_sidecars = blob_sidecars.force();

                bencher.iter_with_large_drop(|| slice_to_ssz(blob_sidecars))
            })
            .bench_function("from JSON", |bencher| {
                let json_bytes = json_bytes.iter().map(Vec::as_slice);

                bencher.iter_with_large_drop(|| {
                    vec_from_json::<Arc<BlobSidecar<P>>>(json_bytes.clone())
                })
            })
            .bench_function("to JSON directly", |bencher| {
                let blob_sidecars = blob_sidecars.force();

                bencher.iter_with_large_drop(|| slice_to_json_directly(blob_sidecars))
            })
            .bench_function("to JSON via serde_utils::stringify", |bencher| {
                let blob_sidecars = blob_sidecars.force();

                bencher.iter_with_large_drop(|| slice_to_json_via_stringify(blob_sidecars))
            });

        self
    }
}

fn state_from_ssz<P: Preset>(config: &Config, bytes: &[u8]) -> Arc<BeaconState<P>> {
    Arc::from_ssz(config, bytes).expect("state has already been successfully deserialized")
}

fn state_to_ssz(state: &BeaconState<impl Preset>) -> Vec<u8> {
    state
        .to_ssz()
        .expect("state can be serialized because it has already been serialized to a file")
}

fn state_to_json_directly(state: &BeaconState<impl Preset>) -> Vec<u8> {
    serde_json::to_vec(state).expect("state should be serializable to JSON")
}

fn state_to_json_via_stringify(state: &BeaconState<impl Preset>) -> Vec<u8> {
    serde_utils::stringify(state)
        .and_then(|json| serde_json::to_vec(&json))
        .expect("state should be serializable to JSON")
}

fn vec_from_ssz<'bytes, C, T: SszRead<C>>(
    context: &C,
    bytes: impl IntoIterator<Item = &'bytes [u8]>,
) -> Vec<T> {
    bytes
        .into_iter()
        .map(|bytes| T::from_ssz(context, bytes))
        .try_collect()
        .expect("iterator items have already been successfully deserialized from SSZ")
}

fn slice_to_ssz(slice: &[impl SszWrite]) -> Vec<Vec<u8>> {
    slice.iter().map(SszWrite::to_ssz).try_collect().expect(
        "slice elements can be serialized to SSZ because \
         they have already been serialized to a file",
    )
}

fn vec_from_json<'bytes, T: Deserialize<'bytes>>(
    bytes: impl IntoIterator<Item = &'bytes [u8]>,
) -> Vec<T> {
    bytes
        .into_iter()
        .map(serde_json::from_slice)
        .try_collect()
        .expect("iterator items should be deserializable from JSON")
}

fn slice_to_json_directly(slice: &[impl Serialize]) -> Vec<Vec<u8>> {
    slice
        .iter()
        .map(serde_json::to_vec)
        .try_collect()
        .expect("slice elements should be serializable to JSON")
}

fn slice_to_json_via_stringify(slice: &[impl Serialize]) -> Vec<Vec<u8>> {
    slice
        .iter()
        .map(|element| serde_utils::stringify(element).and_then(|json| serde_json::to_vec(&json)))
        .try_collect()
        .expect("slice elements should be serializable to JSON")
}
