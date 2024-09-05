// The `unused_crate_dependencies` lint checks every crate in a package separately.
// See <https://github.com/rust-lang/rust/issues/57274>.
#![allow(unused_crate_dependencies)]

use core::cell::LazyCell;
use std::sync::Arc;

use allocator as _;
use anyhow::Result;
use criterion::{BatchSize, Criterion, Throughput};
use easy_ext::ext;
use eth2_cache_utils::{goerli, mainnet, medalla, LazyBeaconBlocks, LazyBeaconState};
use helper_functions::{accessors, misc};
use std_ext::ArcExt as _;
use transition_functions::{combined, unphased};
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    nonstandard::RelativeEpoch,
    phase0::primitives::Slot,
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

// This should be set high enough to cover all of epoch processing.
const EMPTY_SLOT_COUNT: u64 = 1024;

// Criterion macros only add confusion.
#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    // Initialize the global Rayon thread pool in advance for more consistent results.
    binary_utils::initialize_rayon()?;

    Criterion::default()
        .configure_from_args()
        .benchmark_empty_slots(
            format!("{EMPTY_SLOT_COUNT} empty slots in mainnet Phase 0 starting from genesis"),
            &Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
        )
        .benchmark_empty_slots(
            format!("{EMPTY_SLOT_COUNT} empty slots in mainnet Phase 0 starting from slot 8192"),
            &Config::mainnet(),
            &mainnet::BEACON_STATE_AT_SLOT_8192,
        )
        .benchmark_empty_slots(
            format!("{EMPTY_SLOT_COUNT} empty slots in mainnet Altair starting from slot 3078848"),
            &Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
        )
        .benchmark_empty_slots(
            format!("{EMPTY_SLOT_COUNT} empty slots in Goerli Phase 0 starting from genesis"),
            &Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
        )
        .benchmark_empty_slots(
            format!("{EMPTY_SLOT_COUNT} empty slots in Medalla Phase 0 starting from genesis"),
            &Config::medalla(),
            &medalla::GENESIS_BEACON_STATE,
        )
        .benchmark_empty_slots(
            format!("{EMPTY_SLOT_COUNT} empty slots in Medalla Phase 0 during roughtime incident"),
            &Config::medalla(),
            &medalla::BEACON_STATE_DURING_ROUGHTIME,
        )
        .benchmark_last_epoch_processing(
            "before epoch 32 in mainnet Phase 0",
            &Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_1024,
        )
        .benchmark_last_epoch_processing(
            "before epoch 96218 in mainnet Altair",
            &Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
            &mainnet::ALTAIR_BEACON_BLOCKS_FROM_128_SLOTS,
        )
        .benchmark_last_epoch_processing(
            "before epoch 32 in Goerli Phase 0",
            &Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
            &goerli::BEACON_BLOCKS_UP_TO_SLOT_1024,
        )
        .benchmark_last_epoch_processing(
            "before epoch 32 in Medalla Phase 0",
            &Config::medalla(),
            &medalla::GENESIS_BEACON_STATE,
            &medalla::BEACON_BLOCKS_UP_TO_SLOT_1024,
        )
        .benchmark_justification_and_finalization(
            "mainnet genesis state",
            &mainnet::GENESIS_BEACON_STATE,
        )
        .benchmark_justification_and_finalization(
            "mainnet state at slot 8192",
            &mainnet::BEACON_STATE_AT_SLOT_8192,
        )
        .benchmark_justification_and_finalization(
            "mainnet Altair state",
            &mainnet::ALTAIR_BEACON_STATE,
        )
        .benchmark_blocks(
            "mainnet Phase 0 blocks up to slot 128",
            &Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_128,
        )
        .benchmark_blocks(
            "mainnet Phase 0 blocks up to slot 1024",
            &Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_1024,
        )
        .benchmark_blocks(
            "mainnet Phase 0 blocks up to slot 2048",
            &Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_2048,
        )
        .benchmark_blocks(
            "mainnet Phase 0 blocks up to slot 8192",
            &Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_8192,
        )
        .benchmark_blocks(
            "mainnet Altair blocks from 128 slots",
            &Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
            &mainnet::ALTAIR_BEACON_BLOCKS_FROM_128_SLOTS,
        )
        .benchmark_blocks(
            "mainnet Altair blocks from 1024 slots",
            &Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
            &mainnet::ALTAIR_BEACON_BLOCKS_FROM_1024_SLOTS,
        )
        .benchmark_blocks(
            "mainnet Altair blocks from 2048 slots",
            &Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
            &mainnet::ALTAIR_BEACON_BLOCKS_FROM_2048_SLOTS,
        )
        .benchmark_blocks(
            "mainnet Altair blocks from 8192 slots",
            &Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
            &mainnet::ALTAIR_BEACON_BLOCKS_FROM_8192_SLOTS,
        )
        .benchmark_blocks(
            "Goerli Phase 0 blocks up to slot 128",
            &Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
            &goerli::BEACON_BLOCKS_UP_TO_SLOT_128,
        )
        .benchmark_blocks(
            "Goerli Phase 0 blocks up to slot 1024",
            &Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
            &goerli::BEACON_BLOCKS_UP_TO_SLOT_1024,
        )
        .benchmark_blocks(
            "Goerli Phase 0 blocks up to slot 2048",
            &Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
            &goerli::BEACON_BLOCKS_UP_TO_SLOT_2048,
        )
        .benchmark_blocks(
            "Goerli Phase 0 blocks up to slot 8192",
            &Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
            &goerli::BEACON_BLOCKS_UP_TO_SLOT_8192,
        )
        .benchmark_blocks(
            "Medalla Phase 0 blocks up to slot 128",
            &Config::medalla(),
            &medalla::GENESIS_BEACON_STATE,
            &medalla::BEACON_BLOCKS_UP_TO_SLOT_128,
        )
        .benchmark_blocks(
            "Medalla Phase 0 blocks up to slot 1024",
            &Config::medalla(),
            &medalla::GENESIS_BEACON_STATE,
            &medalla::BEACON_BLOCKS_UP_TO_SLOT_1024,
        )
        .benchmark_blocks(
            "Medalla Phase 0 blocks from 1024 slots during roughtime incident",
            &Config::medalla(),
            &medalla::BEACON_STATE_DURING_ROUGHTIME,
            &medalla::BEACON_BLOCKS_DURING_ROUGHTIME,
        )
        .final_summary();

    Ok(())
}

#[ext]
impl Criterion {
    fn benchmark_empty_slots(
        &mut self,
        group_name: impl Into<String>,
        config: &Config,
        state: &LazyBeaconState<impl Preset>,
    ) -> &mut Self {
        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(EMPTY_SLOT_COUNT))
            .bench_function("with single state", |bencher| {
                let state = state.force();
                let last_slot = state.slot() + EMPTY_SLOT_COUNT;

                bencher.iter_batched_ref(
                    || state.clone_arc(),
                    |state| empty_slots_with_single_state(config, state.make_mut(), last_slot),
                    BatchSize::SmallInput,
                );
            })
            .bench_function("with intermediate states", |bencher| {
                let state = state.force();
                let last_slot = state.slot() + EMPTY_SLOT_COUNT;

                bencher.iter_batched(
                    || state.clone_arc(),
                    |state| empty_slots_with_intermediate_states(config, state, last_slot),
                    BatchSize::SmallInput,
                );
            });

        self
    }

    // This method is rather fragile. It should panic if any assumptions are violated, however.
    fn benchmark_last_epoch_processing<P: Preset>(
        &mut self,
        function_id: &str,
        config: &Config,
        state: &LazyBeaconState<P>,
        blocks: &LazyBeaconBlocks<P>,
    ) -> &mut Self {
        let state_before_last_epoch_processing = LazyCell::new(|| {
            let [_, transition_blocks @ .., last_block] = blocks.force() else {
                panic!("blocks should contain at least two blocks")
            };

            let post_slot = last_block.message().slot();
            let pre_slot = post_slot - 1;

            assert!(misc::is_epoch_start::<P>(post_slot));

            let mut state = state.force().clone_arc();

            trusted_blocks_with_single_state(config, state.make_mut(), transition_blocks);

            if state.slot() < pre_slot {
                empty_slots_with_single_state(config, state.make_mut(), pre_slot);
            }

            unphased::process_slot(state.make_mut());

            // Initialize caches used during epoch processing to make the benchmark more
            // representative of real execution. This should make no difference due to the block
            // processing above, but we sometimes modify these benchmarks while profiling.
            accessors::active_validator_indices_shuffled(&state, RelativeEpoch::Previous);
            accessors::active_validator_indices_shuffled(&state, RelativeEpoch::Current);
            accessors::total_active_balance(&state);

            state
        });

        self.benchmark_group("epoch processing")
            .throughput(Throughput::Elements(1))
            .bench_function(function_id, |bencher| {
                bencher.iter_batched_ref(
                    || state_before_last_epoch_processing.clone(),
                    |state| {
                        combined::process_epoch(config, state.make_mut())
                            .expect("epoch processing should succeed")
                    },
                    BatchSize::SmallInput,
                );
            });

        self
    }

    fn benchmark_justification_and_finalization<P: Preset>(
        &mut self,
        function_id: &str,
        state: &LazyBeaconState<P>,
    ) -> &mut Self {
        self.benchmark_group("combined::process_justification_and_finalization")
            .throughput(Throughput::Elements(1))
            .bench_function(function_id, |bencher| {
                bencher.iter_batched_ref(
                    || state.force().clone_arc(),
                    |state| combined::process_justification_and_finalization(state.make_mut()),
                    BatchSize::SmallInput,
                )
            });

        self
    }

    fn benchmark_blocks<P: Preset>(
        &mut self,
        group_name: &str,
        config: &Config,
        state: &LazyBeaconState<P>,
        blocks: &LazyBeaconBlocks<P>,
    ) -> &mut Self {
        let rest = LazyCell::new(|| {
            blocks
                .force()
                .split_first()
                .expect("blocks should contain at least one block")
                .1
        });

        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(blocks.count()))
            .bench_function("untrusted with single state", |bencher| {
                let rest = LazyCell::force(&rest);

                bencher.iter_batched_ref(
                    || state.force().clone_arc(),
                    |state| untrusted_blocks_with_single_state(config, state.make_mut(), rest),
                    BatchSize::SmallInput,
                );
            })
            .bench_function("untrusted with intermediate states", |bencher| {
                let rest = LazyCell::force(&rest);

                bencher.iter_batched(
                    || state.force().clone_arc(),
                    |state| untrusted_blocks_with_intermediate_states(config, state, rest),
                    BatchSize::SmallInput,
                );
            })
            .bench_function("trusted with single state", |bencher| {
                let rest = LazyCell::force(&rest);

                bencher.iter_batched_ref(
                    || state.force().clone_arc(),
                    |state| trusted_blocks_with_single_state(config, state.make_mut(), rest),
                    BatchSize::SmallInput,
                );
            })
            .bench_function("trusted with intermediate states", |bencher| {
                let rest = LazyCell::force(&rest);

                bencher.iter_batched(
                    || state.force().clone_arc(),
                    |state| trusted_blocks_with_intermediate_states(config, state, rest),
                    BatchSize::SmallInput,
                );
            });

        self
    }
}

// The functions named `*_with_intermediate_states` keep all intermediate states in memory.
// That should be more representative of real execution in both CPU and memory usage.

fn empty_slots_with_single_state<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    last_slot: Slot,
) {
    combined::process_slots(config, state, last_slot).expect("slot processing should succeed");
}

fn empty_slots_with_intermediate_states<P: Preset>(
    config: &Config,
    state: Arc<BeaconState<P>>,
    last_slot: Slot,
) -> Vec<Arc<BeaconState<P>>> {
    core::iter::successors(Some(state), |previous_state| {
        let mut state = previous_state.clone_arc();
        let slot = state.slot() + 1;
        empty_slots_with_single_state(config, state.make_mut(), slot);
        Some(state)
    })
    .take_while(|state| state.slot() <= last_slot)
    .collect()
}

fn untrusted_blocks_with_single_state<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    blocks: &[Arc<SignedBeaconBlock<P>>],
) {
    for block in blocks {
        combined::untrusted_state_transition(config, state, block)
            .expect("state transition should succeed");
    }
}

fn untrusted_blocks_with_intermediate_states<P: Preset>(
    config: &Config,
    state: Arc<BeaconState<P>>,
    blocks: &[Arc<SignedBeaconBlock<P>>],
) -> Vec<Arc<BeaconState<P>>> {
    core::iter::once(state.clone_arc())
        .chain(blocks.iter().scan(state, |state, block| {
            untrusted_blocks_with_single_state(
                config,
                state.make_mut(),
                core::slice::from_ref(block),
            );
            Some(state.clone_arc())
        }))
        .collect()
}

fn trusted_blocks_with_single_state<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    blocks: &[Arc<SignedBeaconBlock<P>>],
) {
    for block in blocks {
        combined::trusted_state_transition(config, state, block)
            .expect("state transition should succeed");
    }
}

fn trusted_blocks_with_intermediate_states<P: Preset>(
    config: &Config,
    state: Arc<BeaconState<P>>,
    blocks: &[Arc<SignedBeaconBlock<P>>],
) -> Vec<Arc<BeaconState<P>>> {
    core::iter::once(state.clone_arc())
        .chain(blocks.iter().scan(state, |state, block| {
            trusted_blocks_with_single_state(
                config,
                state.make_mut(),
                core::slice::from_ref(block),
            );
            Some(state.clone_arc())
        }))
        .collect()
}
