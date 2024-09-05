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
use eth2_libp2p::GossipId;
use fork_choice_control::BenchController;
use std_ext::ArcExt as _;
use typenum::Unsigned as _;
use types::{
    combined::SignedBeaconBlock, config::Config, phase0::primitives::H256, preset::Preset,
    traits::SignedBeaconBlock as _,
};

// Criterion macros only add confusion.
#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    // Initialize the global Rayon thread pool in advance for more consistent results.
    binary_utils::initialize_rayon()?;

    Criterion::default()
        .configure_from_args()
        .benchmark_block_processing(
            "mainnet Phase 0 blocks up to slot 128",
            Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_128,
        )
        .benchmark_block_processing(
            "mainnet Phase 0 blocks up to slot 1024",
            Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_1024,
        )
        .benchmark_block_processing(
            "mainnet Phase 0 blocks up to slot 2048",
            Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_2048,
        )
        .benchmark_block_processing(
            "mainnet Phase 0 blocks up to slot 8192",
            Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_8192,
        )
        .benchmark_block_processing(
            "mainnet Altair blocks from 128 slots",
            Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
            &mainnet::ALTAIR_BEACON_BLOCKS_FROM_128_SLOTS,
        )
        .benchmark_block_processing(
            "mainnet Altair blocks from 1024 slots",
            Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
            &mainnet::ALTAIR_BEACON_BLOCKS_FROM_1024_SLOTS,
        )
        .benchmark_block_processing(
            "mainnet Altair blocks from 2048 slots",
            Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
            &mainnet::ALTAIR_BEACON_BLOCKS_FROM_2048_SLOTS,
        )
        .benchmark_block_processing(
            "mainnet Altair blocks from 8192 slots",
            Config::mainnet(),
            &mainnet::ALTAIR_BEACON_STATE,
            &mainnet::ALTAIR_BEACON_BLOCKS_FROM_8192_SLOTS,
        )
        .benchmark_block_processing(
            "Goerli Phase 0 blocks up to slot 128",
            Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
            &goerli::BEACON_BLOCKS_UP_TO_SLOT_128,
        )
        .benchmark_block_processing(
            "Goerli Phase 0 blocks up to slot 1024",
            Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
            &goerli::BEACON_BLOCKS_UP_TO_SLOT_1024,
        )
        .benchmark_block_processing(
            "Goerli Phase 0 blocks up to slot 2048",
            Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
            &goerli::BEACON_BLOCKS_UP_TO_SLOT_2048,
        )
        .benchmark_block_processing(
            "Goerli Phase 0 blocks up to slot 8192",
            Config::goerli(),
            &goerli::GENESIS_BEACON_STATE,
            &goerli::BEACON_BLOCKS_UP_TO_SLOT_8192,
        )
        .benchmark_block_processing(
            "Medalla Phase 0 blocks up to slot 128",
            Config::medalla(),
            &medalla::GENESIS_BEACON_STATE,
            &medalla::BEACON_BLOCKS_UP_TO_SLOT_128,
        )
        .benchmark_block_processing(
            "Medalla Phase 0 blocks from 1024 slots during roughtime incident",
            Config::medalla(),
            &medalla::BEACON_STATE_DURING_ROUGHTIME,
            &medalla::BEACON_BLOCKS_DURING_ROUGHTIME,
        )
        .benchmark_head(
            "after mainnet Phase 0 blocks up to slot 128",
            Config::mainnet(),
            &mainnet::GENESIS_BEACON_STATE,
            &mainnet::BEACON_BLOCKS_UP_TO_SLOT_128,
        )
        .benchmark_head(
            "after Medalla Phase 0 blocks from 1024 slots during roughtime incident",
            Config::medalla(),
            &medalla::BEACON_STATE_DURING_ROUGHTIME,
            &medalla::BEACON_BLOCKS_DURING_ROUGHTIME,
        )
        .final_summary();

    Ok(())
}

#[ext]
impl Criterion {
    fn benchmark_block_processing<P: Preset>(
        &mut self,
        group_name: &str,
        config: Config,
        state: &LazyBeaconState<P>,
        blocks: &LazyBeaconBlocks<P>,
    ) -> &mut Self {
        let config = Arc::new(config);

        let controller_with_blocks = || {
            let (first_block, remaining_blocks) = blocks
                .force()
                .split_first()
                .expect("blocks should contain at least one block");

            let config = config.clone_arc();
            let first_block = first_block.clone_arc();
            let state = state.force().clone_arc();
            let (controller, mutator_handle) = BenchController::quiet(config, first_block, state);
            let blocks = remaining_blocks.to_vec();

            (controller, mutator_handle, blocks)
        };

        let expected_head_block_root = LazyCell::new(|| {
            blocks
                .force()
                .last()
                .expect("blocks should contain at least one block")
                .message()
                .hash_tree_root()
        });

        self.benchmark_group(group_name)
            .throughput(Throughput::Elements(blocks.count()))
            .bench_function("in their own slots", |bencher| {
                let expected_head_block_root = *expected_head_block_root;

                bencher.iter_batched(
                    controller_with_blocks,
                    |(controller, _mutator_handle, blocks)| {
                        process_blocks_in_their_slots(
                            &controller,
                            blocks,
                            expected_head_block_root,
                        );
                    },
                    BatchSize::SmallInput,
                );
            })
            .bench_function("in a future slot synchronously", |bencher| {
                let expected_head_block_root = *expected_head_block_root;

                bencher.iter_batched(
                    controller_with_blocks,
                    |(controller, _mutator_handle, blocks)| {
                        process_blocks_in_future_slot_synchronously(
                            &controller,
                            blocks,
                            expected_head_block_root,
                        );
                    },
                    BatchSize::SmallInput,
                );
            })
            .bench_function("in a future slot asynchronously", |bencher| {
                let expected_head_block_root = *expected_head_block_root;

                bencher.iter_batched(
                    controller_with_blocks,
                    |(controller, _mutator_handle, blocks)| {
                        process_blocks_in_future_slot_asynchronously(
                            &controller,
                            blocks,
                            expected_head_block_root,
                        );
                    },
                    BatchSize::SmallInput,
                );
            });

        self
    }

    fn benchmark_head<P: Preset>(
        &mut self,
        function_id: &str,
        config: Config,
        state: &LazyBeaconState<P>,
        blocks: &LazyBeaconBlocks<P>,
    ) -> &mut Self {
        let controller = LazyCell::new(|| {
            let expected_head_block_root = blocks
                .force()
                .last()
                .expect("blocks should contain at least one block")
                .message()
                .hash_tree_root();

            let (first_block, remaining_blocks) = blocks
                .force()
                .split_first()
                .expect("blocks should contain at least one block");

            let config = Arc::new(config);
            let first_block = first_block.clone_arc();
            let state = state.force().clone_arc();
            let (controller, mutator_handle) = BenchController::quiet(config, first_block, state);
            let blocks = remaining_blocks.to_vec();

            process_blocks_in_their_slots(&controller, blocks, expected_head_block_root);

            (controller, mutator_handle)
        });

        self.benchmark_group("Controller::head")
            .throughput(Throughput::Elements(1))
            .bench_function(function_id, |bencher| {
                let (controller, _) = LazyCell::force(&controller);

                bencher.iter_with_large_drop(|| controller.head());
            });

        self
    }
}

fn process_blocks_in_their_slots<P: Preset>(
    controller: &BenchController<P>,
    blocks: Vec<Arc<SignedBeaconBlock<P>>>,
    expected_head_block_root: H256,
) {
    for block in blocks {
        controller.on_slot(block.message().slot());
        controller.wait_for_tasks();
        controller.on_gossip_block(block, GossipId::default());
    }

    controller.wait_for_tasks();

    assert_eq!(controller.head_block_root().value, expected_head_block_root);
}

fn process_blocks_in_future_slot_synchronously<P: Preset>(
    controller: &BenchController<P>,
    blocks: Vec<Arc<SignedBeaconBlock<P>>>,
    expected_head_block_root: H256,
) {
    let last_block = blocks
        .last()
        .expect("blocks should contain at least one block");

    // Advance to a slot 2 epochs after the last block to make the store ignore any attestations
    // in the blocks.
    controller.on_slot(last_block.message().slot() + 2 * P::SlotsPerEpoch::U64);
    controller.wait_for_tasks();

    for block in blocks {
        controller.on_requested_block(block.clone_arc(), None);
        controller.wait_for_tasks();
    }

    assert_eq!(controller.head_block_root().value, expected_head_block_root);
}

fn process_blocks_in_future_slot_asynchronously<P: Preset>(
    controller: &BenchController<P>,
    blocks: Vec<Arc<SignedBeaconBlock<P>>>,
    expected_head_block_root: H256,
) {
    let last_block = blocks
        .last()
        .expect("blocks should contain at least one block");

    // Advance to a slot 2 epochs after the last block to make the store ignore any attestations
    // in the blocks.
    controller.on_slot(last_block.message().slot() + 2 * P::SlotsPerEpoch::U64);
    controller.wait_for_tasks();

    for block in blocks {
        controller.on_requested_block(block.clone_arc(), None);
    }
    controller.wait_for_tasks();

    assert_eq!(controller.head_block_root().value, expected_head_block_root);
}
