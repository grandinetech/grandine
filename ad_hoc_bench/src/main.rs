use core::ops::RangeInclusive;
use std::{collections::BTreeMap, sync::Arc, time::Instant};

use allocator as _;
use anyhow::{Error, Result};
use bytesize::ByteSize;
use clap::{Parser, ValueEnum};
use eth2_cache_utils::{goerli, holesky, holesky_devnet, mainnet, medalla, withdrawal_devnet_4};
use fork_choice_control::AdHocBenchController;
use fork_choice_store::StoreConfig;
use jemalloc_ctl::Result as JemallocResult;
use log::info;
use rand::seq::SliceRandom as _;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config as ChainConfig,
    deneb::containers::BlobSidecar,
    phase0::{consts::GENESIS_SLOT, primitives::Slot},
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

#[derive(Clone, Copy, Parser)]
struct Options {
    #[clap(value_enum)]
    blocks: Blocks,
    #[clap(value_enum)]
    order: Order,
    #[clap(value_enum)]
    mode: Mode,
    #[clap(long)]
    unfinalized_states_in_memory: Option<u64>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Blocks {
    #[clap(name = "mainnet-genesis-128")]
    MainnetGenesis128,
    #[clap(name = "mainnet-genesis-1024")]
    MainnetGenesis1024,
    #[clap(name = "mainnet-genesis-2048")]
    MainnetGenesis2048,
    #[clap(name = "mainnet-genesis-8192")]
    MainnetGenesis8192,

    #[clap(name = "mainnet-altair-128")]
    MainnetAltair128,
    #[clap(name = "mainnet-altair-1024")]
    MainnetAltair1024,
    #[clap(name = "mainnet-altair-2048")]
    MainnetAltair2048,
    #[clap(name = "mainnet-altair-8192")]
    MainnetAltair8192,

    #[clap(name = "mainnet-deneb-1024")]
    MainnetDeneb1024,

    #[clap(name = "medalla-genesis-128")]
    MedallaGenesis128,
    #[clap(name = "medalla-genesis-1024")]
    MedallaGenesis1024,

    #[clap(name = "medalla-roughtime-1024")]
    MedallaRoughtime1024,
    MedallaRoughtimeFull,

    #[clap(name = "goerli-genesis-128")]
    GoerliGenesis128,
    #[clap(name = "goerli-genesis-1024")]
    GoerliGenesis1024,
    #[clap(name = "goerli-genesis-2048")]
    GoerliGenesis2048,
    #[clap(name = "goerli-genesis-8192")]
    GoerliGenesis8192,
    #[clap(name = "goerli-genesis-16384")]
    GoerliGenesis16384,

    #[clap(name = "withdrawals-2368")]
    Withdrawals2368,
    #[clap(name = "withdrawals-2496")]
    Withdrawals2496,

    #[clap(name = "holesky")]
    Holesky,
    #[clap(name = "holesky-devnet")]
    HoleskyDevnet,
}

#[derive(Clone, Copy, ValueEnum)]
enum Order {
    Forward,
    Reverse,
    Shuffle,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    Asynchronous,
    Synchronous,
}

enum Chain {
    Mainnet,
    Medalla,
    Goerli,
    Withdrawals,
    Holesky,
    HoleskyDevnet,
}

// This could be replaced with statics from `eth2_cache_utils` if it weren't for the slot width.
// The slot width is needed to deserialize the anchor state and ultimately because `eth2-cache` uses
// an inconsistent number of digits to represent slots.
struct BlockParameters {
    first_slot: Slot,
    last_slot: Slot,
    slot_width: usize,
}

impl From<Blocks> for Chain {
    fn from(blocks: Blocks) -> Self {
        match blocks {
            Blocks::MainnetGenesis128
            | Blocks::MainnetGenesis1024
            | Blocks::MainnetGenesis2048
            | Blocks::MainnetGenesis8192
            | Blocks::MainnetAltair128
            | Blocks::MainnetAltair1024
            | Blocks::MainnetAltair2048
            | Blocks::MainnetAltair8192
            | Blocks::MainnetDeneb1024 => Self::Mainnet,
            Blocks::MedallaGenesis128
            | Blocks::MedallaGenesis1024
            | Blocks::MedallaRoughtime1024
            | Blocks::MedallaRoughtimeFull => Self::Medalla,
            Blocks::GoerliGenesis128
            | Blocks::GoerliGenesis1024
            | Blocks::GoerliGenesis2048
            | Blocks::GoerliGenesis8192
            | Blocks::GoerliGenesis16384 => Self::Goerli,
            Blocks::Withdrawals2368 | Blocks::Withdrawals2496 => Self::Withdrawals,
            Blocks::Holesky => Self::Holesky,
            Blocks::HoleskyDevnet => Self::HoleskyDevnet,
        }
    }
}

impl From<Blocks> for BlockParameters {
    fn from(blocks: Blocks) -> Self {
        match blocks {
            Blocks::MainnetGenesis128 | Blocks::GoerliGenesis128 => Self {
                first_slot: GENESIS_SLOT,
                last_slot: 128,
                slot_width: 6,
            },
            Blocks::MainnetGenesis1024 | Blocks::GoerliGenesis1024 => Self {
                first_slot: GENESIS_SLOT,
                last_slot: 1024,
                slot_width: 6,
            },
            Blocks::MainnetGenesis2048 | Blocks::GoerliGenesis2048 => Self {
                first_slot: GENESIS_SLOT,
                last_slot: 2048,
                slot_width: 6,
            },
            Blocks::MainnetGenesis8192 | Blocks::GoerliGenesis8192 => Self {
                first_slot: GENESIS_SLOT,
                last_slot: 8192,
                slot_width: 6,
            },
            Blocks::MainnetAltair128 => Self {
                first_slot: 3_078_848,
                last_slot: 3_078_976,
                slot_width: 7,
            },
            Blocks::MainnetAltair1024 => Self {
                first_slot: 3_078_848,
                last_slot: 3_079_872,
                slot_width: 7,
            },
            Blocks::MainnetAltair2048 => Self {
                first_slot: 3_078_848,
                last_slot: 3_080_896,
                slot_width: 7,
            },
            Blocks::MainnetAltair8192 => Self {
                first_slot: 3_078_848,
                last_slot: 3_087_040,
                slot_width: 7,
            },
            Blocks::MainnetDeneb1024 => Self {
                first_slot: 9_481_344,
                last_slot: 9_482_368,
                slot_width: 7,
            },
            Blocks::MedallaGenesis128 => Self {
                first_slot: GENESIS_SLOT,
                last_slot: 128,
                slot_width: 4,
            },
            Blocks::MedallaGenesis1024 => Self {
                first_slot: GENESIS_SLOT,
                last_slot: 1_024,
                slot_width: 4,
            },
            Blocks::MedallaRoughtime1024 => Self {
                first_slot: 73_248,
                last_slot: 74_272,
                slot_width: 5,
            },
            Blocks::MedallaRoughtimeFull => Self {
                first_slot: 74_496,
                last_slot: 127_999,
                slot_width: 6,
            },
            Blocks::GoerliGenesis16384 => Self {
                first_slot: GENESIS_SLOT,
                last_slot: 0x4000,
                slot_width: 6,
            },
            // Chain does not finalize
            Blocks::Withdrawals2368 => Self {
                first_slot: GENESIS_SLOT,
                last_slot: 2368,
                slot_width: 6,
            },
            // Chain finalizes
            Blocks::Withdrawals2496 => Self {
                first_slot: GENESIS_SLOT,
                last_slot: 2496,
                slot_width: 6,
            },
            Blocks::Holesky => Self {
                first_slot: 49920,
                last_slot: 50016,
                slot_width: 6,
            },
            Blocks::HoleskyDevnet => Self {
                first_slot: GENESIS_SLOT,
                last_slot: 2584,
                slot_width: 6,
            },
        }
    }
}

fn main() -> Result<()> {
    binary_utils::initialize_logger(module_path!(), false)?;
    binary_utils::initialize_rayon()?;

    print_jemalloc_stats()?;

    let options = Options::parse();

    match options.blocks.into() {
        Chain::Mainnet => run(
            ChainConfig::mainnet(),
            options,
            mainnet::beacon_state,
            mainnet::beacon_blocks,
            mainnet::blob_sidecars,
        ),
        Chain::Medalla => run(
            ChainConfig::medalla(),
            options,
            medalla::beacon_state,
            medalla::beacon_blocks,
            |_, _| BTreeMap::new(),
        ),
        Chain::Goerli => run(
            ChainConfig::goerli(),
            options,
            goerli::beacon_state,
            goerli::beacon_blocks,
            |_, _| BTreeMap::new(),
        ),
        Chain::Withdrawals => run(
            ChainConfig::withdrawal_devnet_4(),
            options,
            withdrawal_devnet_4::beacon_state,
            withdrawal_devnet_4::beacon_blocks,
            |_, _| BTreeMap::new(),
        ),
        Chain::Holesky => run(
            ChainConfig::holesky(),
            options,
            holesky::beacon_state,
            holesky::beacon_blocks,
            holesky::blob_sidecars,
        ),
        Chain::HoleskyDevnet => run(
            ChainConfig::holesky_devnet(),
            options,
            holesky_devnet::beacon_state,
            holesky_devnet::beacon_blocks,
            |_, _| BTreeMap::new(),
        ),
    }?;

    print_jemalloc_stats()?;

    Ok(())
}

#[expect(clippy::cast_precision_loss)]
#[expect(clippy::float_arithmetic)]
fn run<P: Preset>(
    chain_config: ChainConfig,
    options: Options,
    beacon_state: impl FnOnce(Slot, usize) -> Arc<BeaconState<P>>,
    beacon_blocks: impl FnOnce(RangeInclusive<Slot>, usize) -> Vec<Arc<SignedBeaconBlock<P>>>,
    blob_sidecars: impl FnOnce(RangeInclusive<Slot>, usize) -> BTreeMap<Slot, Vec<Arc<BlobSidecar<P>>>>,
) -> Result<()> {
    print_jemalloc_stats()?;

    let Options {
        blocks,
        order,
        mode,
        unfinalized_states_in_memory,
    } = options;

    let BlockParameters {
        first_slot,
        last_slot,
        slot_width,
    } = blocks.into();

    let mut blocks = beacon_blocks(first_slot..=last_slot, slot_width).into_iter();
    let mut blobs = blob_sidecars(first_slot..=last_slot, slot_width);

    let last_block_root = blocks
        .as_slice()
        .last()
        .expect("range should contain at least one block")
        .message()
        .hash_tree_root();

    let chain_config = Arc::new(chain_config);

    let unfinalized_states_in_memory = unfinalized_states_in_memory
        .unwrap_or_else(|| StoreConfig::default().unfinalized_states_in_memory);

    let store_config = StoreConfig {
        unfinalized_states_in_memory,
        ..StoreConfig::default()
    };

    let anchor_block = blocks
        .next()
        .expect("range should contain at least one block");

    let anchor_state = beacon_state(first_slot, slot_width);

    let (controller, _mutator_handle) = AdHocBenchController::with_p2p_tx(
        chain_config,
        store_config,
        anchor_block,
        anchor_state,
        futures::sink::drain(),
    );

    controller.on_slot(last_slot);
    controller.wait_for_tasks();

    match order {
        Order::Forward => {}
        Order::Reverse => blocks.as_mut_slice().reverse(),
        Order::Shuffle => blocks.as_mut_slice().shuffle(&mut rand::thread_rng()),
    }

    let block_count = blocks.len();
    let slot_count = last_slot - first_slot;

    info!("processing {block_count} blocks in {slot_count} slots (not including anchor)");

    let start = Instant::now();

    for block in blocks {
        let slot = block.message().slot();

        controller.on_requested_block(block, None);

        if let Some(block_blobs) = blobs.remove(&slot) {
            for blob in block_blobs {
                controller.on_api_blob_sidecar(blob, None)
            }
        }

        if mode == Mode::Synchronous {
            controller.wait_for_tasks();
        }
    }

    if mode == Mode::Asynchronous {
        controller.wait_for_tasks();
    }

    let time = start.elapsed().as_secs_f64();

    let head = controller.head().value;
    assert_eq!(head.block_root, last_block_root);
    assert_eq!(head.slot(), last_slot);

    let time_per_block = time / block_count as f64;
    let time_per_slot = time / slot_count as f64;
    let block_throughput = time_per_block.recip();
    let slot_throughput = time_per_slot.recip();

    info!("blocks processed:         {block_count}");
    info!("slots processed:          {slot_count}");
    info!("time taken:               {time:.3} s");
    info!(
        "average time per block:   {:.3} ms",
        time_per_block * 1000_f64,
    );
    info!(
        "average time per slot:    {:.3} ms",
        time_per_slot * 1000_f64,
    );
    info!("average block throughput: {block_throughput:.3} blocks/s");
    info!("average slot throughput:  {slot_throughput:.3} slots/s");

    print_jemalloc_stats()
}

fn print_jemalloc_stats() -> Result<()> {
    jemalloc_ctl::epoch::advance().map_err(Error::msg)?;

    info!(
        "allocated: {}, \
         active: {}, \
         metadata: {}, \
         resident: {}, \
         mapped: {}, \
         retained: {}",
        human_readable_size(jemalloc_ctl::stats::allocated::read())?,
        human_readable_size(jemalloc_ctl::stats::active::read())?,
        human_readable_size(jemalloc_ctl::stats::metadata::read())?,
        human_readable_size(jemalloc_ctl::stats::resident::read())?,
        human_readable_size(jemalloc_ctl::stats::mapped::read())?,
        human_readable_size(jemalloc_ctl::stats::retained::read())?,
    );

    Ok(())
}

fn human_readable_size(result: JemallocResult<usize>) -> Result<String> {
    let size = result.map_err(Error::msg)?;
    let size = size.try_into()?;
    Ok(ByteSize(size).to_string_as(true))
}
