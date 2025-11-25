use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    path::Path,
    time::Instant,
};
use xz2::write::XzDecoder;

use anyhow::Result;
use backend::{Vm, VmBackend as _};
use bls as _;
use clap::{Parser, Subcommand};
use database::Database;
use pubkey_cache::PubkeyCache;
use reqwest::IntoUrl;
use snap::raw::Decoder as SnappyDecoder;
use ssz::{H256, SszHash as _, SszRead as _, SszWrite as _};
use transition_functions::combined::untrusted_state_transition as state_transition;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    nonstandard::Phase,
    preset::Mainnet,
};

use crate::backend::{ConfigKind, ProofTrait, ReportTrait};

mod backend;

#[derive(Clone, Debug)]
struct Test {
    name: &'static str,

    block: &'static str,
    block_url: &'static str,
    state: &'static str,
    state_url: &'static str,

    container_params: ContainerParams,

    config: ConfigKind,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    test: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Execute,
    Prove,
}

#[derive(Clone, Copy, Default, Debug)]
struct ContainerParams {
    phase: Option<Phase>,
    decompress_snappy: bool,
}

fn get_or_download(path: impl AsRef<Path>, url: impl IntoUrl, decode_xz: bool) -> Result<Vec<u8>> {
    let path = path.as_ref();

    File::open(path)
        .and_then(|mut f| {
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            Ok(buf)
        })
        .or_else(move |err| {
            if err.kind() != ErrorKind::NotFound {
                return Err(anyhow::anyhow!(err));
            }

            let mut response = reqwest::blocking::Client::new()
                .get(url)
                .send()?
                .error_for_status()?;
            let mut file = File::create(path)?;

            if decode_xz {
                let mut decoder = XzDecoder::new(Vec::new());
                response.copy_to(&mut decoder)?;
                let buf = decoder.finish()?;

                file.write_all(&buf)?;

                Ok(buf)
            } else {
                let bytes = response.bytes()?;
                file.write_all(&bytes)?;

                Ok(bytes.to_vec())
            }
        })
}

fn main() -> Result<()> {
    let tests = [
        Test {
            name: "pectra-devnet-6 with epoch transition",

            block: "../data/pectra-devnet-6/beacon_block_slot_00021568_root_0xb28a634b89c669141990ed5deceb1ea4777869a64cb8eaccb6cb9f4796c5110d.ssz",
            block_url: "https://assets.grandine.io/beacon_block_slot_00021568_root_0xb28a634b89c669141990ed5deceb1.xz",
            state: "../data/pectra-devnet-6/beacon_state_slot_00021567_root_0xd51b605669c3e1ec96d83b6ab191d921f276d363621009fa6fd4a171a6bbf943.ssz",
            state_url: "https://assets.grandine.io/beacon_state_slot_00021567_root_0xd51b605669c3e1ec96d83b6ab191d.xz",

            container_params: ContainerParams::default(),

            config: ConfigKind::PectraDevnet6,
        },
        Test {
            name: "pectra-devnet-6 without epoch transition",

            block: "../data/pectra-devnet-6/beacon_block_slot_00021569_root_0x91008e253d2dafd1c9cd6a8ccae68a3d3010a85697ba588ef0be3dcb9b93332d.ssz",
            block_url: "https://assets.grandine.io/beacon_block_slot_00021569_root_0x91008e253d2dafd1c9cd6a8ccae68.xz",
            state: "../data/pectra-devnet-6/beacon_state_slot_00021568_root_0xb28a634b89c669141990ed5deceb1ea4777869a64cb8eaccb6cb9f4796c5110d.ssz",
            state_url: "https://assets.grandine.io/beacon_state_slot_00021568_root_0xb28a634b89c669141990ed5deceb1.xz",

            container_params: ContainerParams::default(),

            config: ConfigKind::PectraDevnet6,
        },
        Test {
            name: "mainnet without epoch transition",

            block: "../data/mainnet/beacon_block_slot_11893759_root_0x3a74cd235bf22d0d637b41b320f9162c6a7c81639b3fff28d1bceb1627fe82fb.ssz",
            block_url: "https://assets.grandine.io/beacon_block_slot_11893759_root_0x3a74cd235bf22d0d637b41b320f91.xz",
            state: "../data/mainnet/beacon_state_slot_11893758_root_0x6ae5cfd675459d878fc43a4205967660abc21e8e399195da5013af6b0547420b.ssz",
            state_url: "https://assets.grandine.io/beacon_state_slot_11893758_root_0x6ae5cfd675459d878fc43a4205967.xz",

            container_params: ContainerParams::default(),

            config: ConfigKind::Mainnet,
        },
        Test {
            name: "consensus spec tests mainnet electra empty block transition",

            block: "../data/consensus-spec-tests/tests/mainnet/electra/sanity/blocks/pyspec_tests/empty_block_transition/blocks_0.ssz_snappy",
            block_url: "https://raw.githubusercontent.com/ethereum/consensus-spec-tests/refs/tags/v1.6.0-alpha.3/tests/mainnet/electra/sanity/blocks/pyspec_tests/empty_block_transition/blocks_0.ssz_snappy",
            state: "../data/consensus-spec-tests/tests/mainnet/electra/sanity/blocks/pyspec_tests/empty_block_transition/pre.ssz_snappy",
            state_url: "https://raw.githubusercontent.com/ethereum/consensus-spec-tests/refs/tags/v1.6.0-alpha.3/tests/mainnet/electra/sanity/blocks/pyspec_tests/empty_block_transition/pre.ssz_snappy",

            container_params: ContainerParams {
                phase: Some(Phase::Electra),
                decompress_snappy: true,
            },

            config: ConfigKind::Mainnet,
        },
    ];

    let args = Args::parse();

    let selected_test = tests
        .iter()
        .find(|i| i.name.contains(&args.test))
        .expect("No matching test");

    println!("Running test \"{}\"", selected_test.name);

    let config = match selected_test.config {
        ConfigKind::PectraDevnet6 => Config::pectra_devnet_6(),
        ConfigKind::Mainnet => Config::mainnet(),
    };

    let mut block_ssz = get_or_download(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(selected_test.block),
        selected_test.block_url,
        !selected_test.container_params.decompress_snappy,
    )?;

    let mut state_ssz = get_or_download(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(selected_test.state),
        selected_test.state_url,
        !selected_test.container_params.decompress_snappy,
    )?;

    if selected_test.container_params.decompress_snappy {
        block_ssz = SnappyDecoder::new().decompress_vec(&block_ssz)?;
        state_ssz = SnappyDecoder::new().decompress_vec(&state_ssz)?;
    }

    let (expected_root, cache) = {
        let block = match selected_test.container_params.phase {
            Some(phase) => SignedBeaconBlock::<Mainnet>::from_ssz_at_phase(phase, &block_ssz)?,
            None => SignedBeaconBlock::<Mainnet>::from_ssz(&config, &block_ssz)?,
        };

        let mut state = match selected_test.container_params.phase {
            Some(phase) => BeaconState::<Mainnet>::from_ssz_at_phase(phase, &state_ssz)?,
            None => BeaconState::<Mainnet>::from_ssz(&config, &state_ssz)?,
        };

        let cache = PubkeyCache::load(Database::in_memory());

        state_transition(&config, &cache, &mut state, &block)?;

        cache.persist(&state).unwrap();

        (state.hash_tree_root(), cache.to_ssz().unwrap())
    };

    let phase_byte = enum_iterator::all::<Phase>()
        .zip(0_u8..)
        .find(|(phase, _)| Some(*phase) == selected_test.container_params.phase)
        .map(|(_, index)| index)
        .unwrap_or(255_u8);

    match args.command {
        Command::Execute => {
            let started_at = Instant::now();
            let vm = Vm::new()?;
            let (output_bytes, report) = vm.execute(
                selected_test.config,
                state_ssz,
                block_ssz,
                cache,
                vec![phase_byte],
            )?;
            let state_root = H256(output_bytes.try_into().unwrap());

            println!("elapsed: {:?}", started_at.elapsed());
            println!("cycles: {}", report.cycles());

            println!("state root after state transition: {:?}", state_root);
            assert_eq!(state_root, expected_root);
        }
        Command::Prove => {
            let started_at = Instant::now();
            let vm = Vm::new()?;
            let (output_bytes, proof) = vm.prove(
                selected_test.config,
                state_ssz,
                block_ssz,
                cache,
                vec![phase_byte],
            )?;
            let state_root = H256(output_bytes.try_into().unwrap());
            println!("elapsed: {:?}", started_at.elapsed());
            println!("state root after state transition: {:?}", state_root);

            proof.save(Path::new(env!("CARGO_MANIFEST_DIR")).join("proof.bin"))?;

            assert_eq!(proof.verify(), true);
            assert_eq!(state_root, expected_root);
        }
    }

    Ok(())
}
