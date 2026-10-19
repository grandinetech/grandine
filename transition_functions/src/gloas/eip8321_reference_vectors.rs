//! Read-only runners for the reference vectors generated from consensus-specs.
//! Run explicitly with scripts/test_randao.sh vectors. Never modifies fixtures.
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use helper_functions::{
    gloas::align_randao_commitments,
    slot_report::NullSlotReport,
    verifier::{NullVerifier, SingleVerifier},
};
use pubkey_cache::PubkeyCache;
use spec_test_utils::{BlsSetting, Case};
use ssz::{Hc, SszHash as _};
use types::{
    config::Config,
    gloas::{
        beacon_state::BeaconState,
        containers::{BeaconBlock, SignedBeaconBlock, SignedRandaoCommitmentRegistration},
    },
    preset::{Mainnet, Minimal, Preset},
};

use super::{epoch_processing, hash_chain_randao};
use crate::unphased::{ProcessSlots, StateRootPolicy};

fn vector_root() -> PathBuf {
    std::env::var_os("EIP8321_VECTORS_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/eip8321"),
        PathBuf::from,
    )
}

fn collect_cases(root: &Path) -> Result<Vec<PathBuf>> {
    ensure!(
        root.is_dir(),
        "missing generated reference vectors: {}; set EIP8321_VECTORS_DIR",
        root.display()
    );
    fn visit(path: &Path, result: &mut Vec<PathBuf>) -> Result<()> {
        if path.join("pre.ssz_snappy").is_file() {
            result.push(path.to_path_buf());
        } else {
            for entry in std::fs::read_dir(path)? {
                let path = entry?.path();
                if path.is_dir() {
                    visit(&path, result)?;
                }
            }
        }
        Ok(())
    }
    let mut result = vec![];
    visit(root, &mut result)?;
    result.sort();
    ensure!(
        !result.is_empty(),
        "no test cases found in {}",
        root.display()
    );
    Ok(result)
}

fn run_operations<P: Preset>(
    preset: &str,
    config: &Config,
    category: &str,
    operation: impl Fn(&Config, &PubkeyCache, &mut BeaconState<P>, Case<'_>) -> Result<()>,
) -> Result<()> {
    let root = vector_root().join(preset).join("eip8321").join(category);
    let cases = collect_cases(&root)?;
    let pubkey_cache = PubkeyCache::default();
    for path in &cases {
        let case = Case::from(path.to_str().expect("UTF-8 fixture path"));
        let mut pre: BeaconState<P> = case.ssz_default("pre");
        let post: Option<BeaconState<P>> = case.try_ssz_default("post");
        let result = operation(config, &pubkey_cache, &mut pre, case)
            .with_context(|| path.display().to_string());
        match post {
            Some(post) => {
                result?;
                ensure!(
                    pre.hash_tree_root() == post.hash_tree_root(),
                    "post-state mismatch: {}",
                    path.display()
                );
            }
            None => ensure!(result.is_err(), "invalid case accepted: {}", path.display()),
        }
    }
    eprintln!(
        "{preset}/{category}: {} official vector cases passed",
        cases.len()
    );
    Ok(())
}

fn randao<P: Preset>(
    config: &Config,
    cache: &PubkeyCache,
    state: &mut BeaconState<P>,
    case: Case<'_>,
) -> Result<()> {
    let block: BeaconBlock<P> = case.ssz_default("block");
    if matches!(case.meta().bls_setting, BlsSetting::Required) {
        hash_chain_randao::process_randao(config, cache, state, &block.body, SingleVerifier)
    } else {
        hash_chain_randao::process_randao(config, cache, state, &block.body, NullVerifier)
    }
}

fn registration<P: Preset>(
    config: &Config,
    cache: &PubkeyCache,
    state: &mut BeaconState<P>,
    case: Case<'_>,
) -> Result<()> {
    let registration: SignedRandaoCommitmentRegistration =
        case.ssz_default("randao_commitment_registration");
    if matches!(case.meta().bls_setting, BlsSetting::Required) {
        hash_chain_randao::process_randao_commitment_registration(
            config,
            cache,
            state,
            registration,
            SingleVerifier,
        )
    } else {
        hash_chain_randao::process_randao_commitment_registration(
            config,
            cache,
            state,
            registration,
            NullVerifier,
        )
    }
}

#[test]
#[ignore = "requires generated EIP-8321 reference vectors; use the vectors script mode"]
fn official_randao_vectors() -> Result<()> {
    run_operations::<Minimal>("minimal", &Config::minimal(), "operations/randao", randao)?;
    run_operations::<Mainnet>("mainnet", &Config::mainnet(), "operations/randao", randao)
}

#[test]
#[ignore = "requires generated EIP-8321 reference vectors; use the vectors script mode"]
fn official_registration_vectors() -> Result<()> {
    run_operations::<Minimal>(
        "minimal",
        &Config::minimal(),
        "operations/randao_commitment_registration",
        registration,
    )?;
    run_operations::<Mainnet>(
        "mainnet",
        &Config::mainnet(),
        "operations/randao_commitment_registration",
        registration,
    )
}

#[test]
#[ignore = "requires generated EIP-8321 reference vectors; use the vectors script mode"]
fn official_pending_commitment_vectors() -> Result<()> {
    fn operation<P: Preset>(
        _: &Config,
        _: &PubkeyCache,
        state: &mut BeaconState<P>,
        _: Case<'_>,
    ) -> Result<()> {
        hash_chain_randao::process_pending_randao_commitments(state)
    }
    run_operations::<Minimal>(
        "minimal",
        &Config::minimal(),
        "epoch_processing/pending_randao_commitments",
        operation,
    )?;
    run_operations::<Mainnet>(
        "mainnet",
        &Config::mainnet(),
        "epoch_processing/pending_randao_commitments",
        operation,
    )
}

#[test]
#[ignore = "requires generated EIP-8321 reference vectors; use the vectors script mode"]
fn official_pending_deposit_vectors() -> Result<()> {
    fn operation<P: Preset>(
        config: &Config,
        cache: &PubkeyCache,
        state: &mut BeaconState<P>,
        _: Case<'_>,
    ) -> Result<()> {
        epoch_processing::process_pending_deposits(config, cache, state)?;
        align_randao_commitments(state)
    }
    run_operations::<Minimal>(
        "minimal",
        &Config::minimal(),
        "epoch_processing/pending_deposits",
        operation,
    )?;
    run_operations::<Mainnet>(
        "mainnet",
        &Config::mainnet(),
        "epoch_processing/pending_deposits",
        operation,
    )
}

#[test]
#[ignore = "requires generated EIP-8321 reference vectors; use the vectors script mode"]
fn official_registration_lifecycle_vector() -> Result<()> {
    let root = vector_root().join(
        "minimal/eip8321/sanity/blocks/pyspec_tests/randao_commitment_registration_lifecycle",
    );
    let cases = collect_cases(&root)?;
    let config = Config::minimal();
    let cache = PubkeyCache::default();
    for path in cases {
        let case = Case::from(path.to_str().expect("UTF-8 fixture path"));
        let mut state: Hc<BeaconState<Minimal>> = Hc::new(case.ssz_default("pre"));
        let block_count = case.meta().blocks_count;
        ensure!(block_count > 0, "lifecycle has no blocks");
        for index in 0..block_count {
            let block: SignedBeaconBlock<Minimal> = case.ssz_default(format!("blocks_{index}"));
            super::state_transition(
                &config,
                &cache,
                &mut state,
                &block,
                ProcessSlots::Always,
                StateRootPolicy::Verify,
                NullVerifier,
                NullSlotReport,
            )
            .with_context(|| format!("{}: block {index}", path.display()))?;
        }
        let post: BeaconState<Minimal> = case.ssz_default("post");
        ensure!(
            state.hash_tree_root() == post.hash_tree_root(),
            "lifecycle final root mismatch"
        );
    }
    eprintln!("minimal: official registration lifecycle passed, including every block state root");
    Ok(())
}
