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

// Every bundled manifest is accounted for. The state-transition suite includes
// operations, epochs, rewards, slots, blocks, finality, and Heze -> EIP-8321.
// Client/network categories are explicitly reported outside this suite.
mod full_suite {
    use super::super::{
        block_processing as bp, epoch_intermediates as ei, execution_payload_processing as ep,
    };
    use super::*;
    use crate::{altair, capella, electra, fulu, unphased};
    use helper_functions::misc::vec_of_default;
    use std::{collections::BTreeMap, io::Write as _, panic::AssertUnwindSafe};

    fn operation<P: Preset>(
        config: &Config,
        cache: &PubkeyCache,
        state: &mut BeaconState<P>,
        case: Case<'_>,
        name: &str,
    ) -> Result<()> {
        macro_rules! load {
            ($name:expr) => {
                case.ssz_default($name)
            };
        }
        match name {
            "randao" => randao(config, cache, state, case),
            "randao_commitment_registration" => registration(config, cache, state, case),
            "block_header" => {
                let block: Hc<BeaconBlock<P>> = Hc::new(load!("block"));
                unphased::process_block_header(config, state, &block)
            }
            "proposer_slashing" => bp::process_proposer_slashing(
                config,
                cache,
                state,
                load!("proposer_slashing"),
                SingleVerifier,
                NullSlotReport,
            ),
            "attester_slashing" => {
                let slashing: types::gloas::containers::AttesterSlashing<P> =
                    load!("attester_slashing");
                bp::process_attester_slashing(
                    config,
                    cache,
                    state,
                    &slashing,
                    SingleVerifier,
                    NullSlotReport,
                )
            }
            "attestation" => {
                let attestation = load!("attestation");
                if matches!(case.meta().bls_setting, BlsSetting::Ignored) {
                    bp::validate_attestation_with_verifier(
                        config,
                        cache,
                        state,
                        &attestation,
                        NullVerifier,
                    )?;
                } else {
                    bp::validate_attestation_with_verifier(
                        config,
                        cache,
                        state,
                        &attestation,
                        SingleVerifier,
                    )?;
                }
                let parent_slot = case
                    .meta()
                    .parent_slot
                    .unwrap_or(state.latest_execution_payload_bid.slot);
                bp::apply_attestation(config, state, &attestation, parent_slot, NullSlotReport)
            }
            "bls_to_execution_change" => capella::process_bls_to_execution_change(
                config,
                cache,
                state,
                load!("address_change"),
                SingleVerifier,
            ),
            "voluntary_exit" | "voluntary_exit_churn" => electra::process_voluntary_exit(
                config,
                cache,
                state,
                load!("voluntary_exit"),
                SingleVerifier,
            ),
            "sync_aggregate" => altair::process_sync_aggregate(
                config,
                cache,
                state,
                load!("sync_aggregate"),
                SingleVerifier,
                NullSlotReport,
            ),
            "payload_attestation" => bp::process_payload_attestation(
                config,
                cache,
                state,
                &load!("payload_attestation"),
                SingleVerifier,
            ),
            "execution_payload_bid" => bp::process_execution_payload_bid(
                config,
                cache,
                state,
                &load!("execution_payload_bid"),
            ),
            "parent_execution_payload" => {
                bp::process_parent_execution_payload(config, cache, state, &Hc::new(load!("block")))
            }
            "withdrawals" => bp::process_withdrawals(state),
            "deposit_request" => fulu::process_deposit_request(state, load!("deposit_request")),
            "withdrawal_request" => {
                electra::process_withdrawal_request(config, state, load!("withdrawal_request"))
            }
            "consolidation_request" => electra::process_consolidation_request(
                config,
                state,
                load!("consolidation_request"),
            ),
            "builder_deposit_request" => ep::process_builder_deposit_request(
                config,
                cache,
                state,
                load!("builder_deposit_request"),
            ),
            "builder_exit_request" => {
                ep::process_builder_exit_request(config, state, load!("builder_exit_request"))
            }
            _ => anyhow::bail!("no operation runner for {name}"),
        }
    }

    fn epoch<P: Preset>(
        config: &Config,
        cache: &PubkeyCache,
        state: &mut BeaconState<P>,
        name: &str,
    ) -> Result<()> {
        match name {
            "pending_randao_commitments" => {
                hash_chain_randao::process_pending_randao_commitments(state)
            }
            "pending_deposits" | "pending_deposits_churn" => {
                epoch_processing::process_pending_deposits(config, cache, state)
            }
            "justification_and_finalization" => {
                let (statistics, _, _) = altair::statistics_and_summaries(state)?;
                altair::process_justification_and_finalization(state, statistics)
            }
            "inactivity_updates" => {
                let (_, summaries, participation) = altair::statistics_and_summaries(state)?;
                altair::process_inactivity_updates(config, state, summaries, participation)
            }
            "rewards_and_penalties" => {
                let (statistics, summaries, participation) =
                    altair::statistics_and_summaries(state)?;
                let deltas: Vec<altair::EpochDeltasForTransition> =
                    ei::epoch_deltas(config, state, statistics, summaries, participation)?;
                unphased::process_rewards_and_penalties(state, deltas)
            }
            "registry_updates" => {
                let mut summaries: Vec<altair::ValidatorSummary> = vec_of_default(state);
                electra::process_registry_updates(config, state, summaries.as_mut_slice())
            }
            "slashings" => {
                let (_, summaries, _) = altair::statistics_and_summaries(state)?;
                electra::process_slashings::<_, ()>(state, summaries)
            }
            "effective_balance_updates" => electra::process_effective_balance_updates(state),
            "slashings_reset" => unphased::process_slashings_reset(state),
            "randao_mixes_reset" => unphased::process_randao_mixes_reset(state),
            "historical_summaries_update" => {
                epoch_processing::process_historical_summaries_update(state)
            }
            "participation_flag_updates" => {
                altair::process_participation_flag_updates(state);
                Ok(())
            }
            "sync_committee_updates" => altair::process_sync_committee_updates(cache, state),
            "pending_consolidations" => electra::process_pending_consolidations(state),
            "proposer_lookahead" => fulu::process_proposer_lookahead(config, state),
            "builder_pending_payments" => epoch_processing::process_builder_pending_payments(state),
            "ptc_window" => epoch_processing::process_ptc_window(state),
            _ => anyhow::bail!("no epoch runner for {name}"),
        }
    }

    fn rewards<P: Preset>(config: &Config, state: &BeaconState<P>, case: Case<'_>) -> Result<()> {
        let (statistics, summaries, participation) = altair::statistics_and_summaries(state)?;
        let deltas: Vec<altair::EpochDeltasForReport> =
            ei::epoch_deltas(config, state, statistics, summaries, participation)?;
        unphased::TestDeltas::assert_equal(
            deltas.iter().map(|d| d.source_reward),
            deltas.iter().map(|d| d.source_penalty),
            case.ssz_default("source_deltas"),
        );
        unphased::TestDeltas::assert_equal(
            deltas.iter().map(|d| d.target_reward),
            deltas.iter().map(|d| d.target_penalty),
            case.ssz_default("target_deltas"),
        );
        unphased::TestDeltas::assert_equal(
            deltas.iter().map(|d| d.head_reward),
            std::iter::repeat_n(0, deltas.len()),
            case.ssz_default("head_deltas"),
        );
        unphased::TestDeltas::assert_equal(
            std::iter::repeat_n(0, deltas.len()),
            deltas.iter().map(|d| d.inactivity_penalty),
            case.ssz_default("inactivity_penalty_deltas"),
        );
        Ok(())
    }

    fn differences<P: Preset>(a: &BeaconState<P>, b: &BeaconState<P>) -> Vec<&'static str> {
        let mut fields = vec![];
        if a.genesis_time.hash_tree_root() != b.genesis_time.hash_tree_root() {
            fields.push("genesis_time");
        }
        if a.genesis_validators_root.hash_tree_root() != b.genesis_validators_root.hash_tree_root()
        {
            fields.push("genesis_validators_root");
        }
        if a.slot.hash_tree_root() != b.slot.hash_tree_root() {
            fields.push("slot");
        }
        if a.fork.hash_tree_root() != b.fork.hash_tree_root() {
            fields.push("fork");
        }
        if a.latest_block_header.hash_tree_root() != b.latest_block_header.hash_tree_root() {
            fields.push("latest_block_header");
        }
        if a.block_roots.hash_tree_root() != b.block_roots.hash_tree_root() {
            fields.push("block_roots");
        }
        if a.state_roots.hash_tree_root() != b.state_roots.hash_tree_root() {
            fields.push("state_roots");
        }
        if a.historical_roots.hash_tree_root() != b.historical_roots.hash_tree_root() {
            fields.push("historical_roots");
        }
        if a.validators.hash_tree_root() != b.validators.hash_tree_root() {
            fields.push("validators");
        }
        if a.balances.hash_tree_root() != b.balances.hash_tree_root() {
            fields.push("balances");
        }
        if a.randao_mixes.hash_tree_root() != b.randao_mixes.hash_tree_root() {
            fields.push("randao_mixes");
        }
        if a.slashings.hash_tree_root() != b.slashings.hash_tree_root() {
            fields.push("slashings");
        }
        if a.previous_epoch_participation.hash_tree_root()
            != b.previous_epoch_participation.hash_tree_root()
        {
            fields.push("previous_epoch_participation");
        }
        if a.current_epoch_participation.hash_tree_root()
            != b.current_epoch_participation.hash_tree_root()
        {
            fields.push("current_epoch_participation");
        }
        if a.justification_bits.hash_tree_root() != b.justification_bits.hash_tree_root() {
            fields.push("justification_bits");
        }
        if a.previous_justified_checkpoint.hash_tree_root()
            != b.previous_justified_checkpoint.hash_tree_root()
        {
            fields.push("previous_justified_checkpoint");
        }
        if a.current_justified_checkpoint.hash_tree_root()
            != b.current_justified_checkpoint.hash_tree_root()
        {
            fields.push("current_justified_checkpoint");
        }
        if a.finalized_checkpoint.hash_tree_root() != b.finalized_checkpoint.hash_tree_root() {
            fields.push("finalized_checkpoint");
        }
        if a.inactivity_scores.hash_tree_root() != b.inactivity_scores.hash_tree_root() {
            fields.push("inactivity_scores");
        }
        if a.current_sync_committee.hash_tree_root() != b.current_sync_committee.hash_tree_root() {
            fields.push("current_sync_committee");
        }
        if a.next_sync_committee.hash_tree_root() != b.next_sync_committee.hash_tree_root() {
            fields.push("next_sync_committee");
        }
        if a.latest_block_hash.hash_tree_root() != b.latest_block_hash.hash_tree_root() {
            fields.push("latest_block_hash");
        }
        if a.next_withdrawal_index.hash_tree_root() != b.next_withdrawal_index.hash_tree_root() {
            fields.push("next_withdrawal_index");
        }
        if a.next_withdrawal_validator_index.hash_tree_root()
            != b.next_withdrawal_validator_index.hash_tree_root()
        {
            fields.push("next_withdrawal_validator_index");
        }
        if a.historical_summaries.hash_tree_root() != b.historical_summaries.hash_tree_root() {
            fields.push("historical_summaries");
        }
        if a.deposit_balance_to_consume.hash_tree_root()
            != b.deposit_balance_to_consume.hash_tree_root()
        {
            fields.push("deposit_balance_to_consume");
        }
        if a.exit_balance_to_consume.hash_tree_root() != b.exit_balance_to_consume.hash_tree_root()
        {
            fields.push("exit_balance_to_consume");
        }
        if a.earliest_exit_epoch.hash_tree_root() != b.earliest_exit_epoch.hash_tree_root() {
            fields.push("earliest_exit_epoch");
        }
        if a.consolidation_balance_to_consume.hash_tree_root()
            != b.consolidation_balance_to_consume.hash_tree_root()
        {
            fields.push("consolidation_balance_to_consume");
        }
        if a.earliest_consolidation_epoch.hash_tree_root()
            != b.earliest_consolidation_epoch.hash_tree_root()
        {
            fields.push("earliest_consolidation_epoch");
        }
        if a.pending_deposits.hash_tree_root() != b.pending_deposits.hash_tree_root() {
            fields.push("pending_deposits");
        }
        if a.pending_partial_withdrawals.hash_tree_root()
            != b.pending_partial_withdrawals.hash_tree_root()
        {
            fields.push("pending_partial_withdrawals");
        }
        if a.pending_consolidations.hash_tree_root() != b.pending_consolidations.hash_tree_root() {
            fields.push("pending_consolidations");
        }
        if a.proposer_lookahead.hash_tree_root() != b.proposer_lookahead.hash_tree_root() {
            fields.push("proposer_lookahead");
        }
        if a.builders.hash_tree_root() != b.builders.hash_tree_root() {
            fields.push("builders");
        }
        if a.next_withdrawal_builder_index.hash_tree_root()
            != b.next_withdrawal_builder_index.hash_tree_root()
        {
            fields.push("next_withdrawal_builder_index");
        }
        if a.execution_payload_availability.hash_tree_root()
            != b.execution_payload_availability.hash_tree_root()
        {
            fields.push("execution_payload_availability");
        }
        if a.builder_pending_payments.hash_tree_root()
            != b.builder_pending_payments.hash_tree_root()
        {
            fields.push("builder_pending_payments");
        }
        if a.builder_pending_withdrawals.hash_tree_root()
            != b.builder_pending_withdrawals.hash_tree_root()
        {
            fields.push("builder_pending_withdrawals");
        }
        if a.latest_execution_payload_bid.hash_tree_root()
            != b.latest_execution_payload_bid.hash_tree_root()
        {
            fields.push("latest_execution_payload_bid");
        }
        if a.payload_expected_withdrawals.hash_tree_root()
            != b.payload_expected_withdrawals.hash_tree_root()
        {
            fields.push("payload_expected_withdrawals");
        }
        if a.ptc_window.hash_tree_root() != b.ptc_window.hash_tree_root() {
            fields.push("ptc_window");
        }
        if a.randao_commitments.hash_tree_root() != b.randao_commitments.hash_tree_root() {
            fields.push("randao_commitments");
        }
        if a.pending_randao_commitments.hash_tree_root()
            != b.pending_randao_commitments.hash_tree_root()
        {
            fields.push("pending_randao_commitments");
        }
        fields
    }

    fn verify_post<P: Preset>(
        state: &BeaconState<P>,
        case: Case<'_>,
        result: Result<()>,
    ) -> Result<()> {
        match case.try_ssz_default::<BeaconState<P>>("post") {
            Some(post) => {
                result?;
                ensure!(
                    state.hash_tree_root() == post.hash_tree_root(),
                    "post-state root mismatch: {:?}",
                    differences(state, &post)
                );
            }
            None => ensure!(result.is_err(), "invalid case accepted"),
        }
        Ok(())
    }

    // This upstream property emits only a manifest, not pre/post SSZ. Execute
    // its equivalent using a real fixture state, and report it separately.
    fn two_link_property<P: Preset>(
        config: &Config,
        cache: &PubkeyCache,
        root: &Path,
    ) -> Result<()> {
        use bls::traits::SignatureBytes as _;
        use ssz::{SszList as _, SszListMut as _};
        let source = root.join("operations/randao/pyspec_tests/hash_chain_reveal");
        let case = Case::from(source.to_str().context("UTF-8 fixture path")?);
        let mut state: BeaconState<P> = case.ssz_default("pre");
        let index = helper_functions::accessors::get_beacon_proposer_index(config, &state)?;
        let secret = types::phase0::primitives::H256::repeat_byte(42);
        let first = hashing::blake3_hash_chain_link(secret);
        *state.randao_commitments.get_mut(index)? = hashing::blake3_hash_chain_link(first);
        for reveal in [first, secret] {
            let body = types::gloas::containers::BeaconBlockBody::<P> {
                hash_chain_reveal: reveal,
                randao_reveal: bls::SignatureBytes::empty(),
                ..Default::default()
            };
            hash_chain_randao::process_randao(config, cache, &mut state, &body, SingleVerifier)?;
            ensure!(
                *state.randao_commitments.get(index)? == reveal,
                "chain did not advance one link"
            );
        }
        Ok(())
    }

    fn in_scope(category: &str) -> bool {
        category.starts_with("operations/")
            || category.starts_with("epoch_processing/")
            || category.starts_with("rewards/")
            || matches!(
                category,
                "sanity/blocks" | "sanity/slots" | "finality/finality" | "fork/fork"
            )
    }

    fn execute<P: Preset>(
        config: &Config,
        cache: &PubkeyCache,
        case: Case<'_>,
        category: &str,
    ) -> Result<()> {
        ensure!(in_scope(category), "UNSUPPORTED: {category}");
        if category == "fork/fork" {
            let pre: types::heze::beacon_state::BeaconState<P> = case.ssz_default("pre");
            let version = match P::default_config().preset_base {
                types::preset::PresetName::Minimal => {
                    types::phase0::primitives::H32([0xe8, 0x32, 0x10, 1])
                }
                _ => types::phase0::primitives::H32([0xe8, 0x32, 0x10, 0]),
            };
            let post = helper_functions::fork::upgrade_to_eip8321(pre, version)?;
            return verify_post(&post, case, Ok(()));
        }
        ensure!(
            case.exists("pre"),
            "MISSING_INPUT: manifest has no pre-state"
        );
        let mut state: BeaconState<P> = case.ssz_default("pre");
        if let Some(name) = category.strip_prefix("operations/") {
            let result = operation(config, cache, &mut state, case, name);
            verify_post(&state, case, result)?;
        } else if let Some(name) = category.strip_prefix("epoch_processing/") {
            let result = epoch(config, cache, &mut state, name);
            verify_post(&state, case, result)?;
            if let Some(pre_epoch) = case.try_ssz_default::<BeaconState<P>>("pre_epoch") {
                let mut full = pre_epoch;
                let result = epoch_processing::process_epoch(config, cache, &mut full);
                match case.try_ssz_default::<BeaconState<P>>("post_epoch") {
                    Some(post) => {
                        result?;
                        ensure!(
                            full.hash_tree_root() == post.hash_tree_root(),
                            "full epoch root mismatch: {:?}",
                            differences(&full, &post)
                        );
                    }
                    None => ensure!(result.is_err(), "invalid full epoch accepted"),
                }
            }
        } else if category.starts_with("rewards/") {
            rewards(config, &state, case)?;
        } else if category == "sanity/slots" {
            let target = state
                .slot
                .checked_add(case.yaml::<u64>("slots"))
                .context("slot overflow")?;
            let mut state = Hc::new(state);
            super::super::process_slots(config, cache, &mut state, target)?;
            verify_post(&state, case, Ok(()))?;
        } else {
            let mut state = Hc::new(state);
            let result = (|| -> Result<()> {
                for i in 0..case.meta().blocks_count {
                    let block: SignedBeaconBlock<P> = case.ssz_default(format!("blocks_{i}"));
                    if matches!(case.meta().bls_setting, BlsSetting::Ignored) {
                        super::super::state_transition(
                            config,
                            cache,
                            &mut state,
                            &block,
                            ProcessSlots::Always,
                            StateRootPolicy::Verify,
                            NullVerifier,
                            NullSlotReport,
                        )?;
                    } else {
                        super::super::state_transition(
                            config,
                            cache,
                            &mut state,
                            &block,
                            ProcessSlots::Always,
                            StateRootPolicy::Verify,
                            SingleVerifier,
                            NullSlotReport,
                        )?;
                    }
                }
                Ok(())
            })();
            verify_post(&state, case, result)?;
        }
        Ok(())
    }

    fn run<P: Preset>(preset: &str, config: &Config) -> Result<()> {
        let root = vector_root().join(preset).join("eip8321");
        fn manifests(path: &Path, all: &mut Vec<PathBuf>) -> Result<()> {
            if path.join("manifest.yaml").is_file() {
                all.push(path.to_path_buf());
            } else {
                for entry in std::fs::read_dir(path)? {
                    let p = entry?.path();
                    if p.is_dir() {
                        manifests(&p, all)?;
                    }
                }
            }
            Ok(())
        }
        let mut cases = vec![];
        manifests(&root, &mut cases)?;
        cases.sort();
        ensure!(!cases.is_empty(), "empty full vector suite");
        let filter = std::env::var("EIP8321_CATEGORY").ok();
        let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/reports");
        std::fs::create_dir_all(&out)?;
        let mut report = std::fs::File::create(out.join(format!("all-{preset}.tsv")))?;
        writeln!(report, "status\tcase\tdetail")?;
        let cache = PubkeyCache::default();
        let mut groups: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let (mut passed, mut failed, mut properties, mut outside) =
            (0usize, 0usize, 0usize, 0usize);
        for path in &cases {
            let relative = path.strip_prefix(&root)?;
            let parts: Vec<_> = relative
                .components()
                .take(2)
                .map(|c| c.as_os_str().to_string_lossy())
                .collect();
            let category = parts.join("/");
            if !in_scope(&category) {
                ensure!(
                    matches!(
                        parts[0].as_ref(),
                        "networking" | "fork_choice" | "fast_confirmation" | "light_client"
                    ),
                    "unclassified category: {category}"
                );
                outside += 1;
                writeln!(
                    report,
                    "OUT_OF_SCOPE\t{}\tclient/network category",
                    relative.display()
                )?;
                continue;
            }
            if filter.as_ref().is_some_and(|f| !category.starts_with(f)) {
                continue;
            }
            if !path.join("pre.ssz_snappy").is_file() {
                ensure!(
                    relative.to_string_lossy()
                        == "operations/randao/pyspec_tests/hash_chain_reveal_consumes_one_link_per_block",
                    "unexpected missing fixture: {}",
                    relative.display()
                );
                two_link_property::<P>(config, &cache, &root)?;
                properties += 1;
                writeln!(
                    report,
                    "PROPERTY_PASS\t{}\tupstream emits no SSZ; equivalent two-link property executed separately",
                    relative.display()
                )?;
                continue;
            }
            let case = Case::from(path.to_str().expect("UTF-8 fixture path"));
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                execute::<P>(config, &cache, case, &category)
            }))
            .unwrap_or_else(|panic| {
                Err(anyhow::anyhow!(
                    "PANIC: {}",
                    panic
                        .downcast_ref::<String>()
                        .map(String::as_str)
                        .or_else(|| panic.downcast_ref::<&str>().copied())
                        .unwrap_or("unknown")
                ))
            });
            let group = groups.entry(category).or_default();
            match result {
                Ok(()) => {
                    passed += 1;
                    group.0 += 1;
                    writeln!(report, "PASS\t{}\t", relative.display())?;
                }
                Err(e) => {
                    failed += 1;
                    group.1 += 1;
                    writeln!(report, "FAIL\t{}\t{e:#}", relative.display())?;
                }
            }
        }
        for (cat, (p, f)) in groups {
            eprintln!("{preset}/{cat}: {p} passed, {f} failed");
        }
        eprintln!(
            "{preset}: {passed} vector cases passed, {failed} failed, {properties} local properties passed, {outside} client/network manifests outside scope; report {}",
            out.display()
        );
        ensure!(passed + failed > 0, "filter selected zero cases");
        ensure!(
            failed == 0,
            "{preset}: {failed} of {} manifests failed; see report",
            passed + failed
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires all bundled EIP-8321 fixtures; use vectors-all mode"]
    fn official_all_minimal() -> Result<()> {
        run::<Minimal>(
            "minimal",
            &Config::minimal().upgrade_once(types::nonstandard::Phase::Gloas, 0),
        )
    }

    #[test]
    #[ignore = "requires all bundled EIP-8321 fixtures; use vectors-all mode"]
    fn official_all_mainnet() -> Result<()> {
        run::<Mainnet>(
            "mainnet",
            &Config::mainnet().upgrade_once(types::nonstandard::Phase::Gloas, 0),
        )
    }
}
