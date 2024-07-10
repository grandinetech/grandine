use anyhow::{ensure, Result};
use execution_engine::{ExecutionEngine, NullExecutionEngine};
use helper_functions::{
    accessors::{self, get_current_epoch, get_randao_mix},
    error::SignatureKind,
    misc::{compute_timestamp_at_slot, kzg_commitment_to_versioned_hash},
    signing::SignForSingleFork as _,
    slot_report::SlotReport,
    verifier::{SingleVerifier, Verifier},
};
use pubkey_cache::PubkeyCache;
use ssz::SszHash as _;
use types::{
    combined::ExecutionPayloadParams,
    config::Config,
    deneb::containers::ExecutionPayloadHeader,
    fulu::{
        beacon_state::BeaconState as FuluBeaconState,
        containers::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock},
    },
    phase0::primitives::H256,
    preset::Preset,
};

use crate::{
    altair, electra,
    unphased::{self, Error},
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

/// [`process_block`](TODO(feature/electra))
///
/// This also serves as a substitute for [`compute_new_state_root`]. `compute_new_state_root` as
/// defined in `consensus-specs` uses `state_transition`, but in practice `state` will already be
/// processed up to `block.slot`, which would make `process_slots` fail due to the restriction added
/// in [version 0.11.3]. `consensus-specs` [originally used `process_block`] but it was [lost].
///
/// [`compute_new_state_root`]:        https://github.com/ethereum/consensus-specs/blob/2ef55744df782eb153fc0a3b1c7875b8c2e11730/specs/phase0/validator.md#state-root
/// [version 0.11.3]:                  https://github.com/ethereum/consensus-specs/releases/tag/v0.11.3
/// [originally used `process_block`]: https://github.com/ethereum/consensus-specs/commit/103a66b2af9d9ec1fd1c70adc8e9029af5775c1c#diff-abbdef70b08ada829d740f06c004c154R298-R301
/// [lost]:                            https://github.com/ethereum/consensus-specs/commit/2dbc33327084d2814958f92eb0a838b9bc161903#diff-e96c612010477fc9536e3ff1ef1a1d5dR343-R346
pub fn process_block<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut FuluBeaconState<P>,
    block: &BeaconBlock<P>,
    mut verifier: impl Verifier,
    slot_report: impl SlotReport,
) -> Result<()> {
    #[cfg(feature = "metrics")]
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.block_transition_times.start_timer());

    verifier.reserve(count_required_signatures(block));

    custom_process_block(
        config,
        pubkey_cache,
        state,
        block,
        NullExecutionEngine,
        &mut verifier,
        slot_report,
    )?;

    verifier.finish()
}

pub fn process_block_for_gossip<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &FuluBeaconState<P>,
    block: &SignedBeaconBlock<P>,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.message.slot);

    unphased::process_block_header_for_gossip(config, state, &block.message)?;

    process_execution_payload_for_gossip(config, state, &block.message.body)?;

    let public_key = accessors::public_key(state, block.message.proposer_index)?;

    SingleVerifier.verify_singular(
        block.message.signing_root(config, state),
        block.signature,
        pubkey_cache.get_or_insert(*public_key)?,
        SignatureKind::Block,
    )?;

    Ok(())
}

// TODO(feature/electra): Reuse function from `transition_functions::capella::block_processing`.
pub fn count_required_signatures<P: Preset>(block: &BeaconBlock<P>) -> usize {
    altair::count_required_signatures(block) + block.body.bls_to_execution_changes.len()
}

pub fn custom_process_block<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut FuluBeaconState<P>,
    block: &BeaconBlock<P>,
    execution_engine: impl ExecutionEngine<P>,
    mut verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.slot);

    unphased::process_block_header(config, state, block)?;

    // > [Modified in Electra:EIP7251]
    electra::process_withdrawals(state, &block.body.execution_payload)?;

    // > [Modified in Electra:EIP6110]
    process_execution_payload(
        config,
        state,
        // TODO(Grandine Team): Try caching `block.hash_tree_root()`.
        //                      Also consider removing the parameter entirely.
        //                      It's only used for error reporting.
        //                      Perhaps it would be better to send the whole block?
        block.hash_tree_root(),
        &block.body,
        execution_engine,
    )?;

    unphased::process_randao(config, pubkey_cache, state, &block.body, &mut verifier)?;
    unphased::process_eth1_data(state, &block.body)?;

    // > [Modified in Electra:EIP6110:EIP7002:EIP7549:EIP7251]
    electra::process_operations(
        config,
        pubkey_cache,
        state,
        &block.body,
        &mut verifier,
        &mut slot_report,
    )?;

    // > [New in Electra:EIP6110]
    for deposit_request in &block.body.execution_requests.deposits {
        electra::process_deposit_request(state, *deposit_request)?;
    }

    // > [New in Electra:EIP7002:EIP7251]
    for withdrawal_request in &block.body.execution_requests.withdrawals {
        electra::process_withdrawal_request(config, state, *withdrawal_request)?;
    }

    // > [New in Electra:EIP7251]
    for consolidation_request in &block.body.execution_requests.consolidations {
        electra::process_consolidation_request(config, state, *consolidation_request)?;
    }

    altair::process_sync_aggregate(
        config,
        pubkey_cache,
        state,
        block.body.sync_aggregate,
        verifier,
        slot_report,
    )
}

fn process_execution_payload_for_gossip<P: Preset>(
    config: &Config,
    state: &FuluBeaconState<P>,
    body: &BeaconBlockBody<P>,
) -> Result<()> {
    let payload = &body.execution_payload;

    // > Verify timestamp
    let computed = compute_timestamp_at_slot(config, state, state.slot);
    let in_block = payload.timestamp;

    ensure!(
        computed == in_block,
        Error::<P>::ExecutionPayloadTimestampMismatch { computed, in_block },
    );

    // > [Modified in Fulu:EIP7594] Verify commitments are under limit
    let maximum = config.get_max_blobs_per_block(get_current_epoch(state))?;
    let in_block = body.blob_kzg_commitments.len();

    ensure!(
        in_block <= maximum,
        Error::<P>::TooManyBlockKzgCommitments { in_block, maximum },
    );

    Ok(())
}

fn process_execution_payload<P: Preset>(
    config: &Config,
    state: &mut FuluBeaconState<P>,
    block_root: H256,
    body: &BeaconBlockBody<P>,
    execution_engine: impl ExecutionEngine<P>,
) -> Result<()> {
    let payload = &body.execution_payload;
    let execution_requests = &body.execution_requests;

    // > Verify consistency of the parent hash with respect to the previous execution payload header
    let in_state = state.latest_execution_payload_header.block_hash;
    let in_block = payload.parent_hash;

    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadParentHashMismatch { in_state, in_block },
    );

    // > Verify prev_randao
    let in_state = get_randao_mix(state, get_current_epoch(state));
    let in_block = payload.prev_randao;

    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadPrevRandaoMismatch { in_state, in_block },
    );

    process_execution_payload_for_gossip(config, state, body)?;

    // > Verify the execution payload is valid
    let versioned_hashes = body
        .blob_kzg_commitments
        .iter()
        .copied()
        .map(kzg_commitment_to_versioned_hash)
        .collect();

    execution_engine.notify_new_payload(
        block_root,
        payload.clone().into(),
        Some(ExecutionPayloadParams::Electra {
            versioned_hashes,
            parent_beacon_block_root: state.latest_block_header.parent_root,
            execution_requests: execution_requests.clone(),
        }),
        None,
    )?;

    // > Cache execution payload header
    state.latest_execution_payload_header = ExecutionPayloadHeader::from(payload);

    Ok(())
}

#[cfg(test)]
mod spec_tests {
    use core::fmt::Debug;

    use execution_engine::MockExecutionEngine;
    use helper_functions::{
        slot_report::NullSlotReport,
        verifier::{NullVerifier, SingleVerifier},
    };
    use serde::Deserialize;
    use spec_test_utils::{BlsSetting, Case};
    use ssz::SszReadDefault;
    use test_generator::test_resources;
    use types::{
        deneb::containers::ExecutionPayload,
        electra::containers::{Attestation, AttesterSlashing},
        phase0::containers::Deposit,
        preset::{Mainnet, Minimal},
        traits::BeaconState as _,
    };

    use super::*;

    use crate::{capella, electra};

    // We only honor `bls_setting` in `Attestation` tests. They are the only ones that set it to 2.

    #[derive(Deserialize)]
    struct Execution {
        execution_valid: bool,
    }

    macro_rules! processing_tests {
        (
            $module_name: ident,
            $processing_function: expr,
            $operation_name: literal,
            $mainnet_glob: literal,
            $minimal_glob: literal,
        ) => {
            mod $module_name {
                use super::*;

                #[test_resources($mainnet_glob)]
                fn mainnet(case: Case) {
                    run_processing_case_specialized::<Mainnet>(case);
                }

                #[test_resources($minimal_glob)]
                fn minimal(case: Case) {
                    run_processing_case_specialized::<Minimal>(case);
                }

                fn run_processing_case_specialized<P: Preset>(case: Case) {
                    run_processing_case::<P, _>(case, $operation_name, $processing_function);
                }
            }
        };
    }

    macro_rules! validation_tests {
        (
            $module_name: ident,
            $validation_function: expr,
            $operation_name: literal,
            $mainnet_glob: literal,
            $minimal_glob: literal,
        ) => {
            mod $module_name {
                use super::*;

                #[test_resources($mainnet_glob)]
                fn mainnet(case: Case) {
                    run_validation_case_specialized::<Mainnet>(case);
                }

                #[test_resources($minimal_glob)]
                fn minimal(case: Case) {
                    run_validation_case_specialized::<Minimal>(case);
                }

                fn run_validation_case_specialized<P: Preset>(case: Case) {
                    run_validation_case::<P, _, _>(case, $operation_name, $validation_function);
                }
            }
        };
    }

    // Test files for `process_block_header` are named `block.*` and contain `BeaconBlock`s.
    processing_tests! {
        process_block_header,
        |config, _, state, block: BeaconBlock<_>, _| unphased::process_block_header(config, state, &block),
        "block",
        "consensus-spec-tests/tests/mainnet/fulu/operations/block_header/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/block_header/*/*",
    }

    processing_tests! {
        process_consolidation_request,
        |config, _, state, consolidation_request, _| electra::process_consolidation_request(config, state, consolidation_request),
        "consolidation_request",
        "consensus-spec-tests/tests/mainnet/fulu/operations/consolidation_request/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/consolidation_request/*/*",
    }

    processing_tests! {
        process_proposer_slashing,
        |config, pubkey_cache, state, proposer_slashing, _| {
            electra::process_proposer_slashing(
                config,
                pubkey_cache,
                state,
                proposer_slashing,
                SingleVerifier,
                NullSlotReport,
            )
        },
        "proposer_slashing",
        "consensus-spec-tests/tests/mainnet/fulu/operations/proposer_slashing/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/proposer_slashing/*/*",
    }

    processing_tests! {
        process_attester_slashing,
        |config, pubkey_cache, state, attester_slashing: AttesterSlashing<P>, _| {
            electra::process_attester_slashing(
                config,
                pubkey_cache,
                state,
                &attester_slashing,
                SingleVerifier,
                NullSlotReport,
            )
        },
        "attester_slashing",
        "consensus-spec-tests/tests/mainnet/fulu/operations/attester_slashing/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/attester_slashing/*/*",
    }

    processing_tests! {
        process_attestation,
        |config, pubkey_cache, state, attestation, bls_setting| {
            process_attestation(
                config,
                pubkey_cache,
                state,
                &attestation,
                bls_setting,
            )
        },
        "attestation",
        "consensus-spec-tests/tests/mainnet/fulu/operations/attestation/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/attestation/*/*",
    }

    processing_tests! {
        process_bls_to_execution_change,
        |config, pubkey_cache, state, bls_to_execution_change, _| {
            capella::process_bls_to_execution_change(
                config,
                pubkey_cache,
                state,
                bls_to_execution_change,
                SingleVerifier,
            )
        },
        "address_change",
        "consensus-spec-tests/tests/mainnet/fulu/operations/bls_to_execution_change/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/bls_to_execution_change/*/*",
    }

    processing_tests! {
        process_deposit,
        |config, pubkey_cache, state, deposit, _| process_deposit(config, pubkey_cache, state, deposit),
        "deposit",
        "consensus-spec-tests/tests/mainnet/fulu/operations/deposit/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/deposit/*/*",
    }

    // `process_deposit_data` reimplements deposit validation differently for performance reasons,
    // so we need to test it separately.
    processing_tests! {
        process_deposit_data,
        |config, pubkey_cache, state, deposit, _| {
            unphased::verify_deposit_merkle_branch(state, state.eth1_deposit_index, deposit)?;
            electra::process_deposit_data(config, pubkey_cache, state, deposit.data)?;
            Ok(())
        },
        "deposit",
        "consensus-spec-tests/tests/mainnet/fulu/operations/deposit/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/deposit/*/*",
    }

    processing_tests! {
        process_voluntary_exit,
        |config, pubkey_cache, state, voluntary_exit, _| {
            electra::process_voluntary_exit(
                config,
                pubkey_cache,
                state,
                voluntary_exit,
                SingleVerifier,
            )
        },
        "voluntary_exit",
        "consensus-spec-tests/tests/mainnet/fulu/operations/voluntary_exit/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/voluntary_exit/*/*",
    }

    processing_tests! {
        process_sync_aggregate,
        |config, pubkey_cache, state, sync_aggregate, _| {
            altair::process_sync_aggregate(
                config,
                pubkey_cache,
                state,
                sync_aggregate,
                SingleVerifier,
                NullSlotReport,
            )
        },
        "sync_aggregate",
        "consensus-spec-tests/tests/mainnet/fulu/operations/sync_aggregate/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/sync_aggregate/*/*",
    }

    processing_tests! {
        process_deposit_request,
        |_, _, state, deposit_request, _| electra::process_deposit_request(state, deposit_request),
        "deposit_request",
        "consensus-spec-tests/tests/mainnet/fulu/operations/deposit_request/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/deposit_request/*/*",
    }

    processing_tests! {
        process_withdrawal_request,
        |config, _, state, withdrawal_request, _| electra::process_withdrawal_request(config, state, withdrawal_request),
        "withdrawal_request",
        "consensus-spec-tests/tests/mainnet/fulu/operations/withdrawal_request/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/withdrawal_request/*/*",
    }

    validation_tests! {
        validate_proposer_slashing,
        |config, pubkey_cache, state, proposer_slashing| {
            unphased::validate_proposer_slashing(config, pubkey_cache, state, proposer_slashing)
        },
        "proposer_slashing",
        "consensus-spec-tests/tests/mainnet/fulu/operations/proposer_slashing/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/proposer_slashing/*/*",
    }

    validation_tests! {
        validate_attester_slashing,
        |config, pubkey_cache, state, attester_slashing: AttesterSlashing<P>| {
            unphased::validate_attester_slashing(config, pubkey_cache, state, &attester_slashing)
        },
        "attester_slashing",
        "consensus-spec-tests/tests/mainnet/fulu/operations/attester_slashing/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/attester_slashing/*/*",
    }

    validation_tests! {
        validate_voluntary_exit,
        |config, pubkey_cache, state, voluntary_exit| {
            electra::validate_voluntary_exit_with_verifier(config, pubkey_cache, state, voluntary_exit, SingleVerifier)
        },
        "voluntary_exit",
        "consensus-spec-tests/tests/mainnet/fulu/operations/voluntary_exit/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/voluntary_exit/*/*",
    }

    // TODO(feature/electra): comment this & run missing test script
    validation_tests! {
        validate_bls_to_execution_change,
        |config, pubkey_cache, state, bls_to_execution_change| {
            capella::validate_bls_to_execution_change(config, pubkey_cache, state, bls_to_execution_change)
        },
        "address_change",
        "consensus-spec-tests/tests/mainnet/fulu/operations/bls_to_execution_change/*/*",
        "consensus-spec-tests/tests/minimal/fulu/operations/bls_to_execution_change/*/*",
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/fulu/operations/execution_payload/*/*")]
    fn mainnet_execution_payload(case: Case) {
        run_execution_payload_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/fulu/operations/execution_payload/*/*")]
    fn minimal_execution_payload(case: Case) {
        run_execution_payload_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/fulu/operations/withdrawals/*/*")]
    fn mainnet_withdrawals(case: Case) {
        run_withdrawals_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/fulu/operations/withdrawals/*/*")]
    fn minimal_withdrawals(case: Case) {
        run_withdrawals_case::<Minimal>(case);
    }

    fn run_processing_case<P: Preset, O: SszReadDefault>(
        case: Case,
        operation_name: &str,
        processing_function: impl FnOnce(
            &Config,
            &PubkeyCache,
            &mut FuluBeaconState<P>,
            O,
            BlsSetting,
        ) -> Result<()>,
    ) {
        let pubkey_cache = PubkeyCache::default();
        let mut state = case.ssz_default("pre");
        let operation = case.ssz_default(operation_name);
        let post_option = case.try_ssz_default("post");
        let bls_setting = case.meta().bls_setting;

        let result = processing_function(
            &P::default_config(),
            &pubkey_cache,
            &mut state,
            operation,
            bls_setting,
        )
        .map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("operation processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("operation processing should fail");
        }
    }

    fn run_validation_case<P: Preset, O: SszReadDefault, R: Debug>(
        case: Case,
        operation_name: &str,
        validation_function: impl FnOnce(&Config, &PubkeyCache, &mut FuluBeaconState<P>, O) -> Result<R>,
    ) {
        let pubkey_cache = PubkeyCache::default();
        let mut state = case.ssz_default("pre");
        let operation = case.ssz_default(operation_name);
        let post_exists = case.exists("post");

        let result =
            validation_function(&P::default_config(), &pubkey_cache, &mut state, operation);

        if post_exists {
            result.expect("validation should succeed");
        } else {
            result.expect_err("validation should fail");
        }
    }

    fn run_execution_payload_case<P: Preset>(case: Case) {
        let mut state = case.ssz_default::<FuluBeaconState<P>>("pre");
        let body = case.ssz_default("body");
        let post_option = case.try_ssz_default("post");
        let Execution { execution_valid } = case.yaml("execution");
        let execution_engine = MockExecutionEngine::new(execution_valid, false, None);

        let result = process_execution_payload(
            &P::default_config(),
            &mut state,
            H256::default(),
            &body,
            &execution_engine,
        )
        .map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("execution payload processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("execution payload processing should fail");
        }
    }

    fn run_withdrawals_case<P: Preset>(case: Case) {
        let mut state = case.ssz_default::<FuluBeaconState<P>>("pre");
        let payload = case.ssz_default::<ExecutionPayload<P>>("execution_payload");
        let post_option = case.try_ssz_default("post");

        let result = electra::process_withdrawals(&mut state, &payload).map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("withdrawals processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("withdrawals processing should fail");
        }
    }

    fn process_attestation<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut FuluBeaconState<P>,
        attestation: &Attestation<P>,
        bls_setting: BlsSetting,
    ) -> Result<()> {
        match bls_setting {
            BlsSetting::Optional | BlsSetting::Required => {
                electra::validate_attestation_with_verifier(
                    config,
                    pubkey_cache,
                    state,
                    attestation,
                    SingleVerifier,
                )?
            }
            BlsSetting::Ignored => electra::validate_attestation_with_verifier(
                config,
                pubkey_cache,
                state,
                attestation,
                NullVerifier,
            )?,
        }

        electra::apply_attestation(config, state, attestation, NullSlotReport)
    }

    fn process_deposit<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut FuluBeaconState<P>,
        deposit: Deposit,
    ) -> Result<()> {
        let combined_deposits =
            unphased::validate_deposits(config, pubkey_cache, state, core::iter::once(deposit))?;

        // > Deposits must be processed in order
        *state.eth1_deposit_index_mut() += 1;

        electra::apply_deposits(state, combined_deposits, NullSlotReport)
    }
}
