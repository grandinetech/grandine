use anyhow::{ensure, Result};
use execution_engine::{ExecutionEngine, NullExecutionEngine};
use helper_functions::{
    accessors::{
        attestation_epoch, get_current_epoch, get_randao_mix, initialize_shuffled_indices,
    },
    error::SignatureKind,
    misc::{compute_epoch_at_slot, compute_timestamp_at_slot, kzg_commitment_to_versioned_hash},
    phase0::get_indexed_attestation,
    predicates::validate_constructed_indexed_attestation,
    slot_report::SlotReport,
    verifier::{Triple, Verifier},
};
use prometheus_metrics::METRICS;
use rayon::iter::{IntoParallelRefIterator as _, ParallelIterator as _};
use ssz::SszHash as _;
use typenum::Unsigned as _;
use types::{
    combined::ExecutionPayloadParams,
    config::Config,
    deneb::{
        beacon_state::BeaconState as DenebBeaconState,
        containers::{BeaconBlock, BeaconBlockBody, ExecutionPayloadHeader},
    },
    nonstandard::AttestationEpoch,
    phase0::{
        containers::{Attestation, AttestationData},
        primitives::H256,
    },
    preset::Preset,
    traits::{
        BeaconState, PostCapellaBeaconBlockBody, PostCapellaBeaconState, PreElectraBeaconBlockBody,
    },
};

use crate::{
    altair, bellatrix, capella,
    unphased::{self, Error},
};

/// [`process_block`](TODO(feature/deneb))
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
    state: &mut DenebBeaconState<P>,
    block: &BeaconBlock<P>,
    mut verifier: impl Verifier,
    slot_report: impl SlotReport,
) -> Result<()> {
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.block_transition_times.start_timer());

    verifier.reserve(count_required_signatures(block));

    custom_process_block(
        config,
        state,
        block,
        NullExecutionEngine,
        &mut verifier,
        slot_report,
    )?;

    verifier.finish()
}

// TODO(feature/deneb): Reuse function from `transition_functions::capella::block_processing`.
pub fn count_required_signatures<P: Preset>(block: &BeaconBlock<P>) -> usize {
    altair::count_required_signatures(block) + block.body.bls_to_execution_changes.len()
}

pub fn custom_process_block<P: Preset>(
    config: &Config,
    state: &mut DenebBeaconState<P>,
    block: &BeaconBlock<P>,
    execution_engine: impl ExecutionEngine<P>,
    mut verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.slot);

    unphased::process_block_header(state, block)?;

    capella::process_withdrawals(state, &block.body.execution_payload)?;

    // > [Modified in Deneb]
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

    unphased::process_randao(config, state, &block.body, &mut verifier)?;
    unphased::process_eth1_data(state, &block.body)?;

    process_operations(config, state, &block.body, &mut verifier, &mut slot_report)?;

    altair::process_sync_aggregate(
        config,
        state,
        block.body.sync_aggregate,
        verifier,
        slot_report,
    )
}

fn process_execution_payload<P: Preset>(
    config: &Config,
    state: &mut DenebBeaconState<P>,
    block_root: H256,
    body: &BeaconBlockBody<P>,
    execution_engine: impl ExecutionEngine<P>,
) -> Result<()> {
    let payload = &body.execution_payload;

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

    // > Verify timestamp
    let computed = compute_timestamp_at_slot(config, state, state.slot);
    let in_block = payload.timestamp;

    ensure!(
        computed == in_block,
        Error::<P>::ExecutionPayloadTimestampMismatch { computed, in_block },
    );

    // > [New in Deneb:EIP4844] Verify commitments are under limit
    let maximum = P::MaxBlobsPerBlock::USIZE;
    let in_block = body.blob_kzg_commitments.len();

    ensure!(
        in_block <= maximum,
        Error::<P>::TooManyBlockKzgCommitments { in_block },
    );

    // TODO(feature/deneb): Verify `is_valid_block_hash`.
    // TODO(feature/deneb): Verify `versioned_hashes`.
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
        Some(ExecutionPayloadParams::Deneb {
            versioned_hashes,
            parent_beacon_block_root: state.latest_block_header.parent_root,
        }),
        None,
    )?;

    // > Cache execution payload header
    state.latest_execution_payload_header = ExecutionPayloadHeader::from(payload);

    Ok(())
}

pub fn process_operations<P: Preset, V: Verifier>(
    config: &Config,
    state: &mut impl PostCapellaBeaconState<P>,
    body: &(impl PostCapellaBeaconBlockBody<P> + PreElectraBeaconBlockBody<P>),
    mut verifier: V,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    // > Verify that outstanding deposits are processed up to the maximum number of deposits
    let computed =
        P::MaxDeposits::U64.min(state.eth1_data().deposit_count - state.eth1_deposit_index());
    let in_block = body.deposits().len().try_into()?;

    ensure!(
        computed == in_block,
        Error::<P>::DepositCountMismatch { computed, in_block },
    );

    for proposer_slashing in body.proposer_slashings().iter().copied() {
        bellatrix::process_proposer_slashing(
            config,
            state,
            proposer_slashing,
            &mut verifier,
            &mut slot_report,
        )?;
    }

    for attester_slashing in body.attester_slashings() {
        bellatrix::process_attester_slashing(
            config,
            state,
            attester_slashing,
            &mut verifier,
            &mut slot_report,
        )?;
    }

    // Parallel iteration with Rayon has some overhead, which is most noticeable when the active
    // thread pool is busy. `ParallelIterator::collect` appears to wait for worker threads to become
    // available even if the current thread is itself a worker thread. This tends to happen when
    // verifying signatures for batches of blocks outside the state transition function.
    // Fortunately, the other validations in `validate_attestation_with_verifier` take a negligible
    // amount of time, so we can avoid the issue by running them sequentially.
    if V::IS_NULL {
        for attestation in body.attestations() {
            validate_attestation_with_verifier(config, state, attestation, &mut verifier)?;
        }
    } else {
        initialize_shuffled_indices(state, body.attestations().iter())?;

        let triples = body
            .attestations()
            .par_iter()
            .map(|attestation| {
                let mut triple = Triple::default();

                validate_attestation_with_verifier(config, state, attestation, &mut triple)?;

                Ok(triple)
            })
            .collect::<Result<Vec<_>>>()?;

        verifier.extend(triples, SignatureKind::Attestation)?;
    }

    for attestation in body.attestations() {
        altair::apply_attestation(state, attestation, &mut slot_report)?;
    }

    // The conditional is not needed for correctness.
    // It only serves to avoid overhead when processing blocks with no deposits.
    if !body.deposits().is_empty() {
        let combined_deposits =
            unphased::validate_deposits(config, state, body.deposits().iter().copied())?;

        altair::apply_deposits(state, body.deposits().len(), combined_deposits, slot_report)?;
    }

    for voluntary_exit in body.voluntary_exits().iter().copied() {
        unphased::process_voluntary_exit(config, state, voluntary_exit, &mut verifier)?;
    }

    for bls_to_execution_change in body.bls_to_execution_changes().iter().copied() {
        capella::process_bls_to_execution_change(
            config,
            state,
            bls_to_execution_change,
            &mut verifier,
        )?;
    }

    Ok(())
}

pub fn validate_attestation_with_verifier<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
    verifier: impl Verifier,
) -> Result<()> {
    let AttestationData {
        slot: attestation_slot,
        source,
        target,
        ..
    } = attestation.data;

    let attestation_epoch = attestation_epoch(state, target.epoch)?;

    // Cause a compilation error if a new variant is added to `AttestationEpoch`.
    // Blocks cannot contain attestations from the future or epochs before the previous one.
    match attestation_epoch {
        AttestationEpoch::Previous | AttestationEpoch::Current => {}
    }

    ensure!(
        target.epoch == compute_epoch_at_slot::<P>(attestation_slot),
        Error::AttestationTargetsWrongEpoch {
            attestation: attestation.clone().into(),
        },
    );

    ensure!(
        attestation_slot + P::MIN_ATTESTATION_INCLUSION_DELAY.get() <= state.slot(),
        Error::<P>::AttestationOutsideInclusionRange {
            state_slot: state.slot(),
            attestation_slot,
        },
    );

    // Don't check the length of `attestation.aggregation_bits`.
    // It's already done in `get_attesting_indices`, which is called by `get_indexed_attestation`.

    let in_state = match attestation_epoch {
        AttestationEpoch::Previous => state.previous_justified_checkpoint(),
        AttestationEpoch::Current => state.current_justified_checkpoint(),
    };
    let in_block = source;

    ensure!(
        in_state == in_block,
        Error::<P>::AttestationSourceMismatch { in_state, in_block },
    );

    let indexed_attestation = get_indexed_attestation(state, attestation)?;

    // > Verify signature
    validate_constructed_indexed_attestation(config, state, &indexed_attestation, verifier)
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
        phase0::containers::{Attestation, AttesterSlashing, Deposit},
        preset::{Mainnet, Minimal},
    };

    use super::*;

    use crate::bellatrix;

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
        |_, state, block: BeaconBlock<_>, _| unphased::process_block_header(state, &block),
        "block",
        "consensus-spec-tests/tests/mainnet/deneb/operations/block_header/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/block_header/*/*",
    }

    processing_tests! {
        process_proposer_slashing,
        |config, state, proposer_slashing, _| {
            bellatrix::process_proposer_slashing(
                config,
                state,
                proposer_slashing,
                SingleVerifier,
                NullSlotReport,
            )
        },
        "proposer_slashing",
        "consensus-spec-tests/tests/mainnet/deneb/operations/proposer_slashing/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/proposer_slashing/*/*",
    }

    processing_tests! {
        process_attester_slashing,
        |config, state, attester_slashing: AttesterSlashing<P>, _| {
            bellatrix::process_attester_slashing(
                config,
                state,
                &attester_slashing,
                SingleVerifier,
                NullSlotReport,
            )
        },
        "attester_slashing",
        "consensus-spec-tests/tests/mainnet/deneb/operations/attester_slashing/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/attester_slashing/*/*",
    }

    processing_tests! {
        process_attestation,
        |config, state, attestation, bls_setting| {
            process_attestation(
                config,
                state,
                &attestation,
                bls_setting,
            )
        },
        "attestation",
        "consensus-spec-tests/tests/mainnet/deneb/operations/attestation/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/attestation/*/*",
    }

    processing_tests! {
        process_bls_to_execution_change,
        |config, state, bls_to_execution_change, _| {
            capella::process_bls_to_execution_change(
                config,
                state,
                bls_to_execution_change,
                SingleVerifier,
            )
        },
        "address_change",
        "consensus-spec-tests/tests/mainnet/deneb/operations/bls_to_execution_change/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/bls_to_execution_change/*/*",
    }

    processing_tests! {
        process_deposit,
        |config, state, deposit, _| process_deposit(config, state, deposit),
        "deposit",
        "consensus-spec-tests/tests/mainnet/deneb/operations/deposit/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/deposit/*/*",
    }

    // `process_deposit_data` reimplements deposit validation differently for performance reasons,
    // so we need to test it separately.
    processing_tests! {
        process_deposit_data,
        |config, state, deposit, _| {
            unphased::verify_deposit_merkle_branch(state, state.eth1_deposit_index, deposit)?;
            altair::process_deposit_data(config, state, deposit.data)?;
            Ok(())
        },
        "deposit",
        "consensus-spec-tests/tests/mainnet/deneb/operations/deposit/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/deposit/*/*",
    }

    processing_tests! {
        process_voluntary_exit,
        |config, state, voluntary_exit, _| {
            unphased::process_voluntary_exit(
                config,
                state,
                voluntary_exit,
                SingleVerifier,
            )
        },
        "voluntary_exit",
        "consensus-spec-tests/tests/mainnet/deneb/operations/voluntary_exit/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/voluntary_exit/*/*",
    }

    processing_tests! {
        process_sync_aggregate,
        |config, state, sync_aggregate, _| {
            altair::process_sync_aggregate(
                config,
                state,
                sync_aggregate,
                SingleVerifier,
                NullSlotReport,
            )
        },
        "sync_aggregate",
        "consensus-spec-tests/tests/mainnet/deneb/operations/sync_aggregate/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/sync_aggregate/*/*",
    }

    validation_tests! {
        validate_proposer_slashing,
        |config, state, proposer_slashing| {
            unphased::validate_proposer_slashing(config, state, proposer_slashing)
        },
        "proposer_slashing",
        "consensus-spec-tests/tests/mainnet/deneb/operations/proposer_slashing/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/proposer_slashing/*/*",
    }

    validation_tests! {
        validate_attester_slashing,
        |config, state, attester_slashing: AttesterSlashing<P>| {
            unphased::validate_attester_slashing(config, state, &attester_slashing)
        },
        "attester_slashing",
        "consensus-spec-tests/tests/mainnet/deneb/operations/attester_slashing/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/attester_slashing/*/*",
    }

    validation_tests! {
        validate_voluntary_exit,
        |config, state, voluntary_exit| {
            unphased::validate_voluntary_exit(config, state, voluntary_exit)
        },
        "voluntary_exit",
        "consensus-spec-tests/tests/mainnet/deneb/operations/voluntary_exit/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/voluntary_exit/*/*",
    }

    // TODO(feature/deneb): comment this & run missing test script
    validation_tests! {
        validate_bls_to_execution_change,
        |config, state, bls_to_execution_change| {
            capella::validate_bls_to_execution_change(config, state, bls_to_execution_change)
        },
        "address_change",
        "consensus-spec-tests/tests/mainnet/deneb/operations/bls_to_execution_change/*/*",
        "consensus-spec-tests/tests/minimal/deneb/operations/bls_to_execution_change/*/*",
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/deneb/operations/execution_payload/*/*")]
    fn mainnet_execution_payload(case: Case) {
        run_execution_payload_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/deneb/operations/execution_payload/*/*")]
    fn minimal_execution_payload(case: Case) {
        run_execution_payload_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/deneb/operations/withdrawals/*/*")]
    fn mainnet_withdrawals(case: Case) {
        run_withdrawals_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/deneb/operations/withdrawals/*/*")]
    fn minimal_withdrawals(case: Case) {
        run_withdrawals_case::<Minimal>(case);
    }

    fn run_processing_case<P: Preset, O: SszReadDefault>(
        case: Case,
        operation_name: &str,
        processing_function: impl FnOnce(&Config, &mut DenebBeaconState<P>, O, BlsSetting) -> Result<()>,
    ) {
        let mut state = case.ssz_default("pre");
        let operation = case.ssz_default(operation_name);
        let post_option = case.try_ssz_default("post");
        let bls_setting = case.meta().bls_setting;

        let result = processing_function(&P::default_config(), &mut state, operation, bls_setting)
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
        validation_function: impl FnOnce(&Config, &mut DenebBeaconState<P>, O) -> Result<R>,
    ) {
        let mut state = case.ssz_default("pre");
        let operation = case.ssz_default(operation_name);
        let post_exists = case.exists("post");

        let result = validation_function(&P::default_config(), &mut state, operation);

        if post_exists {
            result.expect("validation should succeed");
        } else {
            result.expect_err("validation should fail");
        }
    }

    fn run_execution_payload_case<P: Preset>(case: Case) {
        let mut state = case.ssz_default::<DenebBeaconState<P>>("pre");
        let body = case.ssz_default("body");
        let post_option = case.try_ssz_default("post");
        let Execution { execution_valid } = case.yaml("execution");
        let execution_engine = MockExecutionEngine::new(execution_valid, false);

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
        let mut state = case.ssz_default::<DenebBeaconState<P>>("pre");
        let payload = case.ssz_default::<ExecutionPayload<P>>("execution_payload");
        let post_option = case.try_ssz_default("post");

        let result = capella::process_withdrawals(&mut state, &payload).map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("withdrawals processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("withdrawals processing should fail");
        }
    }

    fn process_attestation<P: Preset>(
        config: &Config,
        state: &mut DenebBeaconState<P>,
        attestation: &Attestation<P>,
        bls_setting: BlsSetting,
    ) -> Result<()> {
        match bls_setting {
            BlsSetting::Optional | BlsSetting::Required => {
                validate_attestation_with_verifier(config, state, attestation, SingleVerifier)?
            }
            BlsSetting::Ignored => {
                validate_attestation_with_verifier(config, state, attestation, NullVerifier)?
            }
        }

        altair::apply_attestation(state, attestation, NullSlotReport)
    }

    fn process_deposit<P: Preset>(
        config: &Config,
        state: &mut DenebBeaconState<P>,
        deposit: Deposit,
    ) -> Result<()> {
        let combined_deposits =
            unphased::validate_deposits(config, state, core::iter::once(deposit))?;

        altair::apply_deposits(state, 1, combined_deposits, NullSlotReport)
    }
}
