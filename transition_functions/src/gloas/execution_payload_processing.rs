use anyhow::{Result, ensure};
use bls::{PublicKeyBytes, SignatureBytes};
use execution_engine::ExecutionEngine;
use helper_functions::{
    accessors::get_current_epoch,
    error::SignatureKind,
    misc::{self, compute_timestamp_at_slot, kzg_commitment_to_versioned_hash},
    mutators::{builder_balance, increase_balance},
    predicates::is_builder_withdrawal_credential,
    signing::{SignForAllForks as _, SignForSingleFork as _},
    verifier::Verifier,
};
use pubkey_cache::PubkeyCache;
use ssz::{H256, SszHash as _};
use typenum::Unsigned as _;
use types::{
    combined::ExecutionPayloadParams,
    config::Config,
    electra::containers::{DepositRequest, ExecutionRequests, PendingDeposit},
    gloas::{
        consts::BUILDER_INDEX_SELF_BUILD,
        containers::{
            Builder, BuilderPendingPayment, ExecutionPayloadEnvelope,
            SignedExecutionPayloadEnvelope,
        },
        primitives::BuilderIndex,
    },
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        containers::DepositMessage,
        primitives::{ExecutionAddress, Gwei},
    },
    preset::{Preset, SlotsPerHistoricalRoot},
    traits::PostGloasBeaconState,
};

use crate::{electra, unphased::Error};

pub fn verify_execution_payload_envelope_signature<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    signed_envelope: &SignedExecutionPayloadEnvelope<P>,
    mut verifier: impl Verifier,
) -> Result<()> {
    let builder_index = signed_envelope.message.builder_index;
    let pubkey = if builder_index == BUILDER_INDEX_SELF_BUILD {
        let validator_index = state.latest_block_header().proposer_index;
        state.validators().get(validator_index)?.pubkey
    } else {
        state.builders().get(builder_index)?.pubkey
    };

    verifier.verify_singular(
        signed_envelope.message.signing_root(config, state),
        signed_envelope.signature,
        pubkey_cache.get_or_insert(pubkey)?,
        SignatureKind::ExecutionPayloadEnvelope,
    )?;

    Ok(())
}

pub fn validate_execution_payload_envelope_for_gossip<P: Preset>(
    config: &Config,
    state: &impl PostGloasBeaconState<P>,
    envelope: &ExecutionPayloadEnvelope<P>,
) -> Result<()> {
    let payload = &envelope.payload;

    // > Verify timestamp
    let computed = compute_timestamp_at_slot(config, state, state.slot());
    let in_block = payload.timestamp;

    ensure!(
        computed == in_block,
        Error::<P>::ExecutionPayloadTimestampMismatch { computed, in_block },
    );

    // > [Modified in Fulu:EIP7594] Verify commitments are under limit
    // > [Modified in Fulu:EIP7892] BPO blob schedule
    let maximum = config
        .get_blob_schedule_entry(get_current_epoch(state))
        .max_blobs_per_block;
    let in_block = envelope.blob_kzg_commitments.len();

    ensure!(
        in_block <= maximum,
        Error::<P>::TooManyBlockKzgCommitments { in_block, maximum },
    );

    Ok(())
}

pub fn validate_execution_payload_envelope<P: Preset>(
    config: &Config,
    state: &impl PostGloasBeaconState<P>,
    signed_envelope: &SignedExecutionPayloadEnvelope<P>,
) -> Result<()> {
    let envelope = &signed_envelope.message;
    let payload = &envelope.payload;

    validate_execution_payload_envelope_for_gossip(config, state, envelope)?;

    // > Verify consistency with the beacon block
    let in_envelope = envelope.beacon_block_root;
    let in_state = state.latest_block_header().hash_tree_root();
    ensure!(
        in_envelope == in_state,
        Error::<P>::EnvelopeBlockRootMismatch {
            in_envelope,
            in_state,
        }
    );

    let in_envelope = envelope.slot;
    let in_state = state.slot();
    ensure!(
        in_envelope == in_state,
        Error::<P>::EnvelopeSlotMismatch {
            in_envelope,
            in_state,
        }
    );

    // > Verify consistency with the committed bid
    let committed_bid = state.latest_execution_payload_bid();
    let in_envelope = envelope.builder_index;
    let in_state = committed_bid.builder_index;
    ensure!(
        in_envelope == in_state,
        Error::<P>::EnvelopeBuilderMismatch {
            in_envelope,
            in_state,
        }
    );

    let in_envelope = envelope.blob_kzg_commitments.hash_tree_root();
    let in_state = committed_bid.blob_kzg_commitments_root;
    ensure!(
        in_envelope == in_state,
        Error::<P>::EnvelopeBlobCommitmentsMismatch {
            in_envelope,
            in_state,
        }
    );

    let in_state = committed_bid.prev_randao;
    let in_block = payload.prev_randao;
    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadPrevRandaoMismatch { in_state, in_block },
    );

    // > Verify the consistency with expected withdrawals
    let in_payload = payload.withdrawals.hash_tree_root();
    let in_state = state.payload_expected_withdrawals().hash_tree_root();
    ensure!(
        in_payload == in_state,
        Error::<P>::PayloadWithdrawalsMismatch {
            in_payload,
            in_state,
        }
    );

    // > Verify the gas_limit
    let in_payload = payload.gas_limit;
    let in_state = committed_bid.gas_limit;
    ensure!(
        in_payload == in_state,
        Error::<P>::PayloadGasLimitMismatch {
            in_payload,
            in_state,
        }
    );

    // > Verify the block hash
    let in_payload = payload.block_hash;
    let in_state = committed_bid.block_hash;
    ensure!(
        in_payload == in_state,
        Error::<P>::PayloadBlockHashMismatch {
            in_payload,
            in_state,
        }
    );

    // > Verify consistency of the parent hash with respect to the previous execution payload header
    let in_state = state.latest_block_hash();
    let in_block = payload.parent_hash;
    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadParentHashMismatch { in_state, in_block },
    );

    Ok(())
}

pub fn process_execution_payload<P: Preset, V: Verifier>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    signed_envelope: &SignedExecutionPayloadEnvelope<P>,
    execution_engine: impl ExecutionEngine<P>,
    verifier: V,
) -> Result<()> {
    if !V::IS_NULL {
        verify_execution_payload_envelope_signature(
            config,
            pubkey_cache,
            state,
            signed_envelope,
            verifier,
        )?;
    }

    let envelope = &signed_envelope.message;
    let payload = &envelope.payload;

    // > Cache latest block header state root
    let previous_state_root = state.hash_tree_root();
    if state.latest_block_header().state_root.is_zero() {
        state.latest_block_header_mut().state_root = previous_state_root;
    }

    validate_execution_payload_envelope(config, state, signed_envelope)?;

    // > Verify the execution payload is valid
    let versioned_hashes = envelope
        .blob_kzg_commitments
        .iter()
        .copied()
        .map(kzg_commitment_to_versioned_hash)
        .collect();

    execution_engine.notify_new_payload(
        envelope.beacon_block_root,
        payload.clone().into(),
        Some(ExecutionPayloadParams::Electra {
            versioned_hashes,
            parent_beacon_block_root: state.latest_block_header().parent_root,
            execution_requests: envelope.execution_requests.clone(),
        }),
        None,
    )?;

    process_execution_requests(config, pubkey_cache, state, &envelope.execution_requests)?;

    // > Queue the builder payment
    let payment_slot = misc::builder_payment_index_for_current_epoch::<P>(state.slot());
    let payment = *state.builder_pending_payments().get(payment_slot)?;
    let amount = payment.withdrawal.amount;
    if amount > 0 {
        state
            .builder_pending_withdrawals_mut()
            .push(payment.withdrawal)?;
    }
    *state
        .builder_pending_payments_mut()
        .mod_index_mut(payment_slot) = BuilderPendingPayment::default();

    // > Cache execution payload header
    let slot: usize = state.slot().try_into()?;
    state
        .execution_payload_availability_mut()
        .set(slot % SlotsPerHistoricalRoot::<P>::USIZE, true);
    *state.latest_block_hash_mut() = payload.block_hash;

    if !V::IS_NULL {
        let computed = state.hash_tree_root();
        let in_envelope = envelope.state_root;
        ensure!(
            in_envelope == computed,
            Error::<P>::StateRootMismatch {
                computed,
                in_block: in_envelope
            }
        );
    }

    Ok(())
}

fn process_execution_requests<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    execution_requests: &ExecutionRequests<P>,
) -> Result<()> {
    for deposit_request in &execution_requests.deposits {
        process_deposit_request(config, pubkey_cache, state, *deposit_request)?;
    }

    for withdrawal_request in &execution_requests.withdrawals {
        electra::process_withdrawal_request(config, state, *withdrawal_request)?;
    }

    for consolidation_request in &execution_requests.consolidations {
        electra::process_consolidation_request(config, state, *consolidation_request)?;
    }

    Ok(())
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
pub fn process_deposit_request<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    deposit_request: DepositRequest,
) -> Result<()> {
    let DepositRequest {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        ..
    } = deposit_request;

    // > Regardless of the withdrawal credentials prefix, if a builder/validator
    //   already exists with this pubkey, apply the deposit to their balance
    if state
        .builders()
        .into_iter()
        .any(|builder| builder.pubkey == pubkey)
        || (is_builder_withdrawal_credential(withdrawal_credentials)
            && !state
                .validators()
                .into_iter()
                .any(|validator| validator.pubkey == pubkey))
    {
        apply_deposit_for_builder(
            config,
            pubkey_cache,
            state,
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
        )?;
    } else {
        let slot = state.slot();

        state.pending_deposits_mut().push(PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            slot,
        })?;
    }

    Ok(())
}

pub fn apply_deposit_for_builder<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    pubkey: PublicKeyBytes,
    withdrawal_credentials: H256,
    amount: Gwei,
    signature: SignatureBytes,
) -> Result<()> {
    if let Some(builder_index) = state
        .builders()
        .into_iter()
        .position(|builder| builder.pubkey == pubkey)
    {
        let builder_index = builder_index.try_into()?;

        increase_balance(builder_balance(state, builder_index)?, amount);
    } else {
        // > Verify the deposit signature (proof of possession)
        // > which is not checked by the deposit contract
        let deposit_message = DepositMessage {
            pubkey,
            withdrawal_credentials,
            amount,
        };

        // > Fork-agnostic domain since deposits are valid across forks
        if let Ok(decompressed) = pubkey_cache.get_or_insert(pubkey)
            && deposit_message
                .verify(config, signature, decompressed)
                .is_ok()
        {
            add_builder_to_registry(state, pubkey, withdrawal_credentials, amount)?;
        }
    }

    Ok(())
}

pub fn add_builder_to_registry<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    pubkey: PublicKeyBytes,
    withdrawal_credentials: H256,
    amount: Gwei,
) -> Result<()> {
    let builder_index = get_index_for_new_builder(state);
    let builder = get_builder_from_deposit(state, pubkey, withdrawal_credentials, amount);

    if builder_index == state.builders().len_u64() {
        state.builders_mut().push(builder)?;
    } else {
        *state.builders_mut().get_mut(builder_index)? = builder;
    }

    // TODO(gloas): Should builder indices be cached like validators?
    // if so, it need to pruned since builder index is reusable. remove this TODO if not
    Ok(())
}

fn get_index_for_new_builder<P: Preset>(state: &impl PostGloasBeaconState<P>) -> BuilderIndex {
    let current_epoch = get_current_epoch(state);

    state
        .builders()
        .into_iter()
        .zip(0..)
        .find_map(|(builder, index)| {
            (builder.withdrawable_epoch <= current_epoch && builder.balance == 0).then_some(index)
        })
        .unwrap_or_else(|| state.builders().len_u64())
}

fn get_builder_from_deposit<P: Preset>(
    state: &impl PostGloasBeaconState<P>,
    pubkey: PublicKeyBytes,
    withdrawal_credentials: H256,
    amount: Gwei,
) -> Builder {
    let version = withdrawal_credentials[0];
    let mut address = ExecutionAddress::zero();
    address.assign_from_slice(&withdrawal_credentials[12..]);

    Builder {
        pubkey,
        version,
        execution_address: address,
        balance: amount,
        deposit_epoch: get_current_epoch(state),
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    }
}

#[cfg(test)]
mod spec_tests {
    use execution_engine::MockExecutionEngine;
    use helper_functions::verifier::SingleVerifier;
    use serde::Deserialize;
    use spec_test_utils::{BlsSetting, Case};
    use ssz::SszReadDefault;
    use test_generator::test_resources;
    use types::{
        gloas::beacon_state::BeaconState,
        preset::{Mainnet, Minimal},
    };

    use super::*;

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

    processing_tests! {
        process_deposit_request,
        |config, pubkey_cache, state, deposit_request, _| process_deposit_request(config, pubkey_cache, state, deposit_request),
        "deposit_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/deposit_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/deposit_request/*/*",
    }

    processing_tests! {
        process_withdrawal_request,
        |config, _, state, withdrawal_request, _| electra::process_withdrawal_request(config, state, withdrawal_request),
        "withdrawal_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/withdrawal_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/withdrawal_request/*/*",
    }

    processing_tests! {
        process_consolidation_request,
        |config, _, state, consolidation_request, _| electra::process_consolidation_request(config, state, consolidation_request),
        "consolidation_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/consolidation_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/consolidation_request/*/*",
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/gloas/operations/execution_payload/*/*")]
    fn mainnet_execution_payload(case: Case) {
        run_execution_payload_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/gloas/operations/execution_payload/*/*")]
    fn minimal_execution_payload(case: Case) {
        run_execution_payload_case::<Minimal>(case);
    }

    fn run_execution_payload_case<P: Preset>(case: Case) {
        let mut state = case.ssz_default::<BeaconState<P>>("pre");
        let signed_envelope = case.ssz_default("signed_envelope");
        let post_option = case.try_ssz_default("post");
        let Execution { execution_valid } = case.yaml("execution");
        let execution_engine = MockExecutionEngine::new(execution_valid, false, None);
        let pubkey_cache = PubkeyCache::default();

        let result = process_execution_payload(
            &P::default_config(),
            &pubkey_cache,
            &mut state,
            &signed_envelope,
            &execution_engine,
            SingleVerifier,
        )
        .map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("execution payload processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("execution payload processing should fail");
        }
    }

    fn run_processing_case<P: Preset, O: SszReadDefault>(
        case: Case,
        operation_name: &str,
        processing_function: impl FnOnce(
            &Config,
            &PubkeyCache,
            &mut BeaconState<P>,
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
}
