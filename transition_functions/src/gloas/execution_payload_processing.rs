use std::collections::HashMap;

use anyhow::{Result, ensure};
use bls::{PublicKeyBytes, SignatureBytes};
use helper_functions::{
    error::SignatureKind, gloas::apply_deposit_for_builder, misc::compute_timestamp_at_slot,
    predicates::is_builder_withdrawal_credential, signing::SignForSingleFork as _,
    verifier::Verifier,
};
use pubkey_cache::PubkeyCache;
use ssz::SszHash as _;
use types::{
    config::Config,
    electra::containers::{DepositRequest, ExecutionRequests, PendingDeposit},
    gloas::{
        consts::BUILDER_INDEX_SELF_BUILD,
        containers::{ExecutionPayloadEnvelope, SignedExecutionPayloadEnvelope},
    },
    phase0::containers::DepositMessage,
    preset::Preset,
    traits::PostGloasBeaconState,
};

use crate::{electra, unphased::Error};

type DepositSignatureCache = HashMap<(DepositMessage, SignatureBytes), bool>;

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

    let in_envelope = envelope.payload.slot_number;
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

    // > Verify execution requests against committed bid
    let computed = envelope.execution_requests.hash_tree_root();
    let expected = state.latest_execution_payload_bid().execution_requests_root;

    ensure!(
        computed == expected,
        Error::<P>::ExecutionRequestsRootMismatch { computed, expected },
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

pub fn process_execution_requests<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    execution_requests: &ExecutionRequests<P>,
) -> Result<()> {
    let mut signature_cache = DepositSignatureCache::new();

    for deposit_request in &execution_requests.deposits {
        process_deposit_request(
            config,
            pubkey_cache,
            state,
            *deposit_request,
            &mut signature_cache,
        )?;
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
    signature_cache: &mut DepositSignatureCache,
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
                .any(|validator| validator.pubkey == pubkey)
            && !is_pending_validator(config, pubkey_cache, state, pubkey, signature_cache))
    {
        apply_deposit_for_builder(
            config,
            pubkey_cache,
            state,
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            state.slot(),
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

fn is_pending_validator<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    pubkey: PublicKeyBytes,
    signature_cache: &mut DepositSignatureCache,
) -> bool {
    for deposit in state.pending_deposits() {
        if deposit.pubkey != pubkey {
            continue;
        }

        let PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            ..
        } = *deposit;

        let deposit_message = DepositMessage {
            pubkey,
            withdrawal_credentials,
            amount,
        };

        if *signature_cache
            .entry((deposit_message, signature))
            .or_insert_with(|| electra::is_valid_deposit_signature(config, pubkey_cache, deposit))
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod spec_tests {
    use spec_test_utils::{BlsSetting, Case};
    use ssz::SszReadDefault;
    use test_generator::test_resources;
    use types::{
        gloas::beacon_state::BeaconState,
        preset::{Mainnet, Minimal},
    };

    use super::*;

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
        |config, pubkey_cache, state, deposit_request, _| process_deposit_request(config, pubkey_cache, state, deposit_request, &mut HashMap::new()),
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
