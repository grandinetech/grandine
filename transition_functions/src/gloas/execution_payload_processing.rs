use anyhow::{ensure, Result};
use execution_engine::ExecutionEngine;
use helper_functions::{
    accessors::{get_current_epoch, get_randao_mix},
    error::SignatureKind,
    gloas::compute_exit_epoch_and_update_churn,
    misc::{self, compute_timestamp_at_slot, kzg_commitment_to_versioned_hash},
    signing::SignForSingleFork as _,
    verifier::Verifier,
};
use pubkey_cache::PubkeyCache;
use ssz::{SszHash as _, H256};
use typenum::Unsigned as _;
use types::{
    combined::ExecutionPayloadParams,
    config::Config,
    gloas::containers::{
        BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadEnvelope,
        SignedExecutionPayloadEnvelope,
    },
    preset::{Preset, SlotsPerHistoricalRoot},
    traits::PostGloasBeaconState,
};

use crate::unphased::Error;

pub fn verify_execution_payload_envelope_signature<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    signed_envelope: &SignedExecutionPayloadEnvelope<P>,
    mut verifier: impl Verifier,
) -> Result<()> {
    let builder = state
        .validators()
        .get(signed_envelope.message.builder_index)?;

    verifier.verify_singular(
        signed_envelope.message.signing_root(config, state),
        signed_envelope.signature,
        pubkey_cache.get_or_insert(builder.pubkey)?,
        SignatureKind::ExecutionPayloadEnvelope,
    )?;

    Ok(())
}

pub fn validate_execution_payload_for_gossip<P: Preset>(
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

pub fn validate_execution_payload<P: Preset>(
    config: &Config,
    state: &impl PostGloasBeaconState<P>,
    signed_envelope: &SignedExecutionPayloadEnvelope<P>,
) -> Result<()> {
    let envelope = &signed_envelope.message;
    let payload = &envelope.payload;

    validate_execution_payload_for_gossip(config, state, envelope)?;

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

    // > Verify the withdrawals root
    let in_payload = payload.withdrawals.hash_tree_root();
    let in_state = state.latest_withdrawals_root();
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

    // > Verify prev_randao
    let in_state = get_randao_mix(state, get_current_epoch(state));
    let in_block = payload.prev_randao;
    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadPrevRandaoMismatch { in_state, in_block },
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
    if state.latest_block_header().state_root == H256::zero() {
        state.latest_block_header_mut().state_root = previous_state_root;
    }

    validate_execution_payload(config, state, signed_envelope)?;

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

    // TODO: (gloas): enable once those execution requests processing are gloas compatible
    //
    // process_execution_requests(config, state, envelope.execution_requests)?;

    // > Queue the builder payment
    let payment_slot = misc::builder_payment_index_for_current_epoch::<P>(state.slot());
    let payment = *state.builder_pending_payments().get(payment_slot)?;
    let amount = payment.withdrawal.amount;
    if amount > 0 {
        let exit_queue_epoch = compute_exit_epoch_and_update_churn(config, state, amount);
        let withdrawable_epoch =
            exit_queue_epoch.saturating_add(config.min_validator_withdrawability_delay);
        state
            .builder_pending_withdrawals_mut()
            .push(BuilderPendingWithdrawal {
                withdrawable_epoch,
                ..payment.withdrawal
            })?;
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

// TODO: (gloas): uncomment once those functions are glas compatible
//
// fn process_execution_requests<P: Preset>(
//     config: &Config,
//     state: &mut impl PostGloasBeaconState<P>,
//     execution_requests: &ExecutionRequests<P>,
// ) -> Result<()> {
//     for deposit_request in &execution_requests.deposits {
//         electra::process_deposit_request(state, *deposit_request)?;
//     }
//
//     for withdrawal_request in &execution_requests.withdrawals {
//         electra::process_withdrawal_request(config, state, *withdrawal_request)?;
//     }
//
//     for consolidation_request in &execution_requests.consolidations {
//         electra::process_consolidation_request(config, state, *consolidation_request)?;
//     }
// }

#[cfg(test)]
mod spec_tests {
    use execution_engine::MockExecutionEngine;
    use helper_functions::verifier::SingleVerifier;
    use serde::Deserialize;
    use spec_test_utils::Case;
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
        let signed_envelope_option = case.try_ssz_default("signed_envelope");
        let post_option = case.try_ssz_default("post");
        let Execution { execution_valid } = case.yaml("execution");
        let execution_engine = MockExecutionEngine::new(execution_valid, false, None);
        let pubkey_cache = PubkeyCache::default();

        // TODO(gloas): check for invalid case
        let Some(signed_envelope) = signed_envelope_option else {
            return;
        };

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
}
