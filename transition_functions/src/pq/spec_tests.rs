// Signatures and proofs in the PQ vectors are stubs (`xmss_active = False` in the pyspec), so none
// of these runners check them. VRF proofs are real and are checked by `process_randao`.

use anyhow::Result;
use helper_functions::{misc::vec_of_default, slot_report::NullSlotReport, verifier::NullVerifier};
use pubkey_cache::PubkeyCache;
use spec_test_utils::{Case, Meta};
use ssz::{Hc, SszReadDefault};
use test_generator::test_resources;
use types::{
    config::Config,
    nonstandard::Phase,
    pq::{
        beacon_state::BeaconState,
        containers::{
            Attestation, AttesterSlashing, BeaconBlock, BeaconBlockBody, ProposerSlashing,
            SignedExecutionPayloadBid,
        },
    },
    preset::{Mainnet, Minimal, Preset},
};

use super::{block_processing, epoch_processing, execution_requests, process_epoch};
use crate::{
    altair::{self, EpochDeltasForTransition, ValidatorSummary},
    electra, fulu, gloas, unphased,
};

fn config<P: Preset>() -> Config {
    P::default_config().start_and_stay_in(Phase::Pq)
}

macro_rules! operation_tests {
    (
        $module_name: ident,
        $function: expr,
        $operand: literal,
        $mainnet_glob: literal,
        $minimal_glob: literal,
    ) => {
        mod $module_name {
            use super::*;

            #[test_resources($mainnet_glob)]
            fn mainnet(case: Case) {
                run::<Mainnet>(case);
            }

            #[test_resources($minimal_glob)]
            fn minimal(case: Case) {
                run::<Minimal>(case);
            }

            fn run<P: Preset>(case: Case) {
                run_operation_case::<P, _>(case, $operand, $function);
            }
        }
    };
}

macro_rules! epoch_tests {
    ($module_name: ident, $function: expr, $mainnet_glob: literal, $minimal_glob: literal,) => {
        mod $module_name {
            use super::*;

            #[test_resources($mainnet_glob)]
            fn mainnet(case: Case) {
                run::<Mainnet>(case);
            }

            #[test_resources($minimal_glob)]
            fn minimal(case: Case) {
                run::<Minimal>(case);
            }

            fn run<P: Preset>(case: Case) {
                run_epoch_step_case::<P>(case, $function);
            }
        }
    };
}

operation_tests! {
    block_header,
    |config, state, block: Hc<BeaconBlock<P>>, _| unphased::process_block_header(config, state, &block),
    "block",
    "consensus-spec-tests/tests/mainnet/pq/operations/block_header/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/block_header/*/*",
}

operation_tests! {
    proposer_slashing,
    |config, state, slashing: ProposerSlashing, _| block_processing::process_proposer_slashing(config, state, &slashing, NullSlotReport),
    "proposer_slashing",
    "consensus-spec-tests/tests/mainnet/pq/operations/proposer_slashing/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/proposer_slashing/*/*",
}

operation_tests! {
    attester_slashing,
    |config, state, slashing: AttesterSlashing<P>, _| block_processing::process_attester_slashing(config, state, &slashing, NullSlotReport),
    "attester_slashing",
    "consensus-spec-tests/tests/mainnet/pq/operations/attester_slashing/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/attester_slashing/*/*",
}

operation_tests! {
    attestation,
    |config, state, attestation: Attestation<P>, meta: &Meta| {
            let parent_slot = meta.parent_slot.unwrap_or(state.latest_execution_payload_bid.slot);
            block_processing::process_attestation(config, state, &attestation, parent_slot, NullSlotReport)
        },
    "attestation",
    "consensus-spec-tests/tests/mainnet/pq/operations/attestation/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/attestation/*/*",
}

operation_tests! {
    execution_payload_bid,
    |config, state, bid: SignedExecutionPayloadBid<P>, _| block_processing::process_execution_payload_bid(config, state, &bid),
    "execution_payload_bid",
    "consensus-spec-tests/tests/mainnet/pq/operations/execution_payload_bid/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/execution_payload_bid/*/*",
}

operation_tests! {
    parent_execution_payload,
    |config, state, block: BeaconBlock<P>, _| block_processing::process_parent_execution_payload(
            config,
            state,
            block.body.signed_execution_payload_bid.message.parent_block_hash,
            &block.body.parent_execution_requests,
        ),
    "block",
    "consensus-spec-tests/tests/mainnet/pq/operations/parent_execution_payload/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/parent_execution_payload/*/*",
}

operation_tests! {
    randao,
    |config, state, body: BeaconBlockBody<P>, _| block_processing::process_randao(config, state, &body, &NullVerifier),
    "body",
    "consensus-spec-tests/tests/mainnet/pq/operations/randao/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/randao/*/*",
}

operation_tests! {
    deposit_request,
    |_, state, request, _| execution_requests::process_deposit_request(state, request),
    "deposit_request",
    "consensus-spec-tests/tests/mainnet/pq/operations/deposit_request/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/deposit_request/*/*",
}

operation_tests! {
    withdrawal_request,
    |config, state, request, _| execution_requests::process_withdrawal_request(config, state, request),
    "withdrawal_request",
    "consensus-spec-tests/tests/mainnet/pq/operations/withdrawal_request/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/withdrawal_request/*/*",
}

operation_tests! {
    consolidation_request,
    |config, state, request, _| execution_requests::process_consolidation_request(config, state, request),
    "consolidation_request",
    "consensus-spec-tests/tests/mainnet/pq/operations/consolidation_request/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/consolidation_request/*/*",
}

operation_tests! {
    builder_deposit_request,
    |config, state, request, _| execution_requests::process_builder_deposit_request(config, state, request),
    "builder_deposit_request",
    "consensus-spec-tests/tests/mainnet/pq/operations/builder_deposit_request/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/builder_deposit_request/*/*",
}

operation_tests! {
    builder_exit_request,
    |config, state, request, _| execution_requests::process_builder_exit_request(config, state, request),
    "builder_exit_request",
    "consensus-spec-tests/tests/mainnet/pq/operations/builder_exit_request/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/builder_exit_request/*/*",
}

operation_tests! {
    validator_preregistration_request,
    |_, state, request, _| execution_requests::process_validator_preregistration_request(state, request),
    "validator_preregistration_request",
    "consensus-spec-tests/tests/mainnet/pq/operations/validator_preregistration_request/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/validator_preregistration_request/*/*",
}

operation_tests! {
    builder_preregistration_request,
    |_, state, request, _| execution_requests::process_builder_preregistration_request(state, request),
    "builder_preregistration_request",
    "consensus-spec-tests/tests/mainnet/pq/operations/builder_preregistration_request/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/builder_preregistration_request/*/*",
}

operation_tests! {
    voluntary_exit_request,
    |config, state, request, _| execution_requests::process_voluntary_exit_request(config, state, request),
    "voluntary_exit_request",
    "consensus-spec-tests/tests/mainnet/pq/operations/voluntary_exit_request/*/*",
    "consensus-spec-tests/tests/minimal/pq/operations/voluntary_exit_request/*/*",
}

epoch_tests! {
    justification_and_finalization,
    |_, state| {
            let (statistics, _, _) = altair::statistics_and_summaries(state)?;
            altair::process_justification_and_finalization(state, statistics)
        },
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/justification_and_finalization/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/justification_and_finalization/*/*",
}

epoch_tests! {
    inactivity_updates,
    |config, state| {
            let (_, summaries, participation) = altair::statistics_and_summaries(state)?;
            altair::process_inactivity_updates(config, state, summaries, participation)
        },
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/inactivity_updates/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/inactivity_updates/*/*",
}

epoch_tests! {
    rewards_and_penalties,
    |config, state| {
            let (statistics, summaries, participation) = altair::statistics_and_summaries(state)?;
            let deltas: Vec<EpochDeltasForTransition> = altair::epoch_deltas::<P, _>(
                config,
                P::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
                altair::EpochRewardScalars::new(state, statistics)?,
                summaries,
                participation
                    .iter()
                    .map(|participation| participation.previous),
                state.inactivity_scores.into_iter().copied(),
            )?;
            unphased::process_rewards_and_penalties(state, deltas)
        },
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/rewards_and_penalties/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/rewards_and_penalties/*/*",
}

epoch_tests! {
    registry_updates,
    |config, state| {
            let mut summaries: Vec<ValidatorSummary> = vec_of_default(state);
            electra::process_registry_updates(config, state, summaries.as_mut_slice())
        },
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/registry_updates/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/registry_updates/*/*",
}

epoch_tests! {
    slashings,
    |_, state| {
            let (_, summaries, _) = altair::statistics_and_summaries(state)?;
            electra::process_slashings::<_, ()>(state, summaries)
        },
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/slashings/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/slashings/*/*",
}

epoch_tests! {
    effective_balance_updates,
    |_, state| electra::process_effective_balance_updates(state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/effective_balance_updates/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/effective_balance_updates/*/*",
}

epoch_tests! {
    slashings_reset,
    |_, state| unphased::process_slashings_reset(state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/slashings_reset/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/slashings_reset/*/*",
}

epoch_tests! {
    randao_mixes_reset,
    |_, state| unphased::process_randao_mixes_reset(state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/randao_mixes_reset/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/randao_mixes_reset/*/*",
}

epoch_tests! {
    historical_summaries_update,
    |_, state| epoch_processing::process_historical_summaries_update(state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/historical_summaries_update/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/historical_summaries_update/*/*",
}

epoch_tests! {
    participation_flag_updates,
    |_, state| {
            altair::process_participation_flag_updates(state);
            Ok(())
        },
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/participation_flag_updates/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/participation_flag_updates/*/*",
}

epoch_tests! {
    pending_deposits,
    |config, state| epoch_processing::process_pending_deposits(config, state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/pending_deposits/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/pending_deposits/*/*",
}

epoch_tests! {
    pending_deposits_churn,
    |config, state| epoch_processing::process_pending_deposits(config, state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/pending_deposits_churn/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/pending_deposits_churn/*/*",
}

epoch_tests! {
    pending_consolidations,
    |_, state| electra::process_pending_consolidations(state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/pending_consolidations/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/pending_consolidations/*/*",
}

epoch_tests! {
    proposer_lookahead,
    |config, state| fulu::process_proposer_lookahead(config, state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/proposer_lookahead/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/proposer_lookahead/*/*",
}

epoch_tests! {
    builder_pending_payments,
    |_, state| gloas::process_builder_pending_payments(state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/builder_pending_payments/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/builder_pending_payments/*/*",
}

epoch_tests! {
    ptc_window,
    |_, state| gloas::process_ptc_window(state).map(|_| ()),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/ptc_window/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/ptc_window/*/*",
}

epoch_tests! {
    aggregation_committee_window,
    |_, state| epoch_processing::process_aggregation_committee_window(state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/aggregation_committee_window/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/aggregation_committee_window/*/*",
}

epoch_tests! {
    preregistration_expiry,
    |_, state| execution_requests::process_preregistration_expiry(state),
    "consensus-spec-tests/tests/mainnet/pq/epoch_processing/preregistration_expiry/*/*",
    "consensus-spec-tests/tests/minimal/pq/epoch_processing/preregistration_expiry/*/*",
}

#[test_resources("consensus-spec-tests/tests/mainnet/pq/operations/withdrawals/*/*")]
fn mainnet_withdrawals(case: Case) {
    run_epoch_step_case::<Mainnet>(case, |_, state| gloas::process_withdrawals(state));
}

#[test_resources("consensus-spec-tests/tests/minimal/pq/operations/withdrawals/*/*")]
fn minimal_withdrawals(case: Case) {
    run_epoch_step_case::<Minimal>(case, |_, state| gloas::process_withdrawals(state));
}

#[test_resources("consensus-spec-tests/tests/mainnet/pq/epoch_processing/*/*/*")]
fn mainnet_full_epoch(case: Case) {
    run_full_epoch_case::<Mainnet>(case);
}

#[test_resources("consensus-spec-tests/tests/minimal/pq/epoch_processing/*/*/*")]
fn minimal_full_epoch(case: Case) {
    run_full_epoch_case::<Minimal>(case);
}

fn run_operation_case<P: Preset, O: SszReadDefault>(
    case: Case,
    operand: &str,
    function: impl FnOnce(&Config, &mut BeaconState<P>, O, &Meta) -> Result<()>,
) {
    let mut state = case.ssz_default::<BeaconState<P>>("pre");
    let operation = case.ssz_default(operand);
    let post_option = case.try_ssz_default("post");
    let meta = case.meta();

    let result = function(&config::<P>(), &mut state, operation, &meta).map(|()| state);

    if let Some(expected_post) = post_option {
        assert_eq!(
            result.expect("operation processing should succeed"),
            expected_post
        );
    } else {
        result.expect_err("operation processing should fail");
    }
}

fn run_epoch_step_case<P: Preset>(
    case: Case,
    function: impl FnOnce(&Config, &mut BeaconState<P>) -> Result<()>,
) {
    let mut state = case.ssz_default::<BeaconState<P>>("pre");
    let post_option = case.try_ssz_default("post");

    let result = function(&config::<P>(), &mut state).map(|()| state);

    if let Some(expected_post) = post_option {
        assert_eq!(result.expect("processing should succeed"), expected_post);
    } else {
        result.expect_err("processing should fail");
    }
}

fn run_full_epoch_case<P: Preset>(case: Case) {
    let Some(mut state) = case.try_ssz_default::<BeaconState<P>>("pre_epoch") else {
        return;
    };

    let post_option = case.try_ssz_default::<BeaconState<P>>("post_epoch");
    let result = process_epoch(&config::<P>(), &PubkeyCache::default(), &mut state).map(|()| state);

    if let Some(expected_post) = post_option {
        assert_eq!(
            result.expect("epoch processing should succeed"),
            expected_post
        );
    } else {
        result.expect_err("epoch processing should fail");
    }
}
