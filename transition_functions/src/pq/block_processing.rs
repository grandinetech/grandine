use anyhow::{Result, ensure};
use arithmetic::{NonZeroExt as _, U64Ext as _};
use bit_field::BitField as _;
use helper_functions::{
    accessors::{
        attestation_epoch, get_attestation_participation_flags, get_base_reward,
        get_base_reward_per_increment, get_beacon_proposer_index, get_current_epoch,
        get_previous_epoch, get_randao_mix,
    },
    error::SignatureKind,
    gloas::slash_validator,
    misc::{
        builder_payment_index_for_current_epoch, builder_payment_index_for_previous_epoch,
        compute_epoch_at_slot,
    },
    mutators::{balance, increase_balance},
    pq::{
        compute_xmss_leaf_index, get_attestation_statements, get_attesting_indices,
        is_builder_bid_leaf_index, is_valid_vrf_proof, verify_validator_signature,
    },
    predicates::{
        can_builder_cover_bid, is_active_builder, is_attestation_same_slot,
        is_slashable_attestation_data, is_slashable_validator,
    },
    signing::SignForSingleFork as _,
    slot_report::SlotReport,
    verifier::{Verifier, VerifierOption},
};
use pq_prover::Statement;
use sha2::{Digest as _, Sha256};
use ssz::{Hc, SszHash as _, SszList as _, SszListMut as _};
use typenum::Unsigned as _;
use types::{
    altair::consts::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    config::Config,
    gloas::{
        consts::{BUILDER_INDEX_SELF_BUILD, PAYLOAD_BUILDER_VERSION},
        containers::{BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadBid},
    },
    nonstandard::{AttestationEpoch, SlashingKind},
    phase0::{
        consts::{DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO, GENESIS_SLOT},
        containers::AttestationData,
        primitives::{Gwei, H256, Slot, ValidatorIndex},
    },
    pq::{
        beacon_state::BeaconState,
        consts::LEAF_OFFSET_BEACON_PROPOSER,
        containers::{
            Attestation, AttesterSlashing, BeaconBlock, BeaconBlockBody, ExecutionRequests,
            IndexedAttestation, ProposerSlashing, SignedBeaconBlock, SignedExecutionPayloadBid,
        },
        validator_list::unpadded_pubkey,
    },
    preset::{Preset, SlotsPerHistoricalRoot},
    traits::{BeaconState as BeaconStateTrait, SszValidatorList as _},
};

use crate::{
    gloas,
    pq::execution_requests,
    unphased::{self, Error},
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

pub fn process_block<P: Preset, V: Verifier>(
    config: &Config,
    state: &mut BeaconState<P>,
    block: &Hc<BeaconBlock<P>>,
    verifier: &V,
    slot_report: impl SlotReport,
) -> Result<()> {
    if !V::IS_NULL {
        verify_body_signatures(config, state, block)?;
    }

    custom_process_block(config, state, block, verifier, slot_report)
}

pub fn process_block_for_gossip<P: Preset>(
    config: &Config,
    state: &BeaconState<P>,
    block: &SignedBeaconBlock<P>,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.message.slot);

    unphased::process_block_header_for_gossip(config, state, &block.message)?;

    verify_block_signature(config, state, block)
}

/// [`verify_block_signature`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-verify_block_signature)
pub fn verify_block_signature<P: Preset>(
    config: &Config,
    state: &BeaconState<P>,
    block: &SignedBeaconBlock<P>,
) -> Result<()> {
    let leaf_index = compute_xmss_leaf_index(block.message.slot, LEAF_OFFSET_BEACON_PROPOSER)?;

    ensure_signature(
        verify_validator_signature(
            state,
            block.message.proposer_index,
            leaf_index,
            block.message.signing_root(config, state),
            &block.signature,
        )?,
        SignatureKind::Block,
    )
}

/// The checks of signatures and proofs in `block` other than the block signature: the bid,
/// proposer slashings, attester slashings and the block's `proof` of its attestations.
///
/// Runs on the pre-block state. Committees and the public keys of the validators that operations
/// refer to do not change during block processing. Neither does the key of an active builder:
/// a builder added by the parent payload cannot be active yet.
pub fn verify_body_signatures<P: Preset>(
    config: &Config,
    state: &BeaconState<P>,
    block: &BeaconBlock<P>,
) -> Result<()> {
    let signed_bid = &block.body.signed_execution_payload_bid;

    if signed_bid.message.builder_index != BUILDER_INDEX_SELF_BUILD {
        ensure!(
            verify_execution_payload_bid_signature(config, state, signed_bid)?,
            Error::<P>::ExecutionPayloadBidSignatureInvalid,
        );
    }

    for proposer_slashing in &block.body.proposer_slashings {
        verify_proposer_slashing_signatures(config, state, proposer_slashing)?;
    }

    for attester_slashing in &block.body.attester_slashings {
        for attestation in [
            &attester_slashing.attestation_1,
            &attester_slashing.attestation_2,
        ] {
            verify_indexed_attestation_proof(config, state, attestation)?;
        }
    }

    verify_stark(config, state, &block.body)
}

pub fn custom_process_block<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    block: &Hc<BeaconBlock<P>>,
    verifier: &impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    #[cfg(feature = "metrics")]
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.block_transition_times.start_timer());

    debug_assert_eq!(state.slot, block.slot);

    let parent_slot = state.latest_block_header.slot;

    process_parent_execution_payload(
        config,
        state,
        block
            .body
            .signed_execution_payload_bid
            .message
            .parent_block_hash,
        &block.body.parent_execution_requests,
    )?;

    unphased::process_block_header(config, state, block)?;
    gloas::process_withdrawals(state)?;
    process_execution_payload_bid(config, state, &block.body.signed_execution_payload_bid)?;
    process_randao(config, state, &block.body, verifier)?;
    unphased::process_eth1_data(state, &block.body)?;
    process_operations(config, state, &block.body, parent_slot, &mut slot_report)
}

/// [`process_randao`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_randao)
pub(super) fn process_randao<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    body: &BeaconBlockBody<P>,
    verifier: &impl Verifier,
) -> Result<()> {
    let epoch = get_current_epoch(state);
    let reveal = &*body.randao_reveal;

    // > Verify RANDAO reveal
    if !verifier.has_option(VerifierOption::SkipRandaoVerification) {
        let proposer_index = get_beacon_proposer_index(config, state)?;
        let vrf_root = state.validators.vrf_root(proposer_index)?;

        ensure!(
            is_valid_vrf_proof(vrf_root, state.slot, reveal),
            Error::<P>::RandaoRevealInvalid,
        );
    }

    // > Mix in RANDAO reveal
    let mix = Sha256::new()
        .chain_update(get_randao_mix(state, epoch))
        .chain_update(reveal[0])
        .chain_update(DOMAIN_RANDAO)
        .finalize();

    *state.randao_mixes.mod_index_mut(epoch) = H256(mix.into());

    Ok(())
}

/// [`process_parent_execution_payload`] with the PQ `ExecutionRequests`.
///
/// [`process_parent_execution_payload`]: https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/beacon-chain.md#new-process_parent_execution_payload
pub fn process_parent_execution_payload<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    parent_block_hash: types::phase0::primitives::ExecutionBlockHash,
    parent_execution_requests: &ExecutionRequests<P>,
) -> Result<()> {
    if parent_block_hash != state.latest_execution_payload_bid.block_hash {
        // > Parent was EMPTY -- no execution requests expected
        ensure!(
            *parent_execution_requests == ExecutionRequests::default(),
            Error::<P>::ExecutionRequestsNotEmpty,
        );

        return Ok(());
    }

    let computed = parent_execution_requests.hash_tree_root();
    let expected = state.latest_execution_payload_bid.execution_requests_root;

    ensure!(
        computed == expected,
        Error::<P>::ExecutionRequestsRootMismatch { computed, expected },
    );

    apply_parent_execution_payload(config, state, parent_execution_requests)
}

/// [`apply_parent_execution_payload`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-apply_parent_execution_payload)
pub fn apply_parent_execution_payload<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    requests: &ExecutionRequests<P>,
) -> Result<()> {
    verify_execution_requests_limits(requests)?;

    let parent_bid = state.latest_execution_payload_bid.clone();
    let parent_slot = state.latest_block_header.slot;
    let parent_epoch = compute_epoch_at_slot::<P>(parent_slot);

    // > Settle the builder payment before the requests so that a builder exit
    // > request is rejected while the payment is pending
    if parent_epoch == get_current_epoch(state) {
        let payment_index = builder_payment_index_for_current_epoch::<P>(parent_slot)?;
        gloas::settle_builder_payment(state, payment_index)?;
    } else if parent_epoch == get_previous_epoch(state) {
        let payment_index = builder_payment_index_for_previous_epoch::<P>(parent_slot);
        gloas::settle_builder_payment(state, payment_index)?;
    } else if parent_bid.value > 0 {
        state
            .builder_pending_withdrawals
            .push(BuilderPendingWithdrawal {
                fee_recipient: parent_bid.fee_recipient,
                amount: parent_bid.value,
                builder_index: parent_bid.builder_index,
            })?;
    }

    execution_requests::process_execution_requests(config, state, requests)?;

    // > Update parent payload availability and latest block hash
    let slot: usize = parent_slot.try_into()?;

    state
        .execution_payload_availability
        .set(slot % SlotsPerHistoricalRoot::<P>::non_zero_usize(), true);

    state.latest_block_hash = parent_bid.block_hash;

    Ok(())
}

/// [`verify_execution_requests_limits`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/p2p-interface.md#modified-verify_execution_requests_limits)
pub fn verify_execution_requests_limits<P: Preset>(requests: &ExecutionRequests<P>) -> Result<()> {
    for (kind, in_block, maximum) in [
        (
            "withdrawal requests",
            requests.withdrawals.len(),
            P::MaxWithdrawalRequestsPerPayload::U64,
        ),
        (
            "consolidation requests",
            requests.consolidations.len(),
            P::MaxConsolidationRequestsPerPayload::U64,
        ),
        (
            "builder deposit requests",
            requests.builder_deposits.len(),
            P::MaxBuilderDepositRequestsPerPayload::U64,
        ),
        (
            "builder exit requests",
            requests.builder_exits.len(),
            P::MaxBuilderExitRequestsPerPayload::U64,
        ),
        (
            "validator preregistration requests",
            requests.validator_preregistrations.len(),
            P::MAX_VALIDATOR_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        ),
        (
            "builder preregistration requests",
            requests.builder_preregistrations.len(),
            P::MAX_BUILDER_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        ),
        (
            "voluntary exit requests",
            requests.voluntary_exits.len(),
            P::MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD,
        ),
    ] {
        ensure_operation_count::<P>(kind, in_block, maximum)?;
    }

    Ok(())
}

fn ensure_operation_count<P: Preset>(
    kind: &'static str,
    in_block: usize,
    maximum: u64,
) -> Result<()> {
    let maximum = usize::try_from(maximum)?;

    ensure!(
        in_block <= maximum,
        Error::<P>::TooManyOperations {
            kind,
            maximum,
            in_block,
        },
    );

    Ok(())
}

/// [`process_execution_payload_bid`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_execution_payload_bid)
#[expect(clippy::too_many_lines)]
pub(super) fn process_execution_payload_bid<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    signed_bid: &SignedExecutionPayloadBid<P>,
) -> Result<()> {
    let bid = &signed_bid.message;
    let ExecutionPayloadBid {
        builder_index,
        value: amount,
        slot,
        block_hash,
        parent_block_hash,
        parent_block_root,
        prev_randao,
        fee_recipient,
        ..
    } = *bid;

    // > For self-builds, amount must be zero regardless of withdrawal credential prefix
    if builder_index == BUILDER_INDEX_SELF_BUILD {
        ensure!(amount == 0, Error::<P>::NoneZeroBidValue);
        ensure!(
            signed_bid.signature.is_empty(),
            Error::<P>::ExecutionPayloadBidSignatureInvalid,
        );
    } else {
        let builder = state.builders.get(builder_index)?;

        ensure!(
            is_active_builder(builder, state.finalized_checkpoint.epoch),
            Error::<P>::BuilderNotActive {
                index: builder_index,
                current_epoch: get_current_epoch(state),
            },
        );

        ensure!(
            builder.version == PAYLOAD_BUILDER_VERSION,
            Error::<P>::BuilderVersionMismatch {
                index: builder_index,
                builder_version: builder.version,
                expected: PAYLOAD_BUILDER_VERSION,
            },
        );

        ensure!(
            can_builder_cover_bid(state, builder_index, amount)?,
            Error::<P>::BuilderBalanceNotSufficient {
                index: builder_index,
                amount,
            },
        );
    }

    // > Verify commitments are under limit
    let maximum = config
        .get_blob_schedule_entry(get_current_epoch(state))
        .max_blobs_per_block;
    let in_block = bid.blob_kzg_commitments.len();

    ensure!(
        in_block <= maximum,
        Error::<P>::TooManyBlockKzgCommitments { in_block, maximum },
    );

    // > Verify that the bid is for the current slot
    ensure!(
        slot == state.slot,
        Error::<P>::BidSlotMismatch {
            in_bid: slot,
            in_state: state.slot,
        },
    );

    ensure!(state.slot > GENESIS_SLOT, Error::<P>::BidSlotAtGenesis);

    // > Verify that the bid is for the right parent block
    ensure!(
        parent_block_hash == state.latest_block_hash,
        Error::<P>::BidParentBlockHashMismatch {
            in_bid: parent_block_hash,
            in_state: state.latest_block_hash,
        },
    );

    // > Verify that the bid's block hash differs from its parent block hash
    ensure!(
        block_hash != parent_block_hash,
        Error::<P>::BidBlockHashEqualsParentBlockHash { block_hash },
    );

    let in_state =
        helper_functions::accessors::get_block_root_at_slot(state, state.slot.try_sub(1)?)?;

    ensure!(
        parent_block_root == in_state,
        Error::<P>::BidParentBlockRootMismatch {
            in_bid: parent_block_root,
            in_state,
        },
    );

    let in_state = get_randao_mix(state, get_current_epoch(state));

    ensure!(
        prev_randao == in_state,
        Error::<P>::BidPrevRandaoMismatch {
            in_bid: prev_randao,
            in_state,
        },
    );

    // > Record the pending payment if there is some payment
    if amount > 0 {
        let pending_payment = BuilderPendingPayment {
            weight: 0,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient,
                amount,
                builder_index,
            },
            proposer_index: get_beacon_proposer_index(config, state)?,
        };

        *state
            .builder_pending_payments
            .mod_index_mut(builder_payment_index_for_current_epoch::<P>(slot)?) = pending_payment;
    }

    // > Cache the signed execution payload bid
    state.latest_execution_payload_bid = bid.clone();

    Ok(())
}

/// [`verify_execution_payload_bid_signature`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-verify_execution_payload_bid_signature)
pub fn verify_execution_payload_bid_signature<P: Preset>(
    config: &Config,
    state: &BeaconState<P>,
    signed_bid: &SignedExecutionPayloadBid<P>,
) -> Result<bool> {
    let builder = state.builders.get(signed_bid.message.builder_index)?;
    let leaf_index = u64::from(signed_bid.signature.leaf_index());

    if !is_builder_bid_leaf_index(leaf_index) {
        return Ok(false);
    }

    Ok(xmss::verify_u64(
        &unpadded_pubkey(&builder.pubkey),
        leaf_index,
        signed_bid
            .message
            .signing_root(config, state)
            .as_fixed_bytes(),
        &signed_bid.signature,
    ))
}

/// [`process_operations`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_operations)
///
/// The signatures and proofs of operations are checked by [`verify_body_signatures`].
fn process_operations<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    body: &BeaconBlockBody<P>,
    parent_slot: Slot,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    ensure!(
        body.deposits.is_empty(),
        Error::<P>::DepositCountMismatch {
            computed: 0,
            in_block: body.deposits.len().try_into()?,
        },
    );

    ensure_operation_count::<P>(
        "proposer slashings",
        body.proposer_slashings.len(),
        P::MaxProposerSlashings::U64,
    )?;
    ensure_operation_count::<P>(
        "attester slashings",
        body.attester_slashings.len(),
        P::MaxAttesterSlashingsElectra::U64,
    )?;
    ensure_operation_count::<P>(
        "attestations",
        body.attestations.len(),
        P::MAX_ATTESTATIONS_PQ,
    )?;

    for proposer_slashing in &body.proposer_slashings {
        process_proposer_slashing(config, state, proposer_slashing, &mut slot_report)?;
    }

    for attester_slashing in &body.attester_slashings {
        process_attester_slashing(config, state, attester_slashing, &mut slot_report)?;
    }

    for attestation in &body.attestations {
        process_attestation(config, state, attestation, parent_slot, &mut slot_report)?;
    }

    Ok(())
}

/// [`process_proposer_slashing`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_proposer_slashing)
pub(super) fn process_proposer_slashing<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    proposer_slashing: &ProposerSlashing,
    slot_report: impl SlotReport,
) -> Result<()> {
    let header_1 = proposer_slashing.signed_header_1.message;
    let header_2 = proposer_slashing.signed_header_2.message;

    // > Verify header slots match
    ensure!(
        header_1.slot == header_2.slot,
        Error::<P>::ProposerSlashingSlotMismatch {
            slot_1: header_1.slot,
            slot_2: header_2.slot,
        },
    );

    // > Verify header proposer indices match
    ensure!(
        header_1.proposer_index == header_2.proposer_index,
        Error::<P>::ProposerSlashingProposerMismatch {
            proposer_index_1: header_1.proposer_index,
            proposer_index_2: header_2.proposer_index,
        },
    );

    // > Verify the headers are different
    ensure!(
        header_1 != header_2,
        Error::<P>::ProposerSlashingHeadersIdentical { header: header_1 },
    );

    // > Verify the proposer is slashable
    let index = header_1.proposer_index;

    ensure!(
        is_slashable_validator(
            state.validators.partial_validator(index)?,
            get_current_epoch(state),
        ),
        Error::<P>::ProposerNotSlashable {
            index,
            proposer: state.validators.get(index)?,
        },
    );

    slash_validator(
        config,
        state,
        index,
        None,
        SlashingKind::Proposer,
        slot_report,
    )
}

fn verify_proposer_slashing_signatures<P: Preset>(
    config: &Config,
    state: &BeaconState<P>,
    proposer_slashing: &ProposerSlashing,
) -> Result<()> {
    for signed_header in [
        &proposer_slashing.signed_header_1,
        &proposer_slashing.signed_header_2,
    ] {
        let header = signed_header.message;
        let domain = helper_functions::accessors::get_domain(
            config,
            state,
            DOMAIN_BEACON_PROPOSER,
            Some(compute_epoch_at_slot::<P>(header.slot)),
        );
        let signing_root = helper_functions::misc::compute_signing_root(&header, domain);
        let leaf_index = compute_xmss_leaf_index(header.slot, LEAF_OFFSET_BEACON_PROPOSER)?;

        ensure_signature(
            verify_validator_signature(
                state,
                header.proposer_index,
                leaf_index,
                signing_root,
                &signed_header.signature,
            )?,
            SignatureKind::Block,
        )?;
    }

    Ok(())
}

/// [`process_attester_slashing`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#attester-slashings)
/// with the PQ `is_valid_indexed_attestation`. The proofs are checked by
/// [`verify_body_signatures`].
pub(super) fn process_attester_slashing<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    attester_slashing: &AttesterSlashing<P>,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    for index in validate_attester_slashing(config, state, attester_slashing, false)? {
        slash_validator(
            config,
            state,
            index,
            None,
            SlashingKind::Attester,
            &mut slot_report,
        )?;
    }

    Ok(())
}

/// The validation in [`process_attester_slashing`]. Returns the indices it would slash.
///
/// The proofs of the indexed attestations are only checked if `verify_proofs` is set.
pub fn validate_attester_slashing<P: Preset>(
    config: &Config,
    state: &impl BeaconStateTrait<P>,
    attester_slashing: &AttesterSlashing<P>,
    verify_proofs: bool,
) -> Result<Vec<ValidatorIndex>> {
    let AttesterSlashing {
        attestation_1,
        attestation_2,
    } = attester_slashing;

    ensure!(
        is_slashable_attestation_data(attestation_1.data, attestation_2.data),
        Error::<P>::AttestationDataNotSlashable {
            data_1: attestation_1.data,
            data_2: attestation_2.data,
        },
    );

    for attestation in [attestation_1, attestation_2] {
        validate_indexed_attestation_indices(state, attestation)?;

        if verify_proofs {
            verify_indexed_attestation_proof(config, state, attestation)?;
        }
    }

    let current_epoch = get_current_epoch(state);

    let indices_2 = attestation_2
        .attesting_indices
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();

    let slashable_indices = attestation_1
        .attesting_indices
        .iter()
        .copied()
        .filter(|index| indices_2.contains(index))
        .map(|index| {
            let validator = state.validators().partial_validator(index)?;
            Ok((index, is_slashable_validator(validator, current_epoch)))
        })
        .filter_map(|result: Result<_>| match result {
            Ok((index, true)) => Some(Ok(index)),
            Ok((_, false)) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>>>()?;

    ensure!(
        !slashable_indices.is_empty(),
        Error::<P>::NoAttestersSlashed
    );

    Ok(slashable_indices)
}

/// The structural part of [`is_valid_indexed_attestation`].
///
/// [`is_valid_indexed_attestation`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-is_valid_indexed_attestation
fn validate_indexed_attestation_indices<P: Preset>(
    state: &impl BeaconStateTrait<P>,
    indexed_attestation: &IndexedAttestation<P>,
) -> Result<()> {
    let indices = &indexed_attestation.attesting_indices;
    let maximum =
        P::MaxValidatorsPerCommittee::USIZE.saturating_mul(P::MaxCommitteesPerSlotPq::USIZE);

    ensure!(
        !indices.is_empty()
            && indices.len() <= maximum
            && indices
                .iter()
                .zip(indices.iter().skip(1))
                .all(|(a, b)| a < b),
        helper_functions::error::Error::AttestingIndicesNotSortedAndUnique,
    );

    let validator_count = state.validators().len_u64();

    for index in indices.iter().copied() {
        ensure!(
            index < validator_count,
            helper_functions::error::Error::AttestingIndexOutOfBounds {
                index,
                validator_count,
            },
        );
    }

    Ok(())
}

fn verify_indexed_attestation_proof<P: Preset>(
    config: &Config,
    state: &impl BeaconStateTrait<P>,
    indexed_attestation: &IndexedAttestation<P>,
) -> Result<()> {
    validate_indexed_attestation_indices(state, indexed_attestation)?;

    let target_epoch = indexed_attestation.data.target.epoch;
    let domain = helper_functions::accessors::get_domain(
        config,
        state,
        DOMAIN_BEACON_ATTESTER,
        Some(target_epoch),
    );

    let statement = Statement {
        pubkeys: indexed_attestation
            .attesting_indices
            .iter()
            .map(|index| Ok(unpadded_pubkey(state.validators().pubkey(*index)?)))
            .collect::<Result<_>>()?,
        leaf_index: helper_functions::pq::compute_xmss_attestation_leaf_index(target_epoch)?,
        message: helper_functions::misc::compute_signing_root(&indexed_attestation.data, domain)
            .to_fixed_bytes(),
    };

    ensure_proof::<P>(&[statement], indexed_attestation.proof.as_bytes())
}

/// [`process_attestation`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_attestation)
pub(super) fn process_attestation<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    attestation: &Attestation<P>,
    parent_slot: Slot,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    let AttestationData {
        slot: attestation_slot,
        index,
        target,
        ..
    } = attestation.data;

    let attestation_epoch = attestation_epoch(state, target.epoch)?;

    match attestation_epoch {
        AttestationEpoch::Previous | AttestationEpoch::Current => {}
    }

    ensure!(
        target.epoch == compute_epoch_at_slot::<P>(attestation_slot),
        Error::<P>::PqAttestationTargetsWrongEpoch {
            slot: attestation_slot,
            target_epoch: target.epoch,
        },
    );

    // > [Modified in PQ]
    ensure!(
        attestation_slot.try_add(P::MIN_ATTESTATION_INCLUSION_DELAY_PQ.get())? <= state.slot,
        Error::<P>::AttestationOutsideInclusionRange {
            state_slot: state.slot,
            attestation_slot,
        },
    );

    ensure!(
        index < 2,
        Error::<P>::PqAttestationWithInvalidPayloadStatus { index },
    );

    // Committee bounds, non-empty committees and the length of the aggregation bits.
    let attesting_indices = get_attesting_indices(state, attestation)?;

    // > Participation flag indices
    let inclusion_delay = state.slot.try_sub(attestation_slot)?;
    let participation_flags = get_attestation_participation_flags(
        state,
        attestation.data,
        inclusion_delay,
        Some(parent_slot),
    )?;

    let base_reward_per_increment = get_base_reward_per_increment(state)?;

    let attesters = attesting_indices
        .iter()
        .copied()
        .map(|validator_index| {
            let base_reward = get_base_reward(state, validator_index, base_reward_per_increment)?;
            let effective_balance = state.validators.effective_balance(validator_index)?;
            Ok((validator_index, base_reward, effective_balance))
        })
        .collect::<Result<Vec<_>>>()?;

    let is_attestation_same_slot = is_attestation_same_slot(state, &attestation.data)?;

    let payment_slot = match attestation_epoch {
        AttestationEpoch::Previous => {
            builder_payment_index_for_previous_epoch::<P>(attestation_slot)
        }
        AttestationEpoch::Current => {
            builder_payment_index_for_current_epoch::<P>(attestation_slot)?
        }
    };

    let mut payment = *state.builder_pending_payments.mod_index(payment_slot);

    let epoch_participation = match attestation_epoch {
        AttestationEpoch::Previous => &mut state.previous_epoch_participation,
        AttestationEpoch::Current => &mut state.current_epoch_participation,
    };

    let mut proposer_reward_numerator: Gwei = 0;

    for (validator_index, base_reward, effective_balance) in attesters {
        let epoch_participation = epoch_participation.get_mut(validator_index)?;
        let had_no_participation = *epoch_participation == 0;
        let mut will_set_new_flag = false;

        for (flag_index, weight) in PARTICIPATION_FLAG_WEIGHTS {
            if participation_flags.get_bit(flag_index) && !epoch_participation.get_bit(flag_index) {
                proposer_reward_numerator =
                    proposer_reward_numerator.try_add(base_reward.try_mul(weight)?)?;

                will_set_new_flag = true;
            }
        }

        *epoch_participation |= participation_flags;

        if will_set_new_flag
            && had_no_participation
            && is_attestation_same_slot
            && payment.withdrawal.amount > 0
        {
            payment.weight = payment.weight.try_add(effective_balance)?;
        }
    }

    // > Reward proposer
    let proposer_index = get_beacon_proposer_index(config, state)?;
    let proposer_reward_denominator = WEIGHT_DENOMINATOR
        .get()
        .try_sub(PROPOSER_WEIGHT.get())?
        .try_mul(WEIGHT_DENOMINATOR.get())?
        / PROPOSER_WEIGHT;

    let proposer_reward = proposer_reward_numerator.try_div(proposer_reward_denominator)?;

    increase_balance(balance(state, proposer_index)?, proposer_reward)?;

    // > Update builder payment weight
    *state.builder_pending_payments.mod_index_mut(payment_slot) = payment;

    slot_report.add_attestation_reward(proposer_reward);
    slot_report.update_performance(state, attestation.data, attesting_indices)?;

    Ok(())
}

/// [`process_stark`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-process_stark)
fn verify_stark<P: Preset>(
    config: &Config,
    state: &BeaconState<P>,
    body: &BeaconBlockBody<P>,
) -> Result<()> {
    let mut statements = vec![];

    for attestation in &body.attestations {
        statements.extend(get_attestation_statements(config, state, attestation)?);
    }

    ensure_proof::<P>(&statements, body.proof.as_bytes())
}

fn ensure_proof<P: Preset>(statements: &[Statement], proof: &[u8]) -> Result<()> {
    ensure!(
        pq_prover::block_backend().verify(statements, proof)?,
        Error::<P>::AttestationProofInvalid,
    );

    Ok(())
}

fn ensure_signature(valid: bool, kind: SignatureKind) -> Result<()> {
    ensure!(
        valid,
        helper_functions::error::Error::SignatureInvalid(kind)
    );
    Ok(())
}
