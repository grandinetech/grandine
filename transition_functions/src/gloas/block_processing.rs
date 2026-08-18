use core::ops::Index as _;

use anyhow::{Result, ensure};
use arithmetic::{NonZeroExt as _, U64Ext as _, UsizeExt as _};
use bit_field::BitField as _;
use bls::traits::SignatureBytes as _;
use helper_functions::{
    accessors::{
        self, attestation_epoch, get_attestation_participation_flags, get_base_reward,
        get_base_reward_per_increment, get_beacon_proposer_index, get_current_epoch,
        get_indexed_payload_attestation, get_previous_epoch, get_randao_mix,
        initialize_shuffled_indices,
    },
    electra::{
        get_attesting_indices, is_fully_withdrawable_validator,
        is_partially_withdrawable_validator, slash_validator,
    },
    error::SignatureKind,
    gloas::get_indexed_attestation,
    misc::{
        builder_payment_index_for_current_epoch, builder_payment_index_for_previous_epoch,
        compute_epoch_at_slot, convert_builder_index_to_validator_index, get_max_effective_balance,
        maybe_builder_index,
    },
    mutators::{balance, builder_balance, decrease_balance, increase_balance},
    predicates::{
        can_builder_cover_bid, is_active_builder, is_attestation_same_slot,
        validate_constructed_indexed_attestation, validate_constructed_indexed_payload_attestation,
    },
    signing::SignForSingleFork as _,
    slot_report::SlotReport,
    verifier::{SingleVerifier, Triple, Verifier},
};
use pubkey_cache::PubkeyCache;
#[cfg(not(target_os = "zkvm"))]
use rayon::iter::ParallelIterator as _;
use ssz::{Hc, PersistentProgressiveList, SszHash as _, SszList as _, SszListMut as _};
use tap::Pipe as _;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    altair::consts::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    capella::{containers::Withdrawal, primitives::WithdrawalIndex},
    config::Config,
    gloas::{
        beacon_state::BeaconState as GloasBeaconState,
        consts::{BUILDER_INDEX_SELF_BUILD, PAYLOAD_BUILDER_VERSION},
        containers::{
            Attestation, BeaconBlock, BuilderPendingPayment, BuilderPendingWithdrawal,
            ExecutionPayloadBid, ExecutionRequests, PayloadAttestation, SignedBeaconBlock,
            SignedExecutionPayloadBid,
        },
    },
    nonstandard::{AttestationEpoch, SlashingKind},
    phase0::{
        consts::{FAR_FUTURE_EPOCH, GENESIS_SLOT},
        containers::{AttestationData, ProposerSlashing},
        primitives::{Epoch, ExecutionAddress, Gwei, Slot},
    },
    preset::{BuilderPendingPaymentsLength, Preset, SlotsPerHistoricalRoot},
    traits::{
        BeaconState, BlockBodyWithBlsToExecutionChanges, BlockBodyWithGloasAttestations,
        BlockBodyWithGloasAttesterSlashings, BlockBodyWithPayloadAttestations,
        PostGloasBeaconState,
    },
};

use crate::{
    altair,
    capella::{self, PREFIX_LEN},
    electra,
    gloas::execution_payload_processing::process_execution_requests,
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
    state: &mut GloasBeaconState<P>,
    block: &Hc<BeaconBlock<P>>,
    mut verifier: impl Verifier,
    slot_report: impl SlotReport,
) -> Result<()> {
    #[cfg(feature = "metrics")]
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.block_transition_times.start_timer());

    verifier.reserve(count_required_signatures(block)?);

    custom_process_block(
        config,
        pubkey_cache,
        state,
        block,
        &mut verifier,
        slot_report,
    )?;

    verifier.finish()
}

pub fn process_block_for_gossip<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &GloasBeaconState<P>,
    block: &SignedBeaconBlock<P>,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.message.slot);

    unphased::process_block_header_for_gossip(config, state, &block.message)?;

    let public_key = accessors::public_key(state, block.message.proposer_index)?;

    SingleVerifier.verify_singular(
        block.message.signing_root(config, state),
        block.signature,
        pubkey_cache.get_or_insert(*public_key)?,
        SignatureKind::Block,
    )?;

    Ok(())
}

pub fn count_required_signatures<P: Preset>(block: &Hc<BeaconBlock<P>>) -> Result<usize> {
    altair::count_required_signatures(block)?
        .try_add(block.body.bls_to_execution_changes.len())?
        .try_add(block.body.payload_attestations.len())
        .map_err(Into::into)
}

pub fn custom_process_block<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut GloasBeaconState<P>,
    block: &Hc<BeaconBlock<P>>,
    mut verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.slot);

    // > [New in Gloas:EIP7732]
    process_parent_execution_payload(config, pubkey_cache, state, block)?;

    unphased::process_block_header(config, state, block)?;

    // > [Modified in Gloas:EIP7732]
    process_withdrawals(state)?;

    // > [New in Gloas:EIP7732]
    // This function must be called after `process_withdrawals`
    let parent_slot = process_execution_payload_bid(
        config,
        pubkey_cache,
        state,
        &block.body.signed_execution_payload_bid,
    )?;

    unphased::process_randao(config, pubkey_cache, state, &block.body, &mut verifier)?;
    unphased::process_eth1_data(state, &block.body)?;

    // > [Modified in Gloas:EIP7732]
    process_operations(
        config,
        pubkey_cache,
        state,
        &block.body,
        parent_slot,
        &mut verifier,
        &mut slot_report,
    )?;

    altair::process_sync_aggregate(
        config,
        pubkey_cache,
        state,
        block.body.sync_aggregate,
        verifier,
        slot_report,
    )
}

/// [`get_expected_withdrawals`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.0/specs/gloas/beacon-chain.md#modified-get_expected_withdrawals)
pub fn get_expected_withdrawals<P: Preset>(
    state: &(impl PostGloasBeaconState<P> + ?Sized),
) -> Result<(Vec<Withdrawal>, usize, usize, u64)> {
    // This limit is to ensure the last withdrawal is reserve for validator sweep
    let withdrawal_limit = P::MaxWithdrawalsPerPayload::USIZE.try_sub(1)?;
    let current_epoch = get_current_epoch(state);
    let mut withdrawal_index = state.next_withdrawal_index();
    let mut withdrawals: Vec<Withdrawal> = vec![];

    // > [New in Gloas:EIP7732] Get builder withdrawals
    let processed_builder_withdrawals_count = get_builder_withdrawals_count(
        state,
        &mut withdrawal_index,
        &mut withdrawals,
        withdrawal_limit,
    )?;

    // Get partial withdrawals
    let processed_partial_withdrawals_count = get_pending_partial_withdrawals_count(
        state,
        &mut withdrawal_index,
        &mut withdrawals,
        withdrawal_limit,
        current_epoch,
    )?;

    // > [New in Gloas:EIP7732] Get builders sweep withdrawals
    let processed_builders_sweep_count = get_builders_sweep_withdrawals_count(
        state,
        &mut withdrawal_index,
        &mut withdrawals,
        withdrawal_limit,
        current_epoch,
    )?;

    // Get validators sweep withdrawals
    process_validators_sweep_withdrawals(
        state,
        &mut withdrawal_index,
        &mut withdrawals,
        P::MaxWithdrawalsPerPayload::USIZE,
        current_epoch,
    )?;

    Ok((
        withdrawals,
        processed_builder_withdrawals_count,
        processed_partial_withdrawals_count,
        processed_builders_sweep_count,
    ))
}

fn get_builder_withdrawals_count<P: Preset>(
    state: &(impl PostGloasBeaconState<P> + ?Sized),
    withdrawal_index: &mut WithdrawalIndex,
    withdrawals: &mut Vec<Withdrawal>,
    withdrawal_limit: usize,
) -> Result<usize> {
    let mut processed_count: usize = 0;

    for withdrawal in &state.builder_pending_withdrawals().clone() {
        if withdrawals.len() >= withdrawal_limit {
            break;
        }

        withdrawals.push(Withdrawal {
            index: *withdrawal_index,
            validator_index: convert_builder_index_to_validator_index(withdrawal.builder_index),
            address: withdrawal.fee_recipient,
            amount: withdrawal.amount,
        });

        *withdrawal_index = withdrawal_index
            .checked_add(1)
            .ok_or(Error::<P>::WithdrawalIndexOverflow)?;

        processed_count = processed_count.try_add(1)?;
    }

    Ok(processed_count)
}

fn get_builders_sweep_withdrawals_count<P: Preset>(
    state: &(impl PostGloasBeaconState<P> + ?Sized),
    withdrawal_index: &mut WithdrawalIndex,
    withdrawals: &mut Vec<Withdrawal>,
    withdrawal_limit: usize,
    current_epoch: Epoch,
) -> Result<u64> {
    let total_builders = state.builders().len_u64();
    let bound = total_builders.min(P::MAX_BUILDERS_PER_WITHDRAWALS_SWEEP);
    let mut builder_index = state.next_withdrawal_builder_index();
    let mut processed_count: u64 = 0;

    for _ in 0..bound {
        if withdrawals.len() >= withdrawal_limit {
            break;
        }

        let builder = state.builders().get(builder_index)?;
        if builder.withdrawable_epoch <= current_epoch && builder.balance > 0 {
            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index: convert_builder_index_to_validator_index(builder_index),
                address: builder.execution_address,
                amount: builder.balance,
            });

            *withdrawal_index = withdrawal_index
                .checked_add(1)
                .ok_or(Error::<P>::WithdrawalIndexOverflow)?;
        }

        builder_index = builder_index
            .checked_add(1)
            .ok_or(Error::<P>::BuilderIndexOverflow)?
            .checked_rem(total_builders)
            .expect("total_builders being 0 should prevent the loop from being executed");

        processed_count = processed_count.try_add(1)?;
    }

    Ok(processed_count)
}

fn get_pending_partial_withdrawals_count<P: Preset>(
    state: &(impl PostGloasBeaconState<P> + ?Sized),
    withdrawal_index: &mut WithdrawalIndex,
    withdrawals: &mut Vec<Withdrawal>,
    withdrawal_limit: usize,
    current_epoch: Epoch,
) -> Result<usize> {
    let max_pending_partials_per_withdrawals_sweep: usize =
        P::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP.try_into()?;
    let bound = withdrawals
        .len()
        .try_add(max_pending_partials_per_withdrawals_sweep)?
        .min(withdrawal_limit);
    let mut processed_count: usize = 0;

    for withdrawal in &*state.pending_partial_withdrawals().clone_boxed() {
        if withdrawal.withdrawable_epoch > current_epoch || withdrawals.len() >= bound {
            break;
        }

        let validator = state.validators().get(withdrawal.validator_index)?;
        let has_sufficient_effective_balance =
            validator.effective_balance >= P::MIN_ACTIVATION_BALANCE;
        let total_withdrawn = withdrawals
            .iter()
            .filter(|w| w.validator_index == withdrawal.validator_index)
            .map(|w| w.amount)
            .sum();
        let balance_after_withdrawn = state
            .balances()
            .get(withdrawal.validator_index)
            .copied()?
            .try_sub(total_withdrawn)?;
        let has_excess_balance = balance_after_withdrawn > P::MIN_ACTIVATION_BALANCE;

        if validator.exit_epoch == FAR_FUTURE_EPOCH
            && has_sufficient_effective_balance
            && has_excess_balance
        {
            let withdrawable_balance = withdrawal
                .amount
                .min(balance_after_withdrawn.try_sub(P::MIN_ACTIVATION_BALANCE)?);

            let mut address = ExecutionAddress::zero();

            address.assign_from_slice(&validator.withdrawal_credentials[12..]);

            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index: withdrawal.validator_index,
                address,
                amount: withdrawable_balance,
            });

            *withdrawal_index = withdrawal_index
                .checked_add(1)
                .ok_or(Error::<P>::WithdrawalIndexOverflow)?;
        }

        processed_count = processed_count.try_add(1)?;
    }

    Ok(processed_count)
}

fn process_validators_sweep_withdrawals<P: Preset>(
    state: &(impl PostGloasBeaconState<P> + ?Sized),
    withdrawal_index: &mut WithdrawalIndex,
    withdrawals: &mut Vec<Withdrawal>,
    withdrawal_limit: usize,
    current_epoch: Epoch,
) -> Result<()> {
    let total_validators = state.validators().len_u64();
    let bound = total_validators.min(P::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
    let mut validator_index = state.next_withdrawal_validator_index();

    for _ in 0..bound {
        if withdrawals.len() >= withdrawal_limit {
            break;
        }

        let validator = state.validators().partial_validator(validator_index)?;
        let validator_effective_balance = state.validators().effective_balance(validator_index)?;

        let partially_withdrawn_balance = withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.validator_index == validator_index)
            .map(|withdrawal| withdrawal.amount)
            .sum();

        let balance = state
            .balances()
            .get(validator_index)
            .copied()?
            .try_sub(partially_withdrawn_balance)?;

        let address = validator
            .withdrawal_credentials
            .as_bytes()
            .index(PREFIX_LEN..)
            .pipe(ExecutionAddress::from_slice);

        if is_fully_withdrawable_validator(validator, balance, current_epoch) {
            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index,
                address,
                amount: balance,
            });

            *withdrawal_index = withdrawal_index
                .checked_add(1)
                .ok_or(Error::<P>::WithdrawalIndexOverflow)?;
        } else if is_partially_withdrawable_validator::<P>(
            validator,
            validator_effective_balance,
            balance,
        ) {
            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index,
                address,
                amount: balance
                    .checked_sub(get_max_effective_balance::<P>(validator))
                    .expect(
                        "is_partially_withdrawable_validator should only \
                         return true if the validator has excess balance",
                    ),
            });

            *withdrawal_index = withdrawal_index
                .checked_add(1)
                .ok_or(Error::<P>::WithdrawalIndexOverflow)?;
        }

        validator_index = validator_index
            .checked_add(1)
            .ok_or(Error::<P>::ValidatorIndexOverflow)?
            .checked_rem(total_validators)
            .expect("total_validators being 0 should prevent the loop from being executed");
    }

    Ok(())
}

pub fn process_withdrawals<P: Preset>(state: &mut impl PostGloasBeaconState<P>) -> Result<()> {
    // Return early if the parent block is empty.
    if state.latest_execution_payload_bid().block_hash != state.latest_block_hash() {
        return Ok(());
    }

    let (
        withdrawals,
        processed_builder_withdrawals_count,
        processed_partial_withdrawals_count,
        processed_builders_sweep_count,
    ) = get_expected_withdrawals(state)?;

    apply_withdrawals(state, withdrawals.iter().copied())?;

    // > Update the next withdrawal index if this block contained withdrawals
    if let Some(latest_withdrawal) = withdrawals.last() {
        *state.next_withdrawal_index_mut() = latest_withdrawal.index.try_add(1)?;
    }

    // > Update payload expected withdrawals
    *state.payload_expected_withdrawals_mut() = PersistentProgressiveList::try_from_iter(
        withdrawals
            .iter()
            .copied()
            .take(P::MaxWithdrawalsPerPayload::USIZE),
    )?;

    // > Update the pending builder withdrawals
    *state.builder_pending_withdrawals_mut() = PersistentProgressiveList::try_from_iter(
        state
            .builder_pending_withdrawals()
            .into_iter()
            .copied()
            .skip(processed_builder_withdrawals_count),
    )?;

    // > Update pending partial withdrawals
    let pending_partial_withdrawals = state.pending_partial_withdrawals().clone_boxed();

    state
        .pending_partial_withdrawals_mut()
        .try_assign_from_iter(
            &mut pending_partial_withdrawals
                .iter()
                .copied()
                .skip(processed_partial_withdrawals_count),
        )?;

    // > Update next withdrawal builder index to start the next withdrawal sweep
    update_next_withdrawal_builder_index(state, processed_builders_sweep_count)?;

    // > Update the next validator index to start the next withdrawal sweep
    capella::update_next_withdrawal_validator_index(state, &withdrawals)
}

pub fn update_next_withdrawal_builder_index<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    processed_builders_sweep_count: u64,
) -> Result<()> {
    let total_builders = state.builders().len_u64();

    if total_builders > 0 {
        let next_index = state
            .next_withdrawal_builder_index()
            .try_add(processed_builders_sweep_count)?;

        *state.next_withdrawal_builder_index_mut() = next_index.try_rem(total_builders)?;
    }

    Ok(())
}

fn apply_withdrawals<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    withdrawals: impl Iterator<Item = Withdrawal>,
) -> Result<()> {
    for withdrawal in withdrawals {
        let Withdrawal {
            amount,
            validator_index,
            ..
        } = withdrawal;

        if let Some(builder_index) = maybe_builder_index(validator_index) {
            decrease_balance(builder_balance(state, builder_index)?, amount);
        } else {
            decrease_balance(balance(state, validator_index)?, amount);
        }
    }

    Ok(())
}

fn validate_execution_payload_bid_signature_with_verifier<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    signed_bid: &SignedExecutionPayloadBid<P>,
    mut verifier: impl Verifier,
) -> Result<()> {
    let SignedExecutionPayloadBid {
        message: execution_payload_bid,
        signature,
    } = signed_bid;

    let builder = state.builders().get(execution_payload_bid.builder_index)?;

    // > Verify signature
    verifier.verify_singular(
        execution_payload_bid.signing_root(config, state),
        *signature,
        pubkey_cache.get_or_insert(builder.pubkey)?,
        SignatureKind::ExecutionPayloadBid,
    )
}

fn validate_execution_payload_bid<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    signed_bid: &SignedExecutionPayloadBid<P>,
) -> Result<()> {
    let current_epoch = get_current_epoch(state);
    let ExecutionPayloadBid {
        builder_index,
        value: amount,
        slot,
        parent_block_hash,
        parent_block_root,
        prev_randao,
        ..
    } = signed_bid.message;

    // > For self-builds, `amount` must be zero and `signature` must be empty,
    // Otherwise verify builder is active, has valid signature, and can pay bid.
    if builder_index == BUILDER_INDEX_SELF_BUILD {
        ensure!(amount == 0, Error::<P>::NoneZeroBidValue);
        ensure!(
            signed_bid.signature.is_empty(),
            Error::<P>::ExecutionPayloadBidSignatureInvalid
        );
    } else {
        let builder = state.builders().get(builder_index)?;
        ensure!(
            is_active_builder(builder, state.finalized_checkpoint().epoch),
            Error::<P>::BuilderNotActive {
                index: builder_index,
                current_epoch
            }
        );
        ensure!(
            builder.version == PAYLOAD_BUILDER_VERSION,
            Error::<P>::BuilderVersionMismatch {
                index: builder_index,
                builder_version: builder.version,
                expected: PAYLOAD_BUILDER_VERSION,
            }
        );
        ensure!(
            can_builder_cover_bid(state, builder_index, amount)?,
            Error::<P>::BuilderBalanceNotSufficient {
                index: builder_index,
                amount
            }
        );
        ensure!(
            validate_execution_payload_bid_signature_with_verifier(
                config,
                pubkey_cache,
                state,
                signed_bid,
                SingleVerifier,
            )
            .is_ok(),
            Error::<P>::ExecutionPayloadBidSignatureInvalid
        );
    }

    // > Verify commitments are under limit
    let maximum = config
        .get_blob_schedule_entry(get_current_epoch(state))
        .max_blobs_per_block;
    let in_block = signed_bid.message.blob_kzg_commitments.len();

    ensure!(
        in_block <= maximum,
        Error::<P>::TooManyBlockKzgCommitments { in_block, maximum },
    );

    // > Verify that the bid is for the current slot
    ensure!(
        slot == state.slot(),
        Error::<P>::BidSlotMismatch {
            in_bid: slot,
            in_state: state.slot(),
        }
    );
    ensure!(state.slot() > GENESIS_SLOT, Error::<P>::BidSlotAtGenesis);

    // > Verify that the bid is for the right parent block
    ensure!(
        parent_block_hash == state.latest_block_hash(),
        Error::<P>::BidParentBlockHashMismatch {
            in_bid: parent_block_hash,
            in_state: state.latest_block_hash(),
        }
    );

    let parent_beacon_block_root =
        accessors::get_block_root_at_slot(state, state.slot().saturating_sub(1))?;

    ensure!(
        parent_block_root == parent_beacon_block_root,
        Error::<P>::BidParentBlockRootMismatch {
            in_bid: parent_block_root,
            in_state: parent_beacon_block_root,
        }
    );

    // > Verify prev_randao
    let in_state = get_randao_mix(state, current_epoch);
    ensure!(
        prev_randao == in_state,
        Error::<P>::BidPrevRandaoMismatch {
            in_bid: prev_randao,
            in_state,
        },
    );

    Ok(())
}

pub fn process_parent_execution_payload<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    block: &BeaconBlock<P>,
) -> Result<()> {
    let bid = &block.body.signed_execution_payload_bid.message;
    let parent_bid = state.latest_execution_payload_bid();
    let requests = &block.body.parent_execution_requests;

    if bid.parent_block_hash != parent_bid.block_hash {
        // Parent was EMPTY -- no execution requests expected
        ensure!(
            *requests == ExecutionRequests::<P>::default(),
            Error::<P>::ExecutionRequestsNotEmpty
        );
        return Ok(());
    }

    let computed = requests.hash_tree_root();

    ensure!(
        computed == parent_bid.execution_requests_root,
        Error::<P>::ExecutionRequestsRootMismatch {
            computed,
            expected: parent_bid.execution_requests_root,
        }
    );

    apply_parent_execution_payload(config, pubkey_cache, state, requests)
}

pub fn apply_parent_execution_payload<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    execution_requests: &ExecutionRequests<P>,
) -> Result<()> {
    // > [New in Gloas:EIP7688] Progressive lists are unbounded at the SSZ level.
    // > Request counts are validated during processing instead.
    // > Note that `deposits` intentionally has no limit in the spec.
    ensure_operation_count::<P>(
        "withdrawal requests",
        execution_requests.withdrawals.len_usize(),
        P::MaxWithdrawalRequestsPerPayload::USIZE,
    )?;
    ensure_operation_count::<P>(
        "consolidation requests",
        execution_requests.consolidations.len_usize(),
        P::MaxConsolidationRequestsPerPayload::USIZE,
    )?;
    ensure_operation_count::<P>(
        "builder deposit requests",
        execution_requests.builder_deposits.len_usize(),
        P::MaxBuilderDepositRequestsPerPayload::USIZE,
    )?;
    ensure_operation_count::<P>(
        "builder exit requests",
        execution_requests.builder_exits.len_usize(),
        P::MaxBuilderExitRequestsPerPayload::USIZE,
    )?;

    process_execution_requests(config, pubkey_cache, state, execution_requests)?;

    let parent_bid = state.latest_execution_payload_bid().clone();
    let parent_slot = parent_bid.slot;
    let parent_epoch = compute_epoch_at_slot::<P>(parent_slot);

    if parent_epoch == get_current_epoch(state) {
        let payment_index = builder_payment_index_for_current_epoch::<P>(parent_slot)?;
        settle_builder_payment(state, payment_index)?;
    } else if parent_epoch == get_previous_epoch(state) {
        let payment_index = builder_payment_index_for_previous_epoch::<P>(parent_slot);
        settle_builder_payment(state, payment_index)?;
    } else if parent_bid.value > 0 {
        state
            .builder_pending_withdrawals_mut()
            .push(BuilderPendingWithdrawal {
                fee_recipient: parent_bid.fee_recipient,
                amount: parent_bid.value,
                builder_index: parent_bid.builder_index,
            })?;
    }

    let slot: usize = parent_slot.try_into()?;

    state
        .execution_payload_availability_mut()
        .set(slot % SlotsPerHistoricalRoot::<P>::non_zero_usize(), true);

    *state.latest_block_hash_mut() = parent_bid.block_hash;

    Ok(())
}

fn settle_builder_payment<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    payment_index: u64,
) -> Result<()> {
    ensure!(
        payment_index < BuilderPendingPaymentsLength::<P>::U64,
        Error::<P>::BuilderPaymentIndexOutOfBounds {
            index: payment_index,
            length: BuilderPendingPaymentsLength::<P>::U64,
        }
    );

    let payment = *state.builder_pending_payments().mod_index(payment_index);

    if payment.withdrawal.amount > 0 {
        state
            .builder_pending_withdrawals_mut()
            .push(payment.withdrawal)?;
    }

    *state
        .builder_pending_payments_mut()
        .mod_index_mut(payment_index) = BuilderPendingPayment::default();

    Ok(())
}

pub fn process_execution_payload_bid<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    signed_bid: &SignedExecutionPayloadBid<P>,
) -> Result<Slot> {
    let ExecutionPayloadBid {
        value: amount,
        builder_index,
        slot,
        fee_recipient,
        ..
    } = signed_bid.message;

    validate_execution_payload_bid(config, pubkey_cache, state, signed_bid)?;

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
            .builder_pending_payments_mut()
            .mod_index_mut(builder_payment_index_for_current_epoch::<P>(slot)?) = pending_payment;
    }

    // > Cache the parent block's slot before overwriting the bid
    let parent_slot = state.latest_execution_payload_bid().slot;

    // > Cache the signed execution payload bid
    *state.latest_execution_payload_bid_mut() = signed_bid.message.clone();

    Ok(parent_slot)
}

fn ensure_operation_count<P: Preset>(
    kind: &'static str,
    in_block: usize,
    maximum: usize,
) -> Result<()> {
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

#[expect(clippy::too_many_lines)]
pub fn process_operations<P: Preset, V: Verifier, B>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    body: &B,
    parent_slot: Slot,
    mut verifier: V,
    mut slot_report: impl SlotReport,
) -> Result<()>
where
    B: BlockBodyWithGloasAttestations<P>
        + BlockBodyWithGloasAttesterSlashings<P>
        + BlockBodyWithBlsToExecutionChanges<P>
        + BlockBodyWithPayloadAttestations<P>,
{
    // > [Modified in Fulu:EIP6110]
    ensure!(
        body.deposits().len_usize() == 0,
        Error::<P>::DepositCountMismatch {
            computed: 0,
            in_block: body.deposits().len_usize().try_into()?,
        },
    );

    // > [New in Gloas:EIP7688] Progressive lists are unbounded at the SSZ level.
    // > Operation counts are validated during processing instead.
    ensure_operation_count::<P>(
        "proposer slashings",
        body.proposer_slashings().len_usize(),
        P::MaxProposerSlashings::USIZE,
    )?;
    ensure_operation_count::<P>(
        "attester slashings",
        body.attester_slashings().len_usize(),
        P::MaxAttesterSlashingsElectra::USIZE,
    )?;
    ensure_operation_count::<P>(
        "attestations",
        body.attestations().len_usize(),
        P::MaxAttestationsElectra::USIZE,
    )?;
    ensure_operation_count::<P>(
        "voluntary exits",
        body.voluntary_exits().len_usize(),
        P::MaxVoluntaryExits::USIZE,
    )?;
    ensure_operation_count::<P>(
        "BLS to execution changes",
        body.bls_to_execution_changes().len_usize(),
        P::MaxBlsToExecutionChanges::USIZE,
    )?;
    ensure_operation_count::<P>(
        "payload attestations",
        body.payload_attestations().len_usize(),
        P::MaxPayloadAttestation::USIZE,
    )?;

    for proposer_slashing in body.proposer_slashings().iter().copied() {
        process_proposer_slashing(
            config,
            pubkey_cache,
            state,
            proposer_slashing,
            &mut verifier,
            &mut slot_report,
        )?;
    }

    for attester_slashing in body.attester_slashings() {
        electra::process_attester_slashing(
            config,
            pubkey_cache,
            state,
            attester_slashing,
            &mut verifier,
            &mut slot_report,
        )?;
    }

    // TODO: update on https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.1/specs/electra/beacon-chain.md#modified-process_attestation
    // Parallel iteration with Rayon has some overhead, which is most noticeable when the active
    // thread pool is busy. `ParallelIterator::collect` appears to wait for worker threads to become
    // available even if the current thread is itself a worker thread. This tends to happen when
    // verifying signatures for batches of blocks outside the state transition function.
    // Fortunately, the other validations in `validate_attestation_with_verifier` take a negligible
    // amount of time, so we can avoid the issue by running them sequentially.
    if V::IS_NULL {
        for attestation in body.attestations() {
            validate_attestation_with_verifier(
                config,
                pubkey_cache,
                state,
                attestation,
                &mut verifier,
            )?;
        }
    } else {
        initialize_shuffled_indices(state, body.attestations().iter())?;

        let attestations = body.attestations().iter().collect::<Vec<_>>();
        let triples = helper_functions::par_iter!(attestations)
            .map(|attestation| {
                let mut triple = Triple::default();

                validate_attestation_with_verifier(
                    config,
                    pubkey_cache,
                    state,
                    attestation,
                    &mut triple,
                )?;

                Ok(triple)
            })
            .collect::<Result<Vec<_>>>()?;

        verifier.extend(triples, SignatureKind::Attestation)?;
    }

    for attestation in body.attestations() {
        apply_attestation(config, state, attestation, parent_slot, &mut slot_report)?;
    }

    for voluntary_exit in body.voluntary_exits().iter().copied() {
        electra::process_voluntary_exit(
            config,
            pubkey_cache,
            state,
            voluntary_exit,
            &mut verifier,
        )?;
    }

    for bls_to_execution_change in body.bls_to_execution_changes().iter().copied() {
        capella::process_bls_to_execution_change(
            config,
            pubkey_cache,
            state,
            bls_to_execution_change,
            &mut verifier,
        )?;
    }

    for payload_attestation in body.payload_attestations() {
        process_payload_attestation(
            config,
            pubkey_cache,
            state,
            payload_attestation,
            &mut verifier,
        )?;
    }

    Ok(())
}

pub fn apply_attestation<P: Preset>(
    config: &Config,
    state: &mut impl PostGloasBeaconState<P>,
    attestation: &Attestation<P>,
    parent_slot: Slot,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    // > Participation flag indices
    // > [Modified in Gloas:EIP7732]
    let inclusion_delay = state.slot().try_sub(attestation.data.slot)?;
    let participation_flags = get_attestation_participation_flags(
        state,
        attestation.data,
        inclusion_delay,
        Some(parent_slot),
    )?;

    // > Update epoch participation flags
    let base_reward_per_increment = get_base_reward_per_increment(state)?;

    let attesting_indices_with_base_rewards = get_attesting_indices(state, attestation)?
        .into_iter()
        .map(|validator_index| {
            let base_reward = get_base_reward(state, validator_index, base_reward_per_increment)?;
            let effective_balance = state.validators().effective_balance(validator_index)?;
            Ok((validator_index, base_reward, effective_balance))
        })
        .collect::<Result<Vec<_>>>()?;

    // > [New in Gloas:EIP7732]
    let is_attestation_same_slot = is_attestation_same_slot(state, &attestation.data)?;
    let attestation_epoch = attestation_epoch(state, attestation.data.target.epoch)?;
    let payment_slot = match attestation_epoch {
        AttestationEpoch::Previous => {
            builder_payment_index_for_previous_epoch::<P>(attestation.data.slot)
        }
        AttestationEpoch::Current => {
            builder_payment_index_for_current_epoch::<P>(attestation.data.slot)?
        }
    };

    let mut payment = state
        .builder_pending_payments()
        .get(payment_slot)?
        .to_owned();

    let epoch_participation = match attestation_epoch {
        AttestationEpoch::Previous => state.previous_epoch_participation_mut(),
        AttestationEpoch::Current => state.current_epoch_participation_mut(),
    };

    let mut proposer_reward_numerator: Gwei = 0;

    for (validator_index, base_reward, effective_balance) in attesting_indices_with_base_rewards {
        let epoch_participation = epoch_participation.get_mut(validator_index)?;

        // > [New in Gloas:EIP7732]
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

        // > [New in Gloas:EIP7732]
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
    *state
        .builder_pending_payments_mut()
        .mod_index_mut(payment_slot) = payment;

    slot_report.add_attestation_reward(proposer_reward);
    slot_report.update_performance(
        state,
        attestation.data,
        get_attesting_indices(state, attestation)?,
    )?;

    Ok(())
}

pub fn validate_attestation_with_verifier<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
    verifier: impl Verifier,
) -> Result<()> {
    let AttestationData {
        slot: attestation_slot,
        index,
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
        attestation_slot.try_add(P::MIN_ATTESTATION_INCLUSION_DELAY.get())? <= state.slot(),
        Error::<P>::AttestationOutsideInclusionRange {
            state_slot: state.slot(),
            attestation_slot,
        },
    );

    // > [Modified in Gloas:EIP7732] Support index of `0` and `1` to signal payload status
    ensure!(
        index < 2,
        Error::<P>::AttestationWithInvalidPayloadStatus {
            attestation: attestation.clone().into(),
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
    validate_constructed_indexed_attestation(
        config,
        pubkey_cache,
        state,
        &indexed_attestation,
        verifier,
    )
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
pub fn process_payload_attestation<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    payload_attestation: &PayloadAttestation<P>,
    verifier: impl Verifier,
) -> Result<()> {
    // > Check that the attestation is for the parent beacon block
    let data = payload_attestation.data;
    let in_attestation = data.beacon_block_root;
    let in_header = state.latest_block_header().parent_root;
    ensure!(
        in_attestation == in_header,
        Error::<P>::PayloadAttestationBlockRootMismatch {
            in_header,
            in_attestation
        }
    );

    // > Check that the attestation is for the previous slot
    let state_slot = state.slot();
    ensure!(
        data.slot.try_add(1)? == state_slot,
        Error::<P>::PayloadAttestationNotForPreviousSlot {
            in_attestation: data.slot,
            state_slot,
        }
    );

    // > Verify signature
    let indexed_payload_attestation = get_indexed_payload_attestation(state, payload_attestation)?;

    validate_constructed_indexed_payload_attestation(
        config,
        pubkey_cache,
        state,
        &indexed_payload_attestation,
        verifier,
    )
}

pub fn process_proposer_slashing<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    proposer_slashing: ProposerSlashing,
    verifier: impl Verifier,
    slot_report: impl SlotReport,
) -> Result<()> {
    unphased::validate_proposer_slashing_with_verifier(
        config,
        pubkey_cache,
        state,
        proposer_slashing,
        verifier,
    )?;

    // > Remove the BuilderPendingPayment corresponding to this proposal if it is
    // > still in the 2-epoch window. Only clear it when the slashed validator is
    // > the proposer associated with the payment; otherwise an unrelated same-slot
    // > equivocation could grief an honest proposer's payment
    let slot = proposer_slashing.signed_header_1.message.slot;
    let proposer_index = proposer_slashing.signed_header_1.message.proposer_index;
    let proposal_epoch = compute_epoch_at_slot::<P>(slot);

    let payment_index = if proposal_epoch == get_current_epoch(state) {
        Some(builder_payment_index_for_current_epoch::<P>(slot)?)
    } else if proposal_epoch == get_previous_epoch(state) {
        Some(builder_payment_index_for_previous_epoch::<P>(slot))
    } else {
        None
    };

    if let Some(payment_index) = payment_index {
        let payment = state
            .builder_pending_payments_mut()
            .mod_index_mut(payment_index);

        if payment.proposer_index == proposer_index {
            *payment = BuilderPendingPayment::default();
        }
    }

    slash_validator(
        config,
        state,
        proposer_index,
        None,
        SlashingKind::Proposer,
        slot_report,
    )
}

#[cfg(test)]
mod spec_tests {
    use core::fmt::Debug;

    use helper_functions::{slot_report::NullSlotReport, verifier::NullVerifier};
    use spec_test_utils::{BlsSetting, Case, Meta};
    use ssz::SszReadDefault;
    use test_generator::test_resources;
    use types::{
        gloas::containers::AttesterSlashing,
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
        |config, _, state, block: Hc<BeaconBlock<_>>, _| unphased::process_block_header(config, state, &block),
        "block",
        "consensus-spec-tests/tests/mainnet/gloas/operations/block_header/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/block_header/*/*",
    }

    processing_tests! {
        process_proposer_slashing,
        |config, pubkey_cache, state, proposer_slashing, _| {
            process_proposer_slashing(
                config,
                pubkey_cache,
                state,
                proposer_slashing,
                SingleVerifier,
                NullSlotReport,
            )
        },
        "proposer_slashing",
        "consensus-spec-tests/tests/mainnet/gloas/operations/proposer_slashing/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/proposer_slashing/*/*",
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
        "consensus-spec-tests/tests/mainnet/gloas/operations/attester_slashing/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/attester_slashing/*/*",
    }

    processing_tests! {
        process_attestation,
        |config, pubkey_cache, state, attestation, meta| {
            process_attestation(
                config,
                pubkey_cache,
                state,
                &attestation,
                meta,
            )
        },
        "attestation",
        "consensus-spec-tests/tests/mainnet/gloas/operations/attestation/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/attestation/*/*",
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
        "consensus-spec-tests/tests/mainnet/gloas/operations/bls_to_execution_change/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/bls_to_execution_change/*/*",
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
        "consensus-spec-tests/tests/mainnet/gloas/operations/voluntary_exit/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/voluntary_exit/*/*",
    }

    processing_tests! {
        process_voluntary_exit_churn,
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
        "consensus-spec-tests/tests/mainnet/gloas/operations/voluntary_exit_churn/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/voluntary_exit_churn/*/*",
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
        "consensus-spec-tests/tests/mainnet/gloas/operations/sync_aggregate/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/sync_aggregate/*/*",
    }

    processing_tests! {
        process_execution_payload_bid,
        |config, pubkey_cache, state, execution_payload_bid, _| {
            process_execution_payload_bid(
                config,
                pubkey_cache,
                state,
                &execution_payload_bid,
            )
            .map(|_parent_slot| ())
        },
        "execution_payload_bid",
        "consensus-spec-tests/tests/mainnet/gloas/operations/execution_payload_bid/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/execution_payload_bid/*/*",
    }

    processing_tests! {
        process_payload_attestation,
        |config, pubkey_cache, state, payload_attestation, _| {
            process_payload_attestation(
                config,
                pubkey_cache,
                state,
                &payload_attestation,
                SingleVerifier,
            )
        },
        "payload_attestation",
        "consensus-spec-tests/tests/mainnet/gloas/operations/payload_attestation/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/payload_attestation/*/*",
    }

    processing_tests! {
        process_parent_execution_payload,
        |config, pubkey_cache, state, block, _| process_parent_execution_payload(config, pubkey_cache, state, &block),
        "block",
        "consensus-spec-tests/tests/mainnet/gloas/operations/parent_execution_payload/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/parent_execution_payload/*/*",
    }

    validation_tests! {
        validate_proposer_slashing,
        |config, pubkey_cache, state, proposer_slashing| {
            unphased::validate_proposer_slashing(config, pubkey_cache, state, proposer_slashing)
        },
        "proposer_slashing",
        "consensus-spec-tests/tests/mainnet/gloas/operations/proposer_slashing/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/proposer_slashing/*/*",
    }

    validation_tests! {
        validate_attester_slashing,
        |config, pubkey_cache, state, attester_slashing: AttesterSlashing<P>| {
            unphased::validate_attester_slashing(config, pubkey_cache, state, &attester_slashing)
        },
        "attester_slashing",
        "consensus-spec-tests/tests/mainnet/gloas/operations/attester_slashing/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/attester_slashing/*/*",
    }

    validation_tests! {
        validate_voluntary_exit,
        |config, pubkey_cache, state, voluntary_exit| {
            electra::validate_voluntary_exit_with_verifier(config, pubkey_cache, state, voluntary_exit, SingleVerifier)
        },
        "voluntary_exit",
        "consensus-spec-tests/tests/mainnet/gloas/operations/voluntary_exit/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/voluntary_exit/*/*",
    }

    // TODO(feature/electra): comment this & run missing test script
    validation_tests! {
        validate_bls_to_execution_change,
        |config, pubkey_cache, state, bls_to_execution_change| {
            capella::validate_bls_to_execution_change(config, pubkey_cache, state, bls_to_execution_change)
        },
        "address_change",
        "consensus-spec-tests/tests/mainnet/gloas/operations/bls_to_execution_change/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/bls_to_execution_change/*/*",
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/gloas/operations/withdrawals/*/*")]
    fn mainnet_withdrawals(case: Case) {
        run_withdrawals_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/gloas/operations/withdrawals/*/*")]
    fn minimal_withdrawals(case: Case) {
        run_withdrawals_case::<Minimal>(case);
    }

    fn run_processing_case<P: Preset, O: SszReadDefault>(
        case: Case,
        operation_name: &str,
        processing_function: impl FnOnce(
            &Config,
            &PubkeyCache,
            &mut GloasBeaconState<P>,
            O,
            &Meta,
        ) -> Result<()>,
    ) {
        let pubkey_cache = PubkeyCache::default();
        let mut state = case.ssz_default("pre");
        let operation = case.ssz_default(operation_name);
        let post_option = case.try_ssz_default("post");
        let meta = case.meta();

        let result = processing_function(
            &P::default_config(),
            &pubkey_cache,
            &mut state,
            operation,
            &meta,
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
        validation_function: impl FnOnce(
            &Config,
            &PubkeyCache,
            &mut GloasBeaconState<P>,
            O,
        ) -> Result<R>,
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

    fn run_withdrawals_case<P: Preset>(case: Case) {
        let mut state = case.ssz_default::<GloasBeaconState<P>>("pre");
        let post_option = case.try_ssz_default("post");

        let result = process_withdrawals(&mut state).map(|()| state);

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
        state: &mut GloasBeaconState<P>,
        attestation: &Attestation<P>,
        meta: &Meta,
    ) -> Result<()> {
        match meta.bls_setting {
            BlsSetting::Optional | BlsSetting::Required => validate_attestation_with_verifier(
                config,
                pubkey_cache,
                state,
                attestation,
                SingleVerifier,
            )?,
            BlsSetting::Ignored => validate_attestation_with_verifier(
                config,
                pubkey_cache,
                state,
                attestation,
                NullVerifier,
            )?,
        }

        // The bid is not processed here, so the bid in the state
        // is still the parent block's bid and its slot is the parent block's slot.
        let parent_slot = meta
            .parent_slot
            .unwrap_or(state.latest_execution_payload_bid.slot);

        apply_attestation(config, state, attestation, parent_slot, NullSlotReport)
    }
}
