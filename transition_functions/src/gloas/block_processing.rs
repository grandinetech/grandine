use core::ops::{Add as _, Index as _, Rem as _};

use anyhow::{ensure, Result};
use bit_field::BitField as _;
use bls::traits::SignatureBytes as _;
use helper_functions::{
    accessors::{
        self, attestation_epoch, get_attestation_participation_flags, get_base_reward,
        get_base_reward_per_increment, get_beacon_proposer_index, get_current_epoch,
        get_indexed_payload_attestation, get_previous_epoch, initialize_shuffled_indices,
    },
    electra::{
        get_attesting_indices, get_indexed_attestation, is_fully_withdrawable_validator,
        is_partially_withdrawable_validator, slash_validator,
    },
    error::SignatureKind,
    misc::{
        builder_payment_index_for_current_epoch, builder_payment_index_for_previous_epoch,
        compute_epoch_at_slot, get_max_effective_balance,
    },
    mutators::{balance, decrease_balance, increase_balance},
    predicates::{
        has_builder_withdrawal_credential, is_active_validator, is_attestation_same_slot,
        is_builder_payment_withdrawable, is_parent_block_full,
        validate_constructed_indexed_attestation, validate_constructed_indexed_payload_attestation,
    },
    signing::SignForSingleFork as _,
    slot_report::SlotReport,
    verifier::{SingleVerifier, Triple, Verifier},
};
use pubkey_cache::PubkeyCache;
#[cfg(not(target_os = "zkvm"))]
use rayon::iter::ParallelIterator as _;
use ssz::{ContiguousList, PersistentList, SszHash as _};
use tap::Pipe as _;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    altair::consts::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    capella::containers::Withdrawal,
    config::Config,
    electra::containers::Attestation,
    gloas::{
        beacon_state::BeaconState as GloasBeaconState,
        containers::{
            BeaconBlock, BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadBid,
            PayloadAttestation, SignedBeaconBlock, SignedExecutionPayloadBid,
        },
    },
    nonstandard::{AttestationEpoch, SlashingKind},
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        containers::{AttestationData, ProposerSlashing},
        primitives::{DepositIndex, ExecutionAddress, H256},
    },
    preset::Preset,
    traits::{
        BeaconState, BlockBodyWithBlsToExecutionChanges, BlockBodyWithElectraAttestations,
        BlockBodyWithPayloadAttestations, PostGloasBeaconState,
    },
};

use crate::{
    altair, capella, electra,
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

pub fn count_required_signatures<P: Preset>(block: &BeaconBlock<P>) -> usize {
    altair::count_required_signatures(block) + block.body.bls_to_execution_changes.len()
}

pub fn custom_process_block<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut GloasBeaconState<P>,
    block: &BeaconBlock<P>,
    mut verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.slot);

    unphased::process_block_header(config, state, block)?;

    // > [Modified in Gloas:EIP7732]
    process_withdrawals(state)?;

    // > [New in Gloas:EIP7732]
    process_execution_payload_bid(config, pubkey_cache, state, block)?;

    unphased::process_randao(config, pubkey_cache, state, &block.body, &mut verifier)?;
    unphased::process_eth1_data(state, &block.body)?;

    // > [Modified in Gloas:EIP7732]
    process_operations(
        config,
        pubkey_cache,
        state,
        &block.body,
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

/// [`get_expected_withdrawals`](https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/beacon-chain.md#modified-get_expected_withdrawals)
#[expect(clippy::too_many_lines)]
pub fn get_expected_withdrawals<P: Preset>(
    state: &(impl PostGloasBeaconState<P> + ?Sized),
) -> Result<(Vec<Withdrawal>, usize, usize)> {
    let epoch = get_current_epoch(state);
    let total_validators = state.validators().len_u64();
    let max_pending_partials_per_withdrawals_sweep: usize =
        P::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP.try_into()?;

    let mut withdrawal_index = state.next_withdrawal_index();
    let mut validator_index = state.next_withdrawal_validator_index();
    let mut withdrawals: Vec<Withdrawal> = vec![];
    let mut processed_partial_withdrawals_count = 0;
    let mut processed_builder_withdrawals_count = 0;

    // > [New in Gloas:EIP7732] Sweep for builder payments
    for withdrawal in &state.builder_pending_withdrawals().clone() {
        if withdrawal.withdrawable_epoch > epoch
            || withdrawals.len() + 1 == P::MaxWithdrawalsPerPayload::USIZE
        {
            break;
        }

        if is_builder_payment_withdrawable(state, withdrawal)? {
            let builder = state.validators().get(withdrawal.builder_index)?;
            let total_withdrawn = withdrawals
                .iter()
                .filter(|w| w.validator_index == withdrawal.builder_index)
                .map(|w| w.amount)
                .sum();
            let balance = state
                .balances()
                .get(withdrawal.builder_index)
                .copied()?
                .saturating_sub(total_withdrawn);

            let withdrawable_balance = if builder.slashed {
                withdrawal.amount.min(balance)
            } else if balance > P::MIN_ACTIVATION_BALANCE {
                withdrawal
                    .amount
                    .min(balance.saturating_sub(P::MIN_ACTIVATION_BALANCE))
            } else {
                0
            };

            if withdrawable_balance > 0 {
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index: withdrawal.builder_index,
                    address: withdrawal.fee_recipient,
                    amount: withdrawable_balance,
                });
                withdrawal_index += 1;
            }
        }

        processed_builder_withdrawals_count += 1;
    }

    // > Sweep for pending partial withdrawals
    let bound = withdrawals
        .len()
        .saturating_add(max_pending_partials_per_withdrawals_sweep)
        .min(P::MaxWithdrawalsPerPayload::USIZE - 1);
    for withdrawal in &state.pending_partial_withdrawals().clone() {
        if withdrawal.withdrawable_epoch > epoch || withdrawals.len() == bound {
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
        let validator_balance = state
            .balances()
            .get(withdrawal.validator_index)
            .copied()?
            .saturating_sub(total_withdrawn);
        let has_excess_balance = validator_balance > P::MIN_ACTIVATION_BALANCE;

        if validator.exit_epoch == FAR_FUTURE_EPOCH
            && has_sufficient_effective_balance
            && has_excess_balance
        {
            let withdrawable_balance = withdrawal
                .amount
                .min(validator_balance - P::MIN_ACTIVATION_BALANCE);

            let mut address = ExecutionAddress::zero();

            address.assign_from_slice(&validator.withdrawal_credentials[12..]);

            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index: withdrawal.validator_index,
                address,
                amount: withdrawable_balance,
            });

            withdrawal_index += 1;
        }

        processed_partial_withdrawals_count += 1;
    }

    // > Sweep for remaining
    let bound = total_validators.min(P::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
    for _ in 0..bound {
        let validator = state.validators().get(validator_index)?;

        let partially_withdrawn_balance = withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.validator_index == validator_index)
            .map(|withdrawal| withdrawal.amount)
            .sum();

        let balance = state
            .balances()
            .get(validator_index)
            .copied()?
            .saturating_sub(partially_withdrawn_balance);

        let address = validator
            .withdrawal_credentials
            .as_bytes()
            .index(H256::len_bytes() - ExecutionAddress::len_bytes()..)
            .pipe(ExecutionAddress::from_slice);

        if is_fully_withdrawable_validator(validator, balance, epoch) {
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address,
                amount: balance,
            });

            withdrawal_index = withdrawal_index
                .checked_add(1)
                .ok_or(Error::<P>::WithdrawalIndexOverflow)?;
        } else if is_partially_withdrawable_validator::<P>(validator, balance) {
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address,
                amount: balance
                    .checked_sub(get_max_effective_balance::<P>(validator))
                    .expect(
                        "is_partially_withdrawable_validator should only \
                         return true if the validator has excess balance",
                    ),
            });

            withdrawal_index = withdrawal_index
                .checked_add(1)
                .ok_or(Error::<P>::WithdrawalIndexOverflow)?;
        }

        if withdrawals.len() == P::MaxWithdrawalsPerPayload::USIZE {
            break;
        }

        validator_index = validator_index
            .checked_add(1)
            .ok_or(Error::<P>::ValidatorIndexOverflow)?
            .checked_rem(total_validators)
            .expect("total_validators being 0 should prevent the loop from being executed");
    }

    Ok((
        withdrawals,
        processed_builder_withdrawals_count,
        processed_partial_withdrawals_count,
    ))
}

pub fn process_withdrawals<P: Preset>(state: &mut impl PostGloasBeaconState<P>) -> Result<()> {
    if !is_parent_block_full(state) {
        return Ok(());
    }

    let (
        expected_withdrawals,
        processed_builder_withdrawals_count,
        processed_partial_withdrawals_count,
    ) = get_expected_withdrawals(state)?;

    *state.latest_withdrawals_root_mut() =
        ContiguousList::<Withdrawal, P::MaxWithdrawalsPerPayload>::try_from_iter(
            expected_withdrawals
                .iter()
                .copied()
                .take(P::MaxWithdrawalsPerPayload::USIZE),
        )?
        .hash_tree_root();

    for withdrawal in expected_withdrawals.iter().copied() {
        let Withdrawal {
            amount,
            validator_index,
            ..
        } = withdrawal;

        decrease_balance(balance(state, validator_index)?, amount);
    }

    // > Update the pending builder withdrawals
    *state.builder_pending_withdrawals_mut() = PersistentList::try_from_iter(
        state
            .builder_pending_withdrawals()
            .into_iter()
            .take(processed_builder_withdrawals_count)
            .filter(|&withdrawal| {
                !is_builder_payment_withdrawable(state, withdrawal).is_ok_and(|is_true| is_true)
            })
            .copied()
            .chain(
                state
                    .builder_pending_withdrawals()
                    .into_iter()
                    .copied()
                    .skip(processed_builder_withdrawals_count),
            )
            .take(P::BuilderPendingWithdrawalsLimit::USIZE),
    )?;

    // > Update pending partial withdrawals
    *state.pending_partial_withdrawals_mut() = PersistentList::try_from_iter(
        state
            .pending_partial_withdrawals()
            .into_iter()
            .copied()
            .skip(processed_partial_withdrawals_count),
    )?;

    // > Update the next withdrawal index if this block contained withdrawals
    if let Some(latest_withdrawal) = expected_withdrawals.last() {
        *state.next_withdrawal_index_mut() = latest_withdrawal.index + 1;
    }

    // > Update the next validator index to start the next withdrawal sweep
    if expected_withdrawals.len() == P::MaxWithdrawalsPerPayload::USIZE {
        // > Next sweep starts after the latest withdrawal's validator index
        let next_validator_index = expected_withdrawals
            .last()
            .expect(
                "the NonZero bound on P::MaxWithdrawalsPerPayload \
                 ensures that expected_withdrawals is not empty",
            )
            .validator_index
            .add(1)
            .rem(state.validators().len_u64());

        *state.next_withdrawal_validator_index_mut() = next_validator_index;
    } else {
        // > Advance sweep by the max length of the sweep if there was not a full set of withdrawals
        let next_index =
            state.next_withdrawal_validator_index() + P::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP;

        let next_validator_index = next_index % state.validators().len_u64();

        *state.next_withdrawal_validator_index_mut() = next_validator_index;
    }

    Ok(())
}

fn validate_execution_payload_bid_signature_with_verifier<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    signed_bid: SignedExecutionPayloadBid,
    mut verifier: impl Verifier,
) -> Result<()> {
    let SignedExecutionPayloadBid {
        message: execution_payload_bid,
        signature,
    } = signed_bid;
    let builder = state
        .validators()
        .get(execution_payload_bid.builder_index)?;

    // > Verify signature
    verifier.verify_singular(
        execution_payload_bid.signing_root(config, state),
        signature,
        pubkey_cache.get_or_insert(builder.pubkey)?,
        SignatureKind::ExecutionPayloadBid,
    )
}

fn validate_execution_payload_bid<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    block: &BeaconBlock<P>,
) -> Result<()> {
    let signed_bid = block.body.signed_execution_payload_bid;
    let ExecutionPayloadBid {
        builder_index,
        value: amount,
        slot,
        parent_block_hash,
        parent_block_root,
        ..
    } = signed_bid.message;
    let builder = state.validators().get(builder_index)?;

    // > For self-builds, amount must be zero regardless of withdrawal credential prefix
    if builder_index == block.proposer_index {
        ensure!(amount == 0, Error::<P>::NoneZeroBidValue);
        ensure!(
            signed_bid.signature.is_empty(),
            Error::<P>::ExecutionPayloadBidSignatureInvalid
        );
    } else {
        ensure!(
            has_builder_withdrawal_credential(builder),
            Error::<P>::ExecutionPayloadBidNotBuilder
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

    let current_epoch = get_current_epoch(state);
    ensure!(
        is_active_validator(builder, current_epoch),
        Error::<P>::ValidatorNotActive {
            index: builder_index,
            validator: builder.clone(),
            current_epoch
        }
    );
    ensure!(
        !builder.slashed,
        Error::<P>::ValidatorAlreadySlashed {
            index: builder_index,
        }
    );

    // > Check that the builder is active, non-slashed, and has funds to cover the bid
    let builder_balance = *state.balances().get(builder_index)?;
    let pending_withdrawals = state
        .builder_pending_withdrawals()
        .into_iter()
        .filter_map(|withdrawal| {
            (withdrawal.builder_index == builder_index).then_some(withdrawal.amount)
        })
        .sum();
    let pending_payments = state
        .builder_pending_payments()
        .into_iter()
        .filter(|payment| payment.withdrawal.builder_index == builder_index)
        .map(|payment| payment.withdrawal.amount)
        .sum();
    let total_payment_withdraw_amount = amount
        .saturating_add(pending_payments)
        .saturating_add(pending_withdrawals)
        .saturating_add(P::MIN_ACTIVATION_BALANCE);
    ensure!(
        amount == 0 || builder_balance >= total_payment_withdraw_amount,
        Error::<P>::BuilderBalanceNotSufficient {
            balance: builder_balance,
            payments: total_payment_withdraw_amount,
        }
    );

    // > Verify that the bid is for the current slot
    ensure!(
        slot == block.slot,
        Error::<P>::BidSlotMismatch {
            in_bid: slot,
            in_block: block.slot
        }
    );

    // > Verify that the bid is for the right parent block
    ensure!(
        parent_block_hash == state.latest_block_hash(),
        Error::<P>::BidParentBlockHashMismatch {
            in_bid: parent_block_hash,
            in_state: state.latest_block_hash(),
        }
    );
    ensure!(
        parent_block_root == block.parent_root,
        Error::<P>::BidParentBlockRootMismatch {
            in_bid: parent_block_hash,
            in_block: block.parent_root,
        }
    );

    Ok(())
}

pub fn process_execution_payload_bid<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    block: &BeaconBlock<P>,
) -> Result<()> {
    let signed_bid = block.body.signed_execution_payload_bid;
    let ExecutionPayloadBid {
        value: amount,
        builder_index,
        slot,
        fee_recipient,
        ..
    } = signed_bid.message;
    validate_execution_payload_bid(config, pubkey_cache, state, block)?;

    // > Record the pending payment if there is some payment
    if amount > 0 {
        let pending_payment = BuilderPendingPayment {
            weight: 0,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient,
                amount,
                builder_index,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
            },
        };
        *state
            .builder_pending_payments_mut()
            .mod_index_mut(builder_payment_index_for_current_epoch::<P>(slot)) = pending_payment;
    }

    // > Cache the signed execution payload bid
    *state.latest_execution_payload_bid_mut() = signed_bid.message;

    Ok(())
}

pub fn process_operations<P: Preset, V: Verifier, B>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    body: &B,
    mut verifier: V,
    mut slot_report: impl SlotReport,
) -> Result<()>
where
    B: BlockBodyWithElectraAttestations<P>
        + BlockBodyWithBlsToExecutionChanges<P>
        + BlockBodyWithPayloadAttestations<P>,
{
    // > Verify that outstanding deposits are processed up to the maximum number of deposits
    let in_block = body.deposits().len().try_into()?;
    let computed = state
        .eth1_data()
        .deposit_count
        .saturating_sub(state.eth1_deposit_index())
        .min(P::MaxDeposits::U64);
    ensure!(
        in_block == computed,
        Error::<P>::DepositCountMismatch { computed, in_block }
    );

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

        let triples = helper_functions::par_iter!(body.attestations())
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
        apply_attestation(config, state, attestation, &mut slot_report)?;
    }

    // The conditional is not needed for correctness.
    // It only serves to avoid overhead when processing blocks with no deposits.
    if !body.deposits().is_empty() {
        let combined_deposits = unphased::validate_deposits(
            config,
            pubkey_cache,
            state,
            body.deposits().iter().copied(),
        )?;

        let deposit_count = body.deposits().len();

        // > Deposits must be processed in order
        *state.eth1_deposit_index_mut() += DepositIndex::try_from(deposit_count)?;

        electra::apply_deposits(state, combined_deposits, slot_report)?;
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

    for payload_attestation in body.payload_attestations().iter().copied() {
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
    mut slot_report: impl SlotReport,
) -> Result<()> {
    // > Participation flag indices
    let inclusion_delay = state.slot() - attestation.data.slot;
    let participation_flags =
        get_attestation_participation_flags(state, attestation.data, inclusion_delay)?;

    // > Update epoch participation flags
    let is_attestation_same_slot = is_attestation_same_slot(state, &attestation.data)?;
    let base_reward_per_increment = get_base_reward_per_increment(state);

    let attesting_indices_with_base_rewards = get_attesting_indices(state, attestation)?
        .into_iter()
        .map(|validator_index| {
            let base_reward = get_base_reward(state, validator_index, base_reward_per_increment)?;
            let effective_balance = state.validators().get(validator_index)?.effective_balance;
            Ok((validator_index, base_reward, effective_balance))
        })
        .collect::<Result<Vec<_>>>()?;

    // > [New in Gloas:EIP7732]
    let attestation_epoch = attestation_epoch(state, attestation.data.target.epoch)?;
    let mut payment = match attestation_epoch {
        AttestationEpoch::Previous => {
            state
                .builder_pending_payments()
                .get(builder_payment_index_for_previous_epoch::<P>(
                    attestation.data.slot,
                ))
        }
        AttestationEpoch::Current => {
            state
                .builder_pending_payments()
                .get(builder_payment_index_for_current_epoch::<P>(
                    attestation.data.slot,
                ))
        }
    }?
    .to_owned();

    let epoch_participation = match attestation_epoch {
        AttestationEpoch::Previous => state.previous_epoch_participation_mut(),
        AttestationEpoch::Current => state.current_epoch_participation_mut(),
    };

    let mut proposer_reward_numerator = 0;

    for (validator_index, base_reward, effective_balance) in attesting_indices_with_base_rewards {
        let epoch_participation = epoch_participation.get_mut(validator_index)?;

        // > For same-slot attestations, check if we're setting any new flags
        // If we are, this validator hasn't contributed to this slot's quorum yet
        let mut will_set_new_flag = false;

        for (flag_index, weight) in PARTICIPATION_FLAG_WEIGHTS {
            if participation_flags.get_bit(flag_index) && !epoch_participation.get_bit(flag_index) {
                proposer_reward_numerator += base_reward * weight;
                will_set_new_flag = true;
            }
        }

        *epoch_participation |= participation_flags;

        // > Add weight for same-slot attestations when any new flag is set
        // This ensures each validator contributes exactly once per slot
        if will_set_new_flag && is_attestation_same_slot && payment.withdrawal.amount > 0 {
            payment.weight += effective_balance;
        }
    }

    // > Reward proposer
    let proposer_index = get_beacon_proposer_index(config, state)?;
    let proposer_reward_denominator =
        (WEIGHT_DENOMINATOR.get() - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR.get() / PROPOSER_WEIGHT;
    let proposer_reward = proposer_reward_numerator / proposer_reward_denominator;

    increase_balance(balance(state, proposer_index)?, proposer_reward);

    // > Update builder payment weight
    match attestation_epoch {
        AttestationEpoch::Current => {
            *state.builder_pending_payments_mut().mod_index_mut(
                builder_payment_index_for_current_epoch::<P>(attestation.data.slot),
            ) = payment
        }
        AttestationEpoch::Previous => {
            *state.builder_pending_payments_mut().mod_index_mut(
                builder_payment_index_for_previous_epoch::<P>(attestation.data.slot),
            ) = payment
        }
    }

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
        attestation_slot + P::MIN_ATTESTATION_INCLUSION_DELAY.get() <= state.slot(),
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

pub fn process_payload_attestation<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    payload_attestation: PayloadAttestation<P>,
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
        data.slot + 1 == state_slot,
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

    // > Remove the BuilderPendingPayment corresponding to this proposal if it is still in the 2-epoch window.
    let slot = proposer_slashing.signed_header_1.message.slot;
    let proposal_epoch = compute_epoch_at_slot::<P>(slot);
    if proposal_epoch == get_current_epoch(state) {
        *state
            .builder_pending_payments_mut()
            .mod_index_mut(builder_payment_index_for_current_epoch::<P>(slot)) =
            BuilderPendingPayment::default();
    } else if proposal_epoch == get_previous_epoch(state) {
        *state
            .builder_pending_payments_mut()
            .mod_index_mut(builder_payment_index_for_previous_epoch::<P>(slot)) =
            BuilderPendingPayment::default();
    }

    let index = proposer_slashing.signed_header_1.message.proposer_index;

    slash_validator(
        config,
        state,
        index,
        None,
        SlashingKind::Proposer,
        slot_report,
    )
}

#[cfg(test)]
mod spec_tests {
    use core::fmt::Debug;

    use helper_functions::{slot_report::NullSlotReport, verifier::NullVerifier};
    use spec_test_utils::{BlsSetting, Case};
    use ssz::SszReadDefault;
    use test_generator::test_resources;
    use types::{
        electra::containers::{Attestation, AttesterSlashing},
        phase0::containers::Deposit,
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
        |config, _, state, block: BeaconBlock<_>, _| unphased::process_block_header(config, state, &block),
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
        process_deposit,
        |config, pubkey_cache, state, deposit, _| process_deposit(config, pubkey_cache, state, deposit),
        "deposit",
        "consensus-spec-tests/tests/mainnet/gloas/operations/deposit/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/deposit/*/*",
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
        "consensus-spec-tests/tests/mainnet/gloas/operations/deposit/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/deposit/*/*",
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
        |config, pubkey_cache, state, block, _| {
            process_execution_payload_bid(
                config,
                pubkey_cache,
                state,
                &block,
            )
        },
        "block",
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
                payload_attestation,
                SingleVerifier,
            )
        },
        "payload_attestation",
        "consensus-spec-tests/tests/mainnet/gloas/operations/payload_attestation/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/payload_attestation/*/*",
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
        bls_setting: BlsSetting,
    ) -> Result<()> {
        match bls_setting {
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

        apply_attestation(config, state, attestation, NullSlotReport)
    }

    fn process_deposit<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut GloasBeaconState<P>,
        deposit: Deposit,
    ) -> Result<()> {
        let combined_deposits =
            unphased::validate_deposits(config, pubkey_cache, state, core::iter::once(deposit))?;

        // > Deposits must be processed in order
        *state.eth1_deposit_index_mut() += 1;

        electra::apply_deposits(state, combined_deposits, NullSlotReport)
    }
}
