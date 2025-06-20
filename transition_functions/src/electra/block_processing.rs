use core::ops::{Add as _, Index as _, Rem as _};

use anyhow::{ensure, Result};
use arithmetic::U64Ext as _;
use bit_field::BitField as _;
use bls::PublicKeyBytes;
use execution_engine::{ExecutionEngine, NullExecutionEngine};
use helper_functions::{
    accessors::{
        self, attestation_epoch, get_attestation_participation_flags, get_base_reward,
        get_base_reward_per_increment, get_beacon_proposer_index, get_consolidation_churn_limit,
        get_current_epoch, get_pending_balance_to_withdraw, get_randao_mix, index_of_public_key,
        initialize_shuffled_indices,
    },
    electra::{
        get_attesting_indices, get_indexed_attestation, initiate_validator_exit,
        is_fully_withdrawable_validator, is_partially_withdrawable_validator, slash_validator,
    },
    error::SignatureKind,
    misc::{
        compute_epoch_at_slot, compute_timestamp_at_slot, get_max_effective_balance,
        kzg_commitment_to_versioned_hash,
    },
    mutators::{
        balance, compute_consolidation_epoch_and_update_churn, compute_exit_epoch_and_update_churn,
        decrease_balance, increase_balance, switch_to_compounding_validator,
    },
    predicates::{
        has_compounding_withdrawal_credential, has_eth1_withdrawal_credential,
        has_execution_withdrawal_credential, is_active_validator,
        validate_constructed_indexed_attestation,
    },
    signing::{SignForAllForks, SignForSingleFork as _},
    slot_report::{NullSlotReport, SlotReport},
    verifier::{SingleVerifier, Triple, Verifier},
};
use itertools::izip;
use pubkey_cache::PubkeyCache;
use rayon::iter::{IntoParallelRefIterator as _, ParallelIterator as _};
use ssz::{PersistentList, SszHash as _};
use tap::Pipe as _;
use try_from_iterator::TryFromIterator as _;
use typenum::{NonZero, Unsigned as _};
use types::{
    altair::consts::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    capella::containers::Withdrawal,
    combined::ExecutionPayloadParams,
    config::Config,
    deneb::containers::ExecutionPayloadHeader,
    electra::{
        beacon_state::BeaconState as ElectraBeaconState,
        consts::{FULL_EXIT_REQUEST_AMOUNT, UNSET_DEPOSIT_REQUESTS_START_INDEX},
        containers::{
            Attestation, BeaconBlock, BeaconBlockBody, ConsolidationRequest, DepositRequest,
            PendingConsolidation, PendingDeposit, PendingPartialWithdrawal, SignedBeaconBlock,
            WithdrawalRequest,
        },
    },
    nonstandard::{smallvec, AttestationEpoch, SlashingKind},
    phase0::{
        consts::{FAR_FUTURE_EPOCH, GENESIS_SLOT},
        containers::{
            AttestationData, DepositData, DepositMessage, ProposerSlashing, SignedVoluntaryExit,
            Validator,
        },
        primitives::{DepositIndex, ExecutionAddress, Gwei, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::{
        AttesterSlashing, BeaconState, PostCapellaExecutionPayload, PostElectraBeaconBlockBody,
        PostElectraBeaconState,
    },
};

use crate::{
    altair, capella,
    unphased::{self, CombinedDeposit, Error},
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
    state: &mut ElectraBeaconState<P>,
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
    state: &ElectraBeaconState<P>,
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
    state: &mut ElectraBeaconState<P>,
    block: &BeaconBlock<P>,
    execution_engine: impl ExecutionEngine<P>,
    mut verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.slot);

    unphased::process_block_header(config, state, block)?;

    // > [Modified in Electra:EIP7251]
    process_withdrawals(state, &block.body.execution_payload)?;

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
    process_operations(
        config,
        pubkey_cache,
        state,
        &block.body,
        &mut verifier,
        &mut slot_report,
    )?;

    // > [New in Electra:EIP6110]
    for deposit_request in &block.body.execution_requests.deposits {
        process_deposit_request(state, *deposit_request)?;
    }

    // > [New in Electra:EIP7002:EIP7251]
    for withdrawal_request in &block.body.execution_requests.withdrawals {
        process_withdrawal_request(config, state, *withdrawal_request)?;
    }

    // > [New in Electra:EIP7251]
    for consolidation_request in &block.body.execution_requests.consolidations {
        process_consolidation_request(config, state, *consolidation_request)?;
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
    state: &ElectraBeaconState<P>,
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

    // > [Modified in Electra:EIP7691] Verify commitments are under limit
    let maximum = config.max_blobs_per_block_electra;
    let in_block = body.blob_kzg_commitments.len();

    ensure!(
        in_block <= maximum,
        Error::<P>::TooManyBlockKzgCommitments { in_block, maximum },
    );

    Ok(())
}

fn process_withdrawals<P: Preset>(
    state: &mut impl PostElectraBeaconState<P>,
    execution_payload: &impl PostCapellaExecutionPayload<P>,
) -> Result<()>
where
    P::MaxWithdrawalsPerPayload: NonZero,
{
    let (expected_withdrawals, processed_partial_withdrawals_count) =
        get_expected_withdrawals(state)?;

    let computed = expected_withdrawals.len();
    let in_block = execution_payload.withdrawals().len();

    ensure!(
        computed == in_block,
        Error::<P>::WithdrawalCountMismatch { computed, in_block },
    );

    for (computed, in_block) in izip!(
        expected_withdrawals.iter().copied(),
        execution_payload.withdrawals().iter().copied(),
    ) {
        ensure!(
            computed == in_block,
            Error::<P>::WithdrawalMismatch { computed, in_block },
        );

        let Withdrawal {
            amount,
            validator_index,
            ..
        } = computed;

        decrease_balance(balance(state, validator_index)?, amount);
    }

    // > Update pending partial withdrawals [New in Electra:EIP7251]
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

/// [`get_expected_withdrawals`](https://github.com/ethereum/consensus-specs/blob/dc17b1e2b6a4ec3a2104c277a33abae75a43b0fa/specs/capella/beacon-chain.md#new-get_expected_withdrawals)
#[expect(clippy::too_many_lines)]
pub fn get_expected_withdrawals<P: Preset>(
    state: &(impl PostElectraBeaconState<P> + ?Sized),
) -> Result<(Vec<Withdrawal>, usize)> {
    let epoch = get_current_epoch(state);
    let total_validators = state.validators().len_u64();
    let bound = total_validators.min(P::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
    let max_pending_partials_per_withdrawals_sweep: usize =
        P::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP.try_into()?;

    let mut withdrawal_index = state.next_withdrawal_index();
    let mut validator_index = state.next_withdrawal_validator_index();
    let mut withdrawals: Vec<Withdrawal> = vec![];
    let mut processed_partial_withdrawals_count = 0;

    // > [New in Electra:EIP7251] Consume pending partial withdrawals
    for withdrawal in &state.pending_partial_withdrawals().clone() {
        if withdrawal.withdrawable_epoch > epoch
            || withdrawals.len() == max_pending_partials_per_withdrawals_sweep
        {
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

    Ok((withdrawals, processed_partial_withdrawals_count))
}

fn process_execution_payload<P: Preset>(
    config: &Config,
    state: &mut ElectraBeaconState<P>,
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

pub fn process_operations<P: Preset, V: Verifier>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostElectraBeaconState<P>,
    body: &impl PostElectraBeaconBlockBody<P>,
    mut verifier: V,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    // > [Modified in Electra:EIP6110]
    // > Disable former deposit mechanism once all prior deposits are processed
    let eth1_deposit_index_limit = state
        .eth1_data()
        .deposit_count
        .min(state.deposit_requests_start_index());

    let in_block = body.deposits().len().try_into()?;

    if state.eth1_deposit_index() < eth1_deposit_index_limit {
        let computed =
            P::MaxDeposits::U64.min(eth1_deposit_index_limit - state.eth1_deposit_index());

        ensure!(
            computed == in_block,
            Error::<P>::DepositCountMismatch { computed, in_block },
        );
    } else {
        ensure!(
            in_block == 0,
            Error::<P>::DepositCountMismatch {
                computed: 0,
                in_block
            },
        );
    }

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
        process_attester_slashing(
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

        let triples = body
            .attestations()
            .par_iter()
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

        apply_deposits(state, combined_deposits, slot_report)?;
    }

    for voluntary_exit in body.voluntary_exits().iter().copied() {
        process_voluntary_exit(config, pubkey_cache, state, voluntary_exit, &mut verifier)?;
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

    Ok(())
}

pub fn process_proposer_slashing<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostElectraBeaconState<P>,
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

pub fn process_attester_slashing<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostElectraBeaconState<P>,
    attester_slashing: &impl AttesterSlashing<P>,
    verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    let slashable_indices = unphased::validate_attester_slashing_with_verifier(
        config,
        pubkey_cache,
        state,
        attester_slashing,
        verifier,
    )?;

    for validator_index in slashable_indices {
        slash_validator(
            config,
            state,
            validator_index,
            None,
            SlashingKind::Attester,
            &mut slot_report,
        )?;
    }

    Ok(())
}

pub fn apply_attestation<P: Preset>(
    config: &Config,
    state: &mut impl PostElectraBeaconState<P>,
    attestation: &Attestation<P>,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    // > Participation flag indices
    let inclusion_delay = state.slot() - attestation.data.slot;
    let participation_flags =
        get_attestation_participation_flags(state, attestation.data, inclusion_delay)?;

    // > Update epoch participation flags
    let base_reward_per_increment = get_base_reward_per_increment(state);

    let attesting_indices_with_base_rewards = get_attesting_indices(state, attestation)?
        .into_iter()
        .map(|validator_index| {
            let base_reward = get_base_reward(state, validator_index, base_reward_per_increment)?;
            Ok((validator_index, base_reward))
        })
        .collect::<Result<Vec<_>>>()?;

    let epoch_participation = match attestation_epoch(state, attestation.data.target.epoch)? {
        AttestationEpoch::Previous => state.previous_epoch_participation_mut(),
        AttestationEpoch::Current => state.current_epoch_participation_mut(),
    };

    let mut proposer_reward_numerator = 0;

    for (validator_index, base_reward) in attesting_indices_with_base_rewards {
        let epoch_participation = epoch_participation.get_mut(validator_index)?;

        for (flag_index, weight) in PARTICIPATION_FLAG_WEIGHTS {
            if participation_flags.get_bit(flag_index) && !epoch_participation.get_bit(flag_index) {
                proposer_reward_numerator += base_reward * weight;
            }
        }

        *epoch_participation |= participation_flags;
    }

    // > Reward proposer
    let proposer_index = get_beacon_proposer_index(config, state)?;
    let proposer_reward_denominator =
        (WEIGHT_DENOMINATOR.get() - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR.get() / PROPOSER_WEIGHT;
    let proposer_reward = proposer_reward_numerator / proposer_reward_denominator;

    increase_balance(balance(state, proposer_index)?, proposer_reward);

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

    ensure!(
        index == 0,
        Error::<P>::AttestationWithNonZeroCommitteeIndex {
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

// This is used to compute the genesis state.
// Unlike `process_deposit`, this doesn't verify `Deposit.proof`.
// Checking deposit proofs during genesis is redundant since we would be the ones constructing them.
//
// This could be implemented in terms of `validate_deposits` if the latter were modified to make
// proof checking optional, but the overhead of Rayon and `multi_verify` for single deposits is
// enough to slow down genesis by over 50%.
pub fn process_deposit_data<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostElectraBeaconState<P>,
    deposit_data: DepositData,
) -> Result<Option<ValidatorIndex>> {
    let DepositData {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
    } = deposit_data;

    *state.eth1_deposit_index_mut() += 1;

    if let Some(validator_index) = index_of_public_key(state, &pubkey) {
        let combined_deposit = CombinedDeposit::TopUp {
            validator_index,
            withdrawal_credentials: vec![withdrawal_credentials],
            amounts: smallvec![amount],
            signatures: vec![signature],
            positions: smallvec![0],
        };

        apply_deposits(state, core::iter::once(combined_deposit), NullSlotReport)?;

        return Ok(Some(validator_index));
    }

    // > Verify the deposit signature (proof of possession)
    // > which is not checked by the deposit contract
    let deposit_message = DepositMessage::from(deposit_data);

    // > Fork-agnostic domain since deposits are valid across forks
    if let Ok(decompressed) = pubkey_cache.get_or_insert(pubkey) {
        if deposit_message
            .verify(config, signature, decompressed)
            .is_ok()
        {
            let validator_index = state.validators().len_u64();

            let combined_deposit = CombinedDeposit::NewValidator {
                pubkey,
                withdrawal_credentials: vec![withdrawal_credentials],
                amounts: smallvec![amount],
                signatures: vec![signature],
                positions: smallvec![0],
            };

            apply_deposits(state, core::iter::once(combined_deposit), NullSlotReport)?;

            return Ok(Some(validator_index));
        }
    }

    Ok(None)
}

pub fn add_validator_to_registry<P: Preset>(
    state: &mut impl PostElectraBeaconState<P>,
    pubkey: PublicKeyBytes,
    withdrawal_credentials: H256,
    amount: Gwei,
) -> Result<()> {
    let validator_index = state.validators().len_u64();

    let mut validator = Validator {
        pubkey,
        withdrawal_credentials,
        effective_balance: 0,
        slashed: false,
        activation_eligibility_epoch: FAR_FUTURE_EPOCH,
        activation_epoch: FAR_FUTURE_EPOCH,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };

    let max_effective_balance = get_max_effective_balance::<P>(&validator);

    validator.effective_balance = amount
        .prev_multiple_of(P::EFFECTIVE_BALANCE_INCREMENT)
        .min(max_effective_balance);

    state.validators_mut().push(validator)?;
    state.balances_mut().push(amount)?;
    state.previous_epoch_participation_mut().push(0)?;
    state.current_epoch_participation_mut().push(0)?;
    state.inactivity_scores_mut().push(0)?;

    state
        .cache_mut()
        .validator_indices
        .get_mut()
        .expect(
            "state.cache.validator_indices is initialized by \
                index_of_public_key, which is called before apply_deposits",
        )
        .insert(pubkey, validator_index);

    Ok(())
}

fn apply_deposits<P: Preset>(
    state: &mut impl PostElectraBeaconState<P>,
    combined_deposits: impl IntoIterator<Item = CombinedDeposit>,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    let mut pending_deposits_with_positions = vec![];

    for combined_deposit in combined_deposits {
        match combined_deposit {
            // > Add validator and balance entries
            CombinedDeposit::NewValidator {
                pubkey,
                withdrawal_credentials,
                amounts,
                signatures,
                positions,
            } => {
                let first_withdrawal_credentials = withdrawal_credentials[0];
                let validator_index = state.validators().len_u64();

                add_validator_to_registry(state, pubkey, first_withdrawal_credentials, 0)?;

                for (withdrawal_credentials, amount, signature, position) in
                    izip!(withdrawal_credentials, amounts, signatures, positions)
                {
                    pending_deposits_with_positions.push((
                        PendingDeposit {
                            pubkey,
                            withdrawal_credentials,
                            amount,
                            signature,
                            slot: GENESIS_SLOT,
                        },
                        position,
                    ));

                    // TODO(feature/electra):
                    slot_report.add_deposit(validator_index, amount);
                }
            }
            // > Increase balance by deposit amount
            CombinedDeposit::TopUp {
                validator_index,
                withdrawal_credentials,
                amounts,
                signatures,
                positions,
            } => {
                let pubkey = accessors::public_key(state, validator_index)?;

                for (withdrawal_credentials, amount, signature, position) in
                    izip!(withdrawal_credentials, amounts, signatures, positions)
                {
                    pending_deposits_with_positions.push((
                        PendingDeposit {
                            pubkey: *pubkey,
                            withdrawal_credentials,
                            amount,
                            signature,
                            slot: GENESIS_SLOT,
                        },
                        position,
                    ));

                    slot_report.add_deposit(validator_index, amount);
                }
            }
        }
    }

    pending_deposits_with_positions.sort_unstable_by_key(|(_, position)| *position);

    for (pending_deposit, _) in pending_deposits_with_positions {
        state.pending_deposits_mut().push(pending_deposit)?;
    }

    Ok(())
}

pub fn process_voluntary_exit<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostElectraBeaconState<P>,
    signed_voluntary_exit: SignedVoluntaryExit,
    verifier: impl Verifier,
) -> Result<()> {
    validate_voluntary_exit_with_verifier(
        config,
        pubkey_cache,
        state,
        signed_voluntary_exit,
        verifier,
    )?;

    // > Initiate exit
    initiate_validator_exit(config, state, signed_voluntary_exit.message.validator_index)
}

pub fn validate_voluntary_exit<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostElectraBeaconState<P>,
    signed_voluntary_exit: SignedVoluntaryExit,
) -> Result<()> {
    validate_voluntary_exit_with_verifier(
        config,
        pubkey_cache,
        state,
        signed_voluntary_exit,
        SingleVerifier,
    )
}

fn validate_voluntary_exit_with_verifier<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostElectraBeaconState<P>,
    signed_voluntary_exit: SignedVoluntaryExit,
    verifier: impl Verifier,
) -> Result<()> {
    unphased::validate_voluntary_exit_with_verifier(
        config,
        pubkey_cache,
        state,
        signed_voluntary_exit,
        verifier,
    )?;

    // > [New in Electra:EIP7251] Only exit validator if it has no pending withdrawals in the queue
    ensure!(
        get_pending_balance_to_withdraw(state, signed_voluntary_exit.message.validator_index) == 0,
        Error::<P>::VoluntaryExitWithPendingWithdrawals,
    );

    Ok(())
}

pub fn process_withdrawal_request<P: Preset>(
    config: &Config,
    state: &mut impl PostElectraBeaconState<P>,
    withdrawal_request: WithdrawalRequest,
) -> Result<()> {
    let amount = withdrawal_request.amount;
    let is_full_exit_request = amount == FULL_EXIT_REQUEST_AMOUNT;

    // > If partial withdrawal queue is full, only full exits are processed
    if state.pending_partial_withdrawals().len_usize() == P::PendingPartialWithdrawalsLimit::USIZE
        && !is_full_exit_request
    {
        return Ok(());
    }

    // > Verify pubkey exists
    let request_pubkey = withdrawal_request.validator_pubkey;
    let Some(validator_index) = index_of_public_key(state, &request_pubkey) else {
        return Ok(());
    };
    let validator_balance = *balance(state, validator_index)?;
    let validator = state.validators().get(validator_index)?;

    // > Verify withdrawal credentials
    let has_correct_credential = has_execution_withdrawal_credential(validator);
    let source_address = validator
        .withdrawal_credentials
        .as_bytes()
        .index(H256::len_bytes() - ExecutionAddress::len_bytes()..)
        .pipe(ExecutionAddress::from_slice);

    let is_correct_source_address = source_address == withdrawal_request.source_address;

    if !(has_correct_credential && is_correct_source_address) {
        return Ok(());
    }

    // > Verify the validator is active
    if !is_active_validator(validator, get_current_epoch(state)) {
        return Ok(());
    }

    // > Verify exit has not been initiated
    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }

    // > Verify the validator has been active long enough
    if get_current_epoch(state) < validator.activation_epoch + config.shard_committee_period {
        return Ok(());
    }

    let pending_balance_to_withdraw = get_pending_balance_to_withdraw(state, validator_index);

    if is_full_exit_request {
        // > Only exit validator if it has no pending withdrawals in the queue
        if pending_balance_to_withdraw == 0 {
            initiate_validator_exit(config, state, validator_index)?;
        }

        return Ok(());
    }

    let has_sufficient_effective_balance = validator.effective_balance >= P::MIN_ACTIVATION_BALANCE;
    let has_excess_balance =
        validator_balance > P::MIN_ACTIVATION_BALANCE + pending_balance_to_withdraw;

    // > Only allow partial withdrawals with compounding withdrawal credentials
    if has_compounding_withdrawal_credential(validator)
        && has_sufficient_effective_balance
        && has_excess_balance
    {
        let to_withdraw =
            amount.min(validator_balance - P::MIN_ACTIVATION_BALANCE - pending_balance_to_withdraw);
        let exit_queue_epoch = compute_exit_epoch_and_update_churn(config, state, to_withdraw);
        let withdrawable_epoch = exit_queue_epoch + config.min_validator_withdrawability_delay;

        state
            .pending_partial_withdrawals_mut()
            .push(PendingPartialWithdrawal {
                validator_index,
                amount: to_withdraw,
                withdrawable_epoch,
            })?;
    }

    Ok(())
}

pub fn process_deposit_request<P: Preset>(
    state: &mut impl PostElectraBeaconState<P>,
    deposit_request: DepositRequest,
) -> Result<()> {
    let DepositRequest {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        index,
    } = deposit_request;

    let slot = state.slot();

    // > Set deposit request start index
    if state.deposit_requests_start_index() == UNSET_DEPOSIT_REQUESTS_START_INDEX {
        *state.deposit_requests_start_index_mut() = index;
    }

    state.pending_deposits_mut().push(PendingDeposit {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        slot,
    })?;

    Ok(())
}

pub fn process_consolidation_request<P: Preset>(
    config: &Config,
    state: &mut impl PostElectraBeaconState<P>,
    consolidation_request: ConsolidationRequest,
) -> Result<()> {
    let ConsolidationRequest {
        source_address,
        source_pubkey,
        target_pubkey,
    } = consolidation_request;

    if is_valid_switch_to_compounding_request(state, consolidation_request)? {
        let Some(source_index) = index_of_public_key(state, &source_pubkey) else {
            return Ok(());
        };

        return switch_to_compounding_validator(state, source_index);
    }

    // > Verify that source != target, so a consolidation cannot be used as an exit.
    if source_pubkey == target_pubkey {
        return Ok(());
    }

    // > If the pending consolidations queue is full, consolidation requests are ignored
    if state.pending_consolidations().len_usize() == P::PendingConsolidationsLimit::USIZE {
        return Ok(());
    }

    // > If there is too little available consolidation churn limit, consolidation requests are ignored
    if get_consolidation_churn_limit(config, state) <= P::MIN_ACTIVATION_BALANCE {
        return Ok(());
    }

    // > Verify pubkeys exists
    let Some(source_index) = index_of_public_key(state, &source_pubkey) else {
        return Ok(());
    };
    let Some(target_index) = index_of_public_key(state, &target_pubkey) else {
        return Ok(());
    };

    let source_validator = state.validators().get(source_index)?;
    let target_validator = state.validators().get(target_index)?;

    // > Verify source withdrawal credentials
    let has_correct_credential = has_execution_withdrawal_credential(source_validator);
    let computed_source_address = compute_source_address(source_validator);

    if !(has_correct_credential && computed_source_address == source_address) {
        return Ok(());
    }

    // > Verify that target has compounding withdrawal credentials
    if !has_compounding_withdrawal_credential(target_validator) {
        return Ok(());
    }

    // > Verify the source and the target are active
    let current_epoch = get_current_epoch(state);
    if !is_active_validator(source_validator, current_epoch) {
        return Ok(());
    }
    if !is_active_validator(target_validator, current_epoch) {
        return Ok(());
    }

    // > Verify exits for source and target have not been initiated
    if source_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    if target_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }

    let source_validator = state.validators().get(source_index)?;

    // > Verify the source has been active long enough
    if current_epoch < source_validator.activation_epoch + config.shard_committee_period {
        return Ok(());
    }

    // > Verify the source has no pending withdrawals in the queue
    if get_pending_balance_to_withdraw(state, source_index) > 0 {
        return Ok(());
    }

    // > Initiate source validator exit and append pending consolidation
    let exit_epoch = compute_consolidation_epoch_and_update_churn(
        config,
        state,
        source_validator.effective_balance,
    );

    let source_validator = state.validators_mut().get_mut(source_index)?;

    source_validator.exit_epoch = exit_epoch;
    source_validator.withdrawable_epoch =
        source_validator.exit_epoch + config.min_validator_withdrawability_delay;

    state
        .pending_consolidations_mut()
        .push(PendingConsolidation {
            source_index,
            target_index,
        })?;

    Ok(())
}

fn is_valid_switch_to_compounding_request<P: Preset>(
    state: &impl PostElectraBeaconState<P>,
    consolidation_request: ConsolidationRequest,
) -> Result<bool> {
    let ConsolidationRequest {
        source_address,
        source_pubkey,
        target_pubkey,
    } = consolidation_request;

    // > Switch to compounding requires source and target be equal
    if source_pubkey != target_pubkey {
        return Ok(false);
    }

    // > Verify pubkey exists
    let Some(source_index) = index_of_public_key(state, &source_pubkey) else {
        return Ok(false);
    };

    let source_validator = state.validators().get(source_index)?;

    // > Verify request has been authorized
    if compute_source_address(source_validator) != source_address {
        return Ok(false);
    }

    // > Verify source withdrawal credentials
    if !has_eth1_withdrawal_credential(source_validator) {
        return Ok(false);
    }

    // > Verify the source is active
    let current_epoch = get_current_epoch(state);

    if !is_active_validator(source_validator, current_epoch) {
        return Ok(false);
    }

    // > Verify exit for source has not been initiated
    if source_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(false);
    }

    Ok(true)
}

fn compute_source_address(validator: &Validator) -> ExecutionAddress {
    let prefix_len = H256::len_bytes() - ExecutionAddress::len_bytes();
    ExecutionAddress::from_slice(&validator.withdrawal_credentials[prefix_len..])
}

#[cfg(test)]
mod spec_tests {
    use core::fmt::Debug;

    use execution_engine::MockExecutionEngine;
    use helper_functions::verifier::{NullVerifier, SingleVerifier};
    use serde::Deserialize;
    use spec_test_utils::{BlsSetting, Case};
    use ssz::SszReadDefault;
    use test_generator::test_resources;
    use types::{
        deneb::containers::ExecutionPayload,
        electra::containers::{Attestation, AttesterSlashing},
        phase0::containers::Deposit,
        preset::{Mainnet, Minimal},
    };

    use super::*;

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
        "consensus-spec-tests/tests/mainnet/electra/operations/block_header/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/block_header/*/*",
    }

    processing_tests! {
        process_consolidation_request,
        |config, _, state, consolidation_request, _| process_consolidation_request(config, state, consolidation_request),
        "consolidation_request",
        "consensus-spec-tests/tests/mainnet/electra/operations/consolidation_request/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/consolidation_request/*/*",
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
        "consensus-spec-tests/tests/mainnet/electra/operations/proposer_slashing/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/proposer_slashing/*/*",
    }

    processing_tests! {
        process_attester_slashing,
        |config, pubkey_cache, state, attester_slashing: AttesterSlashing<P>, _| {
            process_attester_slashing(
                config,
                pubkey_cache,
                state,
                &attester_slashing,
                SingleVerifier,
                NullSlotReport,
            )
        },
        "attester_slashing",
        "consensus-spec-tests/tests/mainnet/electra/operations/attester_slashing/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/attester_slashing/*/*",
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
        "consensus-spec-tests/tests/mainnet/electra/operations/attestation/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/attestation/*/*",
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
        "consensus-spec-tests/tests/mainnet/electra/operations/bls_to_execution_change/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/bls_to_execution_change/*/*",
    }

    processing_tests! {
        process_deposit,
        |config, pubkey_cache, state, deposit, _| process_deposit(config, pubkey_cache, state, deposit),
        "deposit",
        "consensus-spec-tests/tests/mainnet/electra/operations/deposit/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/deposit/*/*",
    }

    // `process_deposit_data` reimplements deposit validation differently for performance reasons,
    // so we need to test it separately.
    processing_tests! {
        process_deposit_data,
        |config, pubkey_cache, state, deposit, _| {
            unphased::verify_deposit_merkle_branch(state, state.eth1_deposit_index, deposit)?;
            process_deposit_data(config, pubkey_cache, state, deposit.data)?;
            Ok(())
        },
        "deposit",
        "consensus-spec-tests/tests/mainnet/electra/operations/deposit/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/deposit/*/*",
    }

    processing_tests! {
        process_voluntary_exit,
        |config, pubkey_cache, state, voluntary_exit, _| {
            process_voluntary_exit(
                config,
                pubkey_cache,
                state,
                voluntary_exit,
                SingleVerifier,
            )
        },
        "voluntary_exit",
        "consensus-spec-tests/tests/mainnet/electra/operations/voluntary_exit/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/voluntary_exit/*/*",
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
        "consensus-spec-tests/tests/mainnet/electra/operations/sync_aggregate/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/sync_aggregate/*/*",
    }

    processing_tests! {
        process_deposit_request,
        |_, _, state, deposit_request, _| process_deposit_request(state, deposit_request),
        "deposit_request",
        "consensus-spec-tests/tests/mainnet/electra/operations/deposit_request/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/deposit_request/*/*",
    }

    processing_tests! {
        process_withdrawal_request,
        |config, _, state, withdrawal_request, _| process_withdrawal_request(config, state, withdrawal_request),
        "withdrawal_request",
        "consensus-spec-tests/tests/mainnet/electra/operations/withdrawal_request/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/withdrawal_request/*/*",
    }

    validation_tests! {
        validate_proposer_slashing,
        |config, pubkey_cache, state, proposer_slashing| {
            unphased::validate_proposer_slashing(config, pubkey_cache, state, proposer_slashing)
        },
        "proposer_slashing",
        "consensus-spec-tests/tests/mainnet/electra/operations/proposer_slashing/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/proposer_slashing/*/*",
    }

    validation_tests! {
        validate_attester_slashing,
        |config, pubkey_cache, state, attester_slashing: AttesterSlashing<P>| {
            unphased::validate_attester_slashing(config, pubkey_cache, state, &attester_slashing)
        },
        "attester_slashing",
        "consensus-spec-tests/tests/mainnet/electra/operations/attester_slashing/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/attester_slashing/*/*",
    }

    validation_tests! {
        validate_voluntary_exit,
        |config, pubkey_cache, state, voluntary_exit| {
            validate_voluntary_exit_with_verifier(config, pubkey_cache, state, voluntary_exit, SingleVerifier)
        },
        "voluntary_exit",
        "consensus-spec-tests/tests/mainnet/electra/operations/voluntary_exit/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/voluntary_exit/*/*",
    }

    // TODO(feature/electra): comment this & run missing test script
    validation_tests! {
        validate_bls_to_execution_change,
        |config, pubkey_cache, state, bls_to_execution_change| {
            capella::validate_bls_to_execution_change(config, pubkey_cache, state, bls_to_execution_change)
        },
        "address_change",
        "consensus-spec-tests/tests/mainnet/electra/operations/bls_to_execution_change/*/*",
        "consensus-spec-tests/tests/minimal/electra/operations/bls_to_execution_change/*/*",
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/electra/operations/execution_payload/*/*")]
    fn mainnet_execution_payload(case: Case) {
        run_execution_payload_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/electra/operations/execution_payload/*/*")]
    fn minimal_execution_payload(case: Case) {
        run_execution_payload_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/electra/operations/withdrawals/*/*")]
    fn mainnet_withdrawals(case: Case) {
        run_withdrawals_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/electra/operations/withdrawals/*/*")]
    fn minimal_withdrawals(case: Case) {
        run_withdrawals_case::<Minimal>(case);
    }

    fn run_processing_case<P: Preset, O: SszReadDefault>(
        case: Case,
        operation_name: &str,
        processing_function: impl FnOnce(
            &Config,
            &PubkeyCache,
            &mut ElectraBeaconState<P>,
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
            &mut ElectraBeaconState<P>,
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

    fn run_execution_payload_case<P: Preset>(case: Case) {
        let mut state = case.ssz_default::<ElectraBeaconState<P>>("pre");
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
        let mut state = case.ssz_default::<ElectraBeaconState<P>>("pre");
        let payload = case.ssz_default::<ExecutionPayload<P>>("execution_payload");
        let post_option = case.try_ssz_default("post");

        let result = process_withdrawals(&mut state, &payload).map(|()| state);

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
        state: &mut ElectraBeaconState<P>,
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
        state: &mut ElectraBeaconState<P>,
        deposit: Deposit,
    ) -> Result<()> {
        let combined_deposits =
            unphased::validate_deposits(config, pubkey_cache, state, core::iter::once(deposit))?;

        // > Deposits must be processed in order
        *state.eth1_deposit_index_mut() += 1;

        apply_deposits(state, combined_deposits, NullSlotReport)
    }
}
