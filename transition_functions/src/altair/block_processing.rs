use anyhow::{ensure, Result};
use arithmetic::U64Ext as _;
use bit_field::BitField as _;
use helper_functions::{
    accessors::{
        self, attestation_epoch, get_attestation_participation_flags, get_base_reward,
        get_base_reward_per_increment, get_beacon_proposer_index, get_block_root_at_slot,
        index_of_public_key, initialize_shuffled_indices, total_active_balance,
    },
    altair::slash_validator,
    error::SignatureKind,
    misc,
    mutators::{balance, decrease_balance, increase_balance},
    phase0::get_attesting_indices,
    signing::{SignForAllForks as _, SignForSingleFork as _, SignForSingleForkAtSlot as _},
    slot_report::{Delta, NullSlotReport, SlotReport, SyncAggregateRewards},
    verifier::{SingleVerifier, Triple, Verifier},
};
use pubkey_cache::PubkeyCache;
#[cfg(not(target_os = "zkvm"))]
use rayon::iter::ParallelIterator as _;
use ssz::Hc;
use std_ext::ArcExt as _;
use typenum::Unsigned as _;
use types::{
    altair::{
        beacon_state::BeaconState,
        consts::{
            PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, SYNC_REWARD_WEIGHT, WEIGHT_DENOMINATOR,
        },
        containers::{
            BeaconBlock as AltairBeaconBlock, BeaconBlockBody, SignedBeaconBlock, SyncAggregate,
        },
    },
    config::Config,
    nonstandard::{smallvec, AttestationEpoch, SlashingKind},
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        containers::{
            Attestation, AttesterSlashing, DepositData, DepositMessage, ProposerSlashing, Validator,
        },
        primitives::{DepositIndex, ValidatorIndex},
    },
    preset::Preset,
    traits::{BeaconBlock, PostAltairBeaconState},
};

use crate::{
    phase0,
    unphased::{self, CombinedDeposit, Error},
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

/// <https://github.com/ethereum/consensus-specs/blob/0b76c8367ed19014d104e3fbd4718e73f459a748/specs/altair/beacon-chain.md#block-processing>
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
    state: &mut BeaconState<P>,
    block: &Hc<AltairBeaconBlock<P>>,
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
    state: &BeaconState<P>,
    block: &SignedBeaconBlock<P>,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.message.slot);

    unphased::process_block_header_for_gossip(config, state, &block.message)?;

    let pubkey = accessors::public_key(state, block.message.proposer_index)?;

    SingleVerifier.verify_singular(
        block.message.signing_root(config, state),
        block.signature,
        pubkey_cache.get_or_insert(*pubkey)?,
        SignatureKind::Block,
    )?;

    Ok(())
}

pub fn custom_process_block<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut BeaconState<P>,
    block: &Hc<AltairBeaconBlock<P>>,
    mut verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.slot);

    unphased::process_block_header(config, state, block)?;
    unphased::process_randao(config, pubkey_cache, state, &block.body, &mut verifier)?;
    unphased::process_eth1_data(state, &block.body)?;

    process_operations(
        config,
        pubkey_cache,
        state,
        &block.body,
        &mut verifier,
        &mut slot_report,
    )?;

    process_sync_aggregate(
        config,
        pubkey_cache,
        state,
        block.body.sync_aggregate,
        verifier,
        slot_report,
    )
}

pub fn count_required_signatures<P: Preset>(block: &impl BeaconBlock<P>) -> usize {
    phase0::count_required_signatures(block) + 1
}

fn process_operations<P: Preset, V: Verifier>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut BeaconState<P>,
    body: &BeaconBlockBody<P>,
    mut verifier: V,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    // > Verify that outstanding deposits are processed up to the maximum number of deposits
    let computed =
        P::MaxDeposits::U64.min(state.eth1_data.deposit_count - state.eth1_deposit_index);
    let in_block = body.deposits.len().try_into()?;

    ensure!(
        computed == in_block,
        Error::<P>::DepositCountMismatch { computed, in_block },
    );

    for proposer_slashing in body.proposer_slashings.iter().copied() {
        process_proposer_slashing(
            config,
            pubkey_cache,
            state,
            proposer_slashing,
            &mut verifier,
            &mut slot_report,
        )?;
    }

    for attester_slashing in &body.attester_slashings {
        process_attester_slashing(
            config,
            pubkey_cache,
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
        for attestation in &body.attestations {
            unphased::validate_attestation_with_verifier(
                config,
                pubkey_cache,
                state,
                attestation,
                &mut verifier,
            )?;
        }
    } else {
        initialize_shuffled_indices(state, &body.attestations)?;

        let triples = helper_functions::par_iter!(body.attestations)
            .map(|attestation| {
                let mut triple = Triple::default();

                unphased::validate_attestation_with_verifier(
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

    for attestation in &body.attestations {
        apply_attestation(config, state, attestation, &mut slot_report)?;
    }

    // The conditional is not needed for correctness.
    // It only serves to avoid overhead when processing blocks with no deposits.
    if !body.deposits.is_empty() {
        let combined_deposits = unphased::validate_deposits(
            config,
            pubkey_cache,
            state,
            body.deposits.iter().copied(),
        )?;

        apply_deposits(state, body.deposits.len(), combined_deposits, slot_report)?;
    }

    for voluntary_exit in body.voluntary_exits.iter().copied() {
        unphased::process_voluntary_exit(
            config,
            pubkey_cache,
            state,
            voluntary_exit,
            &mut verifier,
        )?;
    }

    Ok(())
}

fn process_proposer_slashing<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut BeaconState<P>,
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

fn process_attester_slashing<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut BeaconState<P>,
    attester_slashing: &AttesterSlashing<P>,
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
    state: &mut impl PostAltairBeaconState<P>,
    attestation: &Attestation<P>,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    let Attestation {
        ref aggregation_bits,
        data,
        ..
    } = *attestation;

    // > Participation flag indices
    let inclusion_delay = state.slot() - data.slot;
    let participation_flags = get_attestation_participation_flags(state, data, inclusion_delay)?;

    // > Update epoch participation flags
    let base_reward_per_increment = get_base_reward_per_increment(state);

    let attesting_indices_with_base_rewards = get_attesting_indices(state, data, aggregation_bits)?
        .map(|validator_index| {
            let base_reward = get_base_reward(state, validator_index, base_reward_per_increment)?;
            Ok((validator_index, base_reward))
        })
        .collect::<Result<Vec<_>>>()?;

    let epoch_participation = match attestation_epoch(state, data.target.epoch)? {
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
        get_attesting_indices(state, data, aggregation_bits)?,
    )?;

    Ok(())
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
    state: &mut impl PostAltairBeaconState<P>,
    deposit_data: DepositData,
) -> Result<Option<ValidatorIndex>> {
    let DepositData {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
    } = deposit_data;

    if let Some(validator_index) = index_of_public_key(state, &pubkey) {
        let combined_deposit = CombinedDeposit::TopUp {
            validator_index,
            withdrawal_credentials: vec![withdrawal_credentials],
            amounts: smallvec![amount],
            signatures: vec![signature],
            positions: smallvec![0],
        };

        apply_deposits(state, 1, core::iter::once(combined_deposit), NullSlotReport)?;

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

            apply_deposits(state, 1, core::iter::once(combined_deposit), NullSlotReport)?;

            return Ok(Some(validator_index));
        }
    }

    apply_deposits(state, 1, core::iter::empty(), NullSlotReport)?;

    Ok(None)
}

pub fn apply_deposits<P: Preset>(
    state: &mut impl PostAltairBeaconState<P>,
    deposit_count: usize,
    combined_deposits: impl IntoIterator<Item = CombinedDeposit>,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    // > Deposits must be processed in order
    *state.eth1_deposit_index_mut() += DepositIndex::try_from(deposit_count)?;

    for combined_deposit in combined_deposits {
        match combined_deposit {
            // > Add validator and balance entries
            CombinedDeposit::NewValidator {
                pubkey,
                withdrawal_credentials,
                amounts,
                ..
            } => {
                let public_key_bytes = pubkey;
                let withdrawal_credentials = withdrawal_credentials[0];
                let first_amount = amounts[0];
                let total_amount = amounts.iter().sum();

                let effective_balance = first_amount
                    .prev_multiple_of(P::EFFECTIVE_BALANCE_INCREMENT)
                    .min(P::MAX_EFFECTIVE_BALANCE);

                let validator = Validator {
                    pubkey,
                    withdrawal_credentials,
                    effective_balance,
                    slashed: false,
                    activation_eligibility_epoch: FAR_FUTURE_EPOCH,
                    activation_epoch: FAR_FUTURE_EPOCH,
                    exit_epoch: FAR_FUTURE_EPOCH,
                    withdrawable_epoch: FAR_FUTURE_EPOCH,
                };

                let validator_index = state.validators().len_u64();

                state.validators_mut().push(validator)?;
                state.balances_mut().push(total_amount)?;
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
                    .insert(public_key_bytes, validator_index);

                for amount in amounts {
                    slot_report.add_deposit(validator_index, amount);
                }
            }
            // > Increase balance by deposit amount
            CombinedDeposit::TopUp {
                validator_index,
                amounts,
                ..
            } => {
                let total_amount = amounts.iter().sum();

                increase_balance(balance(state, validator_index)?, total_amount);

                for amount in amounts {
                    slot_report.add_deposit(validator_index, amount);
                }
            }
        }
    }

    Ok(())
}

pub fn process_sync_aggregate<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostAltairBeaconState<P>,
    sync_aggregate: SyncAggregate<P>,
    verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    // > Verify sync committee aggregate signature signing over the previous slot block root
    verify_sync_aggregate_signature(config, pubkey_cache, state, sync_aggregate, verifier)?;

    // > Compute participant and proposer rewards
    let total_active_increments = total_active_balance(state) / P::EFFECTIVE_BALANCE_INCREMENT;
    let total_base_rewards = get_base_reward_per_increment(state) * total_active_increments;
    let max_participant_rewards = (total_base_rewards * SYNC_REWARD_WEIGHT / WEIGHT_DENOMINATOR)
        .div_typenum::<P::SlotsPerEpoch>();
    let participant_reward = max_participant_rewards.div_typenum::<P::SyncCommitteeSize>();
    let proposer_reward =
        participant_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR.get() - PROPOSER_WEIGHT);

    // > Apply participant and proposer rewards
    let proposer_index = get_beacon_proposer_index(config, state)?;

    let mut participation = 0;

    for (participant_pubkey, participation_bit) in state
        .current_sync_committee()
        .clone_arc()
        .pubkeys
        .iter()
        .zip(sync_aggregate.sync_committee_bits)
    {
        let participant_index = index_of_public_key(state, participant_pubkey)
            .expect("public keys in state.current_sync_committee are taken from state.validators");

        if participation_bit {
            increase_balance(balance(state, participant_index)?, participant_reward);
            participation += 1;
        } else {
            decrease_balance(balance(state, participant_index)?, participant_reward);
        }

        slot_report.set_sync_committee_delta(
            participant_index,
            if participation_bit {
                Delta::Reward(participant_reward)
            } else {
                Delta::Penalty(participant_reward)
            },
        );
    }

    increase_balance(
        balance(state, proposer_index)?,
        proposer_reward * participation,
    );

    slot_report.set_sync_aggregate_rewards(SyncAggregateRewards {
        singular_reward: proposer_reward,
        participation,
    });

    Ok(())
}

pub fn verify_sync_aggregate_signature<P: Preset, V: Verifier>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostAltairBeaconState<P>,
    sync_aggregate: SyncAggregate<P>,
    mut verifier: V,
) -> Result<()> {
    if V::IS_NULL {
        return Ok(());
    }

    let SyncAggregate {
        sync_committee_bits,
        sync_committee_signature,
    } = sync_aggregate;

    // Possible optimization: return early if both the bits and the signature are empty.
    // That's how this function was originally implemented
    // (see the doc comment for `Verifier::verify_aggregate_allowing_empty`).
    // This should not matter much in practice because empty sync aggregates are rare.

    let participant_pubkeys = state
        .current_sync_committee()
        .pubkeys
        .iter()
        .zip(sync_committee_bits)
        .filter(|(_, bit)| *bit)
        .map(|(pubkey, _)| pubkey_cache.get_or_insert(*pubkey));

    let previous_slot = misc::previous_slot(state.slot());

    let block_root = get_block_root_at_slot(state, previous_slot).expect(
        "the bound on P::SlotsPerHistoricalRoot ensures that the \
         previous slot is always in range for get_block_root_at_slot",
    );

    let signing_root = block_root.signing_root(config, state, previous_slot);

    itertools::process_results(participant_pubkeys, |public_keys| {
        verifier.verify_aggregate_allowing_empty(
            signing_root,
            sync_committee_signature,
            public_keys,
            SignatureKind::SyncAggregate,
        )
    })?
}

#[cfg(test)]
mod spec_tests {
    use core::fmt::Debug;

    use helper_functions::verifier::{NullVerifier, SingleVerifier};
    use spec_test_utils::{BlsSetting, Case};
    use ssz::SszReadDefault;
    use test_generator::test_resources;
    use types::{
        phase0::containers::Deposit,
        preset::{Mainnet, Minimal},
    };

    use super::*;

    // We only honor `bls_setting` in `Attestation` tests. They are the only ones that set it to 2.

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
        |config, _, state, block: Hc<AltairBeaconBlock<_>>, _| unphased::process_block_header(config, state, &block),
        "block",
        "consensus-spec-tests/tests/mainnet/altair/operations/block_header/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/block_header/*/*",
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
        "consensus-spec-tests/tests/mainnet/altair/operations/proposer_slashing/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/proposer_slashing/*/*",
    }

    processing_tests! {
        process_attester_slashing,
        |config, pubkey_cache,state, attester_slashing, _| {
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
        "consensus-spec-tests/tests/mainnet/altair/operations/attester_slashing/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/attester_slashing/*/*",
    }

    processing_tests! {
        process_attestation,
        |config, pubkey_cache, state, attestation: Attestation<P>, bls_setting| {
            process_attestation(
                config,
                pubkey_cache,
                state,
                &attestation,
                bls_setting,
            )
        },
        "attestation",
        "consensus-spec-tests/tests/mainnet/altair/operations/attestation/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/attestation/*/*",
    }

    processing_tests! {
        process_deposit,
        |config, pubkey_cache, state, deposit, _| process_deposit(config, pubkey_cache, state, deposit),
        "deposit",
        "consensus-spec-tests/tests/mainnet/altair/operations/deposit/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/deposit/*/*",
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
        "consensus-spec-tests/tests/mainnet/altair/operations/deposit/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/deposit/*/*",
    }

    processing_tests! {
        process_voluntary_exit,
        |config, pubkey_cache, state, voluntary_exit, _| {
            unphased::process_voluntary_exit(
                config,
                pubkey_cache,
                state,
                voluntary_exit,
                SingleVerifier,
            )
        },
        "voluntary_exit",
        "consensus-spec-tests/tests/mainnet/altair/operations/voluntary_exit/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/voluntary_exit/*/*",
    }

    processing_tests! {
        process_sync_aggregate,
        |config, pubkey_cache, state, sync_aggregate, _| {
            process_sync_aggregate(
                config,
                pubkey_cache,
                state,
                sync_aggregate,
                SingleVerifier,
                NullSlotReport,
            )
        },
        "sync_aggregate",
        "consensus-spec-tests/tests/mainnet/altair/operations/sync_aggregate/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/sync_aggregate/*/*",
    }

    validation_tests! {
        validate_proposer_slashing,
        |config, pubkey_cache, state, proposer_slashing| {
            unphased::validate_proposer_slashing(config, pubkey_cache, state, proposer_slashing)
        },
        "proposer_slashing",
        "consensus-spec-tests/tests/mainnet/altair/operations/proposer_slashing/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/proposer_slashing/*/*",
    }

    validation_tests! {
        validate_attester_slashing,
        |config, pubkey_cache, state, attester_slashing: AttesterSlashing<P>| {
            unphased::validate_attester_slashing(config, pubkey_cache, state, &attester_slashing)
        },
        "attester_slashing",
        "consensus-spec-tests/tests/mainnet/altair/operations/attester_slashing/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/attester_slashing/*/*",
    }

    validation_tests! {
        validate_voluntary_exit,
        |config, pubkey_cache, state, voluntary_exit| {
            unphased::validate_voluntary_exit(config, pubkey_cache, state, voluntary_exit)
        },
        "voluntary_exit",
        "consensus-spec-tests/tests/mainnet/altair/operations/voluntary_exit/*/*",
        "consensus-spec-tests/tests/minimal/altair/operations/voluntary_exit/*/*",
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

    fn run_validation_case<P: Preset, O: SszReadDefault, R: Debug>(
        case: Case,
        operation_name: &str,
        validation_function: impl FnOnce(&Config, &PubkeyCache, &mut BeaconState<P>, O) -> Result<R>,
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

    fn process_attestation<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut BeaconState<P>,
        attestation: &Attestation<P>,
        bls_setting: BlsSetting,
    ) -> Result<()> {
        match bls_setting {
            BlsSetting::Optional | BlsSetting::Required => {
                unphased::validate_attestation_with_verifier(
                    config,
                    pubkey_cache,
                    state,
                    attestation,
                    SingleVerifier,
                )?
            }
            BlsSetting::Ignored => unphased::validate_attestation_with_verifier(
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
        state: &mut BeaconState<P>,
        deposit: Deposit,
    ) -> Result<()> {
        let combined_deposits =
            unphased::validate_deposits(config, pubkey_cache, state, core::iter::once(deposit))?;
        apply_deposits(state, 1, combined_deposits, NullSlotReport)
    }
}
