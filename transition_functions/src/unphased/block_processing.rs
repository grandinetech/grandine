use anyhow::{ensure, Result};
use bls::CachedPublicKey;
use helper_functions::{
    accessors::{
        attestation_epoch, get_beacon_proposer_index, get_current_epoch, get_indexed_attestation,
        get_randao_mix, index_of_public_key, slashable_indices,
    },
    error::SignatureKind,
    misc::compute_epoch_at_slot,
    mutators::initiate_validator_exit,
    predicates::{
        is_active_validator, is_slashable_attestation_data, is_slashable_validator,
        is_valid_merkle_branch, validate_constructed_indexed_attestation,
        validate_received_indexed_attestation,
    },
    signing::{RandaoEpoch, SignForAllForks, SignForSingleFork as _},
    verifier::{MultiVerifier, SingleVerifier, Triple, Verifier, VerifierOption},
};
use itertools::Itertools as _;
use rayon::iter::{IntoParallelIterator as _, IntoParallelRefIterator as _, ParallelIterator as _};
use ssz::SszHash as _;
use typenum::Unsigned as _;
use types::{
    config::Config,
    nonstandard::{AttestationEpoch, GweiVec},
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        containers::{
            Attestation, AttestationData, AttesterSlashing, BeaconBlockHeader, Deposit,
            DepositData, DepositMessage, ProposerSlashing, SignedVoluntaryExit,
        },
        primitives::{DepositIndex, ValidatorIndex, H256},
    },
    preset::{Preset, SlotsPerEth1VotingPeriod},
    traits::{BeaconBlock, BeaconBlockBody, BeaconState},
};

use crate::unphased::Error;

pub enum CombinedDeposit {
    NewValidator {
        pubkey: CachedPublicKey,
        withdrawal_credentials: H256,
        amounts: GweiVec,
    },
    TopUp {
        validator_index: ValidatorIndex,
        amounts: GweiVec,
    },
}

pub fn process_block_header_for_gossip<P: Preset>(
    state: &impl BeaconState<P>,
    block: &impl BeaconBlock<P>,
) -> Result<()> {
    // > Verify that the slots match
    //
    // This could be an assertion if not for `consensus-spec-tests`.
    // All other callers of this function already ensure the slots match up.
    ensure!(
        block.slot() == state.slot(),
        Error::<P>::SlotMismatch {
            state_slot: state.slot(),
            block_slot: block.slot(),
        },
    );

    // > Verify that the block is newer than latest block header
    ensure!(
        block.slot() > state.latest_block_header().slot,
        Error::<P>::BlockNotNewerThanLatestBlockHeader {
            block_slot: block.slot(),
            block_header_slot: state.latest_block_header().slot,
        },
    );

    // > Verify that proposer index is the correct index
    let computed = get_beacon_proposer_index(state)?;
    let in_block = block.proposer_index();

    ensure!(
        computed == in_block,
        Error::<P>::ProposerIndexMismatch { computed, in_block },
    );

    // > Verify that the parent matches
    let computed = state.latest_block_header().hash_tree_root();
    let in_block = block.parent_root();

    ensure!(
        computed == in_block,
        Error::<P>::ParentRootMismatch { computed, in_block },
    );

    Ok(())
}

pub fn process_block_header<P: Preset>(
    state: &mut impl BeaconState<P>,
    block: &impl BeaconBlock<P>,
) -> Result<()> {
    process_block_header_for_gossip(state, block)?;

    // > Cache current block as the new latest block
    *state.latest_block_header_mut() = BeaconBlockHeader {
        slot: block.slot(),
        proposer_index: block.proposer_index(),
        parent_root: block.parent_root(),
        // > Overwritten in the next process_slot call
        state_root: H256::zero(),
        body_root: block.body().hash_tree_root(),
    };

    // > Verify proposer is not slashed
    let index = block.proposer_index();
    let proposer = state.validators().get(index)?;

    ensure!(!proposer.slashed, Error::<P>::ProposerSlashed { index });

    Ok(())
}

pub fn process_randao<P: Preset>(
    config: &Config,
    state: &mut impl BeaconState<P>,
    body: &impl BeaconBlockBody<P>,
    mut verifier: impl Verifier,
) -> Result<()> {
    let epoch = get_current_epoch(state);
    let randao_reveal = body.randao_reveal();

    // > Verify RANDAO reveal
    let proposer_index = get_beacon_proposer_index(state)?;
    let public_key = &state.validators().get(proposer_index)?.pubkey;

    if !verifier.has_option(VerifierOption::SkipRandaoVerification) {
        verifier.verify_singular(
            RandaoEpoch::from(epoch).signing_root(config, state),
            randao_reveal,
            public_key,
            SignatureKind::Randao,
        )?;
    }

    // > Mix in RANDAO reveal
    //
    // The [Eth Beacon Node API specification] does not say whether the RANDAO reveal should be
    // mixed in when `skip_randao_verification` is `true`. [Lighthouse mixes it in either way].
    //
    // [Eth Beacon Node API specification]: https://ethereum.github.io/beacon-APIs/
    // [Lighthouse mixes it in either way]: https://github.com/sigp/lighthouse/blob/v4.3.0/consensus/state_processing/src/per_block_processing.rs#L282-L309
    let mix = get_randao_mix(state, epoch) ^ hashing::hash_768(randao_reveal);
    *state.randao_mixes_mut().mod_index_mut(epoch) = mix;

    Ok(())
}

pub fn process_eth1_data<P: Preset>(
    state: &mut impl BeaconState<P>,
    body: &impl BeaconBlockBody<P>,
) -> Result<()> {
    // Possible optimization: add a `deduplicating_push` method to `PersistentList` and use it here.
    // Make it deduplicate consecutive list items and reuse cached values of `hash_tree_root`.
    state.eth1_data_votes_mut().push(body.eth1_data())?;

    // Possible optimization: skip vote counting if a previous vote in the voting period passed.
    // We had implemented this, but it didn't have much of an effect and was removed as a precaution
    // after another optimization (exit queue caching in `initiate_validator_exit`) was found to be
    // implemented incorrectly.
    let vote_count = state
        .eth1_data_votes()
        .into_iter()
        .filter(|vote| **vote == body.eth1_data())
        .count();

    if vote_count * 2 > SlotsPerEth1VotingPeriod::<P>::USIZE {
        *state.eth1_data_mut() = body.eth1_data();
    }

    Ok(())
}

pub fn validate_proposer_slashing<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    proposer_slashing: ProposerSlashing,
) -> Result<()> {
    validate_proposer_slashing_with_verifier(config, state, proposer_slashing, SingleVerifier)
}

pub fn validate_proposer_slashing_with_verifier<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    proposer_slashing: ProposerSlashing,
    mut verifier: impl Verifier,
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
    let proposer = state.validators().get(index)?;

    ensure!(
        is_slashable_validator(proposer, get_current_epoch(state)),
        Error::<P>::ProposerNotSlashable {
            index,
            proposer: proposer.clone(),
        },
    );

    // > Verify signatures
    for signed_header in [
        proposer_slashing.signed_header_1,
        proposer_slashing.signed_header_2,
    ] {
        verifier.verify_singular(
            signed_header.message.signing_root(config, state),
            signed_header.signature,
            &proposer.pubkey,
            SignatureKind::Block,
        )?;
    }

    Ok(())
}

pub fn validate_attester_slashing<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    attester_slashing: &AttesterSlashing<P>,
) -> Result<Vec<ValidatorIndex>> {
    validate_attester_slashing_with_verifier(config, state, attester_slashing, SingleVerifier)
}

pub fn validate_attester_slashing_with_verifier<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    attester_slashing: &AttesterSlashing<P>,
    mut verifier: impl Verifier,
) -> Result<Vec<ValidatorIndex>> {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;

    let data_1 = attestation_1.data;
    let data_2 = attestation_2.data;

    ensure!(
        is_slashable_attestation_data(data_1, data_2),
        Error::<P>::AttestationDataNotSlashable { data_1, data_2 },
    );

    validate_received_indexed_attestation(config, state, attestation_1, &mut verifier)?;
    validate_received_indexed_attestation(config, state, attestation_2, verifier)?;

    let current_epoch = get_current_epoch(state);

    let slashable_indices = slashable_indices(attester_slashing)
        .filter(|attester_index| {
            let attester = state
                .validators()
                .get(*attester_index)
                .expect("attester indices are validated in validate_received_indexed_attestation");

            is_slashable_validator(attester, current_epoch)
        })
        .collect_vec();

    ensure!(
        !slashable_indices.is_empty(),
        Error::<P>::NoAttestersSlashed,
    );

    Ok(slashable_indices)
}

pub fn validate_attestation<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
) -> Result<()> {
    validate_attestation_with_verifier(config, state, attestation, SingleVerifier)
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
            attestation: attestation.clone(),
        },
    );

    let low_slot = attestation.data.slot + P::MIN_ATTESTATION_INCLUSION_DELAY.get();
    let high_slot = attestation.data.slot + P::SlotsPerEpoch::U64;

    ensure!(
        (low_slot..=high_slot).contains(&state.slot()),
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

pub fn validate_deposits<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    deposits: impl IntoIterator<Item = Deposit>,
) -> Result<impl Iterator<Item = CombinedDeposit>> {
    let deposits_by_pubkey = (0..)
        .zip(deposits)
        .into_group_map_by(|(_, deposit)| deposit.data.pubkey)
        .into_values()
        .map(|deposits| {
            let (_, first_deposit) = deposits[0];
            let existing_validator_index = index_of_public_key(state, first_deposit.data.pubkey);
            let cached_public_key = CachedPublicKey::from(first_deposit.data.pubkey);
            (existing_validator_index, cached_public_key, deposits)
        })
        .collect_vec();

    // Optimistically verify deposit signatures with `multi_verify` first.
    // If that fails, fall back to verifying them separately in parallel.
    //
    // On our development machines `multi_verify` is a little slower but uses less CPU.
    // It will likely be faster than parallel verification on CPUs with fewer cores.
    let required_signatures_valid = deposits_by_pubkey
        .par_iter()
        .filter(|(existing_validator_index, _, _)| existing_validator_index.is_none())
        .map(|(_, cached_public_key, deposits)| {
            let (_, first_deposit) = deposits[0];

            let public_key = *cached_public_key.decompress()?;

            // > Verify the deposit signature (proof of possession)
            // > which is not checked by the deposit contract
            let deposit_message = DepositMessage::from(first_deposit.data);

            // > Fork-agnostic domain since deposits are valid across forks
            let signing_root = deposit_message.signing_root(config);

            Ok(Triple::new(
                signing_root,
                first_deposit.data.signature,
                public_key,
            ))
        })
        .collect::<Result<Vec<_>>>()
        .and_then(|triples| MultiVerifier::from(triples).finish())
        .is_ok();

    let mut combined_deposits = deposits_by_pubkey
        .into_par_iter()
        .map(|(existing_validator_index, cached_public_key, deposits)| {
            for (position, deposit) in deposits.iter().copied() {
                // > Verify the Merkle branch
                verify_deposit_merkle_branch(
                    state,
                    state.eth1_deposit_index() + position,
                    deposit,
                )?;
            }

            let (first_position, _) = deposits[0];

            if let Some(validator_index) = existing_validator_index {
                let amounts = deposits
                    .into_iter()
                    .map(|(_, deposit)| deposit.data.amount)
                    .collect();

                let combined_deposit = CombinedDeposit::TopUp {
                    validator_index,
                    amounts,
                };

                return Ok(Some((first_position, combined_deposit)));
            }

            let mut deposits = deposits.into_iter();

            let first_valid = if required_signatures_valid {
                deposits.next()
            } else {
                deposits.find(|(_, deposit)| {
                    // > Verify the deposit signature (proof of possession)
                    // > which is not checked by the deposit contract
                    let deposit_message = DepositMessage::from(deposit.data);

                    // > Fork-agnostic domain since deposits are valid across forks
                    deposit_message
                        .verify(config, deposit.data.signature, &cached_public_key)
                        .is_ok()
                })
            };

            Ok(first_valid.map(|(position, deposit)| {
                let DepositData {
                    withdrawal_credentials,
                    amount: first_amount,
                    ..
                } = deposit.data;

                let amounts = core::iter::once(first_amount)
                    .chain(deposits.map(|(_, deposit)| deposit.data.amount))
                    .collect();

                let combined_deposit = CombinedDeposit::NewValidator {
                    pubkey: cached_public_key,
                    withdrawal_credentials,
                    amounts,
                };

                (position, combined_deposit)
            }))
        })
        .filter_map(Result::transpose)
        .collect::<Result<Vec<_>>>()?;

    combined_deposits.sort_unstable_by_key(|(position, _)| *position);

    Ok(combined_deposits
        .into_iter()
        .map(|(_, combined_deposit)| combined_deposit))
}

pub fn verify_deposit_merkle_branch<P: Preset>(
    state: &impl BeaconState<P>,
    eth1_deposit_index: DepositIndex,
    deposit: Deposit,
) -> Result<()> {
    ensure!(
        is_valid_merkle_branch(
            deposit.data.hash_tree_root(),
            deposit.proof,
            eth1_deposit_index,
            state.eth1_data().deposit_root,
        ),
        Error::<P>::DepositProofInvalid {
            deposit: Box::new(deposit),
        },
    );

    Ok(())
}

pub fn process_voluntary_exit<P: Preset>(
    config: &Config,
    state: &mut impl BeaconState<P>,
    signed_voluntary_exit: SignedVoluntaryExit,
    verifier: impl Verifier,
) -> Result<()> {
    validate_voluntary_exit_with_verifier(config, state, signed_voluntary_exit, verifier)?;

    // > Initiate exit
    initiate_validator_exit(config, state, signed_voluntary_exit.message.validator_index)
}

pub fn validate_voluntary_exit<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    signed_voluntary_exit: SignedVoluntaryExit,
) -> Result<()> {
    validate_voluntary_exit_with_verifier(config, state, signed_voluntary_exit, SingleVerifier)
}

fn validate_voluntary_exit_with_verifier<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    signed_voluntary_exit: SignedVoluntaryExit,
    mut verifier: impl Verifier,
) -> Result<()> {
    let voluntary_exit = signed_voluntary_exit.message;
    let index = voluntary_exit.validator_index;
    let validator = state.validators().get(index)?;
    let current_epoch = get_current_epoch(state);

    // > Verify the validator is active
    ensure!(
        is_active_validator(validator, current_epoch),
        Error::<P>::ValidatorNotActive {
            index,
            validator: validator.clone(),
            current_epoch,
        },
    );

    // > Verify exit has not been initiated
    ensure!(
        validator.exit_epoch == FAR_FUTURE_EPOCH,
        Error::<P>::ValidatorAlreadyExited {
            index,
            exit_epoch: validator.exit_epoch,
        },
    );

    // > Exits must specify an epoch when they become valid; they are not valid before then
    ensure!(
        current_epoch >= voluntary_exit.epoch,
        Error::<P>::VoluntaryExitIsExpired {
            current_epoch,
            epoch: voluntary_exit.epoch,
        },
    );

    // > Verify the validator has been active long enough
    ensure!(
        current_epoch >= validator.activation_epoch + config.shard_committee_period,
        Error::<P>::ValidatorHasNotBeenActiveLongEnough {
            index,
            activation_epoch: validator.activation_epoch,
            current_epoch,
        },
    );

    // > Verify signature
    verifier.verify_singular(
        voluntary_exit.signing_root(config, state),
        signed_voluntary_exit.signature,
        &validator.pubkey,
        SignatureKind::VoluntaryExit,
    )?;

    Ok(())
}
