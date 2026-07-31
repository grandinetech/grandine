use core::ops::BitOrAssign as _;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use arithmetic::U64Ext as _;
use bls::{PublicKeyBytes, SignatureBytes, traits::SignatureBytes as _};
use itertools::Itertools as _;
use pubkey_cache::PubkeyCache;
use ssz::{
    BitVector, PersistentList, PersistentProgressiveList, PersistentVector, SszHash,
    SszListMut as _,
};
use std_ext::{ArcExt as _, CopyExt as _};
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    DepositSignatureCache, ProposerLookahead, Ptc, PtcWindow,
    altair::beacon_state::BeaconState as AltairBeaconState,
    bellatrix::{
        beacon_state::BeaconState as BellatrixBeaconState,
        containers::ExecutionPayloadHeader as BellatrixExecutionPayloadHeader,
    },
    capella::{
        beacon_state::BeaconState as CapellaBeaconState,
        containers::ExecutionPayloadHeader as CapellaExecutionPayloadHeader,
    },
    config::Config,
    deneb::{
        beacon_state::BeaconState as DenebBeaconState,
        containers::ExecutionPayloadHeader as DenebExecutionPayloadHeader,
    },
    electra::{
        beacon_state::BeaconState as ElectraBeaconState,
        consts::UNSET_DEPOSIT_REQUESTS_START_INDEX, containers::PendingDeposit,
    },
    fulu::beacon_state::BeaconState as FuluBeaconState,
    gloas::{
        beacon_state::BeaconState as GloasBeaconState,
        consts::PAYLOAD_BUILDER_VERSION,
        containers::{ExecutionPayloadBid, ExecutionRequests},
        primitives::BuilderIndex,
    },
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        consts::{FAR_FUTURE_EPOCH, GENESIS_SLOT},
        containers::{Fork, PendingAttestation},
        primitives::{ExecutionAddress, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, PostElectraBeaconState as _, SszValidatorList as _},
};

use crate::{
    accessors,
    gloas::add_builder_to_registry,
    misc,
    mutators::{self, builder_balance, increase_balance},
    phase0,
    predicates::{self, is_valid_deposit_signature},
};

pub fn upgrade_to_altair<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    pre: Phase0BeaconState<P>,
) -> Result<AltairBeaconState<P>> {
    let epoch = accessors::get_current_epoch(&pre);

    let Phase0BeaconState {
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        validators,
        balances,
        randao_mixes,
        slashings,
        previous_epoch_attestations,
        current_epoch_attestations: _,
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        cache,
    } = pre;

    let fork = Fork {
        previous_version: fork.previous_version,
        current_version: config.altair_fork_version,
        epoch,
    };

    let zero_participation = PersistentList::repeat_zero(validators.len_usize())?;
    let inactivity_scores = PersistentList::repeat_zero(validators.len_usize())?;

    let mut post = AltairBeaconState {
        // > Versioning
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        // > History
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        // > Eth1
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        // > Registry
        validators,
        balances,
        // > Randomness
        randao_mixes,
        // > Slashings
        slashings,
        // > Participation
        previous_epoch_participation: zero_participation.clone(),
        current_epoch_participation: zero_participation,
        // > Finality
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        // > Inactivity
        inactivity_scores,
        // Sync
        current_sync_committee: Arc::default(),
        next_sync_committee: Arc::default(),
        // Cache
        cache,
    };

    // > Fill in previous epoch participation from the pre state's pending attestations
    translate_participation(&mut post, &previous_epoch_attestations)?;

    // > Fill in sync committees
    // > Note: A duplicate committee is assigned for the current and next committee at the fork
    // >       boundary
    let sync_committee = accessors::get_next_sync_committee(pubkey_cache, &post)?;
    post.current_sync_committee = sync_committee.clone_arc();
    post.next_sync_committee = sync_committee;

    Ok(post)
}

fn translate_participation<'attestations, P: Preset>(
    state: &mut AltairBeaconState<P>,
    pending_attestations: impl IntoIterator<Item = &'attestations PendingAttestation<P>>,
) -> Result<()> {
    for attestation in pending_attestations {
        let PendingAttestation {
            ref aggregation_bits,
            data,
            inclusion_delay,
            ..
        } = *attestation;

        let attesting_indices =
            phase0::get_attesting_indices(state, data, aggregation_bits)?.collect_vec();

        // > Translate attestation inclusion info to flag indices
        let participation_flags =
            accessors::get_attestation_participation_flags(state, data, inclusion_delay, None)?;

        // > Apply flags to all attesting validators
        for attesting_index in attesting_indices {
            // Indexing here has a negligible effect on performance and only has to be done once.
            state
                .previous_epoch_participation
                .get_mut(attesting_index)?
                .bitor_assign(participation_flags);
        }
    }

    Ok(())
}

#[must_use]
pub fn upgrade_to_bellatrix<P: Preset>(
    config: &Config,
    pre: AltairBeaconState<P>,
) -> BellatrixBeaconState<P> {
    let epoch = accessors::get_current_epoch(&pre);

    let AltairBeaconState {
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        validators,
        balances,
        randao_mixes,
        slashings,
        previous_epoch_participation,
        current_epoch_participation,
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        inactivity_scores,
        current_sync_committee,
        next_sync_committee,
        cache,
    } = pre;

    let fork = Fork {
        previous_version: fork.current_version,
        current_version: config.bellatrix_fork_version,
        epoch,
    };

    BellatrixBeaconState {
        // > Versioning
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        // > History
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        // > Eth1
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        // > Registry
        validators,
        balances,
        // > Randomness
        randao_mixes,
        // > Slashings
        slashings,
        // > Participation
        previous_epoch_participation,
        current_epoch_participation,
        // > Finality
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        // > Inactivity
        inactivity_scores,
        // > Sync
        current_sync_committee,
        next_sync_committee,
        // > Execution-layer
        latest_execution_payload_header: BellatrixExecutionPayloadHeader::default(),
        // Cache
        cache,
    }
}

#[must_use]
pub fn upgrade_to_capella<P: Preset>(
    config: &Config,
    pre: BellatrixBeaconState<P>,
) -> CapellaBeaconState<P> {
    let epoch = accessors::get_current_epoch(&pre);

    let BellatrixBeaconState {
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        validators,
        balances,
        randao_mixes,
        slashings,
        previous_epoch_participation,
        current_epoch_participation,
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        inactivity_scores,
        current_sync_committee,
        next_sync_committee,
        latest_execution_payload_header,
        cache,
    } = pre;

    let fork = Fork {
        previous_version: fork.current_version,
        current_version: config.capella_fork_version,
        epoch,
    };

    let BellatrixExecutionPayloadHeader {
        parent_hash,
        fee_recipient,
        state_root,
        receipts_root,
        logs_bloom,
        prev_randao,
        block_number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data,
        base_fee_per_gas,
        block_hash,
        transactions_root,
    } = latest_execution_payload_header;

    let latest_execution_payload_header = CapellaExecutionPayloadHeader {
        parent_hash,
        fee_recipient,
        state_root,
        receipts_root,
        logs_bloom,
        prev_randao,
        block_number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data,
        base_fee_per_gas,
        block_hash,
        transactions_root,
        // > [New in Capella]
        withdrawals_root: H256::zero(),
    };

    CapellaBeaconState {
        // > Versioning
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        // > History
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        // > Eth1
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        // > Registry
        validators,
        balances,
        // > Randomness
        randao_mixes,
        // > Slashings
        slashings,
        // > Participation
        previous_epoch_participation,
        current_epoch_participation,
        // > Finality
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        // > Inactivity
        inactivity_scores,
        // > Sync
        current_sync_committee,
        next_sync_committee,
        // > Execution-layer
        latest_execution_payload_header,
        // > Withdrawals
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        // > Deep history valid from Capella onwards
        historical_summaries: PersistentList::default(),
        // Cache
        cache,
    }
}

#[must_use]
#[expect(clippy::too_many_lines)]
pub fn upgrade_to_deneb<P: Preset>(
    config: &Config,
    pre: CapellaBeaconState<P>,
) -> DenebBeaconState<P> {
    let epoch = accessors::get_current_epoch(&pre);

    let CapellaBeaconState {
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        validators,
        balances,
        randao_mixes,
        slashings,
        previous_epoch_participation,
        current_epoch_participation,
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        inactivity_scores,
        current_sync_committee,
        next_sync_committee,
        latest_execution_payload_header,
        next_withdrawal_index,
        next_withdrawal_validator_index,
        historical_summaries,
        cache,
    } = pre;

    let fork = Fork {
        previous_version: fork.current_version,
        current_version: config.deneb_fork_version,
        epoch,
    };

    let CapellaExecutionPayloadHeader {
        parent_hash,
        fee_recipient,
        state_root,
        receipts_root,
        logs_bloom,
        prev_randao,
        block_number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data,
        base_fee_per_gas,
        block_hash,
        transactions_root,
        withdrawals_root,
    } = latest_execution_payload_header;

    let latest_execution_payload_header = DenebExecutionPayloadHeader {
        parent_hash,
        fee_recipient,
        state_root,
        receipts_root,
        logs_bloom,
        prev_randao,
        block_number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data,
        base_fee_per_gas,
        block_hash,
        transactions_root,
        withdrawals_root,
        // > [New in Deneb:EIP4844]
        blob_gas_used: 0,
        excess_blob_gas: 0,
    };

    DenebBeaconState {
        // > Versioning
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        // > History
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        // > Eth1
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        // > Registry
        validators,
        balances,
        // > Randomness
        randao_mixes,
        // > Slashings
        slashings,
        // > Participation
        previous_epoch_participation,
        current_epoch_participation,
        // > Finality
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        // > Inactivity
        inactivity_scores,
        // > Sync
        current_sync_committee,
        next_sync_committee,
        // > Execution-layer
        latest_execution_payload_header,
        // > Withdrawals
        next_withdrawal_index,
        next_withdrawal_validator_index,
        // > Deep history valid from Capella onwards
        historical_summaries,
        // Cache
        cache,
    }
}

#[expect(clippy::too_many_lines)]
pub fn upgrade_to_electra<P: Preset>(
    config: &Config,
    pre: DenebBeaconState<P>,
) -> Result<ElectraBeaconState<P>> {
    let epoch = accessors::get_current_epoch(&pre);

    let DenebBeaconState {
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        validators,
        balances,
        randao_mixes,
        slashings,
        previous_epoch_participation,
        current_epoch_participation,
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        inactivity_scores,
        current_sync_committee,
        next_sync_committee,
        latest_execution_payload_header,
        next_withdrawal_index,
        next_withdrawal_validator_index,
        historical_summaries,
        cache,
    } = pre;

    let fork = Fork {
        previous_version: fork.current_version,
        current_version: config.electra_fork_version,
        epoch,
    };

    // initial value of `earliest_exit_epoch`
    let earliest_activation_epoch = misc::compute_activation_exit_epoch::<P>(epoch)?;

    let earliest_exit_epoch = validators
        .into_iter()
        .map(|validator| validator.exit_epoch)
        .filter(|exit_epoch| *exit_epoch != FAR_FUTURE_EPOCH)
        .fold(earliest_activation_epoch, |earliest, exit_epoch| {
            earliest.max(exit_epoch)
        })
        .try_add(1)?;

    let mut post = ElectraBeaconState {
        // > Versioning
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        // > History
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        // > Eth1
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        // > Registry
        validators,
        balances,
        // > Randomness
        randao_mixes,
        // > Slashings
        slashings,
        // > Participation
        previous_epoch_participation,
        current_epoch_participation,
        // > Finality
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        // > Inactivity
        inactivity_scores,
        // > Sync
        current_sync_committee,
        next_sync_committee,
        // > Execution-layer
        latest_execution_payload_header,
        // > Withdrawals
        next_withdrawal_index,
        next_withdrawal_validator_index,
        // > Deep history valid from Capella onwards
        historical_summaries,
        deposit_requests_start_index: UNSET_DEPOSIT_REQUESTS_START_INDEX,
        deposit_balance_to_consume: 0,
        exit_balance_to_consume: 0,
        earliest_exit_epoch,
        consolidation_balance_to_consume: 0,
        earliest_consolidation_epoch: earliest_activation_epoch,
        pending_deposits: PersistentList::default(),
        pending_partial_withdrawals: PersistentList::default(),
        pending_consolidations: PersistentList::default(),
        // Cache
        cache,
    };

    post.exit_balance_to_consume = accessors::get_activation_exit_churn_limit(config, &post);
    post.consolidation_balance_to_consume =
        accessors::get_consolidation_churn_limit(config, &post)?;

    // > [New in Electra:EIP7251]
    // > add validators that are not yet active to pending balance deposits
    let pre_activation = post
        .validators
        .into_iter()
        .zip(0..)
        .filter(|(validator, _)| validator.activation_epoch == FAR_FUTURE_EPOCH)
        .map(|(validator, index)| (validator.activation_eligibility_epoch, index))
        .sorted()
        .map(|(_, index)| index);

    for index in pre_activation {
        let balance = mutators::balance(&mut post, index)?;
        let validator_balance = *balance;

        *balance = 0;

        *post.validators_mut().effective_balance_mut(index)? = 0;
        post.validators_mut()
            .partial_validator_mut(index)?
            .activation_eligibility_epoch = FAR_FUTURE_EPOCH;

        let withdrawal_credentials = post
            .validators()
            .partial_validator(index)?
            .withdrawal_credentials;
        let pubkey = post.validators().pubkey(index)?.copy();

        post.pending_deposits_mut().push(PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount: validator_balance,
            signature: SignatureBytes::empty(),
            slot: GENESIS_SLOT,
        })?;
    }

    for index in post
        .validators
        .partial_validators()
        .zip(0..)
        .filter(|(validator, _)| predicates::has_compounding_withdrawal_credential(validator))
        .map(|(_, index)| index)
        .collect_vec()
    {
        mutators::queue_excess_active_balance(&mut post, index)?;
    }

    Ok(post)
}

pub fn upgrade_to_fulu<P: Preset>(
    config: &Config,
    pre: ElectraBeaconState<P>,
) -> Result<FuluBeaconState<P>> {
    let epoch = accessors::get_current_epoch(&pre);

    // > [New in Fulu:EIP7917]
    let proposer_lookahead = initialize_proposer_lookahead(config, &pre)?;

    let ElectraBeaconState {
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        validators,
        balances,
        randao_mixes,
        slashings,
        previous_epoch_participation,
        current_epoch_participation,
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        inactivity_scores,
        current_sync_committee,
        next_sync_committee,
        latest_execution_payload_header,
        next_withdrawal_index,
        next_withdrawal_validator_index,
        historical_summaries,
        deposit_requests_start_index,
        deposit_balance_to_consume,
        exit_balance_to_consume,
        earliest_exit_epoch,
        consolidation_balance_to_consume,
        earliest_consolidation_epoch,
        pending_deposits,
        pending_partial_withdrawals,
        pending_consolidations,
        cache,
    } = pre;

    let fork = Fork {
        previous_version: fork.current_version,
        current_version: config.fulu_fork_version,
        epoch,
    };

    Ok(FuluBeaconState {
        // > Versioning
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        // > History
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        // > Eth1
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        // > Registry
        validators,
        balances,
        // > Randomness
        randao_mixes,
        // > Slashings
        slashings,
        // > Participation
        previous_epoch_participation,
        current_epoch_participation,
        // > Finality
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        // > Inactivity
        inactivity_scores,
        // > Sync
        current_sync_committee,
        next_sync_committee,
        // > Execution-layer
        latest_execution_payload_header,
        // > Withdrawals
        next_withdrawal_index,
        next_withdrawal_validator_index,
        // > Deep history valid from Capella onwards
        historical_summaries,
        deposit_requests_start_index,
        deposit_balance_to_consume,
        exit_balance_to_consume,
        earliest_exit_epoch,
        consolidation_balance_to_consume,
        earliest_consolidation_epoch,
        pending_deposits,
        pending_partial_withdrawals,
        pending_consolidations,
        proposer_lookahead,
        // Cache
        cache,
    })
}

#[expect(clippy::too_many_lines)]
pub fn upgrade_to_gloas<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    pre: FuluBeaconState<P>,
) -> Result<GloasBeaconState<P>> {
    let epoch = accessors::get_current_epoch(&pre);
    let ptc_window = initialize_ptc_window(&pre)?;

    let FuluBeaconState {
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        validators,
        balances,
        randao_mixes,
        slashings,
        previous_epoch_participation,
        current_epoch_participation,
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        inactivity_scores,
        current_sync_committee,
        next_sync_committee,
        latest_execution_payload_header,
        next_withdrawal_index,
        next_withdrawal_validator_index,
        historical_summaries,
        deposit_requests_start_index,
        deposit_balance_to_consume,
        exit_balance_to_consume,
        earliest_exit_epoch,
        consolidation_balance_to_consume,
        earliest_consolidation_epoch,
        pending_deposits,
        pending_partial_withdrawals,
        pending_consolidations,
        proposer_lookahead,
        cache,
    } = pre;

    let fork = Fork {
        previous_version: fork.current_version,
        current_version: config.gloas_fork_version,
        epoch,
    };

    let latest_execution_payload_bid = ExecutionPayloadBid {
        block_hash: latest_execution_payload_header.block_hash,
        gas_limit: latest_execution_payload_header.gas_limit,
        execution_requests_root: ExecutionRequests::<P>::default().hash_tree_root(),
        ..Default::default()
    };

    let mut post_state = GloasBeaconState {
        // > Versioning
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        // > History
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        // > Eth1
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        // > Registry
        validators: validators.into(),
        balances: balances.into(),
        // > Randomness
        randao_mixes,
        // > Slashings
        slashings,
        // > Participation
        previous_epoch_participation: previous_epoch_participation.into(),
        current_epoch_participation: current_epoch_participation.into(),
        // > Finality
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        // > Inactivity
        inactivity_scores: inactivity_scores.into(),
        // > Sync
        current_sync_committee,
        next_sync_committee,
        // > Execution
        latest_block_hash: latest_execution_payload_header.block_hash,
        // > Withdrawals
        next_withdrawal_index,
        next_withdrawal_validator_index,
        // > Deep history valid from Capella onwards
        historical_summaries,
        deposit_requests_start_index,
        deposit_balance_to_consume,
        exit_balance_to_consume,
        earliest_exit_epoch,
        consolidation_balance_to_consume,
        earliest_consolidation_epoch,
        pending_deposits: pending_deposits.into(),
        pending_partial_withdrawals: pending_partial_withdrawals.into(),
        pending_consolidations: pending_consolidations.into(),
        proposer_lookahead,
        // > ePBS states introduced in Gloas
        builders: PersistentProgressiveList::default(),
        next_withdrawal_builder_index: 0,
        execution_payload_availability: BitVector::new(true),
        builder_pending_payments: PersistentVector::default(),
        builder_pending_withdrawals: PersistentProgressiveList::default(),
        latest_execution_payload_bid,
        payload_expected_withdrawals: PersistentProgressiveList::default(),
        ptc_window,
        // Cache
        cache,
    };

    // Applies any pending deposit for builders, effectively onboarding builders at the fork.
    onboard_builders(config, pubkey_cache, &mut post_state)?;

    Ok(post_state)
}

fn initialize_proposer_lookahead<P: Preset>(
    config: &Config,
    state: &ElectraBeaconState<P>,
) -> Result<ProposerLookahead<P>> {
    let current_epoch = accessors::get_current_epoch(state);
    let mut lookahead = vec![];

    for i in 0..=P::MinSeedLookahead::U64 {
        let indices =
            accessors::get_beacon_proposer_indices(config, state, current_epoch.try_add(i)?)?;
        lookahead.extend(indices);
    }

    PersistentVector::try_from_iter(lookahead).map_err(Into::into)
}

fn initialize_ptc_window<P: Preset>(state: &FuluBeaconState<P>) -> Result<PtcWindow<P>> {
    let current_epoch = accessors::get_current_epoch(state);
    let start_slot = misc::compute_start_slot_at_epoch::<P>(current_epoch);
    let previous_epoch = (0..P::SlotsPerEpoch::U64).map(|_| Ok(Ptc::<P>::default()));

    let current_and_lookahead_epochs = (start_slot
        ..start_slot.try_add(
            P::MinSeedLookahead::U64
                .try_add(1)?
                .try_mul(P::SlotsPerEpoch::U64)?,
        )?)
        .map(|slot| accessors::ptc_for_slot(state, slot));

    let window = previous_epoch
        .chain(current_and_lookahead_epochs)
        .collect::<Result<Vec<_>>>()?;

    PtcWindow::<P>::try_from_iter(window).map_err(Into::into)
}

fn onboard_builders<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut GloasBeaconState<P>,
) -> Result<()> {
    let mut signature_cache = DepositSignatureCache::new();
    let validator_pubkeys = state.validators.pubkeys().clone();
    let mut builder_indices: HashMap<PublicKeyBytes, BuilderIndex> = HashMap::new();
    let mut pending_deposits = vec![];

    for deposit in &*state.pending_deposits().clone_boxed() {
        let PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount,
            slot,
            ..
        } = *deposit;

        if let Some(builder_index) = builder_indices.get(&pubkey) {
            increase_balance(builder_balance(state, *builder_index)?, amount)?;
        } else {
            let is_not_builder = validator_pubkeys.contains(&pubkey)
                || !predicates::is_builder_withdrawal_credential(withdrawal_credentials)
                || predicates::is_pending_validator(
                    config,
                    &pending_deposits,
                    pubkey,
                    pubkey_cache,
                    &mut signature_cache,
                );

            if is_not_builder {
                pending_deposits.push(*deposit);
            } else if is_valid_deposit_signature(config, pubkey_cache, deposit) {
                let mut address = ExecutionAddress::zero();
                address.assign_from_slice(&withdrawal_credentials[12..]);

                add_builder_to_registry(
                    state,
                    pubkey,
                    PAYLOAD_BUILDER_VERSION,
                    address,
                    amount,
                    slot,
                )?;

                builder_indices.insert(pubkey, builder_indices.len().try_into()?);
            }
        }
    }

    state
        .pending_deposits_mut()
        .try_assign_from_iter(&mut pending_deposits.into_iter())?;

    Ok(())
}

#[cfg(test)]
mod spec_tests {
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::preset::{Mainnet, Minimal, Preset};

    use super::*;

    #[test_resources("consensus-spec-tests/tests/mainnet/altair/fork/*/*/*")]
    fn altair_mainnet(case: Case) {
        run_altair_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/altair/fork/*/*/*")]
    fn altair_minimal(case: Case) {
        run_altair_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/bellatrix/fork/*/*/*")]
    fn bellatrix_mainnet(case: Case) {
        run_bellatrix_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/bellatrix/fork/*/*/*")]
    fn bellatrix_minimal(case: Case) {
        run_bellatrix_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/capella/fork/*/*/*")]
    fn capella_mainnet(case: Case) {
        run_capella_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/capella/fork/*/*/*")]
    fn capella_minimal(case: Case) {
        run_capella_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/deneb/fork/*/*/*")]
    fn deneb_mainnet(case: Case) {
        run_deneb_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/deneb/fork/*/*/*")]
    fn deneb_minimal(case: Case) {
        run_deneb_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/electra/fork/*/*/*")]
    fn electra_mainnet(case: Case) {
        run_electra_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/electra/fork/*/*/*")]
    fn electra_minimal(case: Case) {
        run_electra_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/fulu/fork/*/*/*")]
    fn fulu_mainnet(case: Case) {
        run_fulu_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/fulu/fork/*/*/*")]
    fn fulu_minimal(case: Case) {
        run_fulu_case::<Minimal>(case);
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/gloas/fork/*/*/*")]
    fn gloas_mainnet(case: Case) {
        run_gloas_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/gloas/fork/*/*/*")]
    fn gloas_minimal(case: Case) {
        run_gloas_case::<Minimal>(case);
    }

    fn run_altair_case<P: Preset>(case: Case) {
        let pre = case.ssz_default("pre");
        let expected_post = case.ssz_default("post");
        let pubkey_cache = PubkeyCache::default();

        let actual_post = upgrade_to_altair::<P>(&P::default_config(), &pubkey_cache, pre)
            .expect("upgrade from Phase 0 to Altair to should succeed");

        assert_eq!(actual_post, expected_post);
    }

    fn run_bellatrix_case<P: Preset>(case: Case) {
        let pre = case.ssz_default("pre");
        let expected_post = case.ssz_default("post");

        let actual_post = upgrade_to_bellatrix::<P>(&P::default_config(), pre);

        assert_eq!(actual_post, expected_post);
    }

    fn run_capella_case<P: Preset>(case: Case) {
        let pre = case.ssz_default("pre");
        let expected_post = case.ssz_default("post");

        let actual_post = upgrade_to_capella::<P>(&P::default_config(), pre);

        assert_eq!(actual_post, expected_post);
    }

    fn run_deneb_case<P: Preset>(case: Case) {
        let pre = case.ssz_default("pre");
        let expected_post = case.ssz_default("post");

        let actual_post = upgrade_to_deneb::<P>(&P::default_config(), pre);

        assert_eq!(actual_post, expected_post);
    }

    fn run_electra_case<P: Preset>(case: Case) {
        let pre = case.ssz_default("pre");
        let expected_post = case.ssz_default("post");

        let actual_post = upgrade_to_electra::<P>(&P::default_config(), pre)
            .expect("upgrade from Deneb to Electra to should succeed");

        assert_eq!(actual_post, expected_post);
    }

    fn run_fulu_case<P: Preset>(case: Case) {
        let pre = case.ssz_default("pre");
        let expected_post = case.ssz_default("post");

        let actual_post = upgrade_to_fulu::<P>(&P::default_config(), pre)
            .expect("upgrade from Electra to Fulu should succeed");

        assert_eq!(actual_post, expected_post);
    }

    fn run_gloas_case<P: Preset>(case: Case) {
        let pre = case.ssz_default("pre");
        let pubkey_cache = PubkeyCache::default();
        let expected_post = case.ssz_default("post");

        let actual_post = upgrade_to_gloas::<P>(&P::default_config(), &pubkey_cache, pre)
            .expect("upgrade from Fulu to Gloas should succeed");

        assert_eq!(actual_post, expected_post);
    }
}
