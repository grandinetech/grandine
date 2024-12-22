use core::ops::BitOrAssign as _;
use std::sync::Arc;

use anyhow::Result;
use bls::{
    traits::{BlsCachedPublicKey, BlsSignatureBytes},
    SignatureBytes,
};
use itertools::Itertools as _;
use ssz::PersistentList;
use std_ext::ArcExt as _;
use types::{
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
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        consts::{FAR_FUTURE_EPOCH, GENESIS_SLOT},
        containers::{Fork, PendingAttestation},
        primitives::H256,
    },
    preset::Preset,
    traits::{BeaconState as _, PostElectraBeaconState as _},
};

use crate::{accessors, misc, mutators, phase0, predicates};

pub fn upgrade_to_altair<P: Preset>(
    config: &Config,
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

    let zero_participation = PersistentList::repeat_zero_with_length_of(&validators);
    let inactivity_scores = PersistentList::repeat_zero_with_length_of(&validators);

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
    let sync_committee = accessors::get_next_sync_committee(&post)?;
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
            accessors::get_attestation_participation_flags(state, data, inclusion_delay)?;

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

    let DenebExecutionPayloadHeader {
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
        blob_gas_used,
        excess_blob_gas,
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
        blob_gas_used,
        excess_blob_gas,
    };

    let earliest_exit_epoch = validators
        .into_iter()
        .map(|validator| validator.exit_epoch)
        .filter(|exit_epoch| *exit_epoch != FAR_FUTURE_EPOCH)
        .max()
        .unwrap_or(epoch)
        + 1;

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
        earliest_consolidation_epoch: misc::compute_activation_exit_epoch::<P>(epoch),
        pending_deposits: PersistentList::default(),
        pending_partial_withdrawals: PersistentList::default(),
        pending_consolidations: PersistentList::default(),
        // Cache
        cache,
    };

    post.exit_balance_to_consume = accessors::get_activation_exit_churn_limit(config, &post);
    post.consolidation_balance_to_consume = accessors::get_consolidation_churn_limit(config, &post);

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

        let validator = post.validators_mut().get_mut(index)?;

        validator.effective_balance = 0;
        validator.activation_eligibility_epoch = FAR_FUTURE_EPOCH;

        let withdrawal_credentials = validator.withdrawal_credentials;
        let pubkey = validator.pubkey.to_bytes();

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
        .into_iter()
        .zip(0..)
        .filter(|(validator, _)| predicates::has_compounding_withdrawal_credential(validator))
        .map(|(_, index)| index)
        .collect_vec()
    {
        mutators::queue_excess_active_balance(&mut post, index)?;
    }

    Ok(post)
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

    fn run_altair_case<P: Preset>(case: Case) {
        let pre = case.ssz_default("pre");
        let expected_post = case.ssz_default("post");

        let actual_post = upgrade_to_altair::<P>(&P::default_config(), pre)
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
}
