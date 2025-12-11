use std::sync::Arc;

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::{BitVector, Hc};
use types::{
    altair::containers::SyncCommittee,
    bellatrix::{beacon_state::BeaconState, containers::ExecutionPayloadHeader},
    cache::Cache,
    collections::{Eth1DataVotes, HistoricalRoots},
    phase0::{
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork},
        primitives::{DepositIndex, Slot, UnixSeconds, H256},
    },
    preset::Preset,
};

use super::{
    altair::{
        apply_epoch_participation, apply_inactivity_score, epoch_participation_delta,
        inactivity_scores_delta, InactivityScoreDiff, ParticipationDiff,
    },
    phase0::{
        apply_balances_delta, apply_randao, apply_roots_delta, apply_slashings,
        apply_validators_delta, balances_delta, randao_delta, roots_delta, slashings_delta,
        validators_delta, BalanceDiffs, RandaoChange, SlashingChange, ValidatorsChange,
    },
};

#[derive(Debug, Clone, Default, Derivative, Serialize, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BeaconStateDelta<P: Preset> {
    // > Versioning
    pub genesis_time: UnixSeconds,
    pub genesis_validators_root: H256,
    pub slot: Slot,
    pub fork: Fork,

    // > History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: Vec<H256>,
    pub state_roots: Vec<H256>,
    pub historical_roots: Option<HistoricalRoots<P>>,

    // > Eth1
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: Eth1DataVotes<P>,
    pub eth1_deposit_index: DepositIndex,

    // > Registry
    pub validators: ValidatorsChange,
    pub balances: BalanceDiffs,

    // > Randomness
    pub randao_mixes: RandaoChange,

    // > Slashings
    pub slashings: Option<Vec<SlashingChange>>,

    // > Participation
    pub previous_epoch_participation: ParticipationDiff,
    pub current_epoch_participation: ParticipationDiff,

    // > Finality
    pub justification_bits: Option<BitVector<JustificationBitsLength>>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // > Inactivity
    pub inactivity_scores: InactivityScoreDiff,

    // > Sync
    pub current_sync_committee: Option<Arc<Hc<SyncCommittee<P>>>>,
    pub next_sync_committee: Option<Arc<Hc<SyncCommittee<P>>>>,

    // > Execution
    pub latest_execution_payload_header: ExecutionPayloadHeader<P>,

    // Cache
    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    pub cache: Cache,
}

pub fn delta<P: Preset>(base: &BeaconState<P>, target: BeaconState<P>) -> BeaconStateDelta<P> {
    let base_slot = base.slot;
    let target_slot = target.slot;

    let genesis_time = target.genesis_time;

    let genesis_validators_root = target.genesis_validators_root;
    let fork = target.fork;
    let slot = target_slot;
    let latest_block_header = target.latest_block_header;

    let target_block_roots = target.block_roots;
    let block_roots = roots_delta::<P>(base_slot, target_slot, &target_block_roots);

    let target_state_roots = target.state_roots;
    let state_roots = roots_delta::<P>(base_slot, target_slot, &target_state_roots);

    let historical_roots =
        (target.historical_roots != base.historical_roots).then_some(target.historical_roots);

    let eth1_data = target.eth1_data;
    let eth1_data_votes = target.eth1_data_votes;
    let eth1_deposit_index = target.eth1_deposit_index;

    let validators = validators_delta::<P>(&base.validators, &target.validators);
    let balances = balances_delta::<P>(&base.balances, &target.balances);

    let randao_mixes = randao_delta::<P>(base_slot, target_slot, &target.randao_mixes);

    let slashings =
        slashings_delta::<P>(base_slot, &base.slashings, target_slot, &target.slashings);

    let previous_epoch_participation = epoch_participation_delta::<P>(
        &base.previous_epoch_participation,
        &target.previous_epoch_participation,
    );
    let current_epoch_participation = epoch_participation_delta::<P>(
        &base.current_epoch_participation,
        &target.current_epoch_participation,
    );

    let justification_bits =
        (target.justification_bits != base.justification_bits).then_some(target.justification_bits);

    let previous_justified_checkpoint = target.previous_justified_checkpoint;
    let current_justified_checkpoint = target.current_justified_checkpoint;
    let finalized_checkpoint = target.finalized_checkpoint;

    let inactivity_scores =
        inactivity_scores_delta::<P>(&base.inactivity_scores, &target.inactivity_scores);

    let current_sync_committee = (target.current_sync_committee != base.current_sync_committee)
        .then_some(target.current_sync_committee);

    let next_sync_committee = (target.next_sync_committee != base.next_sync_committee)
        .then_some(target.next_sync_committee);

    let latest_execution_payload_header = target.latest_execution_payload_header;

    let cache = target.cache;

    BeaconStateDelta {
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
    }
}

pub fn apply_delta<P: Preset>(base: BeaconState<P>, delta: BeaconStateDelta<P>) -> BeaconState<P> {
    let genesis_time = delta.genesis_time;
    let genesis_validators_root = delta.genesis_validators_root;
    let fork = delta.fork;
    let slot = delta.slot;

    let latest_block_header = delta.latest_block_header;
    let block_roots = apply_roots_delta::<P>(base.slot, base.block_roots, &delta.block_roots);
    let state_roots = apply_roots_delta::<P>(base.slot, base.state_roots, &delta.state_roots);

    let historical_roots = match delta.historical_roots {
        Some(historical_roots) => historical_roots,
        None => base.historical_roots,
    };

    let eth1_data = delta.eth1_data;
    let eth1_data_votes = delta.eth1_data_votes;
    let eth1_deposit_index = delta.eth1_deposit_index;

    let validators = apply_validators_delta::<P>(base.validators, delta.validators);
    let balances = apply_balances_delta::<P>(base.balances, delta.balances);

    let randao_mixes = apply_randao::<P>(base.randao_mixes, &delta.randao_mixes);

    let slashings = apply_slashings::<P>(base.slashings, delta.slashings);

    let previous_epoch_participation = apply_epoch_participation::<P>(
        base.previous_epoch_participation,
        delta.previous_epoch_participation,
    );
    let current_epoch_participation = apply_epoch_participation::<P>(
        base.current_epoch_participation,
        delta.current_epoch_participation,
    );

    let justification_bits = match delta.justification_bits {
        Some(justification_bits) => justification_bits,
        None => base.justification_bits,
    };

    let previous_justified_checkpoint = delta.previous_justified_checkpoint;
    let current_justified_checkpoint = delta.current_justified_checkpoint;
    let finalized_checkpoint = delta.finalized_checkpoint;

    let inactivity_scores =
        apply_inactivity_score::<P>(base.inactivity_scores, delta.inactivity_scores);

    let current_sync_committee = match delta.current_sync_committee {
        Some(current_sync_committee) => current_sync_committee,
        None => base.current_sync_committee,
    };
    let next_sync_committee = match delta.next_sync_committee {
        Some(next_sync_committee) => next_sync_committee,
        None => base.next_sync_committee,
    };

    let latest_execution_payload_header = delta.latest_execution_payload_header;

    let cache = delta.cache;

    BeaconState {
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
    }
}
