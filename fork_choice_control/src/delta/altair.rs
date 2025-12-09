use std::sync::Arc;

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::{BitVector, Hc, PersistentList};
use try_from_iterator::TryFromIterator;
use types::{
    altair::{beacon_state::BeaconState, containers::SyncCommittee},
    cache::Cache,
    collections::{EpochParticipation, Eth1DataVotes, HistoricalRoots, InactivityScores},
    phase0::{
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork},
        primitives::{DepositIndex, Slot, UnixSeconds, H256},
    },
    preset::Preset,
};

use super::phase0::{
    apply_balances_delta, apply_randao, apply_roots_delta, apply_slashings, apply_validators_delta,
    balances_delta, randao_delta, roots_delta, slashings_delta, validators_delta, BalanceDiffs,
    RandaoChange, SlashingChange, ValidatorsChange,
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

    // Cache
    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    pub cache: Cache,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScoreIndexChange {
    index: u64,
    new_score: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum InactivityScoreDiff {
    ZeroList(usize),
    NonZero {
        new_len: usize,
        updated_values: Vec<ScoreIndexChange>,
        extensions: Vec<u64>,
    },
}

impl Default for InactivityScoreDiff {
    fn default() -> Self {
        Self::ZeroList(0)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ParticipationDiff {
    ZeroList(usize),
    NonZero {
        updated: Vec<(usize, u8)>,
        extension: Vec<u8>,
    },
}

impl Default for ParticipationDiff {
    fn default() -> Self {
        Self::ZeroList(0)
    }
}

pub fn delta<P: Preset>(base: BeaconState<P>, target: BeaconState<P>) -> BeaconStateDelta<P> {
    let base_slot = base.slot;
    let target_slot = target.slot;

    let genesis_time = target.genesis_time;

    let genesis_validators_root = target.genesis_validators_root;
    let fork = target.fork;
    let slot = target_slot;
    let latest_block_header = target.latest_block_header;

    let target_block_roots = target.block_roots;
    let block_roots = roots_delta::<P>(base_slot, target_slot, target_block_roots);

    let target_state_roots = target.state_roots;
    let state_roots = roots_delta::<P>(base_slot, target_slot, target_state_roots);

    let mut historical_roots = None;
    if target.historical_roots != base.historical_roots {
        historical_roots = Some(target.historical_roots);
    }

    let eth1_data = target.eth1_data;
    let eth1_data_votes = target.eth1_data_votes;
    let eth1_deposit_index = target.eth1_deposit_index;

    let validators = validators_delta::<P>(base.validators, target.validators);
    let balances = balances_delta::<P>(base.balances, target.balances);

    let randao_mixes = randao_delta::<P>(base_slot, target_slot, target.randao_mixes);

    let slashings = slashings_delta::<P>(base_slot, base.slashings, target_slot, target.slashings);

    let previous_epoch_participation = epoch_participation_delta::<P>(
        base.previous_epoch_participation,
        target.previous_epoch_participation,
    );
    let current_epoch_participation = epoch_participation_delta::<P>(
        base.current_epoch_participation,
        target.current_epoch_participation,
    );

    let mut justification_bits = None;
    if target.justification_bits != base.justification_bits {
        justification_bits = Some(target.justification_bits);
    }
    let previous_justified_checkpoint = target.previous_justified_checkpoint;
    let current_justified_checkpoint = target.current_justified_checkpoint;
    let finalized_checkpoint = target.finalized_checkpoint;

    let inactivity_scores =
        inactivity_scores_delta::<P>(base.inactivity_scores, target.inactivity_scores);

    let mut current_sync_committee = None;
    if target.current_sync_committee != base.current_sync_committee {
        current_sync_committee = Some(target.current_sync_committee);
    }
    let mut next_sync_committee = None;
    if target.next_sync_committee != base.next_sync_committee {
        next_sync_committee = Some(target.next_sync_committee);
    }

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
        cache,
    }
}

pub fn apply_delta<P: Preset>(base: BeaconState<P>, delta: BeaconStateDelta<P>) -> BeaconState<P> {
    let genesis_time = delta.genesis_time;
    let genesis_validators_root = delta.genesis_validators_root;
    let fork = delta.fork;
    let slot = delta.slot;

    let latest_block_header = delta.latest_block_header;
    let block_roots = apply_roots_delta::<P>(base.slot, base.block_roots, delta.block_roots);
    let state_roots = apply_roots_delta::<P>(base.slot, base.state_roots, delta.state_roots);

    let historical_roots = match delta.historical_roots {
        Some(historical_roots) => historical_roots,
        None => base.historical_roots,
    };

    let eth1_data = delta.eth1_data;
    let eth1_data_votes = delta.eth1_data_votes;
    let eth1_deposit_index = delta.eth1_deposit_index;

    let validators = apply_validators_delta::<P>(base.validators, delta.validators);
    let balances = apply_balances_delta::<P>(base.balances, delta.balances);

    let randao_mixes = apply_randao::<P>(base.randao_mixes, delta.randao_mixes);

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
        cache,
    }
}

pub fn inactivity_scores_delta<P: Preset>(
    base_inactivity_scores: InactivityScores<P>,
    target_inactivity_scores: InactivityScores<P>,
) -> InactivityScoreDiff {
    let base_len = base_inactivity_scores.len_usize();
    let target_len = target_inactivity_scores.len_usize();

    if target_inactivity_scores.into_iter().all(|&v| v == 0) {
        return InactivityScoreDiff::ZeroList(target_len);
    }

    let mut score_index_changes = vec![];

    for (i, (v1, v2)) in base_inactivity_scores
        .into_iter()
        .zip(target_inactivity_scores.into_iter())
        .enumerate()
    {
        if v1 != v2 {
            score_index_changes.push(ScoreIndexChange {
                index: i as u64,
                new_score: *v2,
            });
        }
    }

    let extensions = target_inactivity_scores
        .into_iter()
        .skip(base_len)
        .cloned()
        .collect();

    InactivityScoreDiff::NonZero {
        new_len: target_len,
        updated_values: score_index_changes,
        extensions,
    }
}

pub fn apply_inactivity_score<P: Preset>(
    mut base_inactivity_scores: InactivityScores<P>,
    delta: InactivityScoreDiff,
) -> InactivityScores<P> {
    let target_inactivity_scores = match delta {
        InactivityScoreDiff::ZeroList(len) => {
            PersistentList::try_from_iter(std::iter::repeat(0).take(len)).unwrap()
        }
        InactivityScoreDiff::NonZero {
            new_len: _, // to use for prune
            updated_values,
            extensions,
        } => {
            for change in updated_values {
                *base_inactivity_scores.get_mut(change.index).unwrap() = change.new_score;
            }
            for element in extensions {
                base_inactivity_scores.push(element).unwrap();
            }
            base_inactivity_scores
        } // should prune values if less than
    };

    target_inactivity_scores
}

pub fn epoch_participation_delta<P: Preset>(
    base_epoch_participation: EpochParticipation<P>,
    target_epoch_participation: EpochParticipation<P>,
) -> ParticipationDiff {
    let len = target_epoch_participation.len_usize();
    // check if it is all zeros
    if target_epoch_participation.into_iter().all(|&v| v == 0) {
        return ParticipationDiff::ZeroList(len);
    }

    let mut updated = vec![];
    for (i, (v1, v2)) in base_epoch_participation
        .into_iter()
        .zip(target_epoch_participation.into_iter())
        .enumerate()
    {
        if v1 != v2 {
            updated.push((i, *v2));
        }
    }

    let extension = target_epoch_participation
        .into_iter()
        .skip(base_epoch_participation.len_usize())
        .cloned()
        .collect();

    ParticipationDiff::NonZero { updated, extension }
}

pub fn apply_epoch_participation<P: Preset>(
    mut base_epoch_participation: EpochParticipation<P>,
    pd: ParticipationDiff,
) -> EpochParticipation<P> {
    let base_len = base_epoch_participation.len_usize();
    let target_epoch_participation = match pd {
        ParticipationDiff::ZeroList(new_len) => {
            base_epoch_participation =
                PersistentList::repeat_zero_with_length_of(&base_epoch_participation);
            for _ in base_len..new_len {
                base_epoch_participation.push(0).unwrap();
            }
            base_epoch_participation
        }
        ParticipationDiff::NonZero { updated, extension } => {
            for update in updated {
                *base_epoch_participation.get_mut(update.0 as u64).unwrap() = update.1;
            }
            for element in extension {
                base_epoch_participation.push(element).unwrap();
            }
            base_epoch_participation
        }
    };

    target_epoch_participation
}
