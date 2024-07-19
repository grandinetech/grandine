use std::sync::Arc;

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::{BitVector, Hc, Ssz};

use crate::{
    altair::containers::SyncCommittee,
    cache::Cache,
    capella::{containers::ExecutionPayloadHeader, primitives::WithdrawalIndex},
    collections::{
        Balances, EpochParticipation, Eth1DataVotes, HistoricalRoots, HistoricalSummaries,
        InactivityScores, RandaoMixes, RecentRoots, Slashings, Validators,
    },
    phase0::{
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork},
        primitives::{DepositIndex, Slot, UnixSeconds, ValidatorIndex, H256},
    },
    preset::Preset,
};

#[derive(Clone, Default, Debug, Derivative, Deserialize, Serialize, Ssz)]
#[derivative(PartialEq, Eq)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BeaconState<P: Preset> {
    // > Versioning
    #[serde(with = "serde_utils::string_or_native")]
    pub genesis_time: UnixSeconds,
    pub genesis_validators_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub fork: Fork,

    // > History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: RecentRoots<P>,
    pub state_roots: RecentRoots<P>,
    pub historical_roots: HistoricalRoots<P>,

    // > Eth1
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: Eth1DataVotes<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub eth1_deposit_index: DepositIndex,

    // > Registry
    pub validators: Validators<P>,
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub balances: Balances<P>,

    // > Randomness
    pub randao_mixes: RandaoMixes<P>,

    // > Slashings
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub slashings: Slashings<P>,

    // > Participation
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub previous_epoch_participation: EpochParticipation<P>,
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub current_epoch_participation: EpochParticipation<P>,

    // > Finality
    pub justification_bits: BitVector<JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // > Inactivity
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub inactivity_scores: InactivityScores<P>,

    // > Sync
    pub current_sync_committee: Arc<Hc<SyncCommittee<P>>>,
    pub next_sync_committee: Arc<Hc<SyncCommittee<P>>>,

    // > Execution
    pub latest_execution_payload_header: ExecutionPayloadHeader<P>,

    // > Withdrawals
    #[serde(with = "serde_utils::string_or_native")]
    pub next_withdrawal_index: WithdrawalIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub next_withdrawal_validator_index: ValidatorIndex,

    // > Deep history valid from Capella onwards
    pub historical_summaries: HistoricalSummaries<P>,

    // Cache
    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    #[ssz(skip)]
    pub cache: Cache,
}
