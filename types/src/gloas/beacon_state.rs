use std::sync::Arc;

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::{BitVector, Hc, Ssz};

use crate::{
    altair::containers::SyncCommittee,
    cache::Cache,
    capella::primitives::WithdrawalIndex,
    collections::{
        BuilderPendingPayments, BuilderPendingWithdrawals, Builders, Eth1DataVotes,
        HistoricalRoots, HistoricalSummaries, PayloadExpectedWithdrawals, ProgressiveBalances,
        ProgressiveEpochParticipation, ProgressiveInactivityScores,
        ProgressivePendingConsolidations, ProgressivePendingDeposits,
        ProgressivePendingPartialWithdrawals, ProgressiveValidators, ProposerLookahead, PtcWindow,
        RandaoMixes, RecentRoots, Slashings,
    },
    gloas::{containers::ExecutionPayloadBid, primitives::BuilderIndex},
    phase0::{
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork},
        primitives::{
            DepositIndex, Epoch, ExecutionBlockHash, Gwei, H256, Slot, UnixSeconds, ValidatorIndex,
        },
    },
    preset::{Preset, SlotsPerHistoricalRoot},
};

#[derive(Clone, Debug, Default, Derivative, Deserialize, Serialize, Ssz)]
#[derivative(PartialEq, Eq)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 46]))]
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
    pub validators: ProgressiveValidators,
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub balances: ProgressiveBalances<P>,

    // > Randomness
    pub randao_mixes: RandaoMixes<P>,

    // > Slashings
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub slashings: Slashings<P>,

    // > Participation
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub previous_epoch_participation: ProgressiveEpochParticipation<P>,
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub current_epoch_participation: ProgressiveEpochParticipation<P>,

    // > Finality
    pub justification_bits: BitVector<JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // > Inactivity
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub inactivity_scores: ProgressiveInactivityScores<P>,

    // > Sync
    pub current_sync_committee: Arc<Hc<SyncCommittee<P>>>,
    pub next_sync_committee: Arc<Hc<SyncCommittee<P>>>,

    // > Execution
    pub latest_block_hash: ExecutionBlockHash,

    // > Withdrawals
    #[serde(with = "serde_utils::string_or_native")]
    pub next_withdrawal_index: WithdrawalIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub next_withdrawal_validator_index: ValidatorIndex,

    // > Deep history valid from Capella onwards
    pub historical_summaries: HistoricalSummaries<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub deposit_requests_start_index: DepositIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub deposit_balance_to_consume: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub exit_balance_to_consume: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub earliest_exit_epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    pub consolidation_balance_to_consume: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub earliest_consolidation_epoch: Epoch,
    pub pending_deposits: ProgressivePendingDeposits<P>,
    pub pending_partial_withdrawals: ProgressivePendingPartialWithdrawals<P>,
    pub pending_consolidations: ProgressivePendingConsolidations<P>,

    // > Next proposers
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub proposer_lookahead: ProposerLookahead<P>,

    // > Builders
    pub builders: Builders<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub next_withdrawal_builder_index: BuilderIndex,

    // > Payload availability
    pub execution_payload_availability: BitVector<SlotsPerHistoricalRoot<P>>,

    // > Builder payments
    pub builder_pending_payments: BuilderPendingPayments<P>,
    pub builder_pending_withdrawals: BuilderPendingWithdrawals<P>,
    pub latest_execution_payload_bid: ExecutionPayloadBid<P>,
    pub payload_expected_withdrawals: PayloadExpectedWithdrawals<P>,

    // > Payload timeliness
    #[serde(with = "serde_utils::string_or_native_nested_sequence")]
    pub ptc_window: PtcWindow<P>,

    // Cache
    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    #[ssz(skip)]
    pub cache: Cache,
}
