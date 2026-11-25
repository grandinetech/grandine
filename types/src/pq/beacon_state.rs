use std::sync::Arc;

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::{BitVector, Hc, PersistentProgressiveList, Ssz};

use crate::{
    altair::containers::SyncCommittee,
    cache::Cache,
    capella::primitives::WithdrawalIndex,
    collections::{
        BuilderPendingPayments, BuilderPendingWithdrawals, Eth1DataVotes, HistoricalRoots,
        HistoricalSummaries, PayloadExpectedWithdrawals, ProgressiveBalances,
        ProgressiveEpochParticipation, ProgressiveInactivityScores,
        ProgressivePendingConsolidations, ProgressivePendingDeposits,
        ProgressivePendingPartialWithdrawals, ProposerLookahead, PtcWindow, RandaoMixes,
        RecentRoots, Slashings,
    },
    gloas::{containers::ExecutionPayloadBid, primitives::BuilderIndex},
    phase0::{
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork},
        primitives::{
            DepositIndex, Epoch, ExecutionBlockHash, Gwei, H256, Slot, UnixSeconds, ValidatorIndex,
        },
    },
    pq::{
        builder_list::PqBuilders,
        containers::{BuilderPreregistration, ValidatorPreregistration},
        primitives::AggregationCommitteeWindow,
        validator_list::PqValidatorList,
    },
    preset::{Preset, SlotsPerHistoricalRoot},
};

pub type ValidatorPreregistrations = PersistentProgressiveList<ValidatorPreregistration>;
pub type BuilderPreregistrations = PersistentProgressiveList<BuilderPreregistration>;

#[derive(Clone, Debug, Default, Derivative, Deserialize, Serialize, Ssz)]
#[derivative(PartialEq, Eq)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1,
]))]
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
    pub validators: PqValidatorList,
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub balances: ProgressiveBalances,

    // > Randomness
    pub randao_mixes: RandaoMixes<P>,

    // > Slashings
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub slashings: Slashings<P>,

    // > Participation
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub previous_epoch_participation: ProgressiveEpochParticipation,
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub current_epoch_participation: ProgressiveEpochParticipation,

    // > Finality
    pub justification_bits: BitVector<JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // > Inactivity
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub inactivity_scores: ProgressiveInactivityScores,

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
    pub pending_deposits: ProgressivePendingDeposits,
    pub pending_partial_withdrawals: ProgressivePendingPartialWithdrawals,
    pub pending_consolidations: ProgressivePendingConsolidations,

    // > Next proposers
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub proposer_lookahead: ProposerLookahead<P>,

    // > Builders
    pub builders: PqBuilders,
    #[serde(with = "serde_utils::string_or_native")]
    pub next_withdrawal_builder_index: BuilderIndex,

    // > Payload availability
    pub execution_payload_availability: BitVector<SlotsPerHistoricalRoot<P>>,

    // > Builder payments
    pub builder_pending_payments: BuilderPendingPayments<P>,
    pub builder_pending_withdrawals: BuilderPendingWithdrawals,
    pub latest_execution_payload_bid: ExecutionPayloadBid<P>,
    pub payload_expected_withdrawals: PayloadExpectedWithdrawals,

    // > Payload timeliness
    #[serde(with = "serde_utils::string_or_native_nested_sequence")]
    pub ptc_window: PtcWindow<P>,

    // > Preregistrations
    pub validator_preregistrations: ValidatorPreregistrations,
    pub builder_preregistrations: BuilderPreregistrations,

    // > Aggregators
    #[serde(with = "window_serde")]
    pub aggregation_committee_window: Arc<Hc<AggregationCommitteeWindow<P>>>,

    // Not part of the PQ state. Kept so that traits shared with earlier phases are implemented.
    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    #[ssz(skip)]
    pub current_sync_committee: Arc<Hc<SyncCommittee<P>>>,
    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    #[ssz(skip)]
    pub next_sync_committee: Arc<Hc<SyncCommittee<P>>>,

    // Cache
    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    #[ssz(skip)]
    pub cache: Cache,
}

mod window_serde {
    use std::sync::Arc;

    use generic_array::ArrayLength;
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer, de::Error as _};
    use ssz::{ContiguousVector, Hc, ProgressiveList};
    use try_from_iterator::TryFromIterator as _;

    use crate::{phase0::primitives::ValidatorIndex, pq::primitives::AggregationCommittees};

    type Nested = Vec<Vec<Vec<String>>>;

    pub fn serialize<N: ArrayLength<AggregationCommittees>, S: Serializer>(
        window: &Arc<Hc<ContiguousVector<AggregationCommittees, N>>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        window
            .iter()
            .map(|committees| {
                committees
                    .into_iter()
                    .map(|committee| committee.into_iter().map(ToString::to_string).collect())
                    .collect()
            })
            .collect::<Nested>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, N: ArrayLength<AggregationCommittees>, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Arc<Hc<ContiguousVector<AggregationCommittees, N>>>, D::Error> {
        let parse_committees = |committees: Vec<Vec<String>>| {
            let committees = committees
                .into_iter()
                .map(|committee| {
                    let indices = committee
                        .iter()
                        .map(|index| index.parse::<ValidatorIndex>())
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(D::Error::custom)?;

                    ProgressiveList::try_from_iter(indices).map_err(D::Error::custom)
                })
                .collect::<Result<Vec<_>, _>>()?;

            AggregationCommittees::try_from_iter(committees).map_err(D::Error::custom)
        };

        let window = Nested::deserialize(deserializer)?
            .into_iter()
            .map(parse_committees)
            .collect::<Result<Vec<_>, _>>()?;

        ContiguousVector::try_from_iter(window)
            .map(|window| Arc::new(Hc::from(window)))
            .map_err(D::Error::custom)
    }
}
