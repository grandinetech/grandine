use std::sync::Arc;

use arithmetic::U64Ext as _;
use diff::{Error, Patch, PatchConfig, PositionalPatch, QueuePatch, ReplacePatch, VectorPatch};
use ssz::{BitVector, Compressed, Hc, ReadError, Ssz};
use std_ext::ArcExt as _;

use crate::{
    altair::{containers::SyncCommittee, participation_patch::ParticipationPatch},
    cache::Cache,
    capella::{containers::HistoricalSummary, primitives::WithdrawalIndex},
    collections::{
        Balances, EpochParticipation, Eth1DataVotes, HistoricalRoots, HistoricalSummaries,
        InactivityScores, PendingConsolidations, PendingDeposits, PendingPartialWithdrawals,
        RandaoMixes, RecentRoots, Slashings,
    },
    deneb::containers::ExecutionPayloadHeader,
    electra::{
        beacon_state::BeaconState,
        containers::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
    },
    nonstandard::PubkeyList,
    phase0::stored_validators::StoredValidators,
    phase0::{
        balances_patch::BalancesPatch,
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork},
        primitives::{DepositIndex, Epoch, Gwei, H256, Slot, UnixSeconds, ValidatorIndex},
        validator_list_patch::ValidatorListPatch,
    },
    preset::Preset,
};

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false, derive_cursor = true)]
pub struct BeaconStatePatch<P: Preset> {
    // > Versioning
    // TODO(new-db-layout): with new DB layout, this field probably can be
    // dropped, as it will be saved in key.
    slot: ReplacePatch<Slot>,

    // > History
    latest_block_header: ReplacePatch<BeaconBlockHeader>,
    block_roots: VectorPatch<H256>,
    state_roots: VectorPatch<H256>,
    historical_roots: PositionalPatch<H256>,

    // > Eth1
    eth1_data: ReplacePatch<Eth1Data>,
    eth1_data_votes: Compressed<PositionalPatch<Eth1Data>>,
    eth1_deposit_index: ReplacePatch<DepositIndex>,

    // > Registry
    validators: Compressed<ValidatorListPatch>,
    balances: Compressed<BalancesPatch>,

    // > Randomness
    randao_mixes: VectorPatch<H256>,

    // > Slashings
    slashings: VectorPatch<Gwei>,

    // > Participation
    previous_epoch_participation: Compressed<ParticipationPatch>,
    current_epoch_participation: Compressed<ParticipationPatch>,

    // > Finality
    justification_bits: ReplacePatch<BitVector<JustificationBitsLength>>,
    previous_justified_checkpoint: ReplacePatch<Checkpoint>,
    current_justified_checkpoint: ReplacePatch<Checkpoint>,
    finalized_checkpoint: ReplacePatch<Checkpoint>,

    // > Inactivity
    inactivity_scores: Compressed<PositionalPatch<u64>>,

    // > Sync
    current_sync_committee: ReplacePatch<Arc<Hc<SyncCommittee<P>>>>,
    next_sync_committee: ReplacePatch<Arc<Hc<SyncCommittee<P>>>>,

    // > Execution
    latest_execution_payload_header: ReplacePatch<ExecutionPayloadHeader<P>>,

    // > Withdrawals
    next_withdrawal_index: ReplacePatch<WithdrawalIndex>,
    next_withdrawal_validator_index: ReplacePatch<ValidatorIndex>,

    // > Deep history valid from Capella onwards
    historical_summaries: PositionalPatch<HistoricalSummary>,
    deposit_requests_start_index: ReplacePatch<DepositIndex>,
    deposit_balance_to_consume: ReplacePatch<Gwei>,
    exit_balance_to_consume: ReplacePatch<Gwei>,
    earliest_exit_epoch: ReplacePatch<Epoch>,
    consolidation_balance_to_consume: ReplacePatch<Gwei>,
    earliest_consolidation_epoch: ReplacePatch<Epoch>,
    pending_deposits: Compressed<QueuePatch<PendingDeposit>>,
    pending_partial_withdrawals: Compressed<QueuePatch<PendingPartialWithdrawal>>,
    pending_consolidations: Compressed<QueuePatch<PendingConsolidation>>,
}

impl<P: Preset> Patch<BeaconState<P>> for BeaconStatePatch<P> {
    #[expect(clippy::too_many_lines)]
    fn diff(
        config: PatchConfig,
        base: &BeaconState<P>,
        changed: &BeaconState<P>,
    ) -> Result<Self, Error> {
        if base.genesis_time != changed.genesis_time
            || base.genesis_validators_root != changed.genesis_validators_root
            || base.fork != changed.fork
        {
            return Err(Error::UnsupportedDiff);
        }

        Ok(Self {
            slot: Patch::diff(config, &base.slot, &changed.slot)?,
            latest_block_header: Patch::diff(
                config,
                &base.latest_block_header,
                &changed.latest_block_header,
            )?,
            block_roots: Patch::diff(config, &base.block_roots, &changed.block_roots)?,
            state_roots: Patch::diff(config, &base.state_roots, &changed.state_roots)?,
            historical_roots: Patch::diff(
                config,
                &base.historical_roots,
                &changed.historical_roots,
            )?,
            eth1_data: Patch::diff(config, &base.eth1_data, &changed.eth1_data)?,
            eth1_data_votes: Patch::diff(config, &base.eth1_data_votes, &changed.eth1_data_votes)?,
            eth1_deposit_index: Patch::diff(
                config,
                &base.eth1_deposit_index,
                &changed.eth1_deposit_index,
            )?,
            validators: Patch::diff(config, &base.validators, &changed.validators)?,
            balances: Patch::diff(config, &base.balances, &changed.balances)?,
            randao_mixes: Patch::diff(config, &base.randao_mixes, &changed.randao_mixes)?,
            slashings: Patch::diff(config, &base.slashings, &changed.slashings)?,
            previous_epoch_participation: Patch::diff(
                config,
                &base.previous_epoch_participation,
                &changed.previous_epoch_participation,
            )?,
            current_epoch_participation: Patch::diff(
                config,
                &base.current_epoch_participation,
                &changed.current_epoch_participation,
            )?,
            justification_bits: Patch::diff(
                config,
                &base.justification_bits,
                &changed.justification_bits,
            )?,
            previous_justified_checkpoint: Patch::diff(
                config,
                &base.previous_justified_checkpoint,
                &changed.previous_justified_checkpoint,
            )?,
            current_justified_checkpoint: Patch::diff(
                config,
                &base.current_justified_checkpoint,
                &changed.current_justified_checkpoint,
            )?,
            finalized_checkpoint: Patch::diff(
                config,
                &base.finalized_checkpoint,
                &changed.finalized_checkpoint,
            )?,
            inactivity_scores: Patch::diff(
                config,
                &base.inactivity_scores,
                &changed.inactivity_scores,
            )?,
            current_sync_committee: Patch::diff(
                config,
                &base.current_sync_committee,
                &changed.current_sync_committee,
            )?,
            next_sync_committee: Patch::diff(
                config,
                &base.next_sync_committee,
                &changed.next_sync_committee,
            )?,
            latest_execution_payload_header: Patch::diff(
                config,
                &base.latest_execution_payload_header,
                &changed.latest_execution_payload_header,
            )?,
            next_withdrawal_index: Patch::diff(
                config,
                &base.next_withdrawal_index,
                &changed.next_withdrawal_index,
            )?,
            next_withdrawal_validator_index: Patch::diff(
                config,
                &base.next_withdrawal_validator_index,
                &changed.next_withdrawal_validator_index,
            )?,
            historical_summaries: Patch::diff(
                config,
                &base.historical_summaries,
                &changed.historical_summaries,
            )?,
            deposit_requests_start_index: Patch::diff(
                config,
                &base.deposit_requests_start_index,
                &changed.deposit_requests_start_index,
            )?,
            deposit_balance_to_consume: Patch::diff(
                config,
                &base.deposit_balance_to_consume,
                &changed.deposit_balance_to_consume,
            )?,
            exit_balance_to_consume: Patch::diff(
                config,
                &base.exit_balance_to_consume,
                &changed.exit_balance_to_consume,
            )?,
            earliest_exit_epoch: Patch::diff(
                config,
                &base.earliest_exit_epoch,
                &changed.earliest_exit_epoch,
            )?,
            consolidation_balance_to_consume: Patch::diff(
                config,
                &base.consolidation_balance_to_consume,
                &changed.consolidation_balance_to_consume,
            )?,
            earliest_consolidation_epoch: Patch::diff(
                config,
                &base.earliest_consolidation_epoch,
                &changed.earliest_consolidation_epoch,
            )?,
            pending_deposits: Patch::diff(
                config,
                &base.pending_deposits,
                &changed.pending_deposits,
            )?,
            pending_partial_withdrawals: Patch::diff(
                config,
                &base.pending_partial_withdrawals,
                &changed.pending_partial_withdrawals,
            )?,
            pending_consolidations: Patch::diff(
                config,
                &base.pending_consolidations,
                &changed.pending_consolidations,
            )?,
        })
    }

    fn apply(self, base: &mut BeaconState<P>) -> Result<(), Error> {
        self.slot.apply(&mut base.slot)?;
        self.latest_block_header
            .apply(&mut base.latest_block_header)?;
        self.block_roots.apply(&mut base.block_roots)?;
        self.state_roots.apply(&mut base.state_roots)?;
        self.historical_roots.apply(&mut base.historical_roots)?;
        self.eth1_data.apply(&mut base.eth1_data)?;
        self.eth1_data_votes.apply(&mut base.eth1_data_votes)?;
        self.eth1_deposit_index
            .apply(&mut base.eth1_deposit_index)?;
        self.validators.apply(&mut base.validators)?;
        self.balances.apply(&mut base.balances)?;
        self.randao_mixes.apply(&mut base.randao_mixes)?;
        self.slashings.apply(&mut base.slashings)?;
        self.previous_epoch_participation
            .apply(&mut base.previous_epoch_participation)?;
        self.current_epoch_participation
            .apply(&mut base.current_epoch_participation)?;
        self.justification_bits
            .apply(&mut base.justification_bits)?;
        self.previous_justified_checkpoint
            .apply(&mut base.previous_justified_checkpoint)?;
        self.current_justified_checkpoint
            .apply(&mut base.current_justified_checkpoint)?;
        self.finalized_checkpoint
            .apply(&mut base.finalized_checkpoint)?;
        self.inactivity_scores.apply(&mut base.inactivity_scores)?;
        self.current_sync_committee
            .apply(&mut base.current_sync_committee)?;
        self.next_sync_committee
            .apply(&mut base.next_sync_committee)?;
        self.latest_execution_payload_header
            .apply(&mut base.latest_execution_payload_header)?;
        self.next_withdrawal_index
            .apply(&mut base.next_withdrawal_index)?;
        self.next_withdrawal_validator_index
            .apply(&mut base.next_withdrawal_validator_index)?;
        self.historical_summaries
            .apply(&mut base.historical_summaries)?;
        self.deposit_requests_start_index
            .apply(&mut base.deposit_requests_start_index)?;
        self.deposit_balance_to_consume
            .apply(&mut base.deposit_balance_to_consume)?;
        self.exit_balance_to_consume
            .apply(&mut base.exit_balance_to_consume)?;
        self.earliest_exit_epoch
            .apply(&mut base.earliest_exit_epoch)?;
        self.consolidation_balance_to_consume
            .apply(&mut base.consolidation_balance_to_consume)?;
        self.earliest_consolidation_epoch
            .apply(&mut base.earliest_consolidation_epoch)?;
        self.pending_deposits.apply(&mut base.pending_deposits)?;
        self.pending_partial_withdrawals
            .apply(&mut base.pending_partial_withdrawals)?;
        self.pending_consolidations
            .apply(&mut base.pending_consolidations)
    }
}

#[derive(Ssz)]
#[ssz(derive_hash = false, derive_cursor = true)]
pub struct BeaconStateFrame<P: Preset> {
    // > Versioning
    pub genesis_time: UnixSeconds,
    pub genesis_validators_root: H256,
    pub slot: Slot,
    pub fork: Fork,

    // > History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: RecentRoots<P>,
    pub state_roots: RecentRoots<P>,
    pub historical_roots: HistoricalRoots<P>,

    // > Eth1
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: Compressed<Eth1DataVotes<P>>,
    pub eth1_deposit_index: DepositIndex,

    // > Registry
    pub validators: StoredValidators<P::ValidatorRegistryLimit>,
    pub balances: Compressed<Balances<P>>,

    // > Randomness
    pub randao_mixes: RandaoMixes<P>,

    // > Slashings
    pub slashings: Compressed<Slashings<P>>,

    // > Participation
    pub previous_epoch_participation: Compressed<EpochParticipation<P>>,
    pub current_epoch_participation: Compressed<EpochParticipation<P>>,

    // > Finality
    pub justification_bits: BitVector<JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // > Inactivity
    pub inactivity_scores: Compressed<InactivityScores<P>>,

    // > Sync
    pub current_sync_committee: Arc<Hc<SyncCommittee<P>>>,
    pub next_sync_committee: Arc<Hc<SyncCommittee<P>>>,

    // > Execution
    pub latest_execution_payload_header: ExecutionPayloadHeader<P>,

    // > Withdrawals
    pub next_withdrawal_index: WithdrawalIndex,
    pub next_withdrawal_validator_index: ValidatorIndex,

    // > Deep history valid from Capella onwards
    pub historical_summaries: HistoricalSummaries<P>,
    pub deposit_requests_start_index: DepositIndex,
    pub deposit_balance_to_consume: Gwei,
    pub exit_balance_to_consume: Gwei,
    pub earliest_exit_epoch: Epoch,
    pub consolidation_balance_to_consume: Gwei,
    pub earliest_consolidation_epoch: Epoch,
    pub pending_deposits: Compressed<PendingDeposits<P>>,
    pub pending_partial_withdrawals: Compressed<PendingPartialWithdrawals<P>>,
    pub pending_consolidations: Compressed<PendingConsolidations<P>>,
}

impl<P: Preset> BeaconStateFrame<P> {
    #[must_use]
    pub fn new(state: &BeaconState<P>, finalized_validators: usize, level: i32) -> Self {
        Self {
            genesis_time: state.genesis_time,
            genesis_validators_root: state.genesis_validators_root,
            slot: state.slot,
            fork: state.fork,
            latest_block_header: state.latest_block_header,
            block_roots: state.block_roots.clone(),
            state_roots: state.state_roots.clone(),
            historical_roots: state.historical_roots.clone(),
            eth1_data: state.eth1_data,
            eth1_data_votes: Compressed::with_level(state.eth1_data_votes.clone(), level),
            eth1_deposit_index: state.eth1_deposit_index,
            validators: StoredValidators::new(&state.validators.buf, finalized_validators, level),
            balances: Compressed::with_level(state.balances.clone(), level),
            randao_mixes: state.randao_mixes.clone(),
            slashings: Compressed::with_level(state.slashings.clone(), level),
            previous_epoch_participation: Compressed::with_level(
                state.previous_epoch_participation.clone(),
                level,
            ),
            current_epoch_participation: Compressed::with_level(
                state.current_epoch_participation.clone(),
                level,
            ),
            justification_bits: state.justification_bits,
            previous_justified_checkpoint: state.previous_justified_checkpoint,
            current_justified_checkpoint: state.current_justified_checkpoint,
            finalized_checkpoint: state.finalized_checkpoint,
            inactivity_scores: Compressed::with_level(state.inactivity_scores.clone(), level),
            current_sync_committee: state.current_sync_committee.clone_arc(),
            next_sync_committee: state.next_sync_committee.clone_arc(),
            latest_execution_payload_header: state.latest_execution_payload_header.clone(),
            next_withdrawal_index: state.next_withdrawal_index,
            next_withdrawal_validator_index: state.next_withdrawal_validator_index,
            historical_summaries: state.historical_summaries.clone(),
            deposit_requests_start_index: state.deposit_requests_start_index,
            deposit_balance_to_consume: state.deposit_balance_to_consume,
            exit_balance_to_consume: state.exit_balance_to_consume,
            earliest_exit_epoch: state.earliest_exit_epoch,
            consolidation_balance_to_consume: state.consolidation_balance_to_consume,
            earliest_consolidation_epoch: state.earliest_consolidation_epoch,
            pending_deposits: Compressed::with_level(state.pending_deposits.clone(), level),
            pending_partial_withdrawals: Compressed::with_level(
                state.pending_partial_withdrawals.clone(),
                level,
            ),
            pending_consolidations: Compressed::with_level(
                state.pending_consolidations.clone(),
                level,
            ),
        }
    }

    pub fn into_state(self, finalized_pubkeys: &PubkeyList) -> Result<BeaconState<P>, ReadError> {
        let Self {
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
        } = self;

        Ok(BeaconState {
            genesis_time,
            genesis_validators_root,
            slot,
            fork,
            latest_block_header,
            block_roots,
            state_roots,
            historical_roots,
            eth1_data,
            eth1_data_votes: eth1_data_votes.into_inner(),
            eth1_deposit_index,
            validators: validators.into_list(finalized_pubkeys)?,
            balances: balances.into_inner(),
            randao_mixes,
            slashings: slashings.into_inner(),
            previous_epoch_participation: previous_epoch_participation.into_inner(),
            current_epoch_participation: current_epoch_participation.into_inner(),
            justification_bits,
            previous_justified_checkpoint,
            current_justified_checkpoint,
            finalized_checkpoint,
            inactivity_scores: inactivity_scores.into_inner(),
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
            pending_deposits: pending_deposits.into_inner(),
            pending_partial_withdrawals: pending_partial_withdrawals.into_inner(),
            pending_consolidations: pending_consolidations.into_inner(),
            cache: Cache::default(),
        })
    }
}

#[derive(Clone, Copy, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct SlotDiff {
    pub randao_mix: H256,
}

impl SlotDiff {
    #[must_use]
    pub fn diff<P: Preset>(_base: &BeaconState<P>, changed: &BeaconState<P>) -> Self {
        Self {
            randao_mix: *changed
                .randao_mixes
                .mod_index(changed.slot.div_typenum::<P::SlotsPerEpoch>()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ssz::{PersistentList, SszRead as _, SszWrite as _};
    use try_from_iterator::TryFromIterator as _;

    use crate::{config::Config, preset::Minimal};

    use super::*;

    type PendingConsolidations =
        PersistentList<PendingConsolidation, <Minimal as Preset>::PendingConsolidationsLimit>;

    fn consolidations(source_indices: impl IntoIterator<Item = u64>) -> PendingConsolidations {
        PendingConsolidations::try_from_iter(source_indices.into_iter().map(|source_index| {
            PendingConsolidation {
                source_index,
                target_index: source_index.saturating_add(1),
            }
        }))
        .expect("length is below the maximum")
    }

    #[test]
    fn pending_consolidations_round_trip_through_a_queue_shift() {
        let base = BeaconState::<Minimal> {
            pending_consolidations: consolidations(0..8),
            ..BeaconState::default()
        };

        let mut changed = base.clone();

        // The queue is only ever consumed from the front and appended to at the back, which
        // is the shape `process_pending_consolidations` and `process_consolidation_request`
        // produce.
        changed.pending_consolidations = consolidations((3..8).chain(100..103));

        let patch = BeaconStatePatch::diff(PatchConfig::default(), &base, &changed)
            .expect("electra patch should represent the change");

        let encoded = patch.to_ssz().expect("patch should serialize");
        let patch = BeaconStatePatch::<Minimal>::from_ssz(&Config::minimal(), encoded)
            .expect("patch should deserialize");

        let mut applied = base;
        patch.apply(&mut applied).expect("patch should apply");

        assert_eq!(applied, changed);
    }

    #[test]
    fn pending_consolidations_round_trip_when_the_queue_drains_and_refills() {
        let base = BeaconState::<Minimal> {
            pending_consolidations: consolidations(0..4),
            ..BeaconState::default()
        };

        for changed_queue in [
            consolidations(0..0),
            consolidations(0..4),
            consolidations(0..6),
            consolidations(50..53),
        ] {
            let mut changed = base.clone();

            changed.pending_consolidations = changed_queue;

            let patch = BeaconStatePatch::diff(PatchConfig::default(), &base, &changed)
                .expect("electra patch should represent the change");

            let mut applied = base.clone();
            patch.apply(&mut applied).expect("patch should apply");

            assert_eq!(applied, changed);
        }
    }
}
