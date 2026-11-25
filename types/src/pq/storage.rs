use std::sync::Arc;

use diff::{
    Error, Patch, PatchConfig, PositionalPatch, QueuePatch, ReplacePatch, Unlimited, VectorPatch,
};
use ssz::{BitVector, Compressed, ContiguousList, Hc, ReadError, Ssz};
use std_ext::ArcExt as _;
use try_from_iterator::TryFromIterator as _;

use crate::{
    altair::participation_patch::ParticipationPatch,
    cache::Cache,
    capella::{
        containers::{HistoricalSummary, Withdrawal},
        primitives::WithdrawalIndex,
    },
    collections::{
        BuilderPendingPayments, BuilderPendingWithdrawals, Builders, Eth1DataVotes,
        HistoricalRoots, HistoricalSummaries, PayloadExpectedWithdrawals, ProgressiveBalances,
        ProgressiveEpochParticipation, ProgressiveInactivityScores,
        ProgressivePendingConsolidations, ProgressivePendingDeposits,
        ProgressivePendingPartialWithdrawals, ProposerLookahead, PtcWindow, RandaoMixes,
        RecentRoots, Slashings,
    },
    electra::containers::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
    gloas::{
        builder_list_patch::BuilderListPatch,
        containers::{BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadBid},
        primitives::BuilderIndex,
        ptc_patch::PtcPatch,
    },
    nonstandard::PubkeyList,
    phase0::{
        balances_patch::BalancesPatch,
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork},
        primitives::{
            DepositIndex, Epoch, ExecutionBlockHash, Gwei, H256, Slot, UnixSeconds, ValidatorIndex,
        },
        stored_validators::StoredValidators,
        validator_list_patch::ValidatorListPatch,
    },
    pq::{
        beacon_state::{BeaconState, BuilderPreregistrations, ValidatorPreregistrations},
        builder_list::PqBuilders,
        containers::{BuilderPreregistration, ValidatorPreregistration},
        primitives::AggregationCommitteeWindow,
        validator_list::PqValidatorList,
    },
    preset::{Preset, SlotsPerHistoricalRoot},
    traits::SszValidatorList as _,
};

/// The VRF roots of the validators appended to a [`PqValidatorList`].
///
/// A validator's VRF root is set when it is added and never changes, so a patch only carries the
/// roots of new validators. It is applied after the [`ValidatorListPatch`] that appends them.
#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct VrfRootsPatch {
    base_len: u32,
    appended: ContiguousList<H256, Unlimited>,
}

impl Patch<PqValidatorList> for VrfRootsPatch {
    fn diff(
        _config: PatchConfig,
        base: &PqValidatorList,
        changed: &PqValidatorList,
    ) -> Result<Self, Error> {
        let base_len = base.vrf_roots.len();

        if changed.vrf_roots.len() < base_len
            || base
                .vrf_roots
                .iter()
                .ne(changed.vrf_roots.iter().take(base_len))
        {
            return Err(Error::UnsupportedDiff);
        }

        Ok(Self {
            base_len: u32::try_from(base_len).map_err(|_| Error::PatchListLimitExceeded)?,
            appended: ContiguousList::try_from_iter(
                changed.vrf_roots.iter().skip(base_len).copied(),
            )
            .expect("appended VRF roots should fit in the SSZ list"),
        })
    }

    /// Expects `base` to have the validators of the matching [`ValidatorListPatch`] appended.
    fn apply(self, base: &mut PqValidatorList) -> Result<(), Error> {
        let Self { base_len, appended } = self;

        let base_len = usize::try_from(base_len).map_err(|_| Error::InvalidPatchEncoding)?;

        if base.vrf_roots.len() != base_len.saturating_add(appended.len())
            || base.len_usize() != base.vrf_roots.len()
        {
            return Err(Error::PatchBaseLengthMismatch);
        }

        base.set_appended_vrf_roots(base_len, appended)
            .map_err(|_| Error::PatchIndexOutOfBounds)
    }
}

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false, derive_cursor = true)]
pub struct BeaconStatePatch<P: Preset> {
    // > Versioning
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
    vrf_roots: Compressed<VrfRootsPatch>,
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

    // > Execution
    latest_block_hash: ReplacePatch<ExecutionBlockHash>,

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

    // > Next proposers
    proposer_lookahead: Compressed<VectorPatch<ValidatorIndex>>,

    // > Builders
    builders: Compressed<BuilderListPatch>,
    next_withdrawal_builder_index: ReplacePatch<BuilderIndex>,

    // > Payload availability
    execution_payload_availability: ReplacePatch<Compressed<BitVector<SlotsPerHistoricalRoot<P>>>>,

    // > Builder payments
    builder_pending_payments: Compressed<VectorPatch<BuilderPendingPayment>>,
    builder_pending_withdrawals: Compressed<QueuePatch<BuilderPendingWithdrawal>>,
    latest_execution_payload_bid: ReplacePatch<ExecutionPayloadBid<P>>,
    payload_expected_withdrawals: Compressed<PositionalPatch<Withdrawal>>,

    // > Payload timeliness
    ptc_window: Compressed<PtcPatch<P>>,

    // > Preregistrations
    validator_preregistrations: Compressed<QueuePatch<ValidatorPreregistration>>,
    builder_preregistrations: Compressed<QueuePatch<BuilderPreregistration>>,

    // > Aggregators
    aggregation_committee_window: ReplacePatch<Arc<Hc<AggregationCommitteeWindow<P>>>>,
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
            vrf_roots: Patch::diff(config, &base.validators, &changed.validators)?,
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
            latest_block_hash: Patch::diff(
                config,
                &base.latest_block_hash,
                &changed.latest_block_hash,
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
            proposer_lookahead: Patch::diff(
                config,
                &base.proposer_lookahead,
                &changed.proposer_lookahead,
            )?,
            builders: Patch::diff(config, &base.builders.0, &changed.builders.0)?,
            next_withdrawal_builder_index: Patch::diff(
                config,
                &base.next_withdrawal_builder_index,
                &changed.next_withdrawal_builder_index,
            )?,
            execution_payload_availability: Patch::diff(
                config,
                &base.execution_payload_availability,
                &changed.execution_payload_availability,
            )?,
            builder_pending_payments: Patch::diff(
                config,
                &base.builder_pending_payments,
                &changed.builder_pending_payments,
            )?,
            builder_pending_withdrawals: Patch::diff(
                config,
                &base.builder_pending_withdrawals,
                &changed.builder_pending_withdrawals,
            )?,
            latest_execution_payload_bid: Patch::diff(
                config,
                &base.latest_execution_payload_bid,
                &changed.latest_execution_payload_bid,
            )?,
            payload_expected_withdrawals: Patch::diff(
                config,
                &base.payload_expected_withdrawals,
                &changed.payload_expected_withdrawals,
            )?,
            ptc_window: Patch::diff(config, &base.ptc_window, &changed.ptc_window)?,
            validator_preregistrations: Patch::diff(
                config,
                &base.validator_preregistrations,
                &changed.validator_preregistrations,
            )?,
            builder_preregistrations: Patch::diff(
                config,
                &base.builder_preregistrations,
                &changed.builder_preregistrations,
            )?,
            aggregation_committee_window: Patch::diff(
                config,
                &base.aggregation_committee_window,
                &changed.aggregation_committee_window,
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
        // The validator patch appends new validators with zero VRF roots, which the VRF root
        // patch then fills in.
        self.validators.apply(&mut base.validators)?;
        self.vrf_roots.apply(&mut base.validators)?;
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
        self.latest_block_hash.apply(&mut base.latest_block_hash)?;
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
            .apply(&mut base.pending_consolidations)?;
        self.proposer_lookahead
            .apply(&mut base.proposer_lookahead)?;
        self.builders.apply(&mut base.builders.0)?;
        self.next_withdrawal_builder_index
            .apply(&mut base.next_withdrawal_builder_index)?;
        self.execution_payload_availability
            .apply(&mut base.execution_payload_availability)?;
        self.builder_pending_payments
            .apply(&mut base.builder_pending_payments)?;
        self.builder_pending_withdrawals
            .apply(&mut base.builder_pending_withdrawals)?;
        self.latest_execution_payload_bid
            .apply(&mut base.latest_execution_payload_bid)?;
        self.payload_expected_withdrawals
            .apply(&mut base.payload_expected_withdrawals)?;
        self.ptc_window.apply(&mut base.ptc_window)?;
        self.validator_preregistrations
            .apply(&mut base.validator_preregistrations)?;
        self.builder_preregistrations
            .apply(&mut base.builder_preregistrations)?;
        self.aggregation_committee_window
            .apply(&mut base.aggregation_committee_window)
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
    pub vrf_roots: Compressed<ContiguousList<H256, Unlimited>>,
    pub balances: Compressed<ProgressiveBalances>,

    // > Randomness
    pub randao_mixes: RandaoMixes<P>,

    // > Slashings
    pub slashings: Compressed<Slashings<P>>,

    // > Participation
    pub previous_epoch_participation: Compressed<ProgressiveEpochParticipation>,
    pub current_epoch_participation: Compressed<ProgressiveEpochParticipation>,

    // > Finality
    pub justification_bits: BitVector<JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // > Inactivity
    pub inactivity_scores: Compressed<ProgressiveInactivityScores>,

    // > Execution
    pub latest_block_hash: ExecutionBlockHash,

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
    pub pending_deposits: Compressed<ProgressivePendingDeposits>,
    pub pending_partial_withdrawals: Compressed<ProgressivePendingPartialWithdrawals>,
    pub pending_consolidations: Compressed<ProgressivePendingConsolidations>,

    // > Next proposers
    pub proposer_lookahead: Compressed<ProposerLookahead<P>>,

    // > Builders
    pub builders: Compressed<Builders>,
    pub next_withdrawal_builder_index: BuilderIndex,

    // > Payload availability
    pub execution_payload_availability: BitVector<SlotsPerHistoricalRoot<P>>,

    // > Builder payments
    pub builder_pending_payments: Compressed<BuilderPendingPayments<P>>,
    pub builder_pending_withdrawals: Compressed<BuilderPendingWithdrawals>,
    pub latest_execution_payload_bid: ExecutionPayloadBid<P>,
    pub payload_expected_withdrawals: Compressed<PayloadExpectedWithdrawals>,

    // > Payload timeliness
    pub ptc_window: Compressed<PtcWindow<P>>,

    // > Preregistrations
    pub validator_preregistrations: Compressed<ValidatorPreregistrations>,
    pub builder_preregistrations: Compressed<BuilderPreregistrations>,

    // > Aggregators
    pub aggregation_committee_window: Arc<Hc<AggregationCommitteeWindow<P>>>,
}

impl<P: Preset> BeaconStateFrame<P> {
    #[must_use]
    pub fn new(state: &BeaconState<P>, finalized_validators: usize, level: i32) -> Self {
        let vrf_roots = ContiguousList::try_from_iter(state.validators.vrf_roots.iter().copied())
            .expect("VRF roots should fit in the SSZ list");

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
            validators: StoredValidators::new(
                &state.validators.list.buf,
                finalized_validators,
                level,
            ),
            vrf_roots: Compressed::with_level(vrf_roots, level),
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
            latest_block_hash: state.latest_block_hash,
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
            proposer_lookahead: Compressed::with_level(state.proposer_lookahead.clone(), level),
            builders: Compressed::with_level(state.builders.0.clone(), level),
            next_withdrawal_builder_index: state.next_withdrawal_builder_index,
            execution_payload_availability: state.execution_payload_availability,
            builder_pending_payments: Compressed::with_level(
                state.builder_pending_payments.clone(),
                level,
            ),
            builder_pending_withdrawals: Compressed::with_level(
                state.builder_pending_withdrawals.clone(),
                level,
            ),
            latest_execution_payload_bid: state.latest_execution_payload_bid.clone(),
            payload_expected_withdrawals: Compressed::with_level(
                state.payload_expected_withdrawals.clone(),
                level,
            ),
            ptc_window: Compressed::with_level(state.ptc_window.clone(), level),
            validator_preregistrations: Compressed::with_level(
                state.validator_preregistrations.clone(),
                level,
            ),
            builder_preregistrations: Compressed::with_level(
                state.builder_preregistrations.clone(),
                level,
            ),
            aggregation_committee_window: state.aggregation_committee_window.clone_arc(),
        }
    }

    #[expect(clippy::too_many_lines)]
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
            vrf_roots,
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
            latest_block_hash,
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
            builders,
            next_withdrawal_builder_index,
            execution_payload_availability,
            builder_pending_payments,
            builder_pending_withdrawals,
            latest_execution_payload_bid,
            payload_expected_withdrawals,
            ptc_window,
            validator_preregistrations,
            builder_preregistrations,
            aggregation_committee_window,
        } = self;

        let validators = stored_validator_list(validators, vrf_roots, finalized_pubkeys)?;

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
            validators,
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
            latest_block_hash,
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
            proposer_lookahead: proposer_lookahead.into_inner(),
            builders: PqBuilders(builders.into_inner()),
            next_withdrawal_builder_index,
            execution_payload_availability,
            builder_pending_payments: builder_pending_payments.into_inner(),
            builder_pending_withdrawals: builder_pending_withdrawals.into_inner(),
            latest_execution_payload_bid,
            payload_expected_withdrawals: payload_expected_withdrawals.into_inner(),
            ptc_window: ptc_window.into_inner(),
            validator_preregistrations: validator_preregistrations.into_inner(),
            builder_preregistrations: builder_preregistrations.into_inner(),
            aggregation_committee_window,
            // The PQ state has no sync committees. These are what reading its SSZ gives.
            current_sync_committee: Arc::default(),
            next_sync_committee: Arc::default(),
            cache: Cache::default(),
        })
    }
}

fn stored_validator_list<N: typenum::Unsigned>(
    validators: StoredValidators<N>,
    vrf_roots: Compressed<ContiguousList<H256, Unlimited>>,
    finalized_pubkeys: &PubkeyList,
) -> Result<PqValidatorList, ReadError> {
    let validators = PqValidatorList {
        list: validators.into_progressive_list(finalized_pubkeys)?,
        vrf_roots: vrf_roots.into_inner().into_iter().collect(),
    };

    if validators.vrf_roots.len() != validators.len_usize() {
        return Err(ReadError::Custom {
            message: "stored PQ state has a VRF root count that differs from its validators",
        });
    }

    Ok(validators)
}

#[cfg(test)]
mod tests {
    use ssz::{SszHash as _, SszListMut as _, SszRead as _, SszWrite as _};

    use crate::traits::BeaconState as _;
    use xmss::XmssPublicKey;

    use crate::{
        config::Config,
        gloas::containers::Builder,
        nonstandard::Phase,
        pq::containers::Validator,
        preset::Minimal,
        storage::{
            BeaconStateFrame as CombinedBeaconStateFrame,
            BeaconStatePatch as CombinedBeaconStatePatch,
        },
    };

    use super::*;

    fn validator(byte: u8) -> Validator {
        Validator {
            pubkey: XmssPublicKey::from_array([byte; 32]),
            vrf_root: H256::repeat_byte(byte.wrapping_add(1)),
            effective_balance: u64::from(byte),
            ..Validator::default()
        }
    }

    fn base_state() -> BeaconState<Minimal> {
        let mut state = BeaconState::<Minimal>::default();

        for byte in 0..4 {
            state
                .validators
                .push_pq(validator(byte))
                .expect("list is not full");
        }

        state
    }

    fn changed_state(base: &BeaconState<Minimal>) -> BeaconState<Minimal> {
        let mut changed = base.clone();

        changed.slot = 42;
        changed
            .validators
            .push_pq(validator(9))
            .expect("list is not full");
        *changed
            .validators
            .effective_balance_mut(1)
            .expect("index is within bounds") = 1234;
        changed
            .balances
            .extend(&[32_000_000_000, 31_000_000_000])
            .expect("list is not full");
        changed
            .builders
            .push(Builder::default())
            .expect("list is not full");
        changed
            .validator_preregistrations
            .push(ValidatorPreregistration::default())
            .expect("list is not full");
        changed
            .builder_preregistrations
            .push(BuilderPreregistration::default())
            .expect("list is not full");
        changed.latest_execution_payload_bid.value = 11;
        changed
            .ptc_window
            .get_mut(0)
            .expect("index is within bounds")[0] = 13;

        changed
    }

    #[test]
    fn diff_and_apply_round_trip() {
        let base = base_state();
        let changed = changed_state(&base);

        let patch = BeaconStatePatch::diff(PatchConfig::default(), &base, &changed)
            .expect("PQ patch should represent the change");

        let encoded = patch.to_ssz().expect("patch should serialize");
        let patch = BeaconStatePatch::<Minimal>::from_ssz(&Config::minimal(), encoded)
            .expect("patch should deserialize");

        let mut applied = base;
        patch.apply(&mut applied).expect("patch should apply");

        // Patches leave out the public keys of appended validators, which storage restores.
        applied
            .validators
            .restore_pubkeys_in(changed.validators.pubkeys(), 4..5)
            .expect("public keys should be restored");

        assert_eq!(applied, changed);
        assert_eq!(applied.hash_tree_root(), changed.hash_tree_root());
        assert_eq!(
            applied.validators.vrf_root(4).expect("validator 4 exists"),
            validator(9).vrf_root,
        );
    }

    #[test]
    fn a_changed_vrf_root_is_not_diffed() {
        let base = base_state();

        let changed = BeaconState {
            validators: base
                .validators
                .iter_pq()
                .map(|mut validator| {
                    validator.vrf_root = H256::repeat_byte(0xff);
                    validator
                })
                .collect(),
            ..base.clone()
        };

        let error = BeaconStatePatch::diff(PatchConfig::default(), &base, &changed)
            .expect_err("VRF roots of existing validators never change");

        assert!(matches!(error, Error::UnsupportedDiff));
    }

    #[test]
    fn frame_round_trips_with_and_without_finalized_pubkeys() {
        let state = changed_state(&base_state());
        let config = Config::minimal();

        for finalized_validators in [0, 3] {
            let finalized_pubkeys = state.validators.pubkeys().clone();

            let encoded = BeaconStateFrame::new(
                &state,
                finalized_validators,
                zstd::DEFAULT_COMPRESSION_LEVEL,
            )
            .to_ssz()
            .expect("frame should serialize");

            let restored = BeaconStateFrame::<Minimal>::from_ssz(&config, encoded)
                .expect("frame should deserialize")
                .into_state(&finalized_pubkeys)
                .expect("frame should restore the state");

            assert_eq!(restored, state);
            assert_eq!(restored.hash_tree_root(), state.hash_tree_root());
        }
    }

    #[test]
    fn combined_frame_and_patch_select_the_pq_phase() {
        let base = Arc::new(crate::combined::BeaconState::Pq(base_state().into()));
        let changed = Arc::new(crate::combined::BeaconState::Pq(
            changed_state(&base_state()).into(),
        ));

        let config = Config::minimal().start_and_stay_in(Phase::Pq);

        let encoded = CombinedBeaconStateFrame::new(&changed, 0, zstd::DEFAULT_COMPRESSION_LEVEL)
            .to_ssz()
            .expect("frame should serialize");

        let restored = CombinedBeaconStateFrame::<Minimal>::from_ssz(&config, encoded)
            .expect("frame should deserialize as PQ")
            .into_state(&PubkeyList::default())
            .expect("frame should restore the state");

        assert_eq!(restored, *changed);

        let patch = CombinedBeaconStatePatch::diff(PatchConfig::default(), &base, &changed)
            .expect("PQ patch should represent the change")
            .to_ssz()
            .expect("patch should serialize");

        let mut applied = base;

        CombinedBeaconStatePatch::<Minimal>::from_ssz(&config, patch)
            .expect("patch should deserialize")
            .apply(&mut applied)
            .expect("patch should apply");

        if let crate::combined::BeaconState::Pq(state) = Arc::make_mut(&mut applied) {
            state
                .as_mut()
                .validators
                .restore_pubkeys_in(changed.validators().pubkeys(), 4..5)
                .expect("public keys should be restored");
        }

        assert_eq!(applied, changed);
        assert_eq!(applied.hash_tree_root(), changed.hash_tree_root());
    }
}
