use std::sync::Arc;

use arithmetic::U64Ext as _;
use diff::{Error, Patch, PatchConfig, PositionalPatch, ReplacePatch, VectorPatch};
use ssz::{BitVector, Compressed, Hc, ReadError, Ssz};
use std_ext::ArcExt as _;

use crate::{
    altair::{containers::SyncCommittee, participation_patch::ParticipationPatch},
    cache::Cache,
    capella::{containers::HistoricalSummary, primitives::WithdrawalIndex},
    collections::{
        Balances, EpochParticipation, Eth1DataVotes, HistoricalRoots, HistoricalSummaries,
        InactivityScores, RandaoMixes, RecentRoots, Slashings,
    },
    deneb::{beacon_state::BeaconState, containers::ExecutionPayloadHeader},
    nonstandard::PubkeyList,
    phase0::stored_validators::StoredValidators,
    phase0::{
        balances_patch::BalancesPatch,
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork},
        primitives::{DepositIndex, Gwei, H256, Slot, UnixSeconds, ValidatorIndex},
        validator_list_patch::ValidatorListPatch,
    },
    preset::Preset,
    storage::ProposerRewards,
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
}

impl<P: Preset> Patch<BeaconState<P>> for BeaconStatePatch<P> {
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
            .apply(&mut base.historical_summaries)
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
            cache: Cache::default(),
        })
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct SlotDiff {
    pub randao_mix: H256,
    pub rewards: ProposerRewards,
    pub validators: ValidatorListPatch,
    pub balances: BalancesPatch,
}

impl SlotDiff {
    pub fn diff<P: Preset>(
        config: PatchConfig,
        base: &BeaconState<P>,
        changed: &BeaconState<P>,
        rewards: ProposerRewards,
    ) -> Result<Self, Error> {
        Ok(Self {
            randao_mix: *changed
                .randao_mixes
                .mod_index(changed.slot.div_typenum::<P::SlotsPerEpoch>()),
            rewards,
            validators: Patch::diff(config, &base.validators, &changed.validators)?,
            balances: Patch::diff(config, &base.balances, &changed.balances)?,
        })
    }
}
