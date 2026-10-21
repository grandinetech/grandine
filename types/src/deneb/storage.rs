use std::sync::Arc;

use diff::{Error, Patch, PatchConfig, PositionalPatch, ReplacePatch, VectorPatch};
use ssz::{BitVector, Compressed, Hc, Ssz};

use crate::{
    altair::{containers::SyncCommittee, participation_patch::ParticipationPatch},
    capella::{containers::HistoricalSummary, primitives::WithdrawalIndex},
    deneb::{beacon_state::BeaconState, containers::ExecutionPayloadHeader},
    phase0::{
        balances_patch::BalancesPatch,
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data},
        primitives::{DepositIndex, Gwei, H256, Slot, ValidatorIndex},
        validator_list_patch::ValidatorListPatch,
    },
    preset::Preset,
};

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
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
