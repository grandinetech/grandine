use arithmetic::U64Ext as _;
use diff::{Error, Patch, PatchConfig, PositionalPatch, ReplacePatch, VectorPatch};
use ssz::{BitVector, Compressed, ReadError, Ssz};

use crate::{
    cache::Cache,
    collections::{
        Attestations, Balances, Eth1DataVotes, HistoricalRoots, RandaoMixes, RecentRoots, Slashings,
    },
    nonstandard::PubkeyList,
    phase0::stored_validators::StoredValidators,
    phase0::{
        balances_patch::BalancesPatch,
        beacon_state::BeaconState,
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork, PendingAttestation},
        primitives::{DepositIndex, Gwei, H256, Slot, UnixSeconds},
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

    // > Attestations
    previous_epoch_attestations: Compressed<PositionalPatch<PendingAttestation<P>>>,
    current_epoch_attestations: Compressed<PositionalPatch<PendingAttestation<P>>>,

    // > Finality
    justification_bits: ReplacePatch<BitVector<JustificationBitsLength>>,
    previous_justified_checkpoint: ReplacePatch<Checkpoint>,
    current_justified_checkpoint: ReplacePatch<Checkpoint>,
    finalized_checkpoint: ReplacePatch<Checkpoint>,
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
            previous_epoch_attestations: Patch::diff(
                config,
                &base.previous_epoch_attestations,
                &changed.previous_epoch_attestations,
            )?,
            current_epoch_attestations: Patch::diff(
                config,
                &base.current_epoch_attestations,
                &changed.current_epoch_attestations,
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
        self.previous_epoch_attestations
            .apply(&mut base.previous_epoch_attestations)?;
        self.current_epoch_attestations
            .apply(&mut base.current_epoch_attestations)?;
        self.justification_bits
            .apply(&mut base.justification_bits)?;
        self.previous_justified_checkpoint
            .apply(&mut base.previous_justified_checkpoint)?;
        self.current_justified_checkpoint
            .apply(&mut base.current_justified_checkpoint)?;
        self.finalized_checkpoint
            .apply(&mut base.finalized_checkpoint)
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

    // > Attestations
    pub previous_epoch_attestations: Compressed<Attestations<P>>,
    pub current_epoch_attestations: Compressed<Attestations<P>>,

    // > Finality
    pub justification_bits: BitVector<JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
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
            previous_epoch_attestations: Compressed::with_level(
                state.previous_epoch_attestations.clone(),
                level,
            ),
            current_epoch_attestations: Compressed::with_level(
                state.current_epoch_attestations.clone(),
                level,
            ),
            justification_bits: state.justification_bits,
            previous_justified_checkpoint: state.previous_justified_checkpoint,
            current_justified_checkpoint: state.current_justified_checkpoint,
            finalized_checkpoint: state.finalized_checkpoint,
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
            previous_epoch_attestations,
            current_epoch_attestations,
            justification_bits,
            previous_justified_checkpoint,
            current_justified_checkpoint,
            finalized_checkpoint,
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
            previous_epoch_attestations: previous_epoch_attestations.into_inner(),
            current_epoch_attestations: current_epoch_attestations.into_inner(),
            justification_bits,
            previous_justified_checkpoint,
            current_justified_checkpoint,
            finalized_checkpoint,
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
