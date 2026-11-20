use core::{iter::Peekable, slice::Iter};
use std::sync::Arc;

use anyhow::Result;
use bitvec::vec::BitVec;
use diff::{Error, Patch, PatchConfig, PositionSet, QueuePatch, Unlimited};
use helper_functions::{accessors, predicates};
use itertools::izip;
use pubkey_cache::PubkeyCache;
use ssz::{BitList, ContiguousList, ReadError, Size, Ssz, SszRead, SszSize, SszWrite, WriteError};
use std_ext::ArcExt as _;
use transition_functions::{
    altair::EpochRewardScalars,
    combined::{self, Statistics},
};
use types::{
    altair::{participation_patch::ParticipationPatch, primitives::ParticipationFlags},
    combined::BeaconState,
    config::Config,
    electra::containers::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
    nonstandard::{BlockRewards, Phase},
    phase0::{
        balances_patch::BalancesPatch,
        primitives::{Epoch, Gwei, H256, Slot, ValidatorIndex},
        validator_list_patch::ValidatorListPatch,
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::storage::StoredBlock;

type Blocks<'blocks, P> = Peekable<Iter<'blocks, StoredBlock<P>>>;

#[derive(Clone, Debug)]
pub enum DerivedFields {
    V1(DerivedFieldsV1),
}

impl DerivedFields {
    pub fn new<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut Arc<BeaconState<P>>,
        block_rewards: Option<ProposerRewards>,
        blocks: &[StoredBlock<P>],
        end: Slot,
    ) -> Result<Self> {
        let mut blocks = blocks.iter().peekable();

        DerivedFieldsV1::new(config, pubkey_cache, state, block_rewards, &mut blocks, end)
            .map(Self::V1)
    }

    #[must_use]
    pub fn rewards(&self, count: usize) -> Option<ProposerRewards> {
        match self {
            Self::V1(fields) => fields.rewards(count),
        }
    }

    #[must_use]
    pub fn randao_mix(&self, count: usize) -> Option<H256> {
        match self {
            Self::V1(fields) => fields.randao_mix(count),
        }
    }

    #[must_use]
    pub const fn total_active_balance(&self) -> Gwei {
        match self {
            Self::V1(fields) => fields.total_active_balance(),
        }
    }

    #[must_use]
    pub const fn validator_snapshot(&self) -> Option<&ValidatorSnapshot> {
        match self {
            Self::V1(fields) => fields.validator_snapshot(),
        }
    }

    pub fn apply_active_changes(&self, active: &mut BitVec<u8>) -> Result<()> {
        let active_changes = match self {
            Self::V1(fields) => fields.active_changes(),
        };

        for index in active_changes {
            let index = usize::try_from(*index)?;

            if index >= active.len() {
                active.resize(index.saturating_add(1), false);
            }

            let flipped = !active[index];

            active.set(index, flipped);
        }

        Ok(())
    }

    #[must_use]
    pub fn reward_inputs(&self) -> Option<EpochRewardInputs> {
        match self {
            Self::V1(fields) => fields.reward_inputs(),
        }
    }

    #[must_use]
    pub fn inactivity_scores(&self) -> Option<(PositionSet, ContiguousList<u64, Unlimited>)> {
        match self {
            Self::V1(fields) => fields.inactivity_scores(),
        }
    }

    #[must_use]
    pub fn validator_patches(&self, count: usize) -> Option<Vec<ValidatorListPatch>> {
        match self {
            Self::V1(fields) => fields.validator_patches(count),
        }
    }

    #[must_use]
    pub fn balance_patches(&self, count: usize) -> Option<Vec<BalancesPatch>> {
        match self {
            Self::V1(fields) => fields.balance_patches(count),
        }
    }

    #[must_use]
    pub fn pending_deposit_patches(&self, count: usize) -> Option<Vec<QueuePatch<PendingDeposit>>> {
        match self {
            Self::V1(fields) => fields.pending_deposit_patches(count),
        }
    }

    #[must_use]
    pub fn pending_partial_withdrawal_patches(
        &self,
        count: usize,
    ) -> Option<Vec<QueuePatch<PendingPartialWithdrawal>>> {
        match self {
            Self::V1(fields) => fields.pending_partial_withdrawal_patches(count),
        }
    }

    #[must_use]
    pub fn pending_consolidation_patches(
        &self,
        count: usize,
    ) -> Option<Vec<QueuePatch<PendingConsolidation>>> {
        match self {
            Self::V1(fields) => fields.pending_consolidation_patches(count),
        }
    }
}

impl SszSize for DerivedFields {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl SszWrite for DerivedFields {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::V1(fields) => {
                bytes.push(1);
                fields.write_variable(bytes)
            }
        }
    }
}

impl<C> SszRead<C> for DerivedFields {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let (version, payload) = bytes.split_first().ok_or(ReadError::Custom {
            message: "derived fields are empty",
        })?;

        match *version {
            1 => SszRead::from_ssz(context, payload).map(Self::V1),
            _ => Err(ReadError::Custom {
                message: "unsupported derived fields version",
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub enum DerivedFieldsV1 {
    Phase0(Phase0DerivedFields),
    Altair(AltairDerivedFields),
    Bellatrix(AltairDerivedFields),
    Capella(AltairDerivedFields),
    Deneb(AltairDerivedFields),
    Electra(ElectraDerivedFields),
    Fulu(ElectraDerivedFields),
    Gloas(GloasDerivedFields),
}

impl DerivedFieldsV1 {
    fn new<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut Arc<BeaconState<P>>,
        block_rewards: Option<ProposerRewards>,
        blocks: &mut Blocks<P>,
        end: Slot,
    ) -> Result<Self> {
        let fields = match state.phase() {
            Phase::Phase0 => Self::Phase0(Phase0DerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
            Phase::Altair => Self::Altair(AltairDerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
            Phase::Bellatrix => Self::Bellatrix(AltairDerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
            Phase::Capella => Self::Capella(AltairDerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
            Phase::Deneb => Self::Deneb(AltairDerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
            Phase::Electra => Self::Electra(ElectraDerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
            Phase::Fulu => Self::Fulu(ElectraDerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
            Phase::Gloas => Self::Gloas(GloasDerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
        };

        Ok(fields)
    }

    #[must_use]
    pub fn rewards(&self, count: usize) -> Option<ProposerRewards> {
        match self {
            Self::Phase0(fields) => fields.rewards(count),
            Self::Altair(fields)
            | Self::Bellatrix(fields)
            | Self::Capella(fields)
            | Self::Deneb(fields) => fields.rewards(count),
            Self::Electra(fields) | Self::Fulu(fields) => fields.rewards(count),
            Self::Gloas(fields) => fields.rewards(count),
        }
    }

    #[must_use]
    pub fn randao_mix(&self, count: usize) -> Option<H256> {
        match self {
            Self::Phase0(fields) => fields.randao_mix(count),
            Self::Altair(fields)
            | Self::Bellatrix(fields)
            | Self::Capella(fields)
            | Self::Deneb(fields) => fields.randao_mix(count),
            Self::Electra(fields) | Self::Fulu(fields) => fields.randao_mix(count),
            Self::Gloas(fields) => fields.randao_mix(count),
        }
    }

    #[must_use]
    pub const fn total_active_balance(&self) -> Gwei {
        match self {
            Self::Phase0(fields) => fields.total_active_balance,
            Self::Altair(fields)
            | Self::Bellatrix(fields)
            | Self::Capella(fields)
            | Self::Deneb(fields) => fields.total_active_balance,
            Self::Electra(fields) | Self::Fulu(fields) => fields.total_active_balance,
            Self::Gloas(fields) => fields.total_active_balance,
        }
    }

    #[must_use]
    pub const fn validator_snapshot(&self) -> Option<&ValidatorSnapshot> {
        match self {
            Self::Phase0(fields) => fields.validator_snapshot.as_ref(),
            Self::Altair(fields)
            | Self::Bellatrix(fields)
            | Self::Capella(fields)
            | Self::Deneb(fields) => fields.validator_snapshot.as_ref(),
            Self::Electra(fields) | Self::Fulu(fields) => fields.validator_snapshot.as_ref(),
            Self::Gloas(fields) => fields.validator_snapshot.as_ref(),
        }
    }

    fn active_changes(&self) -> &[ValidatorIndex] {
        match self {
            Self::Phase0(fields) => fields.active_changes.as_ref(),
            Self::Altair(fields)
            | Self::Bellatrix(fields)
            | Self::Capella(fields)
            | Self::Deneb(fields) => fields.active_changes.as_ref(),
            Self::Electra(fields) | Self::Fulu(fields) => fields.active_changes.as_ref(),
            Self::Gloas(fields) => fields.active_changes.as_ref(),
        }
    }

    #[must_use]
    pub fn reward_inputs(&self) -> Option<EpochRewardInputs> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(fields)
            | Self::Bellatrix(fields)
            | Self::Capella(fields)
            | Self::Deneb(fields) => Some(fields.reward_inputs.clone()),
            Self::Electra(fields) | Self::Fulu(fields) => Some(fields.reward_inputs.clone()),
            Self::Gloas(fields) => Some(fields.reward_inputs.clone()),
        }
    }

    #[must_use]
    pub fn inactivity_scores(&self) -> Option<(PositionSet, ContiguousList<u64, Unlimited>)> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(fields)
            | Self::Bellatrix(fields)
            | Self::Capella(fields)
            | Self::Deneb(fields) => Some((
                fields.inactivity_score_positions.clone(),
                fields.inactivity_scores.clone(),
            )),
            Self::Electra(fields) | Self::Fulu(fields) => Some((
                fields.inactivity_score_positions.clone(),
                fields.inactivity_scores.clone(),
            )),
            Self::Gloas(fields) => Some((
                fields.inactivity_score_positions.clone(),
                fields.inactivity_scores.clone(),
            )),
        }
    }

    #[must_use]
    pub fn validator_patches(&self, count: usize) -> Option<Vec<ValidatorListPatch>> {
        match self {
            Self::Phase0(fields) => fields
                .slots(count)
                .map(|slots| slots.iter().map(|slot| slot.validators.clone()).collect()),
            Self::Altair(fields)
            | Self::Bellatrix(fields)
            | Self::Capella(fields)
            | Self::Deneb(fields) => fields
                .slots(count)
                .map(|slots| slots.iter().map(|slot| slot.validators.clone()).collect()),
            Self::Electra(fields) | Self::Fulu(fields) => fields
                .slots(count)
                .map(|slots| slots.iter().map(|slot| slot.validators.clone()).collect()),
            Self::Gloas(fields) => fields
                .slots(count)
                .map(|slots| slots.iter().map(|slot| slot.validators.clone()).collect()),
        }
    }

    #[must_use]
    pub fn balance_patches(&self, count: usize) -> Option<Vec<BalancesPatch>> {
        match self {
            Self::Phase0(fields) => fields
                .slots(count)
                .map(|slots| slots.iter().map(|slot| slot.balances.clone()).collect()),
            Self::Altair(fields)
            | Self::Bellatrix(fields)
            | Self::Capella(fields)
            | Self::Deneb(fields) => fields
                .slots(count)
                .map(|slots| slots.iter().map(|slot| slot.balances.clone()).collect()),
            Self::Electra(fields) | Self::Fulu(fields) => fields
                .slots(count)
                .map(|slots| slots.iter().map(|slot| slot.balances.clone()).collect()),
            Self::Gloas(fields) => fields
                .slots(count)
                .map(|slots| slots.iter().map(|slot| slot.balances.clone()).collect()),
        }
    }

    #[must_use]
    pub fn pending_deposit_patches(&self, count: usize) -> Option<Vec<QueuePatch<PendingDeposit>>> {
        match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => None,
            Self::Electra(fields) | Self::Fulu(fields) => fields.slots(count).map(|slots| {
                slots
                    .iter()
                    .map(|slot| slot.pending_deposits.clone())
                    .collect()
            }),
            Self::Gloas(fields) => fields.slots(count).map(|slots| {
                slots
                    .iter()
                    .map(|slot| slot.pending_deposits.clone())
                    .collect()
            }),
        }
    }

    #[must_use]
    pub fn pending_partial_withdrawal_patches(
        &self,
        count: usize,
    ) -> Option<Vec<QueuePatch<PendingPartialWithdrawal>>> {
        match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => None,
            Self::Electra(fields) | Self::Fulu(fields) => fields.slots(count).map(|slots| {
                slots
                    .iter()
                    .map(|slot| slot.pending_partial_withdrawals.clone())
                    .collect()
            }),
            Self::Gloas(fields) => fields.slots(count).map(|slots| {
                slots
                    .iter()
                    .map(|slot| slot.pending_partial_withdrawals.clone())
                    .collect()
            }),
        }
    }

    #[must_use]
    pub fn pending_consolidation_patches(
        &self,
        count: usize,
    ) -> Option<Vec<QueuePatch<PendingConsolidation>>> {
        match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => None,
            Self::Electra(fields) | Self::Fulu(fields) => fields.slots(count).map(|slots| {
                slots
                    .iter()
                    .map(|slot| slot.pending_consolidations.clone())
                    .collect()
            }),
            Self::Gloas(fields) => fields.slots(count).map(|slots| {
                slots
                    .iter()
                    .map(|slot| slot.pending_consolidations.clone())
                    .collect()
            }),
        }
    }
}

impl SszSize for DerivedFieldsV1 {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl SszWrite for DerivedFieldsV1 {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        let (phase, payload) = match self {
            Self::Phase0(fields) => (1, fields.to_ssz()?),
            Self::Altair(fields) => (2, fields.to_ssz()?),
            Self::Bellatrix(fields) => (3, fields.to_ssz()?),
            Self::Capella(fields) => (4, fields.to_ssz()?),
            Self::Deneb(fields) => (5, fields.to_ssz()?),
            Self::Electra(fields) => (6, fields.to_ssz()?),
            Self::Fulu(fields) => (7, fields.to_ssz()?),
            Self::Gloas(fields) => (8, fields.to_ssz()?),
        };

        bytes.push(phase);
        bytes.extend_from_slice(&payload);

        Ok(())
    }
}

impl<C> SszRead<C> for DerivedFieldsV1 {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let (phase, payload) = bytes.split_first().ok_or(ReadError::Custom {
            message: "derived fields lack a phase",
        })?;

        match *phase {
            1 => SszRead::from_ssz(context, payload).map(Self::Phase0),
            2 => SszRead::from_ssz(context, payload).map(Self::Altair),
            3 => SszRead::from_ssz(context, payload).map(Self::Bellatrix),
            4 => SszRead::from_ssz(context, payload).map(Self::Capella),
            5 => SszRead::from_ssz(context, payload).map(Self::Deneb),
            6 => SszRead::from_ssz(context, payload).map(Self::Electra),
            7 => SszRead::from_ssz(context, payload).map(Self::Fulu),
            8 => SszRead::from_ssz(context, payload).map(Self::Gloas),
            _ => Err(ReadError::Custom {
                message: "unsupported derived fields phase",
            }),
        }
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct Phase0DerivedFields {
    pub block_rewards: Option<ProposerRewards>,
    pub randao_mix: H256,
    pub total_active_balance: Gwei,
    pub validator_snapshot: Option<ValidatorSnapshot>,
    pub active_changes: ContiguousList<ValidatorIndex, Unlimited>,
    pub slots: ContiguousList<Phase0SlotFields, Unlimited>,
}

impl Phase0DerivedFields {
    fn new<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut Arc<BeaconState<P>>,
        block_rewards: Option<ProposerRewards>,
        blocks: &mut Blocks<P>,
        end: Slot,
    ) -> Result<Self> {
        let randao_mix =
            accessors::get_randao_mix(&**state, accessors::get_current_epoch(&**state));

        let total_active_balance = accessors::total_active_balance(&**state);

        let (validator_snapshot, active_changes) =
            validator_snapshot_and_active_changes(config, &**state)?;

        let slots = (state.slot().saturating_add(1)..end)
            .map(|slot| {
                let block = blocks.next_if(|block| block.message().slot() == slot);

                Phase0SlotFields::new(config, pubkey_cache, state, block)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            block_rewards,
            randao_mix,
            total_active_balance,
            validator_snapshot,
            active_changes,
            slots: slots.try_into()?,
        })
    }

    fn rewards(&self, count: usize) -> Option<ProposerRewards> {
        match count.checked_sub(1) {
            Some(index) => self.slots.get(index).map(|slot| slot.rewards),
            None => self.block_rewards,
        }
    }

    fn randao_mix(&self, count: usize) -> Option<H256> {
        match count.checked_sub(1) {
            Some(index) => self.slots.get(index).map(|slot| slot.randao_mix),
            None => Some(self.randao_mix),
        }
    }

    fn slots(&self, count: usize) -> Option<&[Phase0SlotFields]> {
        self.slots.as_ref().get(..count)
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct Phase0SlotFields {
    pub randao_mix: H256,
    pub rewards: ProposerRewards,
    pub validators: ValidatorListPatch,
    pub balances: BalancesPatch,
}

impl Phase0SlotFields {
    fn new<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut Arc<BeaconState<P>>,
        block: Option<&StoredBlock<P>>,
    ) -> Result<Self> {
        let base = state.clone_arc();

        let rewards = block
            .map(|block| block_rewards(config, pubkey_cache, state.make_mut(), block))
            .transpose()?
            .unwrap_or_default();

        let changed = &**state;
        let randao_mix = accessors::get_randao_mix(changed, accessors::get_current_epoch(changed));
        let config = PatchConfig::default();

        Ok(Self {
            randao_mix,
            rewards,
            validators: Patch::diff(config, base.validators(), changed.validators())?,
            balances: Patch::diff(config, base.balances(), changed.balances())?,
        })
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct AltairDerivedFields {
    pub block_rewards: Option<ProposerRewards>,
    pub randao_mix: H256,
    pub total_active_balance: Gwei,
    pub validator_snapshot: Option<ValidatorSnapshot>,
    pub active_changes: ContiguousList<ValidatorIndex, Unlimited>,
    pub reward_inputs: EpochRewardInputs,
    pub inactivity_score_positions: PositionSet,
    pub inactivity_scores: ContiguousList<u64, Unlimited>,
    pub slots: ContiguousList<AltairSlotFields, Unlimited>,
}

impl AltairDerivedFields {
    fn new<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut Arc<BeaconState<P>>,
        block_rewards: Option<ProposerRewards>,
        blocks: &mut Blocks<P>,
        end: Slot,
    ) -> Result<Self> {
        let randao_mix =
            accessors::get_randao_mix(&**state, accessors::get_current_epoch(&**state));

        let total_active_balance = accessors::total_active_balance(&**state);

        let (validator_snapshot, active_changes) =
            validator_snapshot_and_active_changes(config, &**state)?;

        let (inactivity_score_positions, inactivity_scores) = eligible_inactivity_scores(&**state)?;

        let start = state.clone_arc();

        let slots = (state.slot().saturating_add(1)..end)
            .map(|slot| {
                let block = blocks.next_if(|block| block.message().slot() == slot);

                AltairSlotFields::new(config, pubkey_cache, state, block)
            })
            .collect::<Result<Vec<_>>>()?;

        let reward_inputs = EpochRewardInputs::new(&start, &**state)?;

        Ok(Self {
            block_rewards,
            randao_mix,
            total_active_balance,
            validator_snapshot,
            active_changes,
            reward_inputs,
            inactivity_score_positions,
            inactivity_scores,
            slots: slots.try_into()?,
        })
    }

    fn rewards(&self, count: usize) -> Option<ProposerRewards> {
        match count.checked_sub(1) {
            Some(index) => self.slots.get(index).map(|slot| slot.rewards),
            None => self.block_rewards,
        }
    }

    fn randao_mix(&self, count: usize) -> Option<H256> {
        match count.checked_sub(1) {
            Some(index) => self.slots.get(index).map(|slot| slot.randao_mix),
            None => Some(self.randao_mix),
        }
    }

    fn slots(&self, count: usize) -> Option<&[AltairSlotFields]> {
        self.slots.as_ref().get(..count)
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct AltairSlotFields {
    pub randao_mix: H256,
    pub rewards: ProposerRewards,
    pub validators: ValidatorListPatch,
    pub balances: BalancesPatch,
}

impl AltairSlotFields {
    fn new<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut Arc<BeaconState<P>>,
        block: Option<&StoredBlock<P>>,
    ) -> Result<Self> {
        let base = state.clone_arc();

        let rewards = block
            .map(|block| block_rewards(config, pubkey_cache, state.make_mut(), block))
            .transpose()?
            .unwrap_or_default();

        let changed = &**state;
        let randao_mix = accessors::get_randao_mix(changed, accessors::get_current_epoch(changed));
        let config = PatchConfig::default();

        Ok(Self {
            randao_mix,
            rewards,
            validators: Patch::diff(config, base.validators(), changed.validators())?,
            balances: Patch::diff(config, base.balances(), changed.balances())?,
        })
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct ElectraDerivedFields {
    pub block_rewards: Option<ProposerRewards>,
    pub randao_mix: H256,
    pub total_active_balance: Gwei,
    pub validator_snapshot: Option<ValidatorSnapshot>,
    pub active_changes: ContiguousList<ValidatorIndex, Unlimited>,
    pub reward_inputs: EpochRewardInputs,
    pub inactivity_score_positions: PositionSet,
    pub inactivity_scores: ContiguousList<u64, Unlimited>,
    pub slots: ContiguousList<ElectraSlotFields, Unlimited>,
}

impl ElectraDerivedFields {
    fn new<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut Arc<BeaconState<P>>,
        block_rewards: Option<ProposerRewards>,
        blocks: &mut Blocks<P>,
        end: Slot,
    ) -> Result<Self> {
        let randao_mix =
            accessors::get_randao_mix(&**state, accessors::get_current_epoch(&**state));

        let total_active_balance = accessors::total_active_balance(&**state);

        let (validator_snapshot, active_changes) =
            validator_snapshot_and_active_changes(config, &**state)?;

        let (inactivity_score_positions, inactivity_scores) = eligible_inactivity_scores(&**state)?;

        let start = state.clone_arc();

        let slots = (state.slot().saturating_add(1)..end)
            .map(|slot| {
                let block = blocks.next_if(|block| block.message().slot() == slot);

                ElectraSlotFields::new(config, pubkey_cache, state, block)
            })
            .collect::<Result<Vec<_>>>()?;

        let reward_inputs = EpochRewardInputs::new(&start, &**state)?;

        Ok(Self {
            block_rewards,
            randao_mix,
            total_active_balance,
            validator_snapshot,
            active_changes,
            reward_inputs,
            inactivity_score_positions,
            inactivity_scores,
            slots: slots.try_into()?,
        })
    }

    fn rewards(&self, count: usize) -> Option<ProposerRewards> {
        match count.checked_sub(1) {
            Some(index) => self.slots.get(index).map(|slot| slot.rewards),
            None => self.block_rewards,
        }
    }

    fn randao_mix(&self, count: usize) -> Option<H256> {
        match count.checked_sub(1) {
            Some(index) => self.slots.get(index).map(|slot| slot.randao_mix),
            None => Some(self.randao_mix),
        }
    }

    fn slots(&self, count: usize) -> Option<&[ElectraSlotFields]> {
        self.slots.as_ref().get(..count)
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct ElectraSlotFields {
    pub randao_mix: H256,
    pub rewards: ProposerRewards,
    pub validators: ValidatorListPatch,
    pub balances: BalancesPatch,
    pub pending_deposits: QueuePatch<PendingDeposit>,
    pub pending_partial_withdrawals: QueuePatch<PendingPartialWithdrawal>,
    pub pending_consolidations: QueuePatch<PendingConsolidation>,
}

impl ElectraSlotFields {
    fn new<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut Arc<BeaconState<P>>,
        block: Option<&StoredBlock<P>>,
    ) -> Result<Self> {
        let base = state.clone_arc();

        let rewards = block
            .map(|block| block_rewards(config, pubkey_cache, state.make_mut(), block))
            .transpose()?
            .unwrap_or_default();

        let changed = &**state;
        let randao_mix = accessors::get_randao_mix(changed, accessors::get_current_epoch(changed));
        let config = PatchConfig::default();

        let (Some(post_electra_base), Some(post_electra_changed)) =
            (base.post_electra(), changed.post_electra())
        else {
            return Err(Error::CrossPhaseDiff.into());
        };

        Ok(Self {
            randao_mix,
            rewards,
            validators: Patch::diff(config, base.validators(), changed.validators())?,
            balances: Patch::diff(config, base.balances(), changed.balances())?,
            pending_deposits: Patch::diff(
                config,
                post_electra_base.pending_deposits(),
                post_electra_changed.pending_deposits(),
            )?,
            pending_partial_withdrawals: Patch::diff(
                config,
                post_electra_base.pending_partial_withdrawals(),
                post_electra_changed.pending_partial_withdrawals(),
            )?,
            pending_consolidations: Patch::diff(
                config,
                post_electra_base.pending_consolidations(),
                post_electra_changed.pending_consolidations(),
            )?,
        })
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct GloasDerivedFields {
    pub block_rewards: Option<ProposerRewards>,
    pub randao_mix: H256,
    pub total_active_balance: Gwei,
    pub validator_snapshot: Option<ValidatorSnapshot>,
    pub active_changes: ContiguousList<ValidatorIndex, Unlimited>,
    pub reward_inputs: EpochRewardInputs,
    pub inactivity_score_positions: PositionSet,
    pub inactivity_scores: ContiguousList<u64, Unlimited>,
    pub slots: ContiguousList<GloasSlotFields, Unlimited>,
}

impl GloasDerivedFields {
    fn new<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut Arc<BeaconState<P>>,
        block_rewards: Option<ProposerRewards>,
        blocks: &mut Blocks<P>,
        end: Slot,
    ) -> Result<Self> {
        let randao_mix =
            accessors::get_randao_mix(&**state, accessors::get_current_epoch(&**state));

        let total_active_balance = accessors::total_active_balance(&**state);

        let (validator_snapshot, active_changes) =
            validator_snapshot_and_active_changes(config, &**state)?;

        let (inactivity_score_positions, inactivity_scores) = eligible_inactivity_scores(&**state)?;

        let start = state.clone_arc();

        let slots = (state.slot().saturating_add(1)..end)
            .map(|slot| {
                let block = blocks.next_if(|block| block.message().slot() == slot);

                GloasSlotFields::new(config, pubkey_cache, state, block)
            })
            .collect::<Result<Vec<_>>>()?;

        let reward_inputs = EpochRewardInputs::new(&start, &**state)?;

        Ok(Self {
            block_rewards,
            randao_mix,
            total_active_balance,
            validator_snapshot,
            active_changes,
            reward_inputs,
            inactivity_score_positions,
            inactivity_scores,
            slots: slots.try_into()?,
        })
    }

    fn rewards(&self, count: usize) -> Option<ProposerRewards> {
        match count.checked_sub(1) {
            Some(index) => self.slots.get(index).map(|slot| slot.rewards),
            None => self.block_rewards,
        }
    }

    fn randao_mix(&self, count: usize) -> Option<H256> {
        match count.checked_sub(1) {
            Some(index) => self.slots.get(index).map(|slot| slot.randao_mix),
            None => Some(self.randao_mix),
        }
    }

    fn slots(&self, count: usize) -> Option<&[GloasSlotFields]> {
        self.slots.as_ref().get(..count)
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct GloasSlotFields {
    pub randao_mix: H256,
    pub rewards: ProposerRewards,
    pub validators: ValidatorListPatch,
    pub balances: BalancesPatch,
    pub pending_deposits: QueuePatch<PendingDeposit>,
    pub pending_partial_withdrawals: QueuePatch<PendingPartialWithdrawal>,
    pub pending_consolidations: QueuePatch<PendingConsolidation>,
}

impl GloasSlotFields {
    fn new<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut Arc<BeaconState<P>>,
        block: Option<&StoredBlock<P>>,
    ) -> Result<Self> {
        let base = state.clone_arc();

        let rewards = block
            .map(|block| block_rewards(config, pubkey_cache, state.make_mut(), block))
            .transpose()?
            .unwrap_or_default();

        let changed = &**state;
        let randao_mix = accessors::get_randao_mix(changed, accessors::get_current_epoch(changed));
        let config = PatchConfig::default();

        let (Some(post_electra_base), Some(post_electra_changed)) =
            (base.post_electra(), changed.post_electra())
        else {
            return Err(Error::CrossPhaseDiff.into());
        };

        Ok(Self {
            randao_mix,
            rewards,
            validators: Patch::diff(config, base.validators(), changed.validators())?,
            balances: Patch::diff(config, base.balances(), changed.balances())?,
            pending_deposits: Patch::diff(
                config,
                post_electra_base.pending_deposits(),
                post_electra_changed.pending_deposits(),
            )?,
            pending_partial_withdrawals: Patch::diff(
                config,
                post_electra_base.pending_partial_withdrawals(),
                post_electra_changed.pending_partial_withdrawals(),
            )?,
            pending_consolidations: Patch::diff(
                config,
                post_electra_base.pending_consolidations(),
                post_electra_changed.pending_consolidations(),
            )?,
        })
    }
}

pub fn block_rewards<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut BeaconState<P>,
    block: &StoredBlock<P>,
) -> Result<ProposerRewards> {
    let rewards = match block {
        StoredBlock::Full(block) => {
            combined::trusted_state_transition_for_rewards(config, pubkey_cache, state, block)?
        }
        StoredBlock::Blinded(block) => combined::trusted_blinded_state_transition_for_rewards(
            config,
            pubkey_cache,
            state,
            block,
        )?,
    };

    Ok(rewards.into())
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct EpochRewardInputs {
    pub source_balance: Gwei,
    pub target_balance: Gwei,
    pub head_balance: Gwei,
    pub late_participation: ParticipationPatch,
    pub eligibility_edits: ContiguousList<ValidatorIndex, Unlimited>,
}

impl EpochRewardInputs {
    fn new<P: Preset>(start: &BeaconState<P>, last: &BeaconState<P>) -> Result<Self> {
        let (Statistics::Altair(statistics), Some(post_altair_start), Some(post_altair_last)) = (
            combined::statistics(last)?,
            start.post_altair(),
            last.post_altair(),
        ) else {
            return Err(Error::CrossPhaseDiff.into());
        };

        let current_epoch = accessors::get_current_epoch(last);
        let previous_epoch = accessors::get_previous_epoch(last);
        let mut eligibility_edits = vec![];

        for (index, validator) in (0..).zip(last.validators().partial_validators()) {
            if predicates::is_eligible_for_penalties(validator, previous_epoch)?
                != predicates::is_active_validator(validator, current_epoch)
            {
                eligibility_edits.push(index);
            }
        }

        Ok(Self {
            source_balance: statistics.previous_epoch_source_participating_balance,
            target_balance: statistics.previous_epoch_target_participating_balance,
            head_balance: statistics.previous_epoch_head_participating_balance,
            late_participation: Patch::diff(
                PatchConfig::default(),
                post_altair_start.previous_epoch_participation(),
                post_altair_last.previous_epoch_participation(),
            )?,
            eligibility_edits: eligibility_edits.try_into()?,
        })
    }
}

fn eligible_inactivity_scores<P: Preset>(
    state: &BeaconState<P>,
) -> Result<(PositionSet, ContiguousList<u64, Unlimited>)> {
    let Some(post_altair) = state.post_altair() else {
        return Err(Error::CrossPhaseDiff.into());
    };

    let rewarded_epoch = accessors::get_current_epoch(state).saturating_sub(2);
    let mut positions = PositionSet::builder(state.validators().len_usize());
    let mut scores = vec![];

    for (index, validator, score) in izip!(
        0..,
        state.validators().partial_validators(),
        post_altair.inactivity_scores().into_iter().copied(),
    ) {
        if score != 0 && predicates::is_eligible_for_penalties(validator, rewarded_epoch)? {
            positions.record(index);
            scores.push(score);
        }
    }

    Ok((positions.finish(), scores.try_into()?))
}

pub struct AttestationRewardColumns {
    pub scalars: EpochRewardScalars,
    pub participation: Vec<ParticipationFlags>,
    pub inactivity_scores: Vec<u64>,
    pub eligibility_edits: ContiguousList<ValidatorIndex, Unlimited>,
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct ValidatorSnapshot {
    pub active: BitList<Unlimited>,
    pub slashed: BitList<Unlimited>,
    pub effective_balances: ContiguousList<Gwei, Unlimited>,
}

impl ValidatorSnapshot {
    #[must_use]
    pub fn epoch(config: &Config, epoch: Epoch) -> Epoch {
        let fork_epoch = config.fork_epoch(config.phase_at_epoch(epoch));
        let epoch_in_fork = epoch.saturating_sub(fork_epoch);

        epoch.saturating_sub(epoch_in_fork % 32)
    }
}

fn validator_snapshot_and_active_changes<P: Preset>(
    config: &Config,
    state: &BeaconState<P>,
) -> Result<(
    Option<ValidatorSnapshot>,
    ContiguousList<ValidatorIndex, Unlimited>,
)> {
    let epoch = accessors::get_current_epoch(state);
    let snapshot_epoch = ValidatorSnapshot::epoch(config, epoch);
    let (_, effective_balances, validators) = state.validators().columns();

    if epoch == snapshot_epoch {
        let mut active = BitList::with_length(validators.len());
        let mut slashed = BitList::with_length(validators.len());

        for (index, validator) in validators.iter().enumerate() {
            active.set(index, predicates::is_active_validator(validator, epoch));
            slashed.set(index, validator.slashed);
        }

        let effective_balances = effective_balances.iter().copied().collect::<Vec<_>>();

        let snapshot = ValidatorSnapshot {
            active,
            slashed,
            effective_balances: effective_balances.try_into()?,
        };

        return Ok((Some(snapshot), ContiguousList::default()));
    }

    let active_changes = (0..)
        .zip(validators.iter())
        .filter(|(_, validator)| {
            predicates::is_active_validator(validator, snapshot_epoch)
                != predicates::is_active_validator(validator, epoch)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();

    Ok((None, active_changes.try_into()?))
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidatorRecords {
    pub effective_balances: Vec<Gwei>,
    pub active: BitVec<u8>,
    pub slashed: BitVec<u8>,
}

#[derive(Clone, Copy, Default, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct ProposerRewards {
    pub attestations: Gwei,
    pub sync_aggregate: Gwei,
    pub proposer_slashings: Gwei,
    pub attester_slashings: Gwei,
}

impl From<ProposerRewards> for BlockRewards {
    fn from(rewards: ProposerRewards) -> Self {
        let ProposerRewards {
            attestations,
            sync_aggregate,
            proposer_slashings,
            attester_slashings,
        } = rewards;

        Self {
            total: attestations
                .saturating_add(sync_aggregate)
                .saturating_add(proposer_slashings)
                .saturating_add(attester_slashings),
            attestations,
            sync_aggregate,
            proposer_slashings,
            attester_slashings,
        }
    }
}

impl From<BlockRewards> for ProposerRewards {
    fn from(rewards: BlockRewards) -> Self {
        let BlockRewards {
            attestations,
            sync_aggregate,
            proposer_slashings,
            attester_slashings,
            ..
        } = rewards;

        Self {
            attestations,
            sync_aggregate,
            proposer_slashings,
            attester_slashings,
        }
    }
}
