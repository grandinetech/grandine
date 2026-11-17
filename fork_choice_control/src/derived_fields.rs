use core::{iter::Peekable, slice::Iter};
use std::sync::Arc;

use anyhow::Result;
use diff::{Error, Patch, PatchConfig, QueuePatch, Unlimited};
use helper_functions::accessors;
use pubkey_cache::PubkeyCache;
use ssz::{ContiguousList, ReadError, Size, Ssz, SszRead, SszSize, SszWrite, WriteError};
use std_ext::ArcExt as _;
use transition_functions::combined;
use types::{
    combined::BeaconState,
    config::Config,
    electra::containers::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
    nonstandard::{BlockRewards, Phase},
    phase0::{
        balances_patch::BalancesPatch,
        primitives::{Gwei, H256, Slot},
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
    Altair(Phase0DerivedFields),
    Bellatrix(Phase0DerivedFields),
    Capella(Phase0DerivedFields),
    Deneb(Phase0DerivedFields),
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
            Phase::Altair => Self::Altair(Phase0DerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
            Phase::Bellatrix => Self::Bellatrix(Phase0DerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
            Phase::Capella => Self::Capella(Phase0DerivedFields::new(
                config,
                pubkey_cache,
                state,
                block_rewards,
                blocks,
                end,
            )?),
            Phase::Deneb => Self::Deneb(Phase0DerivedFields::new(
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
            Self::Phase0(fields)
            | Self::Altair(fields)
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
            Self::Phase0(fields)
            | Self::Altair(fields)
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
            Self::Phase0(fields)
            | Self::Altair(fields)
            | Self::Bellatrix(fields)
            | Self::Capella(fields)
            | Self::Deneb(fields) => fields.total_active_balance,
            Self::Electra(fields) | Self::Fulu(fields) => fields.total_active_balance,
            Self::Gloas(fields) => fields.total_active_balance,
        }
    }

    #[must_use]
    pub fn validator_patches(&self, count: usize) -> Option<Vec<ValidatorListPatch>> {
        match self {
            Self::Phase0(fields)
            | Self::Altair(fields)
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
            Self::Phase0(fields)
            | Self::Altair(fields)
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
pub struct ElectraDerivedFields {
    pub block_rewards: Option<ProposerRewards>,
    pub randao_mix: H256,
    pub total_active_balance: Gwei,
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

        let slots = (state.slot().saturating_add(1)..end)
            .map(|slot| {
                let block = blocks.next_if(|block| block.message().slot() == slot);

                ElectraSlotFields::new(config, pubkey_cache, state, block)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            block_rewards,
            randao_mix,
            total_active_balance,
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

        let slots = (state.slot().saturating_add(1)..end)
            .map(|slot| {
                let block = blocks.next_if(|block| block.message().slot() == slot);

                GloasSlotFields::new(config, pubkey_cache, state, block)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            block_rewards,
            randao_mix,
            total_active_balance,
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
