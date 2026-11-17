use std::sync::Arc;

use diff::{Error as PatchError, Patch, PatchConfig, QueuePatch, ReplacePatch, VectorPatch};
use enum_iterator::Sequence as _;
use ssz::{
    Compressed, Hc, ReadError, Size, Ssz, SszCursor, SszListMut, SszRead, SszSize, SszWrite,
    WriteError,
};

use crate::{
    altair::containers::SyncCommittee,
    altair::storage::{
        BeaconStateFrame as AltairBeaconStateFrame,
        BeaconStateFrameCursor as AltairBeaconStateFrameCursor,
        BeaconStatePatch as AltairBeaconStatePatch,
        BeaconStatePatchCursor as AltairBeaconStatePatchCursor,
    },
    bellatrix::storage::{
        BeaconStateFrame as BellatrixBeaconStateFrame,
        BeaconStateFrameCursor as BellatrixBeaconStateFrameCursor,
        BeaconStatePatch as BellatrixBeaconStatePatch,
        BeaconStatePatchCursor as BellatrixBeaconStatePatchCursor,
    },
    cache::Cache,
    capella::storage::{
        BeaconStateFrame as CapellaBeaconStateFrame,
        BeaconStateFrameCursor as CapellaBeaconStateFrameCursor,
        BeaconStatePatch as CapellaBeaconStatePatch,
        BeaconStatePatchCursor as CapellaBeaconStatePatchCursor,
    },
    collections::{ProposerLookahead, RandaoMixes},
    combined::BeaconState,
    config::Config,
    deneb::storage::{
        BeaconStateFrame as DenebBeaconStateFrame,
        BeaconStateFrameCursor as DenebBeaconStateFrameCursor,
        BeaconStatePatch as DenebBeaconStatePatch,
        BeaconStatePatchCursor as DenebBeaconStatePatchCursor,
    },
    electra::containers::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
    electra::storage::{
        BeaconStateFrame as ElectraBeaconStateFrame,
        BeaconStateFrameCursor as ElectraBeaconStateFrameCursor,
        BeaconStatePatch as ElectraBeaconStatePatch,
        BeaconStatePatchCursor as ElectraBeaconStatePatchCursor,
    },
    fulu::storage::{
        BeaconStateFrame as FuluBeaconStateFrame,
        BeaconStateFrameCursor as FuluBeaconStateFrameCursor,
        BeaconStatePatch as FuluBeaconStatePatch,
        BeaconStatePatchCursor as FuluBeaconStatePatchCursor,
    },
    gloas::storage::{
        BeaconStateFrame as GloasBeaconStateFrame,
        BeaconStateFrameCursor as GloasBeaconStateFrameCursor,
        BeaconStatePatch as GloasBeaconStatePatch,
        BeaconStatePatchCursor as GloasBeaconStatePatchCursor,
    },
    nonstandard::{EffectiveBalanceList, PartialValidatorList, Phase, PubkeyList},
    phase0::storage::{
        BeaconStateFrame as Phase0BeaconStateFrame,
        BeaconStateFrameCursor as Phase0BeaconStateFrameCursor,
        BeaconStatePatch as Phase0BeaconStatePatch,
        BeaconStatePatchCursor as Phase0BeaconStatePatchCursor,
    },
    phase0::{
        balances_patch::BalancesPatch,
        containers::Checkpoint,
        primitives::{Gwei, H256, ValidatorIndex},
        validator_list_patch::ValidatorListPatch,
    },
    preset::Preset,
    traits::BeaconState as BeaconStateTrait,
};

pub enum BeaconStateFrame<P: Preset> {
    Phase0(Phase0BeaconStateFrame<P>),
    Altair(AltairBeaconStateFrame<P>),
    Bellatrix(BellatrixBeaconStateFrame<P>),
    Capella(CapellaBeaconStateFrame<P>),
    Deneb(DenebBeaconStateFrame<P>),
    Electra(ElectraBeaconStateFrame<P>),
    Fulu(FuluBeaconStateFrame<P>),
    Gloas(GloasBeaconStateFrame<P>),
}

impl<P: Preset> BeaconStateFrame<P> {
    /// The first `finalized_validators` validators are stored without their public keys, which
    /// [`Self::into_state`] takes from the finalized registry.
    #[must_use]
    pub fn new(state: &BeaconState<P>, finalized_validators: usize, level: i32) -> Self {
        match state {
            BeaconState::Phase0(state) => Self::Phase0(Phase0BeaconStateFrame::new(
                state,
                finalized_validators,
                level,
            )),
            BeaconState::Altair(state) => Self::Altair(AltairBeaconStateFrame::new(
                state,
                finalized_validators,
                level,
            )),
            BeaconState::Bellatrix(state) => Self::Bellatrix(BellatrixBeaconStateFrame::new(
                state,
                finalized_validators,
                level,
            )),
            BeaconState::Capella(state) => Self::Capella(CapellaBeaconStateFrame::new(
                state,
                finalized_validators,
                level,
            )),
            BeaconState::Deneb(state) => Self::Deneb(DenebBeaconStateFrame::new(
                state,
                finalized_validators,
                level,
            )),
            BeaconState::Electra(state) => Self::Electra(ElectraBeaconStateFrame::new(
                state,
                finalized_validators,
                level,
            )),
            BeaconState::Fulu(state) => Self::Fulu(FuluBeaconStateFrame::new(
                state,
                finalized_validators,
                level,
            )),
            BeaconState::Gloas(state) => Self::Gloas(GloasBeaconStateFrame::new(
                state,
                finalized_validators,
                level,
            )),
        }
    }

    pub fn into_state(self, finalized_pubkeys: &PubkeyList) -> Result<BeaconState<P>, ReadError> {
        let state: BeaconState<P> = match self {
            Self::Phase0(frame) => frame.into_state(finalized_pubkeys)?.into(),
            Self::Altair(frame) => frame.into_state(finalized_pubkeys)?.into(),
            Self::Bellatrix(frame) => frame.into_state(finalized_pubkeys)?.into(),
            Self::Capella(frame) => frame.into_state(finalized_pubkeys)?.into(),
            Self::Deneb(frame) => frame.into_state(finalized_pubkeys)?.into(),
            Self::Electra(frame) => frame.into_state(finalized_pubkeys)?.into(),
            Self::Fulu(frame) => frame.into_state(finalized_pubkeys)?.into(),
            Self::Gloas(frame) => frame.into_state(finalized_pubkeys)?.into(),
        };

        Ok(state)
    }
}

impl<P: Preset> SszSize for BeaconStateFrame<P> {
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY }>([
        Phase0BeaconStateFrame::<P>::SIZE,
        AltairBeaconStateFrame::<P>::SIZE,
        BellatrixBeaconStateFrame::<P>::SIZE,
        CapellaBeaconStateFrame::<P>::SIZE,
        DenebBeaconStateFrame::<P>::SIZE,
        ElectraBeaconStateFrame::<P>::SIZE,
        FuluBeaconStateFrame::<P>::SIZE,
        GloasBeaconStateFrame::<P>::SIZE,
    ]);
}

impl<P: Preset> SszRead<Config> for BeaconStateFrame<P> {
    fn from_ssz_unchecked(config: &Config, bytes: &[u8]) -> Result<Self, ReadError> {
        let slot = BeaconState::<P>::slot_from_ssz(bytes)?;
        let phase = config.phase_at_slot::<P>(slot);

        let frame = match phase {
            Phase::Phase0 => Self::Phase0(SszRead::from_ssz(config, bytes)?),
            Phase::Altair => Self::Altair(SszRead::from_ssz(config, bytes)?),
            Phase::Bellatrix => Self::Bellatrix(SszRead::from_ssz(config, bytes)?),
            Phase::Capella => Self::Capella(SszRead::from_ssz(config, bytes)?),
            Phase::Deneb => Self::Deneb(SszRead::from_ssz(config, bytes)?),
            Phase::Electra => Self::Electra(SszRead::from_ssz(config, bytes)?),
            Phase::Fulu => Self::Fulu(SszRead::from_ssz(config, bytes)?),
            Phase::Gloas => Self::Gloas(SszRead::from_ssz(config, bytes)?),
        };

        Ok(frame)
    }
}

impl<P: Preset> SszWrite for BeaconStateFrame<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Phase0(frame) => frame.write_variable(bytes),
            Self::Altair(frame) => frame.write_variable(bytes),
            Self::Bellatrix(frame) => frame.write_variable(bytes),
            Self::Capella(frame) => frame.write_variable(bytes),
            Self::Deneb(frame) => frame.write_variable(bytes),
            Self::Electra(frame) => frame.write_variable(bytes),
            Self::Fulu(frame) => frame.write_variable(bytes),
            Self::Gloas(frame) => frame.write_variable(bytes),
        }
    }
}

pub enum BeaconStateFrameCursor<'cursor, P: Preset> {
    Phase0(Phase0BeaconStateFrameCursor<'cursor, P>),
    Altair(AltairBeaconStateFrameCursor<'cursor, P>),
    Bellatrix(BellatrixBeaconStateFrameCursor<'cursor, P>),
    Capella(CapellaBeaconStateFrameCursor<'cursor, P>),
    Deneb(DenebBeaconStateFrameCursor<'cursor, P>),
    Electra(ElectraBeaconStateFrameCursor<'cursor, P>),
    Fulu(FuluBeaconStateFrameCursor<'cursor, P>),
    Gloas(GloasBeaconStateFrameCursor<'cursor, P>),
}

impl<'cursor, P: Preset> BeaconStateFrameCursor<'cursor, P> {
    pub fn new(config: &Config, bytes: &'cursor [u8]) -> Result<Self, ReadError> {
        let slot = BeaconState::<P>::slot_from_ssz(bytes)?;

        let cursor = match config.phase_at_slot::<P>(slot) {
            Phase::Phase0 => Self::Phase0(Phase0BeaconStateFrame::cursor(bytes)),
            Phase::Altair => Self::Altair(AltairBeaconStateFrame::cursor(bytes)),
            Phase::Bellatrix => Self::Bellatrix(BellatrixBeaconStateFrame::cursor(bytes)),
            Phase::Capella => Self::Capella(CapellaBeaconStateFrame::cursor(bytes)),
            Phase::Deneb => Self::Deneb(DenebBeaconStateFrame::cursor(bytes)),
            Phase::Electra => Self::Electra(ElectraBeaconStateFrame::cursor(bytes)),
            Phase::Fulu => Self::Fulu(FuluBeaconStateFrame::cursor(bytes)),
            Phase::Gloas => Self::Gloas(GloasBeaconStateFrame::cursor(bytes)),
        };

        Ok(cursor)
    }

    pub fn previous_justified_checkpoint(&self) -> Result<Checkpoint, ReadError> {
        let value = match self {
            Self::Phase0(frame) => frame.get_previous_justified_checkpoint()?.read(&())?,
            Self::Altair(frame) => frame.get_previous_justified_checkpoint()?.read(&())?,
            Self::Bellatrix(frame) => frame.get_previous_justified_checkpoint()?.read(&())?,
            Self::Capella(frame) => frame.get_previous_justified_checkpoint()?.read(&())?,
            Self::Deneb(frame) => frame.get_previous_justified_checkpoint()?.read(&())?,
            Self::Electra(frame) => frame.get_previous_justified_checkpoint()?.read(&())?,
            Self::Fulu(frame) => frame.get_previous_justified_checkpoint()?.read(&())?,
            Self::Gloas(frame) => frame.get_previous_justified_checkpoint()?.read(&())?,
        };

        Ok(value)
    }

    pub fn current_justified_checkpoint(&self) -> Result<Checkpoint, ReadError> {
        let value = match self {
            Self::Phase0(frame) => frame.get_current_justified_checkpoint()?.read(&())?,
            Self::Altair(frame) => frame.get_current_justified_checkpoint()?.read(&())?,
            Self::Bellatrix(frame) => frame.get_current_justified_checkpoint()?.read(&())?,
            Self::Capella(frame) => frame.get_current_justified_checkpoint()?.read(&())?,
            Self::Deneb(frame) => frame.get_current_justified_checkpoint()?.read(&())?,
            Self::Electra(frame) => frame.get_current_justified_checkpoint()?.read(&())?,
            Self::Fulu(frame) => frame.get_current_justified_checkpoint()?.read(&())?,
            Self::Gloas(frame) => frame.get_current_justified_checkpoint()?.read(&())?,
        };

        Ok(value)
    }

    pub fn finalized_checkpoint(&self) -> Result<Checkpoint, ReadError> {
        let value = match self {
            Self::Phase0(frame) => frame.get_finalized_checkpoint()?.read(&())?,
            Self::Altair(frame) => frame.get_finalized_checkpoint()?.read(&())?,
            Self::Bellatrix(frame) => frame.get_finalized_checkpoint()?.read(&())?,
            Self::Capella(frame) => frame.get_finalized_checkpoint()?.read(&())?,
            Self::Deneb(frame) => frame.get_finalized_checkpoint()?.read(&())?,
            Self::Electra(frame) => frame.get_finalized_checkpoint()?.read(&())?,
            Self::Fulu(frame) => frame.get_finalized_checkpoint()?.read(&())?,
            Self::Gloas(frame) => frame.get_finalized_checkpoint()?.read(&())?,
        };

        Ok(value)
    }

    pub fn current_sync_committee(&self) -> Result<Option<Arc<Hc<SyncCommittee<P>>>>, ReadError> {
        let value = match self {
            Self::Phase0(_) => return Ok(None),
            Self::Altair(frame) => {
                Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?))
            }
            Self::Bellatrix(frame) => {
                Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?))
            }
            Self::Capella(frame) => {
                Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?))
            }
            Self::Deneb(frame) => {
                Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?))
            }
            Self::Electra(frame) => {
                Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?))
            }
            Self::Fulu(frame) => Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?)),
            Self::Gloas(frame) => {
                Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?))
            }
        };

        Ok(Some(value))
    }

    pub fn next_sync_committee(&self) -> Result<Option<Arc<Hc<SyncCommittee<P>>>>, ReadError> {
        let value = match self {
            Self::Phase0(_) => return Ok(None),
            Self::Altair(frame) => Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            Self::Bellatrix(frame) => {
                Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?))
            }
            Self::Capella(frame) => Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            Self::Deneb(frame) => Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            Self::Electra(frame) => Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            Self::Fulu(frame) => Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            Self::Gloas(frame) => Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
        };

        Ok(Some(value))
    }

    pub fn proposer_lookahead(&self) -> Result<Option<ProposerLookahead<P>>, ReadError> {
        let value = match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_)
            | Self::Electra(_) => return Ok(None),
            Self::Fulu(frame) => frame.get_proposer_lookahead()?.into_inner(),
            Self::Gloas(frame) => frame.get_proposer_lookahead()?.into_inner(),
        };

        Ok(Some(value))
    }

    pub fn randao_mixes(&self) -> Result<RandaoMixes<P>, ReadError> {
        let value = match self {
            Self::Phase0(frame) => frame.get_randao_mixes()?,
            Self::Altair(frame) => frame.get_randao_mixes()?,
            Self::Bellatrix(frame) => frame.get_randao_mixes()?,
            Self::Capella(frame) => frame.get_randao_mixes()?,
            Self::Deneb(frame) => frame.get_randao_mixes()?,
            Self::Electra(frame) => frame.get_randao_mixes()?,
            Self::Fulu(frame) => frame.get_randao_mixes()?,
            Self::Gloas(frame) => frame.get_randao_mixes()?,
        };

        Ok(value)
    }

    pub fn partial_validators(&self) -> Result<PartialValidatorList, ReadError> {
        let value = match self {
            Self::Phase0(frame) => frame
                .get_validators()?
                .get_partial_validators()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Altair(frame) => frame
                .get_validators()?
                .get_partial_validators()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Bellatrix(frame) => frame
                .get_validators()?
                .get_partial_validators()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Capella(frame) => frame
                .get_validators()?
                .get_partial_validators()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Deneb(frame) => frame
                .get_validators()?
                .get_partial_validators()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Electra(frame) => frame
                .get_validators()?
                .get_partial_validators()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Fulu(frame) => frame
                .get_validators()?
                .get_partial_validators()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Gloas(frame) => frame
                .get_validators()?
                .get_partial_validators()?
                .into_inner()
                .into_iter()
                .collect(),
        };

        Ok(value)
    }

    pub fn effective_balances(&self) -> Result<EffectiveBalanceList, ReadError> {
        let value = match self {
            Self::Phase0(frame) => frame
                .get_validators()?
                .get_effective_balances()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Altair(frame) => frame
                .get_validators()?
                .get_effective_balances()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Bellatrix(frame) => frame
                .get_validators()?
                .get_effective_balances()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Capella(frame) => frame
                .get_validators()?
                .get_effective_balances()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Deneb(frame) => frame
                .get_validators()?
                .get_effective_balances()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Electra(frame) => frame
                .get_validators()?
                .get_effective_balances()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Fulu(frame) => frame
                .get_validators()?
                .get_effective_balances()?
                .into_inner()
                .into_iter()
                .collect(),
            Self::Gloas(frame) => frame
                .get_validators()?
                .get_effective_balances()?
                .into_inner()
                .into_iter()
                .collect(),
        };

        Ok(value)
    }

    pub fn balances(&self) -> Result<Box<dyn SszListMut<Gwei>>, ReadError> {
        let value: Box<dyn SszListMut<Gwei>> = match self {
            Self::Phase0(frame) => Box::new(frame.get_balances()?.into_inner()),
            Self::Altair(frame) => Box::new(frame.get_balances()?.into_inner()),
            Self::Bellatrix(frame) => Box::new(frame.get_balances()?.into_inner()),
            Self::Capella(frame) => Box::new(frame.get_balances()?.into_inner()),
            Self::Deneb(frame) => Box::new(frame.get_balances()?.into_inner()),
            Self::Electra(frame) => Box::new(frame.get_balances()?.into_inner()),
            Self::Fulu(frame) => Box::new(frame.get_balances()?.into_inner()),
            Self::Gloas(frame) => Box::new(frame.get_balances()?.into_inner()),
        };

        Ok(value)
    }

    pub fn pending_deposits(
        &self,
    ) -> Result<Option<Box<dyn SszListMut<PendingDeposit>>>, ReadError> {
        let value: Box<dyn SszListMut<PendingDeposit>> = match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => return Ok(None),
            Self::Electra(frame) => Box::new(frame.get_pending_deposits()?.into_inner()),
            Self::Fulu(frame) => Box::new(frame.get_pending_deposits()?.into_inner()),
            Self::Gloas(frame) => Box::new(frame.get_pending_deposits()?.into_inner()),
        };

        Ok(Some(value))
    }

    pub fn pending_partial_withdrawals(
        &self,
    ) -> Result<Option<Box<dyn SszListMut<PendingPartialWithdrawal>>>, ReadError> {
        let value: Box<dyn SszListMut<PendingPartialWithdrawal>> = match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => return Ok(None),
            Self::Electra(frame) => Box::new(frame.get_pending_partial_withdrawals()?.into_inner()),
            Self::Fulu(frame) => Box::new(frame.get_pending_partial_withdrawals()?.into_inner()),
            Self::Gloas(frame) => Box::new(frame.get_pending_partial_withdrawals()?.into_inner()),
        };

        Ok(Some(value))
    }

    pub fn pending_consolidations(
        &self,
    ) -> Result<Option<Box<dyn SszListMut<PendingConsolidation>>>, ReadError> {
        let value: Box<dyn SszListMut<PendingConsolidation>> = match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => return Ok(None),
            Self::Electra(frame) => Box::new(frame.get_pending_consolidations()?.into_inner()),
            Self::Fulu(frame) => Box::new(frame.get_pending_consolidations()?.into_inner()),
            Self::Gloas(frame) => Box::new(frame.get_pending_consolidations()?.into_inner()),
        };

        Ok(Some(value))
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false, transparent)]
pub struct BeaconStatePatch<P: Preset>(BeaconStatePatchInternal<P>);

impl<P: Preset> Patch<Arc<BeaconState<P>>> for BeaconStatePatch<P> {
    fn diff(
        config: PatchConfig,
        base: &Arc<BeaconState<P>>,
        changed: &Arc<BeaconState<P>>,
    ) -> Result<Self, PatchError> {
        Patch::diff(config, base, changed)
            .map(BeaconStatePatchInternal::V1)
            .map(Self)
    }

    fn apply(self, base: &mut Arc<BeaconState<P>>) -> Result<(), PatchError> {
        match self.0 {
            BeaconStatePatchInternal::V1(patch) => patch.apply(base),
        }
    }
}

#[derive(Clone, Debug)]
enum BeaconStatePatchInternal<P: Preset> {
    V1(BeaconStatePatchV1<P>),
}

impl<P: Preset> SszSize for BeaconStatePatchInternal<P> {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl<P: Preset> SszWrite for BeaconStatePatchInternal<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::V1(patch) => {
                bytes.push(1);
                patch.write_variable(bytes)
            }
        }
    }
}

impl<P: Preset, C> SszRead<C> for BeaconStatePatchInternal<P> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let (selector, payload) = bytes.split_first().ok_or(ReadError::Custom {
            message: "beacon state patch is empty",
        })?;

        match *selector {
            1 => SszRead::from_ssz(context, payload).map(Self::V1),
            _ => Err(ReadError::Custom {
                message: "unsupported beacon state patch version",
            }),
        }
    }
}

#[derive(Clone, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "patches are short-lived objects, built and consumed one at a time, so the enum \
              variant difference gap is not worth an allocation"
)]
enum BeaconStatePatchV1<P: Preset> {
    Phase0(Phase0BeaconStatePatch<P>),
    Altair(AltairBeaconStatePatch<P>),
    Bellatrix(BellatrixBeaconStatePatch<P>),
    Capella(CapellaBeaconStatePatch<P>),
    Deneb(DenebBeaconStatePatch<P>),
    Electra(ElectraBeaconStatePatch<P>),
    Fulu(FuluBeaconStatePatch<P>),
    Gloas(GloasBeaconStatePatch<P>),
}

impl<P: Preset> SszSize for BeaconStatePatchV1<P> {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl<P: Preset> SszWrite for BeaconStatePatchV1<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Phase0(patch) => {
                bytes.push(1);
                patch.write_variable(bytes)
            }
            Self::Altair(patch) => {
                bytes.push(2);
                patch.write_variable(bytes)
            }
            Self::Bellatrix(patch) => {
                bytes.push(3);
                patch.write_variable(bytes)
            }
            Self::Capella(patch) => {
                bytes.push(4);
                patch.write_variable(bytes)
            }
            Self::Deneb(patch) => {
                bytes.push(5);
                patch.write_variable(bytes)
            }
            Self::Electra(patch) => {
                bytes.push(6);
                patch.write_variable(bytes)
            }
            Self::Fulu(patch) => {
                bytes.push(7);
                patch.write_variable(bytes)
            }
            Self::Gloas(patch) => {
                bytes.push(8);
                patch.write_variable(bytes)
            }
        }
    }
}

impl<P: Preset, C> SszRead<C> for BeaconStatePatchV1<P> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let (selector, payload) = bytes.split_first().ok_or(ReadError::Custom {
            message: "beacon state patch is empty",
        })?;

        match *selector {
            1 => SszRead::from_ssz(context, payload).map(Self::Phase0),
            2 => SszRead::from_ssz(context, payload).map(Self::Altair),
            3 => SszRead::from_ssz(context, payload).map(Self::Bellatrix),
            4 => SszRead::from_ssz(context, payload).map(Self::Capella),
            5 => SszRead::from_ssz(context, payload).map(Self::Deneb),
            6 => SszRead::from_ssz(context, payload).map(Self::Electra),
            7 => SszRead::from_ssz(context, payload).map(Self::Fulu),
            8 => SszRead::from_ssz(context, payload).map(Self::Gloas),
            _ => Err(ReadError::Custom {
                message: "unsupported beacon state patch selector",
            }),
        }
    }
}

impl<P: Preset> Patch<Arc<BeaconState<P>>> for BeaconStatePatchV1<P> {
    fn diff(
        config: PatchConfig,
        base: &Arc<BeaconState<P>>,
        changed: &Arc<BeaconState<P>>,
    ) -> Result<Self, PatchError> {
        match (base.as_ref(), changed.as_ref()) {
            (BeaconState::Phase0(base), BeaconState::Phase0(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(Self::Phase0)
            }
            (BeaconState::Altair(base), BeaconState::Altair(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(Self::Altair)
            }
            (BeaconState::Bellatrix(base), BeaconState::Bellatrix(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(Self::Bellatrix)
            }
            (BeaconState::Capella(base), BeaconState::Capella(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(Self::Capella)
            }
            (BeaconState::Deneb(base), BeaconState::Deneb(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(Self::Deneb)
            }
            (BeaconState::Electra(base), BeaconState::Electra(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(Self::Electra)
            }
            (BeaconState::Fulu(base), BeaconState::Fulu(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(Self::Fulu)
            }
            (BeaconState::Gloas(base), BeaconState::Gloas(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(Self::Gloas)
            }
            (_, _) => Err(PatchError::CrossPhaseDiff),
        }
    }

    fn apply(self, base: &mut Arc<BeaconState<P>>) -> Result<(), PatchError> {
        match (self, Arc::make_mut(base)) {
            (Self::Phase0(patch), BeaconState::Phase0(base)) => patch.apply(reset_cache(base)),
            (Self::Altair(patch), BeaconState::Altair(base)) => patch.apply(reset_cache(base)),
            (Self::Bellatrix(patch), BeaconState::Bellatrix(base)) => {
                patch.apply(reset_cache(base))
            }
            (Self::Capella(patch), BeaconState::Capella(base)) => patch.apply(reset_cache(base)),
            (Self::Deneb(patch), BeaconState::Deneb(base)) => patch.apply(reset_cache(base)),
            (Self::Electra(patch), BeaconState::Electra(base)) => patch.apply(reset_cache(base)),
            (Self::Fulu(patch), BeaconState::Fulu(base)) => patch.apply(reset_cache(base)),
            (Self::Gloas(patch), BeaconState::Gloas(base)) => patch.apply(reset_cache(base)),
            // Nothing is being diffed here: a stored patch is being applied to a base of another
            // phase, which means the chain it was read from is inconsistent.
            (_, _) => Err(PatchError::PatchPhaseMismatch),
        }
    }
}

fn reset_cache<P: Preset, S: BeaconStateTrait<P>>(state: &mut Hc<S>) -> &mut S {
    let state = state.as_mut();

    *state.cache_mut() = Cache::default();

    state
}

pub enum BeaconStatePatchCursor<'cursor, P: Preset> {
    Phase0(Phase0BeaconStatePatchCursor<'cursor, P>),
    Altair(AltairBeaconStatePatchCursor<'cursor, P>),
    Bellatrix(BellatrixBeaconStatePatchCursor<'cursor, P>),
    Capella(CapellaBeaconStatePatchCursor<'cursor, P>),
    Deneb(DenebBeaconStatePatchCursor<'cursor, P>),
    Electra(ElectraBeaconStatePatchCursor<'cursor, P>),
    Fulu(FuluBeaconStatePatchCursor<'cursor, P>),
    Gloas(GloasBeaconStatePatchCursor<'cursor, P>),
}

impl<'cursor, P: Preset> BeaconStatePatchCursor<'cursor, P> {
    pub fn new(bytes: &'cursor [u8]) -> Result<Self, ReadError> {
        let (version, patch) = SszCursor::new(bytes).union()?;

        if version != 1 {
            return Err(ReadError::Custom {
                message: "unsupported beacon state patch version",
            });
        }

        let (selector, patch) = patch.union()?;

        match selector {
            1 => patch.try_into().map(Self::Phase0),
            2 => patch.try_into().map(Self::Altair),
            3 => patch.try_into().map(Self::Bellatrix),
            4 => patch.try_into().map(Self::Capella),
            5 => patch.try_into().map(Self::Deneb),
            6 => patch.try_into().map(Self::Electra),
            7 => patch.try_into().map(Self::Fulu),
            8 => patch.try_into().map(Self::Gloas),
            _ => Err(ReadError::Custom {
                message: "unsupported beacon state patch selector",
            }),
        }
    }

    pub fn previous_justified_checkpoint(&self) -> Result<ReplacePatch<Checkpoint>, ReadError> {
        let value = match self {
            Self::Phase0(patch) => patch.get_previous_justified_checkpoint()?,
            Self::Altair(patch) => patch.get_previous_justified_checkpoint()?,
            Self::Bellatrix(patch) => patch.get_previous_justified_checkpoint()?,
            Self::Capella(patch) => patch.get_previous_justified_checkpoint()?,
            Self::Deneb(patch) => patch.get_previous_justified_checkpoint()?,
            Self::Electra(patch) => patch.get_previous_justified_checkpoint()?,
            Self::Fulu(patch) => patch.get_previous_justified_checkpoint()?,
            Self::Gloas(patch) => patch.get_previous_justified_checkpoint()?,
        };

        Ok(value)
    }

    pub fn current_justified_checkpoint(&self) -> Result<ReplacePatch<Checkpoint>, ReadError> {
        let value = match self {
            Self::Phase0(patch) => patch.get_current_justified_checkpoint()?,
            Self::Altair(patch) => patch.get_current_justified_checkpoint()?,
            Self::Bellatrix(patch) => patch.get_current_justified_checkpoint()?,
            Self::Capella(patch) => patch.get_current_justified_checkpoint()?,
            Self::Deneb(patch) => patch.get_current_justified_checkpoint()?,
            Self::Electra(patch) => patch.get_current_justified_checkpoint()?,
            Self::Fulu(patch) => patch.get_current_justified_checkpoint()?,
            Self::Gloas(patch) => patch.get_current_justified_checkpoint()?,
        };

        Ok(value)
    }

    pub fn finalized_checkpoint(&self) -> Result<ReplacePatch<Checkpoint>, ReadError> {
        let value = match self {
            Self::Phase0(patch) => patch.get_finalized_checkpoint()?,
            Self::Altair(patch) => patch.get_finalized_checkpoint()?,
            Self::Bellatrix(patch) => patch.get_finalized_checkpoint()?,
            Self::Capella(patch) => patch.get_finalized_checkpoint()?,
            Self::Deneb(patch) => patch.get_finalized_checkpoint()?,
            Self::Electra(patch) => patch.get_finalized_checkpoint()?,
            Self::Fulu(patch) => patch.get_finalized_checkpoint()?,
            Self::Gloas(patch) => patch.get_finalized_checkpoint()?,
        };

        Ok(value)
    }

    #[expect(clippy::type_complexity)]
    pub fn current_sync_committee(
        &self,
    ) -> Result<Option<ReplacePatch<Arc<Hc<SyncCommittee<P>>>>>, ReadError> {
        let value = match self {
            Self::Phase0(_) => return Ok(None),
            Self::Altair(patch) => patch.get_current_sync_committee()?,
            Self::Bellatrix(patch) => patch.get_current_sync_committee()?,
            Self::Capella(patch) => patch.get_current_sync_committee()?,
            Self::Deneb(patch) => patch.get_current_sync_committee()?,
            Self::Electra(patch) => patch.get_current_sync_committee()?,
            Self::Fulu(patch) => patch.get_current_sync_committee()?,
            Self::Gloas(patch) => patch.get_current_sync_committee()?,
        };

        Ok(Some(value))
    }

    #[expect(clippy::type_complexity)]
    pub fn next_sync_committee(
        &self,
    ) -> Result<Option<ReplacePatch<Arc<Hc<SyncCommittee<P>>>>>, ReadError> {
        let value = match self {
            Self::Phase0(_) => return Ok(None),
            Self::Altair(patch) => patch.get_next_sync_committee()?,
            Self::Bellatrix(patch) => patch.get_next_sync_committee()?,
            Self::Capella(patch) => patch.get_next_sync_committee()?,
            Self::Deneb(patch) => patch.get_next_sync_committee()?,
            Self::Electra(patch) => patch.get_next_sync_committee()?,
            Self::Fulu(patch) => patch.get_next_sync_committee()?,
            Self::Gloas(patch) => patch.get_next_sync_committee()?,
        };

        Ok(Some(value))
    }

    pub fn proposer_lookahead(
        &self,
    ) -> Result<Option<Compressed<VectorPatch<ValidatorIndex>>>, ReadError> {
        let value = match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_)
            | Self::Electra(_) => return Ok(None),
            Self::Fulu(patch) => patch.get_proposer_lookahead()?,
            Self::Gloas(patch) => patch.get_proposer_lookahead()?,
        };

        Ok(Some(value))
    }

    pub fn randao_mixes(&self) -> Result<VectorPatch<H256>, ReadError> {
        let value = match self {
            Self::Phase0(patch) => patch.get_randao_mixes()?,
            Self::Altair(patch) => patch.get_randao_mixes()?,
            Self::Bellatrix(patch) => patch.get_randao_mixes()?,
            Self::Capella(patch) => patch.get_randao_mixes()?,
            Self::Deneb(patch) => patch.get_randao_mixes()?,
            Self::Electra(patch) => patch.get_randao_mixes()?,
            Self::Fulu(patch) => patch.get_randao_mixes()?,
            Self::Gloas(patch) => patch.get_randao_mixes()?,
        };

        Ok(value)
    }

    pub fn validators(&self) -> Result<Compressed<ValidatorListPatch>, ReadError> {
        let value = match self {
            Self::Phase0(patch) => patch.get_validators()?,
            Self::Altair(patch) => patch.get_validators()?,
            Self::Bellatrix(patch) => patch.get_validators()?,
            Self::Capella(patch) => patch.get_validators()?,
            Self::Deneb(patch) => patch.get_validators()?,
            Self::Electra(patch) => patch.get_validators()?,
            Self::Fulu(patch) => patch.get_validators()?,
            Self::Gloas(patch) => patch.get_validators()?,
        };

        Ok(value)
    }

    pub fn balances(&self) -> Result<Compressed<BalancesPatch>, ReadError> {
        let value = match self {
            Self::Phase0(patch) => patch.get_balances()?,
            Self::Altair(patch) => patch.get_balances()?,
            Self::Bellatrix(patch) => patch.get_balances()?,
            Self::Capella(patch) => patch.get_balances()?,
            Self::Deneb(patch) => patch.get_balances()?,
            Self::Electra(patch) => patch.get_balances()?,
            Self::Fulu(patch) => patch.get_balances()?,
            Self::Gloas(patch) => patch.get_balances()?,
        };

        Ok(value)
    }

    pub fn pending_deposits(
        &self,
    ) -> Result<Option<Compressed<QueuePatch<PendingDeposit>>>, ReadError> {
        let value = match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => return Ok(None),
            Self::Electra(patch) => patch.get_pending_deposits()?,
            Self::Fulu(patch) => patch.get_pending_deposits()?,
            Self::Gloas(patch) => patch.get_pending_deposits()?,
        };

        Ok(Some(value))
    }

    pub fn pending_partial_withdrawals(
        &self,
    ) -> Result<Option<Compressed<QueuePatch<PendingPartialWithdrawal>>>, ReadError> {
        let value = match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => return Ok(None),
            Self::Electra(patch) => patch.get_pending_partial_withdrawals()?,
            Self::Fulu(patch) => patch.get_pending_partial_withdrawals()?,
            Self::Gloas(patch) => patch.get_pending_partial_withdrawals()?,
        };

        Ok(Some(value))
    }

    pub fn pending_consolidations(
        &self,
    ) -> Result<Option<Compressed<QueuePatch<PendingConsolidation>>>, ReadError> {
        let value = match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => return Ok(None),
            Self::Electra(patch) => patch.get_pending_consolidations()?,
            Self::Fulu(patch) => patch.get_pending_consolidations()?,
            Self::Gloas(patch) => patch.get_pending_consolidations()?,
        };

        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use ssz::{H256, SszHash as _};
    use std_ext::ArcExt as _;

    use crate::{
        altair::beacon_state::BeaconState as AltairBeaconState,
        bellatrix::beacon_state::BeaconState as BellatrixBeaconState,
        capella::beacon_state::BeaconState as CapellaBeaconState,
        config::Config,
        deneb::beacon_state::BeaconState as DenebBeaconState,
        electra::beacon_state::BeaconState as ElectraBeaconState,
        fulu::beacon_state::BeaconState as FuluBeaconState,
        gloas::beacon_state::BeaconState as GloasBeaconState,
        phase0::{beacon_state::BeaconState as Phase0BeaconState, containers::Fork},
        preset::Minimal,
    };

    use super::*;

    type StatePair = (
        &'static str,
        Arc<BeaconState<Minimal>>,
        Arc<BeaconState<Minimal>>,
    );

    /// A pair of states of the same phase that differ in a field shared by every phase, plus a
    /// phase-specific one where the phase has any.
    fn state_pairs() -> Vec<StatePair> {
        let mut pairs = Vec::new();

        macro_rules! pair {
            ($name: literal, $variant: ident, $state: ty $(, $extra: expr)?) => {{
                let base = <$state>::default();
                let mut changed = base.clone();

                changed.slot = 42;
                changed.latest_block_header.body_root = H256::repeat_byte(2);

                $({
                    let extra: fn(&mut $state) = $extra;
                    extra(&mut changed);
                })?

                pairs.push((
                    $name,
                    Arc::new(BeaconState::$variant(base.into())),
                    Arc::new(BeaconState::$variant(changed.into())),
                ));
            }};
        }

        pair!("phase0", Phase0, Phase0BeaconState<Minimal>);
        pair!("altair", Altair, AltairBeaconState<Minimal>, |state| {
            state.inactivity_scores.push(7).expect("list is not full");
        });
        pair!(
            "bellatrix",
            Bellatrix,
            BellatrixBeaconState<Minimal>,
            |state| {
                state.latest_execution_payload_header.gas_limit = 7;
            }
        );
        pair!("capella", Capella, CapellaBeaconState<Minimal>, |state| {
            state.latest_execution_payload_header.gas_limit = 7;
            state.next_withdrawal_index = 3;
        });
        pair!("deneb", Deneb, DenebBeaconState<Minimal>, |state| {
            state.latest_execution_payload_header.blob_gas_used = 9;
        });
        pair!("electra", Electra, ElectraBeaconState<Minimal>, |state| {
            state.latest_execution_payload_header.blob_gas_used = 9;
            state.deposit_requests_start_index = 11;
        });
        pair!("fulu", Fulu, FuluBeaconState<Minimal>, |state| {
            state.latest_execution_payload_header.blob_gas_used = 9;
            state.deposit_requests_start_index = 11;
        });
        pair!("gloas", Gloas, GloasBeaconState<Minimal>, |state| {
            state.latest_block_hash = H256::repeat_byte(3);
            state.next_withdrawal_builder_index = 5;
        });

        pairs
    }

    #[test]
    fn every_phase_round_trips_through_the_public_patch() {
        for (name, base, changed) in state_pairs() {
            base.cache()
                .proposer_index
                .set(7)
                .expect("the base cache starts empty");

            let patch = BeaconStatePatch::diff(PatchConfig::default(), &base, &changed)
                .unwrap_or_else(|error| {
                    panic!("{name} patch should represent the change: {error}")
                });

            let encoded = patch
                .to_ssz()
                .unwrap_or_else(|error| panic!("{name} patch should serialize: {error}"));

            let patch = BeaconStatePatch::<Minimal>::from_ssz(&Config::minimal(), encoded)
                .unwrap_or_else(|error| panic!("{name} patch should deserialize: {error}"));

            let mut applied = base;

            patch
                .apply(&mut applied)
                .unwrap_or_else(|error| panic!("{name} patch should apply: {error}"));

            assert_eq!(applied, changed, "{name} state should round trip");
            assert_eq!(
                applied.hash_tree_root(),
                changed.hash_tree_root(),
                "{name} state root should round trip",
            );
            assert!(
                applied.cache().proposer_index.get().is_none(),
                "{name} cache should be reset",
            );
        }
    }

    #[test]
    fn a_change_to_a_versioning_field_is_rejected() {
        let base = Phase0BeaconState::<Minimal>::default();

        for changed in [
            Phase0BeaconState {
                genesis_validators_root: H256::repeat_byte(1),
                ..base.clone()
            },
            Phase0BeaconState {
                genesis_time: 1,
                ..base.clone()
            },
            Phase0BeaconState {
                fork: Fork {
                    epoch: 1,
                    ..Fork::default()
                },
                ..base.clone()
            },
        ] {
            let error = BeaconStatePatch::diff(
                PatchConfig::default(),
                &Arc::new(BeaconState::Phase0(base.clone().into())),
                &Arc::new(BeaconState::Phase0(changed.into())),
            )
            .expect_err("versioning fields are not part of the patch");

            assert!(matches!(error, PatchError::UnsupportedDiff));
        }
    }

    #[test]
    fn a_diff_across_phases_is_rejected() {
        let pairs = state_pairs();

        let phase0 = pairs[0].1.clone_arc();
        let altair = pairs[1].1.clone_arc();

        let error = BeaconStatePatch::diff(PatchConfig::default(), &phase0, &altair)
            .expect_err("states of different phases cannot be diffed");

        assert!(matches!(error, PatchError::CrossPhaseDiff));
    }

    #[test]
    fn a_patch_applied_to_another_phase_is_rejected() {
        let pairs = state_pairs();

        let (_, phase0_base, phase0_changed) = &pairs[0];

        let patch = BeaconStatePatch::diff(PatchConfig::default(), phase0_base, phase0_changed)
            .expect("patch should represent the change");

        let mut altair = pairs[1].1.clone_arc();

        let error = patch
            .apply(&mut altair)
            .expect_err("a phase0 patch cannot be applied to an altair state");

        assert!(matches!(error, PatchError::PatchPhaseMismatch));
    }

    #[test]
    fn selectors_are_the_ones_stored_deltas_already_use() {
        let selectors = state_pairs()
            .into_iter()
            .map(|(name, base, changed)| {
                let encoded = BeaconStatePatch::diff(PatchConfig::default(), &base, &changed)
                    .unwrap_or_else(|error| {
                        panic!("{name} patch should represent the change: {error}")
                    })
                    .to_ssz()
                    .unwrap_or_else(|error| panic!("{name} patch should serialize: {error}"));

                [encoded[0], encoded[1]]
            })
            .collect::<Vec<_>>();

        assert_eq!(
            selectors,
            [
                [1, 1],
                [1, 2],
                [1, 3],
                [1, 4],
                [1, 5],
                [1, 6],
                [1, 7],
                [1, 8],
            ],
        );
    }

    #[test]
    fn an_empty_patch_and_an_unknown_selector_are_rejected() {
        let config = Config::minimal();

        BeaconStatePatch::<Minimal>::from_ssz(&config, [])
            .expect_err("an empty patch has no version selector");

        BeaconStatePatch::<Minimal>::from_ssz(&config, [2])
            .expect_err("2 is not a known patch version");

        BeaconStatePatch::<Minimal>::from_ssz(&config, [1])
            .expect_err("a versioned patch with no phase selector is incomplete");

        BeaconStatePatch::<Minimal>::from_ssz(&config, [1, 0])
            .expect_err("0 is not a known phase selector");

        BeaconStatePatch::<Minimal>::from_ssz(&config, [1, 9])
            .expect_err("9 is not a known phase selector");
    }

    #[test]
    fn every_phase_frame_cursor_navigates_the_stored_frame() -> Result<()> {
        for (name, _, changed) in state_pairs() {
            let config = Config::minimal().start_and_stay_in(changed.phase());

            let encoded =
                BeaconStateFrame::new(&changed, 0, zstd::DEFAULT_COMPRESSION_LEVEL).to_ssz()?;

            let (phase, slot, body_root) =
                match BeaconStateFrameCursor::<Minimal>::new(&config, &encoded)? {
                    BeaconStateFrameCursor::Phase0(frame) => (
                        Phase::Phase0,
                        frame.get_slot()?,
                        frame.get_latest_block_header()?.get_body_root()?,
                    ),
                    BeaconStateFrameCursor::Altair(frame) => (
                        Phase::Altair,
                        frame.get_slot()?,
                        frame.get_latest_block_header()?.get_body_root()?,
                    ),
                    BeaconStateFrameCursor::Bellatrix(frame) => (
                        Phase::Bellatrix,
                        frame.get_slot()?,
                        frame.get_latest_block_header()?.get_body_root()?,
                    ),
                    BeaconStateFrameCursor::Capella(frame) => (
                        Phase::Capella,
                        frame.get_slot()?,
                        frame.get_latest_block_header()?.get_body_root()?,
                    ),
                    BeaconStateFrameCursor::Deneb(frame) => (
                        Phase::Deneb,
                        frame.get_slot()?,
                        frame.get_latest_block_header()?.get_body_root()?,
                    ),
                    BeaconStateFrameCursor::Electra(frame) => (
                        Phase::Electra,
                        frame.get_slot()?,
                        frame.get_latest_block_header()?.get_body_root()?,
                    ),
                    BeaconStateFrameCursor::Fulu(frame) => (
                        Phase::Fulu,
                        frame.get_slot()?,
                        frame.get_latest_block_header()?.get_body_root()?,
                    ),
                    BeaconStateFrameCursor::Gloas(frame) => (
                        Phase::Gloas,
                        frame.get_slot()?,
                        frame.get_latest_block_header()?.get_body_root()?,
                    ),
                };

            assert_eq!(
                phase,
                changed.phase(),
                "{name} frame should be read as its phase"
            );
            assert_eq!(slot, 42, "{name} slot should be navigated to");
            assert_eq!(
                body_root,
                H256::repeat_byte(2),
                "{name} nested field should be navigated to",
            );
        }

        Ok(())
    }

    #[test]
    fn every_phase_patch_cursor_navigates_the_stored_patch() -> Result<()> {
        for (name, base, changed) in state_pairs() {
            let encoded =
                BeaconStatePatch::diff(PatchConfig::default(), &base, &changed)?.to_ssz()?;

            let (phase, slot, header) = match BeaconStatePatchCursor::<Minimal>::new(&encoded)? {
                BeaconStatePatchCursor::Phase0(patch) => (
                    Phase::Phase0,
                    patch.get_slot()?.to_ssz()?,
                    patch.get_latest_block_header()?.to_ssz()?,
                ),
                BeaconStatePatchCursor::Altair(patch) => (
                    Phase::Altair,
                    patch.get_slot()?.to_ssz()?,
                    patch.get_latest_block_header()?.to_ssz()?,
                ),
                BeaconStatePatchCursor::Bellatrix(patch) => (
                    Phase::Bellatrix,
                    patch.get_slot()?.to_ssz()?,
                    patch.get_latest_block_header()?.to_ssz()?,
                ),
                BeaconStatePatchCursor::Capella(patch) => (
                    Phase::Capella,
                    patch.get_slot()?.to_ssz()?,
                    patch.get_latest_block_header()?.to_ssz()?,
                ),
                BeaconStatePatchCursor::Deneb(patch) => (
                    Phase::Deneb,
                    patch.get_slot()?.to_ssz()?,
                    patch.get_latest_block_header()?.to_ssz()?,
                ),
                BeaconStatePatchCursor::Electra(patch) => (
                    Phase::Electra,
                    patch.get_slot()?.to_ssz()?,
                    patch.get_latest_block_header()?.to_ssz()?,
                ),
                BeaconStatePatchCursor::Fulu(patch) => (
                    Phase::Fulu,
                    patch.get_slot()?.to_ssz()?,
                    patch.get_latest_block_header()?.to_ssz()?,
                ),
                BeaconStatePatchCursor::Gloas(patch) => (
                    Phase::Gloas,
                    patch.get_slot()?.to_ssz()?,
                    patch.get_latest_block_header()?.to_ssz()?,
                ),
            };

            assert_eq!(
                phase,
                changed.phase(),
                "{name} patch should be read as its phase"
            );
            assert_eq!(
                slot,
                Some(42_u64).to_ssz()?,
                "{name} slot should be navigated to",
            );
            assert_eq!(
                header,
                Some(changed.latest_block_header()).to_ssz()?,
                "{name} latest block header should be navigated to",
            );
        }

        Ok(())
    }

    #[test]
    fn a_patch_cursor_rejects_an_empty_patch_and_an_unknown_selector() {
        for bytes in [&[][..], &[2, 1], &[1], &[1, 0], &[1, 9]] {
            assert!(BeaconStatePatchCursor::<Minimal>::new(bytes).is_err());
        }
    }
}
