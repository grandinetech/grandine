use std::sync::Arc;

use anyhow::Result;
use diff::{Patch as _, ReplacePatch, VectorPatch};
use helper_functions::misc;
use ssz::{Compressed, Hc};
use std_ext::ArcExt as _;
use types::{
    ProposerLookahead, RandaoMixes,
    altair::containers::SyncCommittee,
    combined::BeaconState,
    nonstandard::{EffectiveBalanceList, PartialValidatorList},
    phase0::{
        containers::Checkpoint,
        primitives::{H256, Slot, ValidatorIndex},
        validator_list_patch::ValidatorListPatch,
    },
    preset::Preset,
    storage::{BeaconStateFrameCursor, BeaconStatePatchCursor},
    traits::BeaconState as _,
};

use crate::storage::{StateRow, StateRows};

pub trait StateField<P: Preset>: Sized {
    fn from_state(state: &BeaconState<P>) -> Self;

    fn reconstruct(slot: Slot, rows: StateRows<'_, P>) -> Result<Option<Self>>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FinalityCheckpoints {
    pub previous_justified: Checkpoint,
    pub current_justified: Checkpoint,
    pub finalized: Checkpoint,
}

impl<P: Preset> StateField<P> for FinalityCheckpoints {
    fn from_state(state: &BeaconState<P>) -> Self {
        Self {
            previous_justified: state.previous_justified_checkpoint(),
            current_justified: state.current_justified_checkpoint(),
            finalized: state.finalized_checkpoint(),
        }
    }

    fn reconstruct(slot: Slot, mut rows: StateRows<'_, P>) -> Result<Option<Self>> {
        if misc::compute_epoch_at_slot::<P>(rows.state_slot())
            != misc::compute_epoch_at_slot::<P>(slot)
        {
            return Ok(None);
        }

        let mut changed = [None; 3];

        while let Some(row) = rows.next()? {
            let base = match row {
                StateRow::Delta(patch) => {
                    for (checkpoint, changed_checkpoint) in
                        changed.iter_mut().zip(Self::changed_in(&patch)?)
                    {
                        if checkpoint.is_none() {
                            *checkpoint = changed_checkpoint;
                        }
                    }

                    if let [
                        Some(previous_justified),
                        Some(current_justified),
                        Some(finalized),
                    ] = changed
                    {
                        return Ok(Some(Self {
                            previous_justified,
                            current_justified,
                            finalized,
                        }));
                    }

                    continue;
                }
                StateRow::Frame(frame) => Self::from_frame(&frame)?,
                StateRow::State(state) => Self::from_state(&state),
            };

            let [previous_justified, current_justified, finalized] = changed;

            return Ok(Some(Self {
                previous_justified: previous_justified.unwrap_or(base.previous_justified),
                current_justified: current_justified.unwrap_or(base.current_justified),
                finalized: finalized.unwrap_or(base.finalized),
            }));
        }

        Ok(None)
    }
}

impl FinalityCheckpoints {
    fn from_frame<P: Preset>(frame: &BeaconStateFrameCursor<P>) -> Result<Self> {
        let checkpoints = match frame {
            BeaconStateFrameCursor::Phase0(frame) => Self {
                previous_justified: frame.get_previous_justified_checkpoint()?.read(&())?,
                current_justified: frame.get_current_justified_checkpoint()?.read(&())?,
                finalized: frame.get_finalized_checkpoint()?.read(&())?,
            },
            BeaconStateFrameCursor::Altair(frame) => Self {
                previous_justified: frame.get_previous_justified_checkpoint()?.read(&())?,
                current_justified: frame.get_current_justified_checkpoint()?.read(&())?,
                finalized: frame.get_finalized_checkpoint()?.read(&())?,
            },
            BeaconStateFrameCursor::Bellatrix(frame) => Self {
                previous_justified: frame.get_previous_justified_checkpoint()?.read(&())?,
                current_justified: frame.get_current_justified_checkpoint()?.read(&())?,
                finalized: frame.get_finalized_checkpoint()?.read(&())?,
            },
            BeaconStateFrameCursor::Capella(frame) => Self {
                previous_justified: frame.get_previous_justified_checkpoint()?.read(&())?,
                current_justified: frame.get_current_justified_checkpoint()?.read(&())?,
                finalized: frame.get_finalized_checkpoint()?.read(&())?,
            },
            BeaconStateFrameCursor::Deneb(frame) => Self {
                previous_justified: frame.get_previous_justified_checkpoint()?.read(&())?,
                current_justified: frame.get_current_justified_checkpoint()?.read(&())?,
                finalized: frame.get_finalized_checkpoint()?.read(&())?,
            },
            BeaconStateFrameCursor::Electra(frame) => Self {
                previous_justified: frame.get_previous_justified_checkpoint()?.read(&())?,
                current_justified: frame.get_current_justified_checkpoint()?.read(&())?,
                finalized: frame.get_finalized_checkpoint()?.read(&())?,
            },
            BeaconStateFrameCursor::Fulu(frame) => Self {
                previous_justified: frame.get_previous_justified_checkpoint()?.read(&())?,
                current_justified: frame.get_current_justified_checkpoint()?.read(&())?,
                finalized: frame.get_finalized_checkpoint()?.read(&())?,
            },
            BeaconStateFrameCursor::Gloas(frame) => Self {
                previous_justified: frame.get_previous_justified_checkpoint()?.read(&())?,
                current_justified: frame.get_current_justified_checkpoint()?.read(&())?,
                finalized: frame.get_finalized_checkpoint()?.read(&())?,
            },
        };

        Ok(checkpoints)
    }

    fn changed_in<P: Preset>(patch: &BeaconStatePatchCursor<P>) -> Result<[Option<Checkpoint>; 3]> {
        let patches = match patch {
            BeaconStatePatchCursor::Phase0(patch) => [
                patch.get_previous_justified_checkpoint()?,
                patch.get_current_justified_checkpoint()?,
                patch.get_finalized_checkpoint()?,
            ],
            BeaconStatePatchCursor::Altair(patch) => [
                patch.get_previous_justified_checkpoint()?,
                patch.get_current_justified_checkpoint()?,
                patch.get_finalized_checkpoint()?,
            ],
            BeaconStatePatchCursor::Bellatrix(patch) => [
                patch.get_previous_justified_checkpoint()?,
                patch.get_current_justified_checkpoint()?,
                patch.get_finalized_checkpoint()?,
            ],
            BeaconStatePatchCursor::Capella(patch) => [
                patch.get_previous_justified_checkpoint()?,
                patch.get_current_justified_checkpoint()?,
                patch.get_finalized_checkpoint()?,
            ],
            BeaconStatePatchCursor::Deneb(patch) => [
                patch.get_previous_justified_checkpoint()?,
                patch.get_current_justified_checkpoint()?,
                patch.get_finalized_checkpoint()?,
            ],
            BeaconStatePatchCursor::Electra(patch) => [
                patch.get_previous_justified_checkpoint()?,
                patch.get_current_justified_checkpoint()?,
                patch.get_finalized_checkpoint()?,
            ],
            BeaconStatePatchCursor::Fulu(patch) => [
                patch.get_previous_justified_checkpoint()?,
                patch.get_current_justified_checkpoint()?,
                patch.get_finalized_checkpoint()?,
            ],
            BeaconStatePatchCursor::Gloas(patch) => [
                patch.get_previous_justified_checkpoint()?,
                patch.get_current_justified_checkpoint()?,
                patch.get_finalized_checkpoint()?,
            ],
        };

        Ok(patches.map(ReplacePatch::into_changed))
    }
}

pub struct SyncCommittees<P: Preset> {
    pub current: Arc<Hc<SyncCommittee<P>>>,
    pub next: Arc<Hc<SyncCommittee<P>>>,
}

impl<P: Preset> StateField<P> for Option<SyncCommittees<P>> {
    fn from_state(state: &BeaconState<P>) -> Self {
        let post_altair = state.post_altair()?;

        Some(SyncCommittees {
            current: post_altair.current_sync_committee().clone_arc(),
            next: post_altair.next_sync_committee().clone_arc(),
        })
    }

    fn reconstruct(slot: Slot, mut rows: StateRows<'_, P>) -> Result<Option<Self>> {
        if misc::compute_epoch_at_slot::<P>(rows.state_slot())
            != misc::compute_epoch_at_slot::<P>(slot)
        {
            return Ok(None);
        }

        let mut changed = [None, None];

        while let Some(row) = rows.next()? {
            let base = match row {
                StateRow::Delta(patch) => {
                    for (committee, changed_committee) in
                        changed.iter_mut().zip(SyncCommittees::patches(&patch)?)
                    {
                        if committee.is_none() {
                            *committee = changed_committee;
                        }
                    }

                    if let [Some(current), Some(next)] = &changed {
                        return Ok(Some(Some(SyncCommittees {
                            current: current.clone_arc(),
                            next: next.clone_arc(),
                        })));
                    }

                    continue;
                }
                StateRow::Frame(frame) => SyncCommittees::from_frame(&frame)?,
                StateRow::State(state) => Self::from_state(&state),
            };

            let Some(base) = base else {
                return Ok(Some(None));
            };

            let [current, next] = changed;

            return Ok(Some(Some(SyncCommittees {
                current: current.unwrap_or(base.current),
                next: next.unwrap_or(base.next),
            })));
        }

        Ok(None)
    }
}

impl<P: Preset> SyncCommittees<P> {
    fn from_frame(frame: &BeaconStateFrameCursor<P>) -> Result<Option<Self>> {
        let committees = match frame {
            BeaconStateFrameCursor::Phase0(_) => return Ok(None),
            BeaconStateFrameCursor::Altair(frame) => Self {
                current: Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?)),
                next: Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            },
            BeaconStateFrameCursor::Bellatrix(frame) => Self {
                current: Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?)),
                next: Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            },
            BeaconStateFrameCursor::Capella(frame) => Self {
                current: Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?)),
                next: Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            },
            BeaconStateFrameCursor::Deneb(frame) => Self {
                current: Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?)),
                next: Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            },
            BeaconStateFrameCursor::Electra(frame) => Self {
                current: Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?)),
                next: Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            },
            BeaconStateFrameCursor::Fulu(frame) => Self {
                current: Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?)),
                next: Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            },
            BeaconStateFrameCursor::Gloas(frame) => Self {
                current: Arc::new(Hc::from(frame.get_current_sync_committee()?.read(&())?)),
                next: Arc::new(Hc::from(frame.get_next_sync_committee()?.read(&())?)),
            },
        };

        Ok(Some(committees))
    }

    #[expect(clippy::type_complexity)]
    fn patches(
        patch: &BeaconStatePatchCursor<P>,
    ) -> Result<[Option<Arc<Hc<SyncCommittee<P>>>>; 2]> {
        let patches = match patch {
            BeaconStatePatchCursor::Phase0(_) => return Ok([None, None]),
            BeaconStatePatchCursor::Altair(patch) => [
                patch.get_current_sync_committee()?,
                patch.get_next_sync_committee()?,
            ],
            BeaconStatePatchCursor::Bellatrix(patch) => [
                patch.get_current_sync_committee()?,
                patch.get_next_sync_committee()?,
            ],
            BeaconStatePatchCursor::Capella(patch) => [
                patch.get_current_sync_committee()?,
                patch.get_next_sync_committee()?,
            ],
            BeaconStatePatchCursor::Deneb(patch) => [
                patch.get_current_sync_committee()?,
                patch.get_next_sync_committee()?,
            ],
            BeaconStatePatchCursor::Electra(patch) => [
                patch.get_current_sync_committee()?,
                patch.get_next_sync_committee()?,
            ],
            BeaconStatePatchCursor::Fulu(patch) => [
                patch.get_current_sync_committee()?,
                patch.get_next_sync_committee()?,
            ],
            BeaconStatePatchCursor::Gloas(patch) => [
                patch.get_current_sync_committee()?,
                patch.get_next_sync_committee()?,
            ],
        };

        Ok(patches.map(ReplacePatch::into_changed))
    }
}

pub struct StateProposerLookahead<P: Preset> {
    pub proposer_lookahead: ProposerLookahead<P>,
}

impl<P: Preset> StateField<P> for Option<StateProposerLookahead<P>> {
    fn from_state(state: &BeaconState<P>) -> Self {
        let post_fulu = state.post_fulu()?;

        Some(StateProposerLookahead {
            proposer_lookahead: post_fulu.proposer_lookahead().clone(),
        })
    }

    fn reconstruct(slot: Slot, mut rows: StateRows<'_, P>) -> Result<Option<Self>> {
        if misc::compute_epoch_at_slot::<P>(rows.state_slot())
            != misc::compute_epoch_at_slot::<P>(slot)
        {
            return Ok(None);
        }

        let mut patches = vec![];

        while let Some(row) = rows.next()? {
            let base = match row {
                StateRow::Delta(patch) => {
                    patches.extend(StateProposerLookahead::patches(&patch)?);

                    continue;
                }
                StateRow::Frame(frame) => StateProposerLookahead::from_frame(&frame)?,
                StateRow::State(state) => Self::from_state(&state),
            };

            let Some(mut base) = base else {
                return Ok(Some(None));
            };

            for patch in patches.into_iter().rev() {
                patch.apply(&mut base.proposer_lookahead)?;
            }

            return Ok(Some(Some(base)));
        }

        Ok(None)
    }
}

impl<P: Preset> StateProposerLookahead<P> {
    fn from_frame(frame: &BeaconStateFrameCursor<P>) -> Result<Option<Self>> {
        let lookahead = match frame {
            BeaconStateFrameCursor::Phase0(_)
            | BeaconStateFrameCursor::Altair(_)
            | BeaconStateFrameCursor::Bellatrix(_)
            | BeaconStateFrameCursor::Capella(_)
            | BeaconStateFrameCursor::Deneb(_)
            | BeaconStateFrameCursor::Electra(_) => return Ok(None),
            BeaconStateFrameCursor::Fulu(frame) => Self {
                proposer_lookahead: frame.get_proposer_lookahead()?.into_inner(),
            },
            BeaconStateFrameCursor::Gloas(frame) => Self {
                proposer_lookahead: frame.get_proposer_lookahead()?.into_inner(),
            },
        };

        Ok(Some(lookahead))
    }

    fn patches(
        patch: &BeaconStatePatchCursor<P>,
    ) -> Result<Option<Compressed<VectorPatch<ValidatorIndex>>>> {
        let patches = match patch {
            BeaconStatePatchCursor::Phase0(_)
            | BeaconStatePatchCursor::Altair(_)
            | BeaconStatePatchCursor::Bellatrix(_)
            | BeaconStatePatchCursor::Capella(_)
            | BeaconStatePatchCursor::Deneb(_)
            | BeaconStatePatchCursor::Electra(_) => return Ok(None),
            BeaconStatePatchCursor::Fulu(patch) => patch.get_proposer_lookahead()?,
            BeaconStatePatchCursor::Gloas(patch) => patch.get_proposer_lookahead()?,
        };

        Ok(Some(patches))
    }
}

pub struct CommitteeFields<P: Preset> {
    pub validators: ValidatorColumns,
    pub randao_mixes: RandaoMixes<P>,
}

impl<P: Preset> StateField<P> for CommitteeFields<P> {
    fn from_state(state: &BeaconState<P>) -> Self {
        Self {
            validators: ValidatorColumns::from_state(state),
            randao_mixes: state.randao_mixes().clone(),
        }
    }

    fn reconstruct(slot: Slot, mut rows: StateRows<'_, P>) -> Result<Option<Self>> {
        if misc::compute_epoch_at_slot::<P>(rows.state_slot())
            != misc::compute_epoch_at_slot::<P>(slot)
        {
            return Ok(None);
        }

        let mut patches = vec![];

        while let Some(row) = rows.next()? {
            let base = match row {
                StateRow::Delta(patch) => {
                    patches.push(Self::patches(&patch)?);

                    continue;
                }
                StateRow::Frame(frame) => Self::from_frame(&frame)?,
                StateRow::State(state) => Self::from_state(&state),
            };

            let mut columns = (
                base.validators.partial_validators,
                base.validators.effective_balances,
            );
            let mut randao_mixes = base.randao_mixes;

            for (validators_patch, randao_mixes_patch) in patches.into_iter().rev() {
                validators_patch.apply(&mut columns)?;
                randao_mixes_patch.apply(&mut randao_mixes)?;
            }

            let (partial_validators, effective_balances) = columns;

            return Ok(Some(Self {
                validators: ValidatorColumns {
                    partial_validators,
                    effective_balances,
                },
                randao_mixes,
            }));
        }

        Ok(None)
    }
}

impl<P: Preset> CommitteeFields<P> {
    fn from_frame(frame: &BeaconStateFrameCursor<P>) -> Result<Self> {
        let randao_mixes = match frame {
            BeaconStateFrameCursor::Phase0(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Altair(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Bellatrix(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Capella(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Deneb(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Electra(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Fulu(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Gloas(frame) => frame.get_randao_mixes()?,
        };

        Ok(Self {
            validators: ValidatorColumns::from_frame(frame)?,
            randao_mixes,
        })
    }

    fn patches(
        patch: &BeaconStatePatchCursor<P>,
    ) -> Result<(Compressed<ValidatorListPatch>, VectorPatch<H256>)> {
        let patches = match patch {
            BeaconStatePatchCursor::Phase0(patch) => {
                (patch.get_validators()?, patch.get_randao_mixes()?)
            }
            BeaconStatePatchCursor::Altair(patch) => {
                (patch.get_validators()?, patch.get_randao_mixes()?)
            }
            BeaconStatePatchCursor::Bellatrix(patch) => {
                (patch.get_validators()?, patch.get_randao_mixes()?)
            }
            BeaconStatePatchCursor::Capella(patch) => {
                (patch.get_validators()?, patch.get_randao_mixes()?)
            }
            BeaconStatePatchCursor::Deneb(patch) => {
                (patch.get_validators()?, patch.get_randao_mixes()?)
            }
            BeaconStatePatchCursor::Electra(patch) => {
                (patch.get_validators()?, patch.get_randao_mixes()?)
            }
            BeaconStatePatchCursor::Fulu(patch) => {
                (patch.get_validators()?, patch.get_randao_mixes()?)
            }
            BeaconStatePatchCursor::Gloas(patch) => {
                (patch.get_validators()?, patch.get_randao_mixes()?)
            }
        };

        Ok(patches)
    }
}

pub struct ValidatorColumns {
    pub partial_validators: PartialValidatorList,
    pub effective_balances: EffectiveBalanceList,
}

impl<P: Preset> StateField<P> for ValidatorColumns {
    fn from_state(state: &BeaconState<P>) -> Self {
        let (_, effective_balances, partial_validators) = match state {
            BeaconState::Phase0(state) => state.validators.clone().into_columns(),
            BeaconState::Altair(state) => state.validators.clone().into_columns(),
            BeaconState::Bellatrix(state) => state.validators.clone().into_columns(),
            BeaconState::Capella(state) => state.validators.clone().into_columns(),
            BeaconState::Deneb(state) => state.validators.clone().into_columns(),
            BeaconState::Electra(state) => state.validators.clone().into_columns(),
            BeaconState::Fulu(state) => state.validators.clone().into_columns(),
            BeaconState::Gloas(state) => state.validators.clone().into_columns(),
        };

        Self {
            partial_validators,
            effective_balances,
        }
    }

    fn reconstruct(slot: Slot, mut rows: StateRows<'_, P>) -> Result<Option<Self>> {
        if misc::compute_epoch_at_slot::<P>(rows.state_slot())
            != misc::compute_epoch_at_slot::<P>(slot)
        {
            return Ok(None);
        }

        let mut patches = vec![];

        while let Some(row) = rows.next()? {
            let base = match row {
                StateRow::Delta(patch) => {
                    patches.push(Self::patches(&patch)?);

                    continue;
                }
                StateRow::Frame(frame) => Self::from_frame(&frame)?,
                StateRow::State(state) => Self::from_state(&state),
            };

            let mut columns = (base.partial_validators, base.effective_balances);

            for patch in patches.into_iter().rev() {
                patch.apply(&mut columns)?;
            }

            let (partial_validators, effective_balances) = columns;

            return Ok(Some(Self {
                partial_validators,
                effective_balances,
            }));
        }

        Ok(None)
    }
}

impl ValidatorColumns {
    #[expect(clippy::too_many_lines)]
    fn from_frame<P: Preset>(frame: &BeaconStateFrameCursor<P>) -> Result<Self> {
        let columns = match frame {
            BeaconStateFrameCursor::Phase0(frame) => {
                let validators = frame.get_validators()?;

                Self {
                    partial_validators: validators
                        .get_partial_validators()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                    effective_balances: validators
                        .get_effective_balances()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                }
            }
            BeaconStateFrameCursor::Altair(frame) => {
                let validators = frame.get_validators()?;

                Self {
                    partial_validators: validators
                        .get_partial_validators()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                    effective_balances: validators
                        .get_effective_balances()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                }
            }
            BeaconStateFrameCursor::Bellatrix(frame) => {
                let validators = frame.get_validators()?;

                Self {
                    partial_validators: validators
                        .get_partial_validators()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                    effective_balances: validators
                        .get_effective_balances()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                }
            }
            BeaconStateFrameCursor::Capella(frame) => {
                let validators = frame.get_validators()?;

                Self {
                    partial_validators: validators
                        .get_partial_validators()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                    effective_balances: validators
                        .get_effective_balances()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                }
            }
            BeaconStateFrameCursor::Deneb(frame) => {
                let validators = frame.get_validators()?;

                Self {
                    partial_validators: validators
                        .get_partial_validators()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                    effective_balances: validators
                        .get_effective_balances()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                }
            }
            BeaconStateFrameCursor::Electra(frame) => {
                let validators = frame.get_validators()?;

                Self {
                    partial_validators: validators
                        .get_partial_validators()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                    effective_balances: validators
                        .get_effective_balances()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                }
            }
            BeaconStateFrameCursor::Fulu(frame) => {
                let validators = frame.get_validators()?;

                Self {
                    partial_validators: validators
                        .get_partial_validators()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                    effective_balances: validators
                        .get_effective_balances()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                }
            }
            BeaconStateFrameCursor::Gloas(frame) => {
                let validators = frame.get_validators()?;

                Self {
                    partial_validators: validators
                        .get_partial_validators()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                    effective_balances: validators
                        .get_effective_balances()?
                        .into_inner()
                        .into_iter()
                        .collect(),
                }
            }
        };

        Ok(columns)
    }

    fn patches<P: Preset>(
        patch: &BeaconStatePatchCursor<P>,
    ) -> Result<Compressed<ValidatorListPatch>> {
        let patches = match patch {
            BeaconStatePatchCursor::Phase0(patch) => patch.get_validators()?,
            BeaconStatePatchCursor::Altair(patch) => patch.get_validators()?,
            BeaconStatePatchCursor::Bellatrix(patch) => patch.get_validators()?,
            BeaconStatePatchCursor::Capella(patch) => patch.get_validators()?,
            BeaconStatePatchCursor::Deneb(patch) => patch.get_validators()?,
            BeaconStatePatchCursor::Electra(patch) => patch.get_validators()?,
            BeaconStatePatchCursor::Fulu(patch) => patch.get_validators()?,
            BeaconStatePatchCursor::Gloas(patch) => patch.get_validators()?,
        };

        Ok(patches)
    }
}

pub struct StateRandaoMixes<P: Preset> {
    pub randao_mixes: RandaoMixes<P>,
}

impl<P: Preset> StateField<P> for StateRandaoMixes<P> {
    fn from_state(state: &BeaconState<P>) -> Self {
        Self {
            randao_mixes: state.randao_mixes().clone(),
        }
    }

    fn reconstruct(slot: Slot, mut rows: StateRows<'_, P>) -> Result<Option<Self>> {
        let epoch = misc::compute_epoch_at_slot::<P>(slot);

        if misc::compute_epoch_at_slot::<P>(rows.state_slot()) != epoch {
            return Ok(None);
        }

        let current_mix = if rows.state_slot() == slot {
            None
        } else {
            let Some(slot_diff) = rows.slot_diff(slot)? else {
                return Ok(None);
            };

            Some(slot_diff.randao_mix())
        };

        let mut patches = vec![];

        while let Some(row) = rows.next()? {
            let mut randao_mixes = match row {
                StateRow::Delta(patch) => {
                    patches.push(Self::patches(&patch)?);

                    continue;
                }
                StateRow::Frame(frame) => Self::from_frame(&frame)?,
                StateRow::State(state) => state.randao_mixes().clone(),
            };

            for patch in patches.into_iter().rev() {
                patch.apply(&mut randao_mixes)?;
            }

            if let Some(current_mix) = current_mix {
                *randao_mixes.mod_index_mut(epoch) = current_mix;
            }

            return Ok(Some(Self { randao_mixes }));
        }

        Ok(None)
    }
}

impl<P: Preset> StateRandaoMixes<P> {
    fn from_frame(frame: &BeaconStateFrameCursor<P>) -> Result<RandaoMixes<P>> {
        let randao_mixes = match frame {
            BeaconStateFrameCursor::Phase0(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Altair(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Bellatrix(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Capella(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Deneb(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Electra(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Fulu(frame) => frame.get_randao_mixes()?,
            BeaconStateFrameCursor::Gloas(frame) => frame.get_randao_mixes()?,
        };

        Ok(randao_mixes)
    }

    fn patches(patch: &BeaconStatePatchCursor<P>) -> Result<VectorPatch<H256>> {
        let patches = match patch {
            BeaconStatePatchCursor::Phase0(patch) => patch.get_randao_mixes()?,
            BeaconStatePatchCursor::Altair(patch) => patch.get_randao_mixes()?,
            BeaconStatePatchCursor::Bellatrix(patch) => patch.get_randao_mixes()?,
            BeaconStatePatchCursor::Capella(patch) => patch.get_randao_mixes()?,
            BeaconStatePatchCursor::Deneb(patch) => patch.get_randao_mixes()?,
            BeaconStatePatchCursor::Electra(patch) => patch.get_randao_mixes()?,
            BeaconStatePatchCursor::Fulu(patch) => patch.get_randao_mixes()?,
            BeaconStatePatchCursor::Gloas(patch) => patch.get_randao_mixes()?,
        };

        Ok(patches)
    }
}
