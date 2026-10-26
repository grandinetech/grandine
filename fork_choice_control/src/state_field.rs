use anyhow::Result;
use diff::ReplacePatch;
use helper_functions::misc;
use types::{
    combined::BeaconState,
    phase0::{containers::Checkpoint, primitives::Slot},
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
