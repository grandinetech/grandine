use std::sync::Arc;

use eth1_api::ApiController;
use fork_choice_control::{StateField, Wait};
use genesis::AnchorCheckpointProvider;
use http_api_utils::StateId;
use tracing::instrument;
use types::{combined::BeaconState, nonstandard::WithStatus, preset::Preset};

use crate::error::Error;

#[instrument(level = "debug", skip_all, fields(%state_id))]
pub fn state<P: Preset, W: Wait>(
    state_id: &StateId,
    controller: &ApiController<P, W>,
    anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
) -> Result<WithStatus<Arc<BeaconState<P>>>, Error> {
    match state_id {
        StateId::Head => Some(controller.head_state()),
        StateId::Genesis => anchor_checkpoint_provider
            .checkpoint()
            .genesis()
            .map(|checkpoint| checkpoint.state)
            .map(WithStatus::valid_and_finalized),
        StateId::Finalized => Some(controller.last_finalized_state()),
        StateId::Justified => Some(controller.justified_state()?),
        StateId::Slot(slot) => {
            tokio::task::block_in_place(|| controller.state_at_slot_checked_blocking(*slot))?
        }
        StateId::Root(root) => controller.state_by_state_root(*root)?,
    }
    .ok_or(Error::StateNotFound)
}

#[instrument(level = "debug", skip_all, fields(%state_id))]
pub fn field<P: Preset, W: Wait, F: StateField<P>>(
    state_id: &StateId,
    controller: &ApiController<P, W>,
    anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
) -> Result<WithStatus<F>, Error> {
    match state_id {
        StateId::Slot(slot) => {
            tokio::task::block_in_place(|| controller.field_at_slot_checked_blocking(*slot))?
        }
        StateId::Root(root) => match controller.slot_by_state_root(*root)? {
            Some(WithStatus { value: slot, .. }) => {
                tokio::task::block_in_place(|| controller.field_at_slot_checked_blocking(slot))?
            }
            None => None,
        },
        StateId::Head | StateId::Genesis | StateId::Finalized | StateId::Justified => Some(
            state(state_id, controller, anchor_checkpoint_provider)?
                .map(|state| F::from_state(&state)),
        ),
    }
    .ok_or(Error::StateNotFound)
}
