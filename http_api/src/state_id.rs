use std::sync::Arc;

use eth1_api::ApiController;
use fork_choice_control::Wait;
use genesis::AnchorCheckpointProvider;
use http_api_utils::StateId;
use types::{combined::BeaconState, nonstandard::WithStatus, preset::Preset};

use crate::error::Error;

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
        StateId::Slot(slot) => controller.state_at_slot_cached(*slot)?,
        StateId::Root(root) => controller.state_by_state_root(*root)?,
    }
    .ok_or(Error::StateNotFound)
}
