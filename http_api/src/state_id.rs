use std::{sync::Arc, time::SystemTime};

use anyhow::Result;
use clock::Tick;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use genesis::AnchorCheckpointProvider;
use http_api_utils::StateId;
use tracing::instrument;
use types::{
    combined::BeaconState, nonstandard::WithStatus, phase0::primitives::Slot, preset::Preset,
};

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
            let current_slot = current_slot_with_clock_disparity(controller)?;

            // States for future slots do not exist yet.
            if *slot > current_slot {
                None
            } else {
                return state_at_slot(*slot, controller);
            }
        }
        StateId::Root(root) => controller.state_by_state_root(*root)?,
    }
    .ok_or(Error::StateNotFound)
}

/// Unlike [`state`], this processes empty slots up to an epoch ahead of the current one.
/// Duties for the next epoch rely on that.
#[instrument(level = "debug", skip_all, fields(%slot))]
pub fn state_at_slot<P: Preset, W: Wait>(
    slot: Slot,
    controller: &ApiController<P, W>,
) -> Result<WithStatus<Arc<BeaconState<P>>>, Error> {
    tokio::task::block_in_place(|| controller.state_at_slot_cached_blocking(slot))?
        .ok_or(Error::StateNotFound)
}

// Like `Controller::slot`, but includes the next slot once the clock (allowing for disparity) has
// reached it. Fork choice enters a slot only once it handles the slot's tick.
fn current_slot_with_clock_disparity<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
) -> Result<Slot> {
    let store_slot = controller.slot();
    let tick = tick_with_clock_disparity(controller)?;

    Ok(tick.slot.clamp(store_slot, store_slot.saturating_add(1)))
}

pub fn tick_with_clock_disparity<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
) -> Result<Tick> {
    let chain_config = controller.chain_config();

    // Fork choice enters a slot only once it handles the slot's tick, which a request sent at
    // the slot boundary can beat by a few milliseconds.
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
    let time = now.saturating_add(chain_config.maximum_gossip_clock_disparity);

    Tick::at_time_in_ms::<P>(
        chain_config,
        u64::try_from(time.as_millis())?,
        controller.genesis_time(),
    )
}
