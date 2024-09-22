use core::time::Duration;
use std::{backtrace::Backtrace, sync::Arc};

use anyhow::{bail, Result};
use features::Feature;
use state_cache::{StateCache, StateWithRewards};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use tracing::{info, trace, warn}; 
use thiserror::Error;
use transition_functions::combined;
use types::{
    combined::BeaconState,
    phase0::primitives::{Slot, H256},
    preset::Preset,
    traits::BeaconState as _,
};

use crate::Store;

pub struct StateCacheProcessor<P: Preset> {
    state_cache: StateCache<P>,
}

impl<P: Preset> StateCacheProcessor<P> {
    #[must_use]
    pub fn new(state_cache_lock_timeout: Duration) -> Self {
        info!("Creating new StateCacheProcessor with lock timeout of {:?}", state_cache_lock_timeout);
        Self {
            state_cache: StateCache::new(state_cache_lock_timeout),
        }
    }

    pub fn before_or_at_slot(
        &self,
        store: &Store<P>,
        block_root: H256,
        slot: Slot,
    ) -> Option<Arc<BeaconState<P>>> {
        trace!("Retrieving state before or at slot {}", slot);
        self.state_cache
            .before_or_at_slot(block_root, slot)
            .ok()
            .flatten()
            .map(|(state, _)| {
                trace!("State found in cache for block root {:?} and slot {}", block_root, slot);
                state
            })
            .or_else(|| {
                trace!("State not found in cache, trying store");
                store_state_before_or_at_slot(store, block_root, slot)
            })
    }

    pub fn existing_state_at_slot(
        &self,
        store: &Store<P>,
        block_root: H256,
        slot: Slot,
    ) -> Option<Arc<BeaconState<P>>> {
        trace!("Checking existing state at slot {}", slot);
        self.before_or_at_slot(store, block_root, slot)
            .filter(|state| state.slot() == slot)
    }

    pub fn get_or_insert_with(
        &self,
        block_root: H256,
        slot: Slot,
        ignore_missing_rewards: bool,
        f: impl FnOnce() -> Result<StateWithRewards<P>>,
    ) -> Result<StateWithRewards<P>> {
        trace!(
            "Attempting to get or insert state for block root {:?} at slot {}",
            block_root,
            slot
        );
        self.state_cache
            .get_or_insert_with(block_root, slot, ignore_missing_rewards, f)
    }

    pub fn len(&self) -> Result<usize> {
        trace!("Getting length of state cache");
        self.state_cache.len()
    }

    pub fn prune(&self, last_pruned_slot: Slot) -> Result<()> {
        trace!("Pruning state cache up to slot {}", last_pruned_slot);
        self.state_cache.prune(last_pruned_slot)
    }

    pub fn try_state_at_slot(
        &self,
        store: &Store<P>,
        block_root: H256,
        slot: Slot,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        trace!("Trying to get state at slot {} for block root {:?}", slot, block_root);
        self.try_get_state_at_slot(
            store,
            block_root,
            slot,
            should_print_slot_processing_warning(store),
        )
    }

    pub fn state_at_slot(
        &self,
        store: &Store<P>,
        block_root: H256,
        slot: Slot,
    ) -> Result<Arc<BeaconState<P>>> {
        trace!("Getting state at slot {} for block root {:?}", slot, block_root);
        self.try_state_at_slot(store, block_root, slot)?
            .ok_or(Error::StateNotFound { block_root })
            .map_err(Into::into)
    }

    pub fn state_at_slot_quiet(
        &self,
        store: &Store<P>,
        block_root: H256,
        slot: Slot,
    ) -> Result<Arc<BeaconState<P>>> {
        trace!("Quietly getting state at slot {} for block root {:?}", slot, block_root);
        self.try_get_state_at_slot(store, block_root, slot, false)?
            .ok_or(Error::StateNotFound { block_root })
            .map_err(Into::into)
    }

    pub fn process_slots(
        &self,
        store: &Store<P>,
        state: Arc<BeaconState<P>>,
        block_root: H256,
        slot: Slot,
    ) -> Result<Arc<BeaconState<P>>> {
        trace!(
            "Processing slots for state from slot {} to {} for block root {:?}",
            state.slot(),
            slot,
            block_root
        );
        let post_state = process_slots(
            store,
            state,
            block_root,
            slot,
            should_print_slot_processing_warning(store),
        )?;

        if store.is_forward_synced() {
            trace!("Inserting processed state into state cache for block root {:?}", block_root);
            self.state_cache
                .insert(block_root, (post_state.clone_arc(), None))?;
        }

        Ok(post_state)
    }

    fn try_get_state_at_slot(
        &self,
        store: &Store<P>,
        block_root: H256,
        slot: Slot,
        warn_on_slot_processing: bool,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        trace!("Attempting to get state at slot {} for block root {:?}", slot, block_root);
        if !store.is_forward_synced() {
            return match self.before_or_at_slot(store, block_root, slot) {
                Some(state) => {
                    trace!("State found, processing slots");
                    Ok(Some(process_slots(
                        store,
                        state,
                        block_root,
                        slot,
                        warn_on_slot_processing,
                    )?))
                }
                None => Ok(None),
            };
        }

        self.state_cache
            .get_or_try_insert_with(block_root, slot, true, |pre_state| {
                trace!("State not found in cache, attempting to retrieve or process");
                let Some(state) = pre_state
                    .map(|(state, _)| state.clone_arc())
                    .or_else(|| store_state_before_or_at_slot(store, block_root, slot))
                else {
                    trace!("No state found before or at slot");
                    return Ok(None);
                };

                let state = process_slots(store, state, block_root, slot, warn_on_slot_processing)?;

                Ok(Some((state, None)))
            })?
            .map(|(state, _)| state)
            .pipe(Ok)
    }
}

fn process_slots<P: Preset>(
    store: &Store<P>,
    mut state: Arc<BeaconState<P>>,
    block_root: H256,
    slot: Slot,
    warn_on_slot_processing: bool,
) -> Result<Arc<BeaconState<P>>> {
    trace!("Processing slots from {} to {} for block root {:?}", state.slot(), slot, block_root);
    if state.slot() < slot {
        if warn_on_slot_processing && store.is_forward_synced() {
            // `Backtrace::force_capture` can be costly and a warning may be excessive,
            // but this is controlled by a `Feature` that should be disabled by default.
            warn!(
                "processing slots for beacon state not found in state cache \
                 (block root: {block_root:?}, from slot {} to {slot})\n{}",
                state.slot(),
                Backtrace::force_capture(),
            );
        }

        let state_slot = state.slot();
        let max_empty_slots = store.store_config().max_empty_slots;
        let is_forward_synced = store.is_forward_synced();

        if !is_forward_synced && state_slot + max_empty_slots < slot {
            bail!(Error::StateFarBehind {
                state_slot,
                max_empty_slots,
                slot,
            });
        }

        combined::process_slots(store.chain_config(), state.make_mut(), slot)?;
    }

    Ok(state)
}

fn should_print_slot_processing_warning<P: Preset>(store: &Store<P>) -> bool {
    Feature::WarnOnStateCacheSlotProcessing.is_enabled() && store.is_forward_synced()
}

fn store_state_before_or_at_slot<P: Preset>(
    store: &Store<P>,
    block_root: H256,
    slot: Slot,
) -> Option<Arc<BeaconState<P>>> {
    store
        .state_by_block_root(block_root)
        .filter(|state| state.slot() <= slot)
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("too many empty slots after state: {state_slot} + {max_empty_slots} < {slot}")]
    StateFarBehind {
        state_slot: Slot,
        max_empty_slots: u64,
        slot: Slot,
    },
    #[error("state not found in fork choice store: {block_root:?}")]
    StateNotFound { block_root: H256 },
}
