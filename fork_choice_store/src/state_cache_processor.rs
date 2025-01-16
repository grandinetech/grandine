use core::time::Duration;
use std::{backtrace::Backtrace, collections::HashSet, sync::Arc};

use anyhow::{bail, Result};
use features::Feature;
use log::warn;
use state_cache::{StateCache, StateWithRewards};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use thiserror::Error;
use transition_functions::combined;
use types::{
    combined::BeaconState,
    phase0::primitives::{Slot, H256},
    preset::Preset,
    traits::BeaconState as _,
};

use crate::Store;

const ALLOWED_EMPTY_SLOTS_MULTIPLIER: u64 = 2;

pub struct StateCacheProcessor<P: Preset> {
    state_cache: StateCache<P>,
}

impl<P: Preset> StateCacheProcessor<P> {
    #[must_use]
    pub fn new(state_cache_lock_timeout: Duration) -> Self {
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
        self.state_cache
            .before_or_at_slot(block_root, slot)
            .ok()
            .flatten()
            .map(|(state, _)| state)
            .or_else(|| store_state_before_or_at_slot(store, block_root, slot))
    }

    pub fn existing_state_at_slot(
        &self,
        store: &Store<P>,
        block_root: H256,
        slot: Slot,
    ) -> Option<Arc<BeaconState<P>>> {
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
        self.state_cache
            .get_or_insert_with(block_root, slot, ignore_missing_rewards, f)
    }

    pub fn prune(&self, last_pruned_slot: Slot, preserved_states: &HashSet<H256>) -> Result<()> {
        self.state_cache.prune(last_pruned_slot, preserved_states)
    }

    pub fn try_state_at_slot(
        &self,
        store: &Store<P>,
        block_root: H256,
        slot: Slot,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
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
        let post_state = process_slots(
            store,
            state,
            block_root,
            slot,
            should_print_slot_processing_warning(store),
        )?;

        if store.is_forward_synced() {
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
        if !store.is_forward_synced() {
            return match self.before_or_at_slot(store, block_root, slot) {
                Some(state) => Ok(Some(process_slots(
                    store,
                    state,
                    block_root,
                    slot,
                    warn_on_slot_processing,
                )?)),
                None => Ok(None),
            };
        }

        self.state_cache
            .get_or_try_insert_with(block_root, slot, true, |pre_state| {
                let Some(state) = pre_state
                    .map(|(state, _)| state.clone_arc())
                    .or_else(|| store_state_before_or_at_slot(store, block_root, slot))
                else {
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
        let max_empty_slots = store.store_config().max_empty_slots * ALLOWED_EMPTY_SLOTS_MULTIPLIER;
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
