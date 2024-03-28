use std::{
    backtrace::Backtrace,
    sync::{mpsc::Sender, Arc},
};

use anyhow::{bail, Result};
use arc_swap::{ArcSwap, Guard};
use derive_more::Constructor;
use features::Feature;
use fork_choice_store::Store;
use log::warn;
use std_ext::ArcExt as _;
use thiserror::Error;
use transition_functions::combined;
use types::{
    combined::BeaconState,
    phase0::primitives::{Slot, H256},
    preset::Preset,
    traits::BeaconState as _,
};

use crate::messages::MutatorMessage;

#[derive(Constructor)]
pub struct StateCache<P: Preset, W> {
    // Both `Controller` and `StateCache` get their snapshots of `Store` through `ArcSwap`.
    // The snapshots they load can be different, leading to race conditions.
    // They appear to be harmless, but we might want to redesign this in the future.
    store_snapshot: Arc<ArcSwap<Store<P>>>,
    mutator_tx: Sender<MutatorMessage<P, W>>,
}

impl<P: Preset, W> StateCache<P, W> {
    pub fn try_state_at_slot(
        &self,
        block_root: H256,
        slot: Slot,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        match self.try_find_state(block_root, slot) {
            Some(state) => Ok(Some(self.process_slots(state, block_root, slot)?)),
            None => Ok(None),
        }
    }

    pub fn state_at_slot(&self, block_root: H256, slot: Slot) -> Result<Arc<BeaconState<P>>> {
        let state = self
            .try_find_state(block_root, slot)
            .ok_or(Error::StateNotFound { block_root })?;

        self.process_slots(state, block_root, slot)
    }

    pub fn state_at_slot_quiet(&self, block_root: H256, slot: Slot) -> Result<Arc<BeaconState<P>>> {
        let state = self
            .try_find_state(block_root, slot)
            .ok_or(Error::StateNotFound { block_root })?;

        self.process_slots_internal(state, block_root, slot, false)
    }

    pub fn process_slots(
        &self,
        state: Arc<BeaconState<P>>,
        block_root: H256,
        slot: Slot,
    ) -> Result<Arc<BeaconState<P>>> {
        self.process_slots_internal(
            state,
            block_root,
            slot,
            self.should_print_slot_processing_warning(),
        )
    }

    fn try_find_state(&self, block_root: H256, slot: Slot) -> Option<Arc<BeaconState<P>>> {
        let store_snapshot = self.store_snapshot.load();

        store_snapshot
            .preprocessed_state_before_or_at_slot(block_root, slot)
            .cloned()
            .or_else(|| store_snapshot.state_by_block_root(block_root))
    }

    fn process_slots_internal(
        &self,
        mut state: Arc<BeaconState<P>>,
        block_root: H256,
        slot: Slot,
        warn_on_slot_processing: bool,
    ) -> Result<Arc<BeaconState<P>>> {
        if state.slot() < slot {
            let store = self.store_snapshot();

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

            let store = self.store_snapshot();
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

            if is_forward_synced {
                MutatorMessage::PreprocessedBeaconState {
                    block_root,
                    state: state.clone_arc(),
                }
                .send(&self.mutator_tx);
            }
        }

        Ok(state)
    }

    fn should_print_slot_processing_warning(&self) -> bool {
        Feature::WarnOnStateCacheSlotProcessing.is_enabled()
            && self.store_snapshot().is_forward_synced()
    }

    fn store_snapshot(&self) -> Guard<Arc<Store<P>>> {
        self.store_snapshot.load()
    }
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
