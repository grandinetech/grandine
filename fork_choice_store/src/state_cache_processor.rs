use core::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use std::{backtrace::Backtrace, collections::HashSet, sync::Arc};

use anyhow::{bail, Result};
use features::Feature;
use logging::{info_with_peers, warn_with_peers};
use pubkey_cache::PubkeyCache;
use state_cache::{QueryOptions, StateCache, StateWithRewards};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use thiserror::Error;
use tracing::instrument;
use transition_functions::combined;
use types::{
    combined::BeaconState,
    phase0::primitives::{Slot, H256},
    preset::Preset,
    traits::BeaconState as _,
};

use crate::{Storage, Store};

const ALLOWED_EMPTY_SLOTS_MULTIPLIER: u64 = 2;
const ALLOWED_EMPTY_SLOTS_MULTIPLIER_FOR_BLOCK_SYNC: u64 = 100;

pub struct StateCacheProcessor<P: Preset> {
    state_cache: StateCache<P>,
    currently_processing: AtomicUsize,
}

impl<P: Preset> StateCacheProcessor<P> {
    #[must_use]
    pub fn new(state_cache_lock_timeout: Duration) -> Self {
        Self {
            state_cache: StateCache::new(state_cache_lock_timeout),
            currently_processing: AtomicUsize::new(0),
        }
    }

    pub fn before_or_at_slot<S: Storage<P>>(
        &self,
        store: &Store<P, S>,
        block_root: H256,
        slot: Slot,
    ) -> Option<Arc<BeaconState<P>>> {
        self.before_or_at_slot_in_cache_only(block_root, slot)
            .or_else(|| store_state_before_or_at_slot(store, block_root, slot))
    }

    pub fn before_or_at_slot_in_cache_only(
        &self,
        block_root: H256,
        slot: Slot,
    ) -> Option<Arc<BeaconState<P>>> {
        self.state_cache
            .before_or_at_slot(block_root, slot)
            .ok()
            .flatten()
            .map(|(state, _)| state)
    }

    pub fn existing_state_at_slot<S: Storage<P>>(
        &self,
        store: &Store<P, S>,
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
        let options = QueryOptions {
            ignore_missing_rewards,
            store_result_state: true,
        };

        self.state_cache
            .get_or_process_with(block_root, slot, options, f)
    }

    pub fn prune(
        &self,
        last_pruned_slot: Slot,
        preserved_older_states: &HashSet<H256>,
        pruned_newer_states: &HashSet<H256>,
    ) -> Result<()> {
        self.state_cache.prune(
            last_pruned_slot,
            preserved_older_states,
            pruned_newer_states,
        )
    }

    pub fn try_state_at_slot<S: Storage<P>>(
        &self,
        pubkey_cache: &PubkeyCache,
        store: &Store<P, S>,
        block_root: H256,
        slot: Slot,
        store_result_state: bool,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        self.try_get_state_at_slot(
            pubkey_cache,
            store,
            block_root,
            slot,
            ALLOWED_EMPTY_SLOTS_MULTIPLIER,
            store_result_state,
            should_print_slot_processing_warning(),
        )
    }

    // Processing long slot distances are expensive and should not be allowed.
    // (especially when the processed state is needed for things like attestations
    // - that could lead to excessive mem and CPU usage and result in DoS).
    // The exception is block sync - which should be allowed, because it's
    // the only way for the chain to progress in long periods without blocks.
    #[instrument(level = "debug", skip_all)]
    pub fn try_state_at_slot_for_block_sync<S: Storage<P>>(
        &self,
        pubkey_cache: &PubkeyCache,
        store: &Store<P, S>,
        block_root: H256,
        slot: Slot,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        self.try_get_state_at_slot(
            pubkey_cache,
            store,
            block_root,
            slot,
            ALLOWED_EMPTY_SLOTS_MULTIPLIER_FOR_BLOCK_SYNC,
            store.is_forward_synced(),
            should_print_slot_processing_warning(),
        )
    }

    pub fn state_at_slot<S: Storage<P>>(
        &self,
        pubkey_cache: &PubkeyCache,
        store: &Store<P, S>,
        block_root: H256,
        slot: Slot,
    ) -> Result<Arc<BeaconState<P>>> {
        self.try_state_at_slot(pubkey_cache, store, block_root, slot, true)?
            .ok_or(Error::StateNotFound { block_root })
            .map_err(Into::into)
    }

    pub fn state_at_slot_quiet<S: Storage<P>>(
        &self,
        pubkey_cache: &PubkeyCache,
        store: &Store<P, S>,
        block_root: H256,
        slot: Slot,
    ) -> Result<Arc<BeaconState<P>>> {
        self.try_get_state_at_slot(
            pubkey_cache,
            store,
            block_root,
            slot,
            ALLOWED_EMPTY_SLOTS_MULTIPLIER,
            store.is_forward_synced(),
            false,
        )?
        .ok_or(Error::StateNotFound { block_root })
        .map_err(Into::into)
    }

    pub fn process_slots<S: Storage<P>>(
        &self,
        pubkey_cache: &PubkeyCache,
        store: &Store<P, S>,
        state: Arc<BeaconState<P>>,
        block_root: H256,
        slot: Slot,
    ) -> Result<Arc<BeaconState<P>>> {
        let post_state = process_slots(
            pubkey_cache,
            store,
            state,
            block_root,
            slot,
            ALLOWED_EMPTY_SLOTS_MULTIPLIER,
            should_print_slot_processing_warning(),
            &self.currently_processing,
        )?;

        if store.is_forward_synced() {
            self.state_cache
                .insert(block_root, (post_state.clone_arc(), None))?;
        }

        Ok(post_state)
    }

    pub fn set_log_lock_timeouts(&self, log_lock_timeouts: bool) {
        self.state_cache.set_log_lock_timeouts(log_lock_timeouts);
    }

    #[expect(clippy::too_many_arguments)]
    #[instrument(level = "debug", skip_all)]
    fn try_get_state_at_slot<S: Storage<P>>(
        &self,
        pubkey_cache: &PubkeyCache,
        store: &Store<P, S>,
        block_root: H256,
        slot: Slot,
        allowed_empty_slots_multiplier: u64,
        store_result_state: bool,
        warn_on_slot_processing: bool,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        let options = QueryOptions {
            ignore_missing_rewards: true,
            store_result_state,
        };

        self.state_cache
            .get_or_try_process_with(block_root, slot, options, |pre_state| {
                let Some(state) = pre_state
                    .map(|(state, _)| state.clone_arc())
                    .or_else(|| store_state_before_or_at_slot(store, block_root, slot))
                else {
                    return Ok(None);
                };

                let state = process_slots(
                    pubkey_cache,
                    store,
                    state,
                    block_root,
                    slot,
                    allowed_empty_slots_multiplier,
                    warn_on_slot_processing,
                    &self.currently_processing,
                )?;

                Ok(Some((state, None)))
            })?
            .map(|(state, _)| state)
            .pipe(Ok)
    }
}

#[expect(clippy::too_many_arguments)]
#[instrument(level = "debug", skip_all)]
fn process_slots<P: Preset, S: Storage<P>>(
    pubkey_cache: &PubkeyCache,
    store: &Store<P, S>,
    mut state: Arc<BeaconState<P>>,
    block_root: H256,
    slot: Slot,
    allowed_empty_slots_multiplier: u64,
    warn_on_slot_processing: bool,
    currently_processing: &AtomicUsize,
) -> Result<Arc<BeaconState<P>>> {
    let from_slot = state.slot();

    if from_slot >= slot {
        return Ok(state);
    }

    let max_empty_slots = store.store_config().max_empty_slots * allowed_empty_slots_multiplier;

    if from_slot + max_empty_slots < slot {
        bail!(Error::StateFarBehind {
            state_slot: from_slot,
            max_empty_slots,
            slot,
        });
    }

    currently_processing.fetch_add(1, Ordering::SeqCst);

    // Log state cache misses after chain is forward synced - mostly to catch cases when
    // some other than preprocessed next slot state is needed.
    // With exception of chain reorgs, this is the symptom that state cache is not used optimally.
    if warn_on_slot_processing {
        // `Backtrace::force_capture` can be costly and a warning may be excessive,
        // but this is controlled by a `Feature` that should be disabled by default.
        warn_with_peers!(
            "processing slots for beacon state not found in state cache \
             (block root: {block_root:?}, from slot {from_slot} to {slot})\n{}",
            Backtrace::force_capture(),
        );

        let processing_count = currently_processing.load(Ordering::SeqCst);

        if processing_count > 1 {
            warn_with_peers!(
                "currently processing slots for {processing_count} states in state cache"
            );
        }
    }

    let started_at = std::time::Instant::now();
    let process_slots_result =
        combined::process_slots(store.chain_config(), pubkey_cache, state.make_mut(), slot);

    currently_processing.fetch_sub(1, Ordering::SeqCst);

    process_slots_result?;

    if warn_on_slot_processing {
        info_with_peers!(
            "processed slots for beacon state not found in state cache in {} ms \
            (block root: {block_root:?}, from slot {from_slot} to {slot})",
            started_at.elapsed().as_millis(),
        );
    }

    Ok(state)
}

fn should_print_slot_processing_warning() -> bool {
    Feature::WarnOnStateCacheSlotProcessing.is_enabled()
}

#[instrument(level = "debug", skip_all)]
fn store_state_before_or_at_slot<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
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
