use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{collections::HashSet, sync::Arc};

use anyhow::{Result, anyhow};
#[cfg(not(target_os = "zkvm"))]
use im::{HashMap, OrdMap};
use logging::{info_with_peers, warn_with_peers};
use parking_lot::{Mutex, MutexGuard};
#[cfg(target_os = "zkvm")]
use std::collections::{BTreeMap as OrdMap, HashMap};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use thiserror::Error;
use types::{
    combined::BeaconState,
    nonstandard::BlockRewards,
    phase0::primitives::{H256, Slot},
    preset::Preset,
    traits::BeaconState as _,
};

type StateMap<P> = OrdMap<Slot, StateWithRewards<P>>;
type StateMapLock<P> = Arc<Mutex<StateMap<P>>>;

pub type StateWithRewards<P> = (Arc<BeaconState<P>>, Option<BlockRewards>);

#[derive(Debug, Error)]
enum CacheLockError {
    #[error("could not obtain state cache lock in {} ms", timeout.as_millis())]
    CacheLockTimeout { timeout: Duration },
    #[error("could not obtain state cache lock in {} ms with block root {block_root:?}", timeout.as_millis())]
    StateMapLockTimeout { block_root: H256, timeout: Duration },
}

pub struct StateCache<P: Preset> {
    cache: Mutex<HashMap<H256, StateMapLock<P>>>,
    try_lock_timeout: Duration,
    log_lock_timeouts: AtomicBool,
}

#[derive(Clone, Copy)]
pub struct QueryOptions {
    pub ignore_missing_rewards: bool,
    pub store_result_state: bool,
}

impl<P: Preset> StateCache<P> {
    #[must_use]
    pub fn new(try_lock_timeout: Duration) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            try_lock_timeout,
            log_lock_timeouts: AtomicBool::new(false),
        }
    }

    pub fn before_or_at_slot(
        &self,
        block_root: H256,
        slot: Slot,
    ) -> Result<Option<StateWithRewards<P>>> {
        let Some(state_map_lock) = self.get_by_root(block_root)? else {
            return Ok(None);
        };

        let state_with_rewards = self
            .try_lock_map(&state_map_lock, block_root)?
            .get_prev(&slot)
            .map(|(_, state_with_rewards)| state_with_rewards.clone());

        Ok(state_with_rewards)
    }

    pub fn get_or_process_with(
        &self,
        block_root: H256,
        slot: Slot,
        options: QueryOptions,
        f: impl FnOnce() -> Result<StateWithRewards<P>>,
    ) -> Result<StateWithRewards<P>> {
        let state_map_lock = match self.get_or_init_by_root(block_root) {
            Ok(lock) => lock,
            Err(error) => {
                if error.is::<CacheLockError>() {
                    return f();
                }

                return Err(error);
            }
        };

        let mut state_map_guard = match self.try_lock_map(&state_map_lock, block_root) {
            Ok(guard) => guard,
            Err(error) => {
                if error.is::<CacheLockError>() {
                    return f();
                }

                return Err(error);
            }
        };

        let pre_state = state_map_guard
            .get_prev(&slot)
            .map(|(_, state_with_rewards)| state_with_rewards);

        if let Some((state, rewards)) = pre_state
            && state.slot() >= slot
        {
            if rewards.is_some() || options.ignore_missing_rewards {
                return Ok((state.clone_arc(), *rewards));
            }

            info_with_peers!(
                "recomputing state cache entry for block {block_root:?} at slot {slot} \
                    because block rewards are missing",
            );
        }

        let (post_state, rewards) = f()?;

        if options.store_result_state {
            state_map_guard.insert(post_state.slot(), (post_state.clone_arc(), rewards));
        }

        Ok((post_state, rewards))
    }

    pub fn get_or_try_process_with(
        &self,
        block_root: H256,
        slot: Slot,
        options: QueryOptions,
        f: impl FnOnce(Option<&StateWithRewards<P>>) -> Result<Option<StateWithRewards<P>>>,
    ) -> Result<Option<StateWithRewards<P>>> {
        let state_map_lock = match self.get_or_init_by_root(block_root) {
            Ok(lock) => lock,
            Err(error) => {
                if error.is::<CacheLockError>() {
                    return f(None);
                }

                return Err(error);
            }
        };

        let mut state_map_guard = match self.try_lock_map(&state_map_lock, block_root) {
            Ok(guard) => guard,
            Err(error) => {
                if error.is::<CacheLockError>() {
                    return f(None);
                }

                return Err(error);
            }
        };

        let pre_state = state_map_guard
            .get_prev(&slot)
            .map(|(_, state_with_rewards)| state_with_rewards);

        if let Some((state, rewards)) = pre_state
            && state.slot() >= slot
        {
            if rewards.is_some() || options.ignore_missing_rewards {
                return Ok(Some((state.clone_arc(), *rewards)));
            }

            info_with_peers!(
                "recomputing state cache entry for block {block_root:?} at slot {slot} \
                because block rewards are missing",
            );
        }

        match f(pre_state)? {
            Some((post_state, rewards)) => {
                if options.store_result_state {
                    state_map_guard.insert(post_state.slot(), (post_state.clone_arc(), rewards));
                }

                Ok(Some((post_state, rewards)))
            }
            None => {
                let is_empty = state_map_guard.is_empty();

                // Release the map lock before taking the cache lock.
                // `prune` locks in the opposite order: cache, then map.
                // Holding both here would invert that order.
                drop(state_map_guard);

                if is_empty {
                    self.remove_if_unused_and_empty(block_root, &state_map_lock)?;
                }

                Ok(None)
            }
        }
    }

    pub fn insert(&self, block_root: H256, state_with_rewards: StateWithRewards<P>) -> Result<()> {
        let state_map_lock = self.get_or_init_by_root(block_root)?;

        self.try_lock_map(&state_map_lock, block_root)?
            .insert(state_with_rewards.0.slot(), state_with_rewards);

        Ok(())
    }

    pub fn len(&self) -> Result<usize> {
        let lengths = self
            .all_state_map_locks()?
            .into_iter()
            .map(|(block_root, state_map_lock)| {
                self.try_lock_map(&state_map_lock, block_root)?
                    .len()
                    .pipe(Ok)
            })
            .collect::<Result<Vec<_>>>()?;

        lengths.into_iter().sum::<usize>().pipe(Ok)
    }

    pub fn prune(
        &self,
        last_pruned_slot: Slot,
        preserved_older_states: &HashSet<H256>,
        pruned_newer_states: &HashSet<H256>,
    ) -> Result<()> {
        // Pruning is best-effort.
        // A busy entry is skipped, not waited on.
        // The next prune will get it.
        let mut busy_roots = vec![];
        let mut emptied = vec![];

        // Snapshot the entries, so the cache lock is not held while pruning.
        for (block_root, state_map_lock) in self.all_state_map_locks()? {
            // `try_lock`, not `try_lock_for`.
            // Waiting 1.5 s per busy entry adds up to minutes.
            let Some(mut state_map) = state_map_lock.try_lock() else {
                busy_roots.push(block_root);
                continue;
            };

            if !preserved_older_states.contains(&block_root) {
                if pruned_newer_states.contains(&block_root) {
                    state_map.clear();
                } else {
                    let (_, retained) = state_map.split(&last_pruned_slot);
                    *state_map = retained;
                }
            }

            if state_map.is_empty() {
                drop(state_map);
                emptied.push((block_root, state_map_lock));
            }
        }

        if !busy_roots.is_empty() {
            warn_with_peers!(
                "skipped {} busy entries while pruning beacon state cache: {busy_roots:?}",
                busy_roots.len(),
            );
        }

        if emptied.is_empty() {
            return Ok(());
        }

        // One cache lock for all removals.
        let mut cache = self.try_lock_cache()?;

        for (block_root, state_map_lock) in emptied {
            Self::remove_locked_if_unused_and_empty(&mut cache, block_root, &state_map_lock);
        }

        Ok(())
    }

    pub fn set_log_lock_timeouts(&self, log_lock_timeouts: bool) {
        self.log_lock_timeouts
            .store(log_lock_timeouts, Ordering::SeqCst);
    }

    fn all_state_map_locks(&self) -> Result<Vec<(H256, StateMapLock<P>)>> {
        self.try_lock_cache()?
            .iter()
            .map(|(block_root, state_map_lock)| (*block_root, state_map_lock.clone_arc()))
            .collect::<Vec<_>>()
            .pipe(Ok)
    }

    fn get_or_init_by_root(&self, block_root: H256) -> Result<StateMapLock<P>> {
        self.try_lock_cache()?
            .entry(block_root)
            .or_insert_with(StateMapLock::default)
            .clone_arc()
            .pipe(Ok)
    }

    /// Removes the entry for `block_root` only if it is safe to drop.
    ///
    /// Call this without holding the lock of `state_map_lock`.
    fn remove_if_unused_and_empty(
        &self,
        block_root: H256,
        state_map_lock: &StateMapLock<P>,
    ) -> Result<()> {
        let mut cache = self.try_lock_cache()?;

        Self::remove_locked_if_unused_and_empty(&mut cache, block_root, state_map_lock);

        Ok(())
    }

    /// Same as [`Self::remove_if_unused_and_empty`], for a caller already holding the cache lock.
    fn remove_locked_if_unused_and_empty(
        cache: &mut HashMap<H256, StateMapLock<P>>,
        block_root: H256,
        state_map_lock: &StateMapLock<P>,
    ) {
        // The entry may have been replaced since we got it.
        // Never remove someone else's entry.
        let is_same_entry = cache
            .get(&block_root)
            .is_some_and(|current| Arc::ptr_eq(current, state_map_lock));

        // 2 = the cache + the caller.
        // More means another thread got this entry and may insert into it soon.
        // Removing it would silently lose that state.
        // The count cannot grow while we hold the cache lock.
        // `get_or_init_by_root` clones only under that lock.
        let is_unused = Arc::strong_count(state_map_lock) == 2;

        // Someone may have inserted after the caller released the map lock.
        // `try_lock`, not `try_lock_for`: never wait on a map while holding the cache lock.
        let is_still_empty = state_map_lock
            .try_lock()
            .is_some_and(|state_map| state_map.is_empty());

        if is_same_entry && is_unused && is_still_empty {
            cache.remove(&block_root);
        }
    }

    fn get_by_root(&self, block_root: H256) -> Result<Option<StateMapLock<P>>> {
        self.try_lock_cache()?.get(&block_root).cloned().pipe(Ok)
    }

    fn try_lock_cache(&self) -> Result<MutexGuard<'_, HashMap<H256, StateMapLock<P>>>> {
        let timeout = self.try_lock_timeout;

        self.cache.try_lock_for(timeout).ok_or_else(|| {
            let error = CacheLockError::CacheLockTimeout { timeout };

            if self.log_lock_timeouts.load(Ordering::SeqCst) {
                warn_with_peers!("{error:?}");
            }

            anyhow!(error)
        })
    }

    fn try_lock_map<'map>(
        &self,
        state_map_lock: &'map StateMapLock<P>,
        block_root: H256,
    ) -> Result<MutexGuard<'map, StateMap<P>>> {
        let timeout = self.try_lock_timeout;

        state_map_lock.try_lock_for(timeout).ok_or_else(|| {
            let error = CacheLockError::StateMapLockTimeout {
                block_root,
                timeout,
            };

            if self.log_lock_timeouts.load(Ordering::SeqCst) {
                warn_with_peers!("{error:?}");
            }

            anyhow!(error)
        })
    }
}

#[cfg(test)]
mod tests {
    use types::{phase0::beacon_state::BeaconState as Phase0BeaconState, preset::Minimal};

    use super::*;

    const ROOT_1: H256 = H256::repeat_byte(1);
    const ROOT_2: H256 = H256::repeat_byte(2);
    const ROOT_3: H256 = H256::repeat_byte(3);

    #[test]
    fn test_state_cache_len() -> Result<()> {
        let cache = new_test_cache()?;

        assert_eq!(cache.len()?, 4);

        Ok(())
    }

    #[test]
    fn test_state_cache_before_or_at_slot() -> Result<()> {
        let cache = new_test_cache()?;

        assert_eq!(cache.before_or_at_slot(ROOT_2, 1)?, None);
        assert_eq!(
            cache.before_or_at_slot(ROOT_2, 3)?,
            Some((state_at_slot(3), None))
        );
        assert_eq!(
            cache.before_or_at_slot(ROOT_2, 4)?,
            Some((state_at_slot(3), None))
        );
        assert_eq!(
            cache.before_or_at_slot(ROOT_2, 9)?,
            Some((state_at_slot(5), None))
        );
        assert_eq!(cache.before_or_at_slot(ROOT_3, 9)?, None);

        Ok(())
    }

    #[test]
    fn test_state_cache_get_or_process_with() -> Result<()> {
        let cache = new_test_cache()?;

        let options = QueryOptions {
            ignore_missing_rewards: true,
            store_result_state: true,
        };

        cache.get_or_process_with(ROOT_2, 1, options, || Ok((state_at_slot(1), None)))?;

        assert_eq!(
            cache.before_or_at_slot(ROOT_2, 1)?,
            Some((state_at_slot(1), None))
        );
        assert_eq!(
            cache.before_or_at_slot(ROOT_2, 2)?,
            Some((state_at_slot(2), None))
        );
        assert_eq!(cache.len()?, 5);

        cache.get_or_try_process_with(ROOT_1, 2, options, |pre_state| {
            assert_eq!(pre_state, Some(&(state_at_slot(1), None)));

            Ok(Some((state_at_slot(2), None)))
        })?;

        assert_eq!(
            cache.before_or_at_slot(ROOT_1, 1)?,
            Some((state_at_slot(1), None))
        );
        assert_eq!(
            cache.before_or_at_slot(ROOT_1, 2)?,
            Some((state_at_slot(2), None))
        );
        assert_eq!(cache.len()?, 6);

        Ok(())
    }

    #[test]
    fn test_state_cache_get_or_try_process_with_none_removes_empty_entry() -> Result<()> {
        let cache = new_test_cache()?;

        let result = cache.get_or_try_process_with(ROOT_3, 1, test_options(), |_| Ok(None))?;

        assert_eq!(result, None);
        assert!(!cache.cache.lock().contains_key(&ROOT_3));

        Ok(())
    }

    #[test]
    fn test_state_cache_get_or_try_process_with_none_keeps_entry_in_use() -> Result<()> {
        let cache = new_test_cache()?;

        // Simulates another thread that got the entry but has not inserted yet.
        let other_holder = cache.get_or_init_by_root(ROOT_3)?;

        cache.get_or_try_process_with(ROOT_3, 1, test_options(), |_| Ok(None))?;

        assert!(cache.cache.lock().contains_key(&ROOT_3));

        // Its insert must land in the cache, not in an orphaned map.
        other_holder.lock().insert(1, (state_at_slot(1), None));

        assert_eq!(
            cache.before_or_at_slot(ROOT_3, 1)?,
            Some((state_at_slot(1), None)),
        );

        Ok(())
    }

    #[test]
    fn test_state_cache_get_or_try_process_with_none_keeps_non_empty_entry() -> Result<()> {
        let cache = new_test_cache()?;

        // Slot 0 is before every cached state, so `f` gets no pre-state.
        cache.get_or_try_process_with(ROOT_2, 0, test_options(), |pre_state| {
            assert_eq!(pre_state, None);
            Ok(None)
        })?;

        assert_eq!(
            cache.before_or_at_slot(ROOT_2, 2)?,
            Some((state_at_slot(2), None)),
        );

        Ok(())
    }

    #[test]
    fn test_state_cache_prune() -> Result<()> {
        let cache = new_test_cache()?;

        cache.prune(2, &[].into(), &[].into())?;

        assert_eq!(cache.before_or_at_slot(ROOT_1, 1)?, None);
        assert_eq!(cache.before_or_at_slot(ROOT_2, 2)?, None);
        assert_eq!(
            cache.before_or_at_slot(ROOT_2, 3)?,
            Some((state_at_slot(3), None))
        );
        assert_eq!(
            cache.before_or_at_slot(ROOT_2, 5)?,
            Some((state_at_slot(5), None))
        );

        assert_eq!(cache.len()?, 2);

        cache.insert(ROOT_1, (state_at_slot(1), None))?;
        cache.insert(ROOT_1, (state_at_slot(2), None))?;
        cache.insert(ROOT_2, (state_at_slot(2), None))?;

        cache.prune(2, &[ROOT_1].into(), &[].into())?;

        assert_eq!(
            cache.before_or_at_slot(ROOT_1, 1)?,
            Some((state_at_slot(1), None)),
        );
        assert_eq!(
            cache.before_or_at_slot(ROOT_1, 2)?,
            Some((state_at_slot(2), None)),
        );
        assert_eq!(cache.before_or_at_slot(ROOT_2, 2)?, None);

        assert_eq!(cache.len()?, 4);

        Ok(())
    }

    #[test]
    fn test_state_cache_prune_skips_busy_entry_without_waiting() -> Result<()> {
        let cache = new_test_cache()?;

        let state_map_lock = cache.get_or_init_by_root(ROOT_2)?;
        let busy_guard = state_map_lock.lock();

        let started_at = std::time::Instant::now();
        cache.prune(4, &[].into(), &[].into())?;

        // The lock timeout is 1 s.
        // Anything close to it means prune waited on the busy entry.
        assert!(started_at.elapsed() < Duration::from_millis(500));

        drop(busy_guard);

        // ROOT_1 was free, so it was pruned and removed.
        assert!(!cache.cache.lock().contains_key(&ROOT_1));

        // ROOT_2 was busy, so it was left untouched.
        assert_eq!(
            cache.before_or_at_slot(ROOT_2, 2)?,
            Some((state_at_slot(2), None)),
        );

        // The next prune gets it.
        cache.prune(4, &[].into(), &[].into())?;

        assert_eq!(cache.before_or_at_slot(ROOT_2, 3)?, None);
        assert_eq!(
            cache.before_or_at_slot(ROOT_2, 5)?,
            Some((state_at_slot(5), None)),
        );

        Ok(())
    }

    #[test]
    fn test_state_cache_prune_keeps_emptied_entry_in_use() -> Result<()> {
        let cache = new_test_cache()?;

        // Simulates another thread that got the entry but has not inserted yet.
        let other_holder = cache.get_or_init_by_root(ROOT_1)?;

        // Empties ROOT_1.
        cache.prune(2, &[].into(), &[].into())?;

        assert!(cache.cache.lock().contains_key(&ROOT_1));

        // Its insert must land in the cache, not in an orphaned map.
        other_holder.lock().insert(3, (state_at_slot(3), None));

        assert_eq!(
            cache.before_or_at_slot(ROOT_1, 3)?,
            Some((state_at_slot(3), None)),
        );

        Ok(())
    }

    const fn test_options() -> QueryOptions {
        QueryOptions {
            ignore_missing_rewards: true,
            store_result_state: true,
        }
    }

    fn new_test_cache() -> Result<StateCache<Minimal>> {
        let cache = StateCache::new(Duration::from_secs(1));

        cache.insert(ROOT_1, (state_at_slot(1), None))?;
        cache.insert(ROOT_2, (state_at_slot(2), None))?;
        cache.insert(ROOT_2, (state_at_slot(3), None))?;
        cache.insert(ROOT_2, (state_at_slot(5), None))?;

        Ok(cache)
    }

    fn state_at_slot(slot: Slot) -> Arc<BeaconState<Minimal>> {
        Arc::new(
            Phase0BeaconState {
                slot,
                ..Phase0BeaconState::default()
            }
            .into(),
        )
    }
}
