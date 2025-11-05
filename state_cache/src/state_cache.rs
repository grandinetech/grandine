use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{collections::HashSet, sync::Arc};

use anyhow::{anyhow, Result};
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
    phase0::primitives::{Slot, H256},
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

        if let Some((state, rewards)) = pre_state {
            if state.slot() >= slot {
                if rewards.is_some() || options.ignore_missing_rewards {
                    return Ok((state.clone_arc(), *rewards));
                }

                info_with_peers!(
                    "recomputing state cache entry for block {block_root:?} at slot {slot} \
                     because block rewards are missing",
                );
            }
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

        if let Some((state, rewards)) = pre_state {
            if state.slot() >= slot {
                if rewards.is_some() || options.ignore_missing_rewards {
                    return Ok(Some((state.clone_arc(), *rewards)));
                }

                info_with_peers!(
                    "recomputing state cache entry for block {block_root:?} at slot {slot} \
                     because block rewards are missing",
                );
            }
        }

        match f(pre_state)? {
            Some((post_state, rewards)) => {
                if options.store_result_state {
                    state_map_guard.insert(post_state.slot(), (post_state.clone_arc(), rewards));
                }

                Ok(Some((post_state, rewards)))
            }
            None => {
                if state_map_guard.is_empty() {
                    self.try_lock_cache()?.remove(&block_root);
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
        for (block_root, state_map_lock) in self.all_state_map_locks()? {
            let mut state_map = match self.try_lock_map(&state_map_lock, block_root) {
                Ok(state_map) => state_map,
                Err(error) => {
                    warn_with_peers!("failed to prune beacon state cache: {error:?}");
                    continue;
                }
            };

            if preserved_older_states.contains(&block_root) {
                continue;
            }

            if pruned_newer_states.contains(&block_root) {
                state_map.clear();
                continue;
            }

            let (_, retained) = state_map.split(&last_pruned_slot);
            *state_map = retained;
        }

        self.try_lock_cache()?.retain(|block_root, state_map_lock| {
            self.try_lock_map(state_map_lock, *block_root)
                .ok()
                .is_some_and(|state_map| !state_map.is_empty())
        });

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
