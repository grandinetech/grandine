/*
 Problem: trying to load states that are older than the finalized checkpoint from the storage
 is time and memory consuming, since states are persisted only at archival epoch intervals.
 And it gets pretty bad when the state at the same slot is requested multiple times in short time periods.

 Solution: cache least recently requested states by slot and prevent concurrent loading of states
 at the same slot from storage.
*/

use core::time::Duration;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use cached::{Cached as _, TimedSizedCache};
use logging::warn_with_peers;
use parking_lot::{Mutex, MutexGuard};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use thiserror::Error;
use types::{combined::BeaconState, phase0::primitives::Slot, preset::Preset};

const CACHE_EXPIRATION: Duration = Duration::from_secs(3600);
const CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1000);
const CACHE_SIZE: usize = 5;

#[derive(Debug, Error)]
enum CacheLockError {
    #[error("could not obtain state at slot cache lock in {} ms", timeout.as_millis())]
    CacheLockTimeout { timeout: Duration },
    #[error("could not obtain state at slot cache lock in {} ms with slot {slot}", timeout.as_millis())]
    StateEntryLockTimeout { slot: Slot, timeout: Duration },
}

type StateEntryMutex<P> = Arc<Mutex<Option<Arc<BeaconState<P>>>>>;
type Cache<P> = TimedSizedCache<Slot, StateEntryMutex<P>>;

pub struct StateAtSlotCache<P: Preset> {
    cache: Mutex<Cache<P>>,
    try_lock_timeout: Duration,
}

impl<P: Preset> StateAtSlotCache<P> {
    #[must_use]
    pub fn build() -> Self {
        Self::new(CACHE_LOCK_TIMEOUT, CACHE_SIZE, CACHE_EXPIRATION)
    }

    #[must_use]
    pub fn new(try_lock_timeout: Duration, cache_size: usize, cache_expiration: Duration) -> Self {
        let cache = TimedSizedCache::with_size_and_lifespan(cache_size, cache_expiration);

        Self {
            cache: Mutex::new(cache),
            try_lock_timeout,
        }
    }

    pub fn flush(&self) -> Result<()> {
        self.try_lock_cache()?.flush();

        Ok(())
    }

    pub fn get_or_try_init<F>(&self, slot: Slot, init: F) -> Result<Option<Arc<BeaconState<P>>>>
    where
        F: FnOnce() -> Result<Option<Arc<BeaconState<P>>>>,
    {
        let state_entry_mutex = self.get_or_init_state_entry_mutex(slot)?;
        let mut state_entry = self.try_lock_state_entry(&state_entry_mutex, slot)?;

        if let Some(state) = state_entry.as_ref() {
            return Ok(Some(state.clone_arc()));
        }

        let state_option = init()?;

        (*state_entry).clone_from(&state_option);

        Ok(state_option)
    }

    #[cfg(test)]
    pub fn get(&self, slot: Slot) -> Result<Option<Arc<BeaconState<P>>>> {
        let state_entry_mutex = self.get_or_init_state_entry_mutex(slot)?;
        let state_entry = self.try_lock_state_entry(&state_entry_mutex, slot)?;

        if let Some(state) = state_entry.as_ref() {
            return Ok(Some(state.clone_arc()));
        }

        Ok(None)
    }

    fn get_or_init_state_entry_mutex(&self, slot: Slot) -> Result<StateEntryMutex<P>> {
        self.try_lock_cache()?
            .cache_get_or_set_with(slot, StateEntryMutex::default)
            .clone_arc()
            .pipe(Ok)
    }

    fn try_lock_cache(&self) -> Result<MutexGuard<'_, Cache<P>>> {
        let timeout = self.try_lock_timeout;

        self.cache.try_lock_for(timeout).ok_or_else(|| {
            let error = CacheLockError::CacheLockTimeout { timeout };

            warn_with_peers!("{error}");

            anyhow!(error)
        })
    }

    fn try_lock_state_entry<'entry>(
        &self,
        state_entry_mutex: &'entry StateEntryMutex<P>,
        slot: Slot,
    ) -> Result<MutexGuard<'entry, Option<Arc<BeaconState<P>>>>> {
        let timeout = self.try_lock_timeout;

        state_entry_mutex.try_lock_for(timeout).ok_or_else(|| {
            let error = CacheLockError::StateEntryLockTimeout { slot, timeout };

            warn_with_peers!("{error}");

            anyhow!(error)
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::bail;
    use types::{phase0::beacon_state::BeaconState as Phase0BeaconState, preset::Minimal};

    use super::*;

    #[test]
    fn test_state_at_slot_cache_get_or_try_init() -> Result<()> {
        let cache = StateAtSlotCache::new(Duration::from_secs(1), 1, Duration::from_secs(1));

        assert_eq!(cache.get(1)?, None);

        assert_eq!(
            cache.get_or_try_init(1, || Ok(Some(state_at_slot(1))))?,
            Some(state_at_slot(1))
        );

        assert_eq!(cache.get(1)?, Some(state_at_slot(1)));

        assert_eq!(
            cache.get_or_try_init(1, || {
                bail!("init should not be called again for the same slot");
            })?,
            Some(state_at_slot(1))
        );

        assert_eq!(cache.get(1)?, Some(state_at_slot(1)));

        assert_eq!(cache.get(2)?, None);

        assert_eq!(
            cache.get_or_try_init(2, || Ok(Some(state_at_slot(2))))?,
            Some(state_at_slot(2))
        );

        assert_eq!(cache.get(2)?, Some(state_at_slot(2)));

        // Since cache size is 1, the state at slot 1 should have been evicted
        assert_eq!(cache.get(1)?, None);

        Ok(())
    }

    #[test]
    fn test_state_at_slot_cache_lock_timeout_error() {
        let cache = StateAtSlotCache::new(Duration::from_millis(1), 1, Duration::from_secs(1));

        // Lock the cache to simulate contention
        let guard = cache.cache.lock();

        let result = cache.get_or_try_init(123, || Ok(Some(state_at_slot(123))));

        match result {
            Err(error) => {
                assert!(error
                    .to_string()
                    .contains("could not obtain state at slot cache lock"))
            }
            _ => panic!("expected an error due to lock timeout"),
        }

        drop(guard);
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
