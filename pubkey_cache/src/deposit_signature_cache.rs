use core::num::NonZeroUsize;
use std::{
    collections::HashSet,
    sync::{Mutex, MutexGuard, PoisonError},
};

use bls::SignatureBytes;
use lru::LruCache;
use nonzero_ext::nonzero;
use types::phase0::primitives::H256;

/// Key of a cached deposit signature verification result.
/// The signing root covers the domain too, so results never leak across configurations.
pub type DepositSignatureKey = (H256, SignatureBytes);

/// The maximum number of results kept in [`DepositSignatureCache`], roughly 13 MB.
/// `pending_deposits` is unbounded, so the cache needs a cap. Evicted results are recomputed.
///
/// The literal is 65536. It is hexadecimal to satisfy `clippy::decimal_literal_representation`.
const CACHE_SIZE: NonZeroUsize = nonzero!(0x0001_0000_usize);

/// A cache of `DepositMessage` signature verification results.
/// Filled ahead of the Gloas fork transition as advised in [`specs/gloas/fork.md`].
///
/// [`specs/gloas/fork.md`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/gloas/fork.md
pub struct DepositSignatureCache {
    entries: Mutex<LruCache<DepositSignatureKey, bool>>,
}

impl Default for DepositSignatureCache {
    fn default() -> Self {
        // Build the cache unbounded and cap it afterwards. The unbounded one allocates
        // lazily, whereas `LruCache::new` preallocates room for all `CACHE_SIZE` entries.
        // Nodes on networks without Gloas never use the cache at all.
        let mut entries = LruCache::unbounded();
        entries.resize(CACHE_SIZE);

        Self {
            entries: Mutex::new(entries),
        }
    }
}

impl DepositSignatureCache {
    #[must_use]
    pub fn get(&self, key: &DepositSignatureKey) -> Option<bool> {
        self.lock().get(key).copied()
    }

    pub fn insert(&self, key: DepositSignatureKey, is_valid: bool) {
        self.lock().put(key, is_valid);
    }

    pub fn insert_all(&self, results: impl IntoIterator<Item = (DepositSignatureKey, bool)>) {
        let mut entries = self.lock();

        for (key, is_valid) in results {
            entries.put(key, is_valid);
        }
    }

    /// Returns the subset of `keys` that is not present in the cache, without duplicates.
    #[must_use]
    pub fn missing(
        &self,
        keys: impl IntoIterator<Item = DepositSignatureKey>,
    ) -> Vec<DepositSignatureKey> {
        let mut entries = self.lock();
        let mut seen = HashSet::new();
        let mut missing = Vec::new();

        for key in keys {
            if entries.get(&key).is_none() && seen.insert(key) {
                missing.push(key);
            }
        }

        missing
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> MutexGuard<'_, LruCache<DepositSignatureKey, bool>> {
        // A panic while the lock is held cannot leave the cache in an invalid state.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
