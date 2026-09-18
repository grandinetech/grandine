use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{collections::HashMap, sync::Arc};

use arc_swap::{ArcSwap, Guard};
use bls::PublicKeyBytes;
use fork_choice_control::Wait;
use itertools::Itertools as _;
use logging::{debug_with_peers, warn_with_peers};
use signer::Signer;
use tokio::sync::Mutex;
use types::{
    phase0::primitives::{Epoch, ValidatorIndex},
    preset::Preset,
};

use crate::misc::ChainSource;

/// Validator indices of the configured keys.
pub struct OwnValidatorIndices {
    signer: Arc<Signer>,
    // Every key the signer holds, with `None` until its index is known. Swapped out whole, as the
    // duty paths read it every slot and a client may hold tens of thousands of keys.
    indices: ArcSwap<HashMap<PublicKeyBytes, Option<ValidatorIndex>>>,
    // Every node reports each finalization, and one request per finalization is enough.
    finalized_epoch: AtomicU64,
    // A failed request is retried every slot; an answered one waits for a finalization.
    last_resolve_failed: AtomicBool,
    // Triggers land together, and a resolve that waits for another finds nothing left to ask.
    resolving: Mutex<()>,
}

impl OwnValidatorIndices {
    #[must_use]
    pub fn new(signer: Arc<Signer>) -> Self {
        Self {
            signer,
            indices: ArcSwap::from_pointee(HashMap::new()),
            finalized_epoch: AtomicU64::new(0),
            last_resolve_failed: AtomicBool::new(false),
            resolving: Mutex::new(()),
        }
    }

    #[must_use]
    pub fn load(&self) -> Guard<Arc<HashMap<PublicKeyBytes, Option<ValidatorIndex>>>> {
        self.indices.load()
    }

    #[must_use]
    pub fn last_resolve_failed(&self) -> bool {
        self.last_resolve_failed.load(Ordering::Relaxed)
    }

    /// The known indices, ascending so that caches keyed by the list see the same list each slot.
    #[must_use]
    pub fn sorted(&self) -> Vec<ValidatorIndex> {
        self.load()
            .values()
            .flatten()
            .copied()
            .sorted()
            .collect_vec()
    }

    /// Follows the signer's keys: new ones enter unresolved, removed ones drop out.
    pub async fn sync_keys<P: Preset, W: Wait + Sync>(&self, chain_source: &ChainSource<P, W>) {
        // Loaded inside, so a swap that lost the race rebuilds from the keys the signer has now.
        self.indices.rcu(|indices| {
            self.signer
                .load()
                .keys()
                .map(|public_key| (*public_key, indices.get(public_key).copied().flatten()))
                .collect::<HashMap<_, _>>()
        });

        self.resolve(chain_source).await;
    }

    /// Asked on a finalization, as only a finalization can make a deposit's validator appear.
    pub async fn resolve_at_finalized_epoch<P: Preset, W: Wait + Sync>(
        &self,
        chain_source: &ChainSource<P, W>,
        finalized_epoch: Epoch,
    ) {
        if self
            .finalized_epoch
            .fetch_max(finalized_epoch, Ordering::Relaxed)
            >= finalized_epoch
        {
            return;
        }

        self.resolve(chain_source).await;
    }

    /// Asks about the keys whose index is not known yet.
    ///
    /// Indices come from the finalized state, so a resolved key is never asked about again.
    pub async fn resolve<P: Preset, W: Wait + Sync>(&self, chain_source: &ChainSource<P, W>) {
        let _resolving = self.resolving.lock().await;

        let to_resolve = self
            .load()
            .iter()
            .filter(|(_, validator_index)| validator_index.is_none())
            .map(|(public_key, _)| *public_key)
            .collect_vec();

        // Cleared first, so a key resolved by another trigger also ends the per-slot retries.
        self.last_resolve_failed.store(false, Ordering::Relaxed);

        if to_resolve.is_empty() {
            return;
        }

        let resolved = match chain_source.validator_indices(&to_resolve).await {
            Ok(resolved) => resolved,
            Err(error) => {
                warn_with_peers!("failed to resolve validator indices: {error:?}");
                self.last_resolve_failed.store(true, Ordering::Relaxed);
                return;
            }
        };

        if resolved.is_empty() {
            return;
        }

        for (public_key, validator_index) in &resolved {
            debug_with_peers!("resolved validator {public_key:?} to index {validator_index}");
        }

        // Only keys still held take an index; a key removed meanwhile stays out.
        self.indices.rcu(|indices| {
            let mut indices = (**indices).clone();

            for (public_key, validator_index) in &resolved {
                if let Some(entry) = indices.get_mut(public_key) {
                    *entry = Some(*validator_index);
                }
            }

            indices
        });
    }
}
