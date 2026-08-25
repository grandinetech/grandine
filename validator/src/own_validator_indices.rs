use std::sync::Arc;

use bls::PublicKeyBytes;
use fork_choice_control::Wait;
use itertools::Itertools as _;
use scc::HashMap as SccHashMap;
use signer::Signer;
use tokio::sync::Mutex;
use types::{
    phase0::primitives::{Epoch, ValidatorIndex},
    preset::Preset,
};

use crate::{beacon_node_api::BeaconNodeApi as _, beacon_nodes::BeaconNodes};

/// Validator indices of the configured keys.
pub struct OwnValidatorIndices {
    signer: Arc<Signer>,
    indices: SccHashMap<PublicKeyBytes, ValidatorIndex>,
    // A key no beacon node knows is retried once an epoch rather than every slot, as a validator
    // only becomes known by being deposited for.
    retry_at_epoch: SccHashMap<PublicKeyBytes, Epoch>,
    // Taken without waiting, so a resolution in flight never stalls a duty behind its requests.
    resolving: Mutex<()>,
}

impl OwnValidatorIndices {
    #[must_use]
    pub fn new(signer: Arc<Signer>) -> Self {
        Self {
            signer,
            indices: SccHashMap::new(),
            retry_at_epoch: SccHashMap::new(),
            resolving: Mutex::new(()),
        }
    }

    /// Resolves the keys whose indices are not known yet.
    ///
    /// An index never changes, so a resolved key is never asked about again.
    pub async fn update<P: Preset, W: Wait + Sync>(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        current_epoch: Epoch,
    ) {
        // Another caller resolving means the same keys are already being asked about; duties use
        // whatever is resolved by the time they read.
        let Ok(_guard) = self.resolving.try_lock() else {
            return;
        };

        let public_keys = self.keys_to_resolve(current_epoch).await;

        if public_keys.is_empty() {
            return;
        }

        // Nothing is recorded when the request fails, so keys the beacon nodes could not be asked
        // about are tried again in the same epoch rather than waiting for the next one.
        let Ok(resolved) = beacon_nodes.validator_indices(&public_keys).await else {
            return;
        };

        for public_key in public_keys {
            match resolved.get(&public_key) {
                Some(validator_index) => {
                    self.indices
                        .upsert_async(public_key, *validator_index)
                        .await;

                    self.retry_at_epoch.remove_async(&public_key).await;
                }
                None => {
                    self.retry_at_epoch
                        .upsert_async(public_key, current_epoch.saturating_add(1))
                        .await;
                }
            }
        }
    }

    /// The indices resolved so far, ascending so that the same validator is asked about every time.
    ///
    /// Keys removed at runtime are filtered out rather than evicted, as an index that was resolved
    /// once stays correct if the key is imported again.
    pub async fn get(&self) -> Vec<ValidatorIndex> {
        let signer_snapshot = self.signer.load();
        let mut indices = vec![];

        self.indices
            .iter_async(|public_key, validator_index| {
                if signer_snapshot.has_key(*public_key) {
                    indices.push(*validator_index);
                }

                true
            })
            .await;

        indices.into_iter().sorted().collect()
    }

    async fn keys_to_resolve(&self, current_epoch: Epoch) -> Vec<PublicKeyBytes> {
        let public_keys = self.signer.load().keys().copied().collect_vec();
        let mut to_resolve = vec![];

        for public_key in public_keys {
            if self.indices.contains_async(&public_key).await {
                continue;
            }

            let due = self
                .retry_at_epoch
                .get_async(&public_key)
                .await
                .is_none_or(|entry| current_epoch >= *entry.get());

            if due {
                to_resolve.push(public_key);
            }
        }

        to_resolve
    }
}
