use core::{hash::Hash, time::Duration};
use std::{collections::HashSet, sync::Arc, time::Instant};

use cached::{Cached, SizedCache, TimedSizedCache};
use eth2_libp2p::PeerId;
use itertools::Itertools as _;
use prometheus_metrics::Metrics;

use crate::{block_sync_service::SyncDirection, misc::RequestId, sync_manager::SyncBatch};

const MAX_ROOT_REQUESTS_PER_KEY: usize = 3;
const REQUEST_BY_RANGE_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_BY_ROOT_TIMEOUT_IN_SECONDS: u64 = 5;

pub struct RangeAndRootRequests<K> {
    requests_by_range: SizedCache<RequestId, (SyncBatch, Instant)>,
    requests_by_root: TimedSizedCache<K, HashSet<PeerId>>,
}

impl<K: Hash + Eq + Clone> Default for RangeAndRootRequests<K> {
    fn default() -> Self {
        Self {
            requests_by_range: SizedCache::with_size(1000),
            requests_by_root: TimedSizedCache::with_size_and_lifespan(
                1000,
                REQUEST_BY_ROOT_TIMEOUT_IN_SECONDS,
            ),
        }
    }
}

impl<K: Hash + Eq + Clone> RangeAndRootRequests<K> {
    pub fn busy_peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.busy_range_peers().chain(self.busy_root_peers())
    }

    pub fn busy_root_peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.requests_by_root
            .value_order()
            .flat_map(|(_, peers)| peers)
            .copied()
    }

    pub fn busy_range_peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.requests_by_range
            .value_order()
            .filter(|(_, time)| time.elapsed() < REQUEST_BY_RANGE_TIMEOUT)
            .map(|(sync_batch, _)| sync_batch.peer_id)
    }

    pub fn record_received_response(&mut self, k: &K, peer_id: &PeerId, request_id: RequestId) {
        if let Some((batch, _)) = self.requests_by_range.cache_get_mut(&request_id) {
            batch.response_received = true;
            return;
        }

        self.requests_by_root
            .cache_get_mut(k)
            .map(|requests| requests.remove(peer_id));
    }

    pub fn add_request_by_range(&mut self, request_id: RequestId, batch: SyncBatch) {
        self.requests_by_range
            .cache_set(request_id, (batch, Instant::now()));
    }

    pub fn add_request_by_root(&mut self, key: K, peer_id: PeerId) -> bool {
        self.requests_by_root
            .cache_get_or_set_with(key, HashSet::new)
            .insert(peer_id)
    }

    pub fn cache_clear(&mut self) {
        self.requests_by_range.cache_clear();
        self.requests_by_root.cache_clear();
    }

    pub fn expired_range_batches(&mut self) -> impl Iterator<Item = (SyncBatch, Instant)> + '_ {
        let expired_keys = self
            .requests_by_range_keys()
            .into_iter()
            .filter(|id| {
                self.requests_by_range
                    .cache_get(id)
                    .is_some_and(|(_, time)| time.elapsed() > REQUEST_BY_RANGE_TIMEOUT)
            })
            .collect_vec();

        expired_keys
            .into_iter()
            .filter_map(|id| self.requests_by_range.cache_remove(&id))
    }

    pub fn ready_to_request_by_range(&mut self) -> bool {
        // self.log_with_feature(format_args!("awaiting responses: {request_count}"));
        self.request_by_range_count() == 0
    }

    pub fn ready_to_request_by_root(&mut self, root: &K, peer_id: Option<PeerId>) -> bool {
        self.requests_by_root.flush();

        let Some(requests) = self.requests_by_root.cache_get(root) else {
            return true;
        };

        if requests.len() >= MAX_ROOT_REQUESTS_PER_KEY {
            return false;
        }

        let Some(peer_id) = peer_id else { return true };

        !requests.contains(&peer_id)
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> impl Iterator<Item = SyncBatch> + '_ {
        let range_keys_to_remove = self
            .requests_by_range_keys()
            .into_iter()
            .filter(|key| {
                self.requests_by_range
                    .cache_get(key)
                    .map(|(batch, _)| &batch.peer_id)
                    == Some(peer_id)
            })
            .collect_vec();

        range_keys_to_remove
            .into_iter()
            .filter_map(|key| self.requests_by_range.cache_remove(&key))
            .map(|(batch, _)| batch)
    }

    pub fn request_direction(&mut self, request_id: RequestId) -> Option<SyncDirection> {
        self.requests_by_range
            .cache_get(&request_id)
            .map(|(batch, _)| batch.direction)
    }

    pub fn request_by_range_count(&mut self) -> usize {
        self.requests_by_range_keys()
            .into_iter()
            .filter(|id| {
                self.requests_by_range
                    .cache_get(id)
                    .is_some_and(|(_, time)| time.elapsed() < REQUEST_BY_RANGE_TIMEOUT)
            })
            .count()
    }

    pub fn request_by_root_count(&mut self) -> usize {
        self.requests_by_root.flush();

        self.requests_by_root.cache_size()
    }

    pub fn request_by_range_finished(
        &mut self,
        request_id: RequestId,
    ) -> Option<(SyncBatch, Instant)> {
        self.requests_by_range.cache_remove(&request_id)
    }

    pub fn requests_by_range_keys(&self) -> Vec<RequestId> {
        self.requests_by_range.key_order().copied().collect()
    }

    pub fn track_collection_metrics(&self, metrics: &Arc<Metrics>) {
        let type_name = tynm::type_name::<Self>();

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "requests_by_root",
            self.requests_by_root.cache_size(),
        );

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "requests_by_range",
            self.requests_by_range.cache_size(),
        );
    }
}
