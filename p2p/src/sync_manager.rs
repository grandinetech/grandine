#![allow(
    clippy::multiple_inherent_impl,
    reason = "https://github.com/rust-lang/rust-clippy/issues/13040"
)]

use core::{fmt::Display, hash::Hash, num::NonZeroUsize, ops::Range, time::Duration};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Instant,
};

use anyhow::Result;
use arithmetic::NonZeroExt as _;
use cached::{Cached as _, TimedSizedCache};
use eth1_api::RealController;
use eth2_libp2p::{rpc::StatusMessage, PeerId};
use helper_functions::misc;
use itertools::Itertools as _;
use log::{log, Level};
use lru::LruCache;
use prometheus_metrics::Metrics;
use rand::{prelude::SliceRandom, seq::IteratorRandom as _, thread_rng};
use typenum::Unsigned as _;
use types::{
    config::Config,
    deneb::containers::BlobIdentifier,
    phase0::primitives::{Epoch, Slot, H256},
    preset::Preset,
};

use crate::{
    block_sync_service::SyncDirection, misc::RequestId,
    range_and_root_requests::RangeAndRootRequests,
};

#[derive(PartialEq, Eq, Hash, Debug)]
struct ChainId {
    finalized_root: H256,
    finalized_epoch: Epoch,
}

impl From<&StatusMessage> for ChainId {
    fn from(status: &StatusMessage) -> Self {
        Self {
            finalized_root: status.finalized_root,
            finalized_epoch: status.finalized_epoch,
        }
    }
}

const BATCHES_PER_PEER: usize = 1;
const EPOCHS_PER_REQUEST: u64 = if cfg!(test) {
    2
} else {
    // max 32
    1
};
const MAX_SYNC_DISTANCE_IN_SLOTS: u64 = 10000;
const NOT_ENOUGH_PEERS_MESSAGE_COOLDOWN: Duration = Duration::from_secs(10);
const PEER_UPDATE_COOLDOWN_IN_SECONDS: u64 = 12;
const SEQUENTIAL_REDOWNLOADS_TILL_RESET: usize = 5;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum SyncTarget {
    BlobSidecar,
    Block,
}

#[derive(Clone, Copy, Debug)]
pub struct SyncBatch {
    pub target: SyncTarget,
    pub direction: SyncDirection,
    pub peer_id: PeerId,
    pub start_slot: Slot,
    pub count: u64,
    pub retry_count: usize,
    pub response_received: bool,
}

pub struct SyncManager {
    peers: HashMap<PeerId, StatusMessage>,
    blob_requests: RangeAndRootRequests<BlobIdentifier>,
    block_requests: RangeAndRootRequests<H256>,
    last_sync_head: Slot,
    last_sync_range: Range<Slot>,
    sequential_redownloads: usize,
    status_updates_cache: TimedSizedCache<Epoch, ()>,
    not_enough_peers_message_shown_at: Option<Instant>,
    sync_from_finalized: bool,
    // store peers that don't serve blocks prior to `MIN_EPOCHS_FOR_BLOCK_REQUESTS`
    // so that we can filter them when back-syncing
    back_sync_black_list: LruCache<PeerId, ()>,
}

impl SyncManager {
    pub fn new(target_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            blob_requests: RangeAndRootRequests::<BlobIdentifier>::default(),
            block_requests: RangeAndRootRequests::<H256>::default(),
            last_sync_range: 0..0,
            last_sync_head: 0,
            sequential_redownloads: 0,
            status_updates_cache: TimedSizedCache::with_size_and_lifespan(
                5,
                PEER_UPDATE_COOLDOWN_IN_SECONDS,
            ),
            not_enough_peers_message_shown_at: None,
            sync_from_finalized: false,
            back_sync_black_list: LruCache::new(
                NonZeroUsize::new(target_peers).expect("target_peers must be be a nonzero"),
            ),
        }
    }

    pub fn record_received_blob_sidecar_response(
        &mut self,
        blob_identifier: BlobIdentifier,
        peer_id: PeerId,
        request_id: RequestId,
    ) {
        self.blob_requests
            .record_received_response(&blob_identifier, &peer_id, request_id);
    }

    pub fn record_received_block_response(
        &mut self,
        block_root: H256,
        peer_id: PeerId,
        request_id: RequestId,
    ) {
        self.block_requests
            .record_received_response(&block_root, &peer_id, request_id);
    }

    pub fn request_direction(&mut self, request_id: RequestId) -> Option<SyncDirection> {
        self.block_requests
            .request_direction(request_id)
            .or_else(|| self.blob_requests.request_direction(request_id))
    }

    pub fn add_peer(&mut self, peer_id: PeerId, status: StatusMessage) {
        self.log(
            Level::Debug,
            format_args!("add peer (peer_id: {peer_id}, status: {status:?})"),
        );

        self.peers.insert(peer_id, status);
    }

    pub fn add_peer_to_back_sync_black_list(&mut self, peer_id: PeerId) {
        self.log(
            Level::Debug,
            format_args!(
                "adding peer to a back-sync blacklist: {peer_id}, black-listed peers: {}",
                self.back_sync_black_list.len()
            ),
        );

        self.back_sync_black_list.put(peer_id, ());
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Vec<SyncBatch> {
        self.log(
            Level::Debug,
            format_args!("remove peer (peer_id: {peer_id})"),
        );

        self.peers.remove(peer_id);
        self.back_sync_black_list.pop(peer_id);

        self.block_requests
            .remove_peer(peer_id)
            .chain(self.blob_requests.remove_peer(peer_id))
            .collect_vec()
    }

    pub fn retry_batch(
        &mut self,
        request_id: RequestId,
        batch: SyncBatch,
        use_black_list: bool,
    ) -> Option<PeerId> {
        let peer = self.random_peer(use_black_list);

        self.log(
            Level::Debug,
            format_args!("retrying batch {batch:?}, new peer: {peer:?}, request_id: {request_id}"),
        );

        match peer {
            Some(peer_id) => {
                let batch = SyncBatch {
                    target: batch.target,
                    direction: batch.direction,
                    peer_id,
                    start_slot: batch.start_slot,
                    count: batch.count,
                    retry_count: batch.retry_count + 1,
                    response_received: false,
                };

                match batch.target {
                    SyncTarget::BlobSidecar => self.add_blob_request_by_range(request_id, batch),
                    SyncTarget::Block => self.add_block_request_by_range(request_id, batch),
                }
            }
            None => {
                if self
                    .not_enough_peers_message_shown_at
                    .map(|instant| instant.elapsed() > NOT_ENOUGH_PEERS_MESSAGE_COOLDOWN)
                    .unwrap_or(true)
                {
                    self.log(
                        Level::Warn,
                        format_args!("not enough non-busy peers to retry batch: {batch:?}"),
                    );
                    self.not_enough_peers_message_shown_at = Some(Instant::now());
                }
            }
        }

        peer
    }

    pub fn build_back_sync_batches<P: Preset>(
        &mut self,
        blob_serve_range_slot: Slot,
        mut current_back_sync_slot: Slot,
        low_slot: Slot,
    ) -> Vec<SyncBatch> {
        let Some(peers_to_sync) = self.find_peers_to_sync(true) else {
            return vec![];
        };

        // Use half of the available peers for back-sync batches.
        let max_sync_batches = peers_to_sync.len() / 2;
        let mut peers = peers_to_sync.iter();
        let mut sync_batches = vec![];

        while let Some(peer) = peers.next() {
            let should_batch_blobs = current_back_sync_slot > blob_serve_range_slot;

            let count = if should_batch_blobs {
                P::SlotsPerEpoch::non_zero().get()
            } else {
                P::SlotsPerEpoch::non_zero().get() * EPOCHS_PER_REQUEST
            };

            let start_slot = current_back_sync_slot.saturating_sub(count);

            if should_batch_blobs {
                match peers.next() {
                    Some(next_peer) => {
                        // test if there is enough space for both blobs and blocks batches
                        if sync_batches.len() + 2 > max_sync_batches {
                            break;
                        }

                        let mut start_slot = start_slot;
                        let mut count = count;

                        if start_slot < blob_serve_range_slot {
                            count = (start_slot + count)
                                .checked_sub(blob_serve_range_slot)
                                .unwrap_or(1);

                            start_slot = blob_serve_range_slot;
                        };

                        let batch = SyncBatch {
                            target: SyncTarget::BlobSidecar,
                            direction: SyncDirection::Back,
                            peer_id: *next_peer,
                            start_slot,
                            count,
                            response_received: false,
                            retry_count: 0,
                        };

                        self.log(
                            Level::Debug,
                            format_args!("back-sync batch built: {batch:?})"),
                        );

                        sync_batches.push(batch);
                    }
                    None => break,
                }
            }

            let batch = SyncBatch {
                target: SyncTarget::Block,
                direction: SyncDirection::Back,
                peer_id: *peer,
                start_slot,
                count,
                response_received: false,
                retry_count: 0,
            };

            self.log(
                Level::Debug,
                format_args!("back-sync batch built: {batch:?})"),
            );

            sync_batches.push(batch);

            if start_slot <= low_slot || sync_batches.len() >= max_sync_batches {
                break;
            }

            current_back_sync_slot = start_slot;
        }

        self.log(
            Level::Debug,
            format_args!("new back-sync batches count: {}", sync_batches.len(),),
        );

        sync_batches
    }

    #[expect(clippy::too_many_lines)]
    pub fn build_forward_sync_batches<P: Preset>(
        &mut self,
        config: &Config,
        current_slot: Slot,
        local_head_slot: Slot,
        local_finalized_slot: Slot,
    ) -> Result<Vec<SyncBatch>> {
        let Some(peers_to_sync) = self.find_peers_to_sync(false) else {
            return Ok(vec![]);
        };

        let Some(remote_head_slot) = self.max_remote_head_slot(&peers_to_sync) else {
            return Ok(vec![]);
        };

        if remote_head_slot <= local_head_slot {
            self.log(
                Level::Debug,
                format_args!(
                    "remote peers have no new slots (local_head_slot: {local_head_slot}, \
                    remote_head_slot: {remote_head_slot})",
                ),
            );

            return Ok(vec![]);
        }

        let slots_per_request = P::SlotsPerEpoch::non_zero().get() * EPOCHS_PER_REQUEST;

        let mut redownloads_increased = false;

        if self.sync_from_finalized && self.last_sync_range.end >= local_head_slot {
            self.sync_from_finalized = false;
        }

        let sync_start_slot = {
            if self.sync_from_finalized {
                self.last_sync_range.end + 1
            } else if local_head_slot <= self.last_sync_head {
                self.log(Level::Debug, "local head not progressing");
                self.sequential_redownloads += 1;
                redownloads_increased = true;

                if self.sequential_redownloads >= SEQUENTIAL_REDOWNLOADS_TILL_RESET {
                    // Redownload failed 5 times, time to redownload blocks from last finalized slot
                    self.sequential_redownloads = 0;
                    self.sync_from_finalized = true;
                    local_finalized_slot + 1
                } else {
                    // If head slot has not changed since last sync,
                    // re-download everything from local head slot minus backtrack distance
                    local_head_slot.saturating_sub(P::SlotsPerEpoch::U64) + 1
                }
            } else {
                // Resume download from last sync batch end slot
                self.sequential_redownloads = 0;
                core::cmp::max(self.last_sync_range.end, local_head_slot) + 1
            }
        };

        self.log(
            Level::Debug,
            format_args!(
                "sequential redownloads: {}, \
                local finalized slot: {local_finalized_slot}, \
                local head slot: {local_head_slot}, \
                last sync head: {}, \
                remote head slot: {remote_head_slot}, \
                last sync range: {:?}, \
                sync start slot: {sync_start_slot},",
                self.sequential_redownloads, self.last_sync_head, self.last_sync_range,
            ),
        );

        self.last_sync_head = local_head_slot;

        if sync_start_slot >= local_head_slot + MAX_SYNC_DISTANCE_IN_SLOTS {
            return Ok(vec![]);
        }

        if remote_head_slot <= sync_start_slot {
            if redownloads_increased {
                self.sequential_redownloads = self.sequential_redownloads.saturating_sub(1);
            }

            self.log(
                Level::Debug,
                format_args!(
                    "remote peers have no new slots (sync_start_slot: {sync_start_slot}, \
                    remote_head_slot: {remote_head_slot})",
                ),
            );

            return Ok(vec![]);
        }

        let slot_distance = remote_head_slot.saturating_sub(sync_start_slot);
        let batches_in_front = usize::try_from(slot_distance / slots_per_request + 1)?;

        let mut max_slot = local_head_slot;
        let blob_serve_range_slot = misc::blob_serve_range_slot::<P>(config, current_slot);

        let mut sync_batches = vec![];
        for (peer_id, index) in Self::peer_sync_batch_assignments(&peers_to_sync)
            .zip(0..)
            .take(batches_in_front)
        {
            let start_slot = sync_start_slot + slots_per_request * index;
            let count = remote_head_slot.saturating_sub(start_slot) + 1;
            let count = count.min(slots_per_request);

            max_slot = start_slot + count - 1;

            if blob_serve_range_slot < max_slot {
                sync_batches.push(SyncBatch {
                    target: SyncTarget::BlobSidecar,
                    direction: SyncDirection::Forward,
                    peer_id,
                    start_slot,
                    count,
                    response_received: false,
                    retry_count: 0,
                });
            }

            sync_batches.push(SyncBatch {
                target: SyncTarget::Block,
                direction: SyncDirection::Forward,
                peer_id,
                start_slot,
                count,
                response_received: false,
                retry_count: 0,
            });
        }

        self.log(
            Level::Debug,
            format_args!("new sync batches count: {}", sync_batches.len()),
        );

        self.last_sync_range = sync_start_slot..max_slot;

        Ok(sync_batches)
    }

    pub fn ready_to_request_by_range(&mut self) -> bool {
        self.block_requests.ready_to_request_by_range()
            && self.blob_requests.ready_to_request_by_range()
    }

    pub fn ready_to_request_block_by_root(
        &mut self,
        block_root: H256,
        peer_id: Option<PeerId>,
    ) -> bool {
        self.block_requests
            .ready_to_request_by_root(&block_root, peer_id)
    }

    pub fn add_blob_request_by_range(&mut self, request_id: RequestId, batch: SyncBatch) {
        self.log(
            Level::Debug,
            format_args!(
                "add blob request by range (request_id: {}, peer_id: {}, range: {:?}, retries: {})",
                request_id,
                batch.peer_id,
                (batch.start_slot..(batch.start_slot + batch.count)),
                batch.retry_count,
            ),
        );

        self.blob_requests.add_request_by_range(request_id, batch)
    }

    pub fn add_blobs_request_by_root(
        &mut self,
        blob_identifiers: Vec<BlobIdentifier>,
        peer_id: PeerId,
    ) -> Vec<BlobIdentifier> {
        self.log(Level::Debug, format_args!(
            "add blobs request by root (blob_identifiers: {blob_identifiers:?}, peer_id: {peer_id})",
        ));

        blob_identifiers
            .into_iter()
            .filter(|blob_id| self.blob_requests.add_request_by_root(*blob_id, peer_id))
            .collect_vec()
    }

    pub fn add_block_request_by_range(&mut self, request_id: RequestId, batch: SyncBatch) {
        self.log(
            Level::Debug,
            format_args!(
                "add block request by range (request_id: {}, peer_id: {}, range: {:?}, retries: {})",
                request_id,
                batch.peer_id,
                (batch.start_slot..(batch.start_slot + batch.count)),
                batch.retry_count,
            ),
        );

        self.block_requests.add_request_by_range(request_id, batch)
    }

    pub fn add_block_request_by_root(&mut self, block_root: H256, peer_id: PeerId) -> bool {
        self.log(
            Level::Debug,
            format_args!(
                "add block request by root (block_root: {block_root:?}, peer_id: {peer_id})",
            ),
        );

        self.block_requests.add_request_by_root(block_root, peer_id)
    }

    pub fn random_peer(&self, use_black_list: bool) -> Option<PeerId> {
        let chain_id = self.chain_to_sync(use_black_list)?;

        let busy_peers = self
            .blob_requests
            .busy_peers()
            .chain(self.block_requests.busy_peers())
            .collect::<HashSet<PeerId>>();

        self.peers(use_black_list)
            .filter(|(peer_id, status)| {
                ChainId::from(*status) == chain_id && !busy_peers.contains(peer_id)
            })
            .map(|(&peer_id, _)| peer_id)
            .choose(&mut thread_rng())
    }

    pub fn blobs_by_range_request_finished(
        &mut self,
        request_id: RequestId,
        request_direction: Option<SyncDirection>,
    ) {
        self.log(
            Level::Debug,
            format_args!("request blob sidecars by range finished (request_id: {request_id})",),
        );

        if let Some((sync_batch, _)) = self.blob_requests.request_by_range_finished(request_id) {
            self.log(
                Level::Debug,
                format_args!(
                    "blob sidecars by range request stats: responses received: {}, count: {}, \
                    direction {request_direction:?}, retries: {}",
                    sync_batch.response_received, sync_batch.count, sync_batch.retry_count,
                ),
            );

            if request_direction == Some(SyncDirection::Back) && !sync_batch.response_received {
                self.retry_batch(request_id, sync_batch, true);
            }
        }
    }

    pub fn blocks_by_range_request_finished<P: Preset>(
        &mut self,
        controller: &RealController<P>,
        peer_id: PeerId,
        request_id: RequestId,
        request_direction: Option<SyncDirection>,
    ) {
        self.log(
            Level::Debug,
            format_args!("request blocks by range finished (request_id: {request_id})"),
        );

        if let Some((sync_batch, _)) = self.block_requests.request_by_range_finished(request_id) {
            self.log(
                Level::Debug,
                format_args!(
                    "blocks by range request stats: responses received: {}, count: {}, \
                    direction {request_direction:?}, retries: {}",
                    sync_batch.response_received, sync_batch.count, sync_batch.retry_count,
                ),
            );

            if request_direction == Some(SyncDirection::Back) && !sync_batch.response_received {
                if misc::compute_epoch_at_slot::<P>(sync_batch.start_slot + sync_batch.count)
                    < controller.min_checked_block_availability_epoch()
                {
                    self.add_peer_to_back_sync_black_list(peer_id);
                }

                self.retry_batch(request_id, sync_batch, true);
            }
        }
    }

    /// Log a message with peer count information.
    fn log(&self, level: Level, message: impl Display) {
        log!(
            level,
            "[Sync Peers: {}/{}] {}",
            self.most_peers(false),
            self.total_peers(),
            message
        );
    }

    fn find_peers_to_sync(&mut self, use_black_list: bool) -> Option<Vec<PeerId>> {
        self.find_chain_to_sync(use_black_list).map(|chain_id| {
            let peers_to_sync = self.chain_peers_shuffled(&chain_id, use_black_list);

            let busy_peers = self
                .blob_requests
                .busy_peers()
                .chain(self.block_requests.busy_peers())
                .collect::<HashSet<PeerId>>();

            let peers_to_sync = peers_to_sync
                .iter()
                .filter(|peer_id| !busy_peers.contains(peer_id))
                .copied()
                .collect::<Vec<_>>();

            self.log(
                Level::Debug,
                format_args!("peers to sync count: {}", peers_to_sync.len()),
            );

            peers_to_sync
        })
    }

    fn find_chain_to_sync(&mut self, use_black_list: bool) -> Option<ChainId> {
        match self.chain_to_sync(use_black_list) {
            Some(chain_id) => {
                self.log(
                    Level::Debug,
                    format_args!(
                        "selected chain to sync (finalized root {:?}, finalized epoch {})",
                        chain_id.finalized_root, chain_id.finalized_epoch,
                    ),
                );

                Some(chain_id)
            }
            None => {
                if self
                    .not_enough_peers_message_shown_at
                    .map(|instant| instant.elapsed() > NOT_ENOUGH_PEERS_MESSAGE_COOLDOWN)
                    .unwrap_or(true)
                {
                    self.log(Level::Debug, "waiting for more peers to join to start sync");
                    self.not_enough_peers_message_shown_at = Some(Instant::now());
                }

                None
            }
        }
    }

    fn chain_peers(&self, chain_id: &ChainId, use_black_list: bool) -> Vec<PeerId> {
        self.peers(use_black_list)
            .filter(|(_, status)| &ChainId::from(*status) == chain_id)
            .map(|(&peer_id, _)| peer_id)
            .collect()
    }

    fn chain_peers_shuffled(&self, chain_id: &ChainId, use_black_list: bool) -> Vec<PeerId> {
        let mut peers = self.chain_peers(chain_id, use_black_list);
        peers.shuffle(&mut thread_rng());
        peers
    }

    fn chain_to_sync(&self, use_black_list: bool) -> Option<ChainId> {
        self.chains_with_peer_counts(use_black_list)
            .into_keys()
            .choose(&mut thread_rng())
    }

    fn peers(&self, use_black_list: bool) -> impl Iterator<Item = (&PeerId, &StatusMessage)> {
        self.peers.iter().filter(move |(&peer_id, _)| {
            use_black_list
                .then(|| !self.back_sync_black_list.contains(&peer_id))
                .unwrap_or(true)
        })
    }

    fn chains_with_peer_counts(&self, use_black_list: bool) -> HashMap<ChainId, usize> {
        self.peers(use_black_list)
            .counts_by(|(_, status)| status.into())
    }

    fn most_peers(&self, use_black_list: bool) -> usize {
        self.chains_with_peer_counts(use_black_list)
            .values()
            .max()
            .copied()
            .unwrap_or_default()
    }

    fn total_peers(&self) -> usize {
        self.peers.len()
    }

    fn max_remote_head_slot(&self, peers: &[PeerId]) -> Option<Slot> {
        peers
            .iter()
            .filter_map(|peer_id| self.peers.get(peer_id))
            .map(|status| status.head_slot)
            .max()
    }

    fn peer_sync_batch_assignments(peers: &[PeerId]) -> impl Iterator<Item = PeerId> + '_ {
        core::iter::repeat(peers)
            .take(BATCHES_PER_PEER)
            .flatten()
            .copied()
    }

    pub fn expired_blob_range_batches(
        &mut self,
    ) -> impl Iterator<Item = (SyncBatch, Instant)> + '_ {
        self.blob_requests.expired_range_batches()
    }

    pub fn expired_block_range_batches(
        &mut self,
    ) -> impl Iterator<Item = (SyncBatch, Instant)> + '_ {
        self.block_requests.expired_range_batches()
    }

    pub fn cache_clear(&mut self) {
        self.blob_requests.cache_clear();
        self.block_requests.cache_clear();
    }

    pub fn track_collection_metrics(&self, metrics: &Arc<Metrics>) {
        let type_name = tynm::type_name::<Self>();

        metrics.set_collection_length(module_path!(), &type_name, "peers", self.peers.len());
        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "status_updates_cache",
            self.status_updates_cache.cache_size(),
        );

        // TODO: Differentiate
        self.blob_requests.track_collection_metrics(metrics);
        self.block_requests.track_collection_metrics(metrics);
    }
}

#[cfg(test)]
impl SyncManager {
    pub fn add_blobs_by_range_busy_peer(&mut self, peer_id: PeerId) {
        self.blob_requests.add_request_by_range(
            1,
            SyncBatch {
                target: SyncTarget::BlobSidecar,
                direction: SyncDirection::Back,
                peer_id,
                start_slot: 0,
                count: 64,
                retry_count: 0,
                response_received: false,
            },
        );
    }

    pub fn add_blobs_by_root_busy_peer(&mut self, peer_id: PeerId) {
        self.blob_requests.add_request_by_root(
            BlobIdentifier {
                block_root: H256::zero(),
                index: 0,
            },
            peer_id,
        );
    }

    pub fn add_blocks_by_range_busy_peer(&mut self, peer_id: PeerId) {
        self.block_requests.add_request_by_range(
            2,
            SyncBatch {
                target: SyncTarget::Block,
                direction: SyncDirection::Back,
                peer_id,
                start_slot: 0,
                count: 64,
                retry_count: 0,
                response_received: false,
            },
        );
    }

    pub fn add_blocks_by_root_busy_peer(&mut self, peer_id: PeerId) {
        self.block_requests
            .add_request_by_root(H256::zero(), peer_id);
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;
    use types::{
        phase0::primitives::H32,
        preset::{Mainnet, Minimal},
    };

    use super::*;

    // `SyncBatch.count` is either 2 (blocks & blobs) or 16 (blocks only) because the test cases use `Minimal`.
    // `Minimal::SlotsPerEpoch::U64` × `EPOCHS_PER_REQUEST` = 8 × 2 = 16.
    // `Minimal::SlotsPerEpoch::U64` = 8
    #[test_case(
        Slot::MAX,
        128,
        [
            (112, 16, SyncTarget::Block),
            (96, 16, SyncTarget::Block),
            (80, 16, SyncTarget::Block),
            (64, 16, SyncTarget::Block),
            (48, 16, SyncTarget::Block),
        ]
    )]
    #[test_case(
        Slot::MAX,
        64,
        [
            (48, 16, SyncTarget::Block),
            (32, 16, SyncTarget::Block),
            (16, 16, SyncTarget::Block),
            (0, 16, SyncTarget::Block),
        ]
    )]
    #[test_case(
        Slot::MAX,
        30,
        [
            (14, 16, SyncTarget::Block),
            (0, 16, SyncTarget::Block),
        ]
    )]
    #[test_case(
        0,
        64,
        [
            (56, 8, SyncTarget::BlobSidecar),
            (56, 8, SyncTarget::Block),
            (48, 8, SyncTarget::BlobSidecar),
            (48, 8, SyncTarget::Block),
        ]
    )]
    #[test_case(
        62,
        64,
        [
            (62, 2, SyncTarget::BlobSidecar),
            (56, 8, SyncTarget::Block),
            (40, 16, SyncTarget::Block),
            (24, 16, SyncTarget::Block),
            (8, 16, SyncTarget::Block),
        ]
    )]
    #[test_case(
        59,
        68,
        [
            (60, 8, SyncTarget::BlobSidecar),
            (60, 8, SyncTarget::Block),
            (59, 1, SyncTarget::BlobSidecar),
            (52, 8, SyncTarget::Block),
            (36, 16, SyncTarget::Block),
        ]
    )]
    #[test_case(
        0,
        9,
        [
            (1, 8, SyncTarget::BlobSidecar),
            (1, 8, SyncTarget::Block),
            (0, 8, SyncTarget::BlobSidecar),
            (0, 8, SyncTarget::Block),
        ]
    )]
    fn build_back_sync_batches(
        blob_serve_start_slot: Slot,
        head_slot: Slot,
        resulting_batches: impl IntoIterator<Item = (Slot, u64, SyncTarget)>,
    ) {
        let peer_status = StatusMessage {
            fork_digest: H32::default(),
            finalized_root: H256::default(),
            finalized_epoch: 0,
            head_root: H256::default(),
            head_slot,
        };

        let mut sync_manager = SyncManager::new(100);

        // Add 10 valid peers.
        // This will indirectly test that half of them are used for back-syncing (5 batches).
        for _ in 0..10 {
            sync_manager.add_peer(PeerId::random(), peer_status);
        }

        // Add one peer to a blacklist
        sync_manager.add_peer_to_back_sync_black_list(PeerId::random());

        // Have some peers busy
        sync_manager.add_blobs_by_range_busy_peer(PeerId::random());
        sync_manager.add_blobs_by_root_busy_peer(PeerId::random());
        sync_manager.add_blocks_by_range_busy_peer(PeerId::random());
        sync_manager.add_blocks_by_root_busy_peer(PeerId::random());

        let batches =
            sync_manager.build_back_sync_batches::<Minimal>(blob_serve_start_slot, head_slot, 0);

        itertools::assert_equal(
            batches
                .into_iter()
                .map(|batch| (batch.start_slot, batch.count, batch.target)),
            resulting_batches,
        );
    }

    #[test]
    fn test_build_forward_sync_batches_when_head_progresses() -> Result<()> {
        let config = Config::mainnet();
        let current_slot = 20_001;
        let local_head_slot = 3000;
        let local_finalized_slot = 1000;
        let slots_per_request = EPOCHS_PER_REQUEST * <Mainnet as Preset>::SlotsPerEpoch::U64;

        let peer_status = StatusMessage {
            fork_digest: H32::default(),
            finalized_root: H256::default(),
            finalized_epoch: 248,
            head_root: H256::default(),
            head_slot: 20_000,
        };

        let mut sync_manager = SyncManager::new(100);

        sync_manager.add_peer(PeerId::random(), peer_status);

        for i in 0..50 {
            let batches = sync_manager.build_forward_sync_batches::<Mainnet>(
                &config,
                current_slot,
                local_head_slot + i,
                local_finalized_slot,
            )?;

            let sync_range_from = local_head_slot + slots_per_request * i + 1;
            let sync_range_to = sync_range_from + slots_per_request - 1;

            assert_eq!(sync_manager.last_sync_range, sync_range_from..sync_range_to);

            let first_batch = batches.first().expect("sync batches should be present");

            assert_eq!(first_batch.direction, SyncDirection::Forward);
            assert_eq!(first_batch.target, SyncTarget::Block);

            itertools::assert_equal(
                batches
                    .into_iter()
                    .map(|batch| (batch.start_slot, batch.count)),
                [(sync_range_from, slots_per_request)],
            );
        }

        Ok(())
    }

    #[test]
    fn test_build_forward_sync_batches_when_head_does_not_progress() -> Result<()> {
        let config = Config::mainnet();
        let current_slot = 20_001;
        let local_head_slot = 3000;
        let local_finalized_slot = 1000;
        let slots_per_request = EPOCHS_PER_REQUEST * <Mainnet as Preset>::SlotsPerEpoch::U64;

        let peer_status = StatusMessage {
            fork_digest: H32::default(),
            finalized_root: H256::default(),
            finalized_epoch: 248,
            head_root: H256::default(),
            head_slot: 20_000,
        };

        let mut sync_manager = SyncManager::new(100);

        sync_manager.add_peer(PeerId::random(), peer_status);

        sync_manager.build_forward_sync_batches::<Mainnet>(
            &config,
            current_slot,
            local_head_slot,
            local_finalized_slot,
        )?;

        let sync_range_from = local_head_slot + 1;
        let sync_range_to = sync_range_from + slots_per_request - 1;

        assert_eq!(sync_manager.last_sync_range, sync_range_from..sync_range_to);

        // From second to fifth retries try to download blocks from local head slot minus one epoch

        for _ in 0..4 {
            sync_manager.build_forward_sync_batches::<Mainnet>(
                &config,
                current_slot,
                local_head_slot,
                local_finalized_slot,
            )?;

            let sync_range_from = local_head_slot - 32 + 1;
            let sync_range_to = sync_range_from + slots_per_request - 1;

            assert_eq!(sync_manager.last_sync_range, sync_range_from..sync_range_to);
        }

        // It local head still fails to progress, re-download blocks from last finalized slot up to local head slot

        let mut i = 0;
        let mut sync_range_to = 0;

        while sync_range_to < local_head_slot {
            sync_manager.build_forward_sync_batches::<Mainnet>(
                &config,
                current_slot,
                local_head_slot,
                local_finalized_slot,
            )?;

            let sync_range_from = local_finalized_slot + slots_per_request * i + 1;
            sync_range_to = sync_range_from + slots_per_request - 1;

            assert_eq!(sync_manager.last_sync_range, sync_range_from..sync_range_to);

            i += 1;
        }

        // Resume normal syncing behaviour

        sync_manager.build_forward_sync_batches::<Mainnet>(
            &config,
            current_slot,
            local_head_slot,
            local_finalized_slot,
        )?;

        let sync_range_from = local_head_slot - 32 + 1;
        let sync_range_to = sync_range_from + slots_per_request - 1;

        assert_eq!(sync_manager.last_sync_range, sync_range_from..sync_range_to);

        Ok(())
    }
}
