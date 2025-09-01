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
use dashmap::DashMap;
use eth1_api::RealController;
use eth2_libp2p::{rpc::StatusMessage, service::api_types::AppRequestId, NetworkGlobals, PeerId};
use helper_functions::misc;
use itertools::Itertools as _;
use log::{log, Level};
use lru::LruCache;
use prometheus_metrics::Metrics;
use rand::{prelude::SliceRandom, seq::IteratorRandom as _, thread_rng};
use ssz::ContiguousList;
use thiserror::Error;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    config::Config,
    deneb::containers::BlobIdentifier,
    fulu::{
        containers::{DataColumnIdentifier, DataColumnsByRootIdentifier},
        primitives::ColumnIndex,
    },
    phase0::primitives::{Epoch, Slot, H256},
    preset::Preset,
};

use crate::{block_sync_service::SyncDirection, range_and_root_requests::RangeAndRootRequests};

#[derive(PartialEq, Eq, Hash, Debug)]
struct ChainId {
    finalized_root: H256,
    finalized_epoch: Epoch,
}

impl From<&StatusMessage> for ChainId {
    fn from(status: &StatusMessage) -> Self {
        Self {
            finalized_root: status.finalized_root(),
            finalized_epoch: status.finalized_epoch(),
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
const PEER_UPDATE_COOLDOWN: Duration = Duration::from_secs(12);
const SEQUENTIAL_REDOWNLOADS_TILL_RESET: usize = 5;
const MAX_COLUMNS_ASSIGNED_PER_PEER: usize = 32;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum SyncTarget {
    BlobSidecar,
    Block,
    DataColumnSidecar,
}

#[derive(Debug, Clone)]
pub struct SyncBatch<P: Preset> {
    pub target: SyncTarget,
    pub direction: SyncDirection,
    pub peer_id: PeerId,
    pub start_slot: Slot,
    pub count: u64,
    pub retry_count: usize,
    pub response_received: bool,
    pub data_columns: Option<Arc<ContiguousList<ColumnIndex, P::NumberOfColumns>>>,
}

pub struct SyncManager<P: Preset> {
    peers: HashMap<PeerId, StatusMessage>,
    blob_requests: RangeAndRootRequests<BlobIdentifier, P>,
    block_requests: RangeAndRootRequests<H256, P>,
    data_column_requests: RangeAndRootRequests<DataColumnIdentifier, P>,
    last_sync_head: Slot,
    last_sync_range: Range<Slot>,
    sequential_redownloads: usize,
    status_updates_cache: TimedSizedCache<Epoch, ()>,
    not_enough_peers_message_shown_at: Option<Instant>,
    sync_from_finalized: bool,
    // store peers that don't serve blocks prior to `MIN_EPOCHS_FOR_BLOCK_REQUESTS`
    // so that we can filter them when back-syncing
    back_sync_black_list: LruCache<PeerId, ()>,
    network_globals: Arc<NetworkGlobals>,
    received_data_column_sidecars: Arc<DashMap<DataColumnIdentifier, Slot>>,
    peers_custodial: HashMap<PeerId, HashSet<ColumnIndex>>,
}

impl<P: Preset> SyncManager<P> {
    pub fn new(
        network_globals: Arc<NetworkGlobals>,
        target_peers: usize,
        received_data_column_sidecars: Arc<DashMap<DataColumnIdentifier, Slot>>,
    ) -> Self {
        Self {
            peers: HashMap::new(),
            blob_requests: RangeAndRootRequests::<BlobIdentifier, P>::default(),
            block_requests: RangeAndRootRequests::<H256, P>::default(),
            data_column_requests: RangeAndRootRequests::<DataColumnIdentifier, P>::default(),
            last_sync_range: 0..0,
            last_sync_head: 0,
            sequential_redownloads: 0,
            status_updates_cache: TimedSizedCache::with_size_and_lifespan(5, PEER_UPDATE_COOLDOWN),
            not_enough_peers_message_shown_at: None,
            sync_from_finalized: false,
            back_sync_black_list: LruCache::new(
                NonZeroUsize::new(target_peers).expect("target_peers must be be a nonzero"),
            ),
            network_globals,
            received_data_column_sidecars,
            peers_custodial: HashMap::new(),
        }
    }

    pub fn record_received_blob_sidecar_response(
        &mut self,
        blob_identifier: BlobIdentifier,
        peer_id: PeerId,
        app_request_id: AppRequestId,
    ) {
        self.blob_requests
            .record_received_response(&blob_identifier, &peer_id, app_request_id);
    }

    pub fn record_received_block_response(
        &mut self,
        block_root: H256,
        peer_id: PeerId,
        app_request_id: AppRequestId,
    ) {
        self.block_requests
            .record_received_response(&block_root, &peer_id, app_request_id);
    }

    pub fn record_received_data_column_sidecar_response(
        &mut self,
        data_column_identifier: DataColumnIdentifier,
        peer_id: PeerId,
        app_request_id: AppRequestId,
    ) {
        self.data_column_requests.record_received_response(
            &data_column_identifier,
            &peer_id,
            app_request_id,
        );
    }

    pub fn request_direction(&mut self, app_request_id: AppRequestId) -> Option<SyncDirection> {
        self.block_requests
            .request_direction(app_request_id)
            .or_else(|| self.blob_requests.request_direction(app_request_id))
            .or_else(|| self.data_column_requests.request_direction(app_request_id))
    }

    pub fn add_peer(&mut self, peer_id: PeerId, status: StatusMessage) {
        self.log(
            Level::Debug,
            format_args!("add peer (peer_id: {peer_id}, status: {status:?})"),
        );

        self.peers.insert(peer_id, status);
        self.update_peer_columns_custody(peer_id);
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

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Vec<SyncBatch<P>> {
        self.log(
            Level::Debug,
            format_args!("remove peer (peer_id: {peer_id})"),
        );

        self.peers.remove(peer_id);
        self.back_sync_black_list.pop(peer_id);
        self.peers_custodial.remove(peer_id);

        self.block_requests
            .remove_peer(peer_id)
            .chain(self.blob_requests.remove_peer(peer_id))
            .chain(self.data_column_requests.remove_peer(peer_id))
            .collect_vec()
    }

    pub fn update_peer_cgc(&mut self, peer_id: PeerId) {
        self.log(
            Level::Debug,
            format_args!("update peer custody group count (peer_id: {peer_id})"),
        );

        self.update_peer_columns_custody(peer_id);
    }

    pub fn retry_batch(
        &mut self,
        app_request_id: AppRequestId,
        mut batch: SyncBatch<P>,
        new_peer: Option<PeerId>,
    ) {
        match new_peer {
            Some(peer_id) => {
                if matches!(batch.target, SyncTarget::Block | SyncTarget::BlobSidecar) {
                    self.log(
                        Level::Debug,
                        format_args!("retrying batch {batch:?}, new peer: {peer_id}, app_request_id: {app_request_id:?}"),
                    );

                    batch = SyncBatch {
                        target: batch.target,
                        direction: batch.direction,
                        peer_id,
                        start_slot: batch.start_slot,
                        count: batch.count,
                        retry_count: batch.retry_count + 1,
                        response_received: false,
                        data_columns: batch.data_columns,
                    };
                }

                match batch.target {
                    SyncTarget::DataColumnSidecar => {
                        self.add_data_columns_request_by_range(app_request_id, batch)
                    }
                    SyncTarget::BlobSidecar => {
                        self.add_blob_request_by_range(app_request_id, batch)
                    }
                    SyncTarget::Block => self.add_block_request_by_range(app_request_id, batch),
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
    }

    #[expect(clippy::too_many_lines)]
    pub fn build_back_sync_batches(
        &mut self,
        config: &Config,
        data_availability_serve_range_slot: Slot,
        mut current_back_sync_slot: Slot,
        low_slot: Slot,
    ) -> Vec<SyncBatch<P>> {
        let Some(peers_to_sync) = self.find_peers_to_sync(true) else {
            return vec![];
        };
        let mut peers_to_request = peers_to_sync.clone();

        // Use half of the available peers for back-sync batches.
        let max_sync_batches = peers_to_sync.len() / 2;
        let mut peers = peers_to_sync.iter();
        let mut sync_batches = vec![];

        while let Some(peer) = peers.next() {
            let should_batch_blobs = current_back_sync_slot > data_availability_serve_range_slot;

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

                        if start_slot < data_availability_serve_range_slot {
                            count = (start_slot + count)
                                .checked_sub(data_availability_serve_range_slot)
                                .unwrap_or(1);

                            start_slot = data_availability_serve_range_slot;
                        }

                        if config.phase_at_slot::<P>(start_slot).is_peerdas_activated() {
                            let missing_column_indices =
                                self.missing_column_indices_by_range(start_slot, count);

                            if !missing_column_indices.is_empty() {
                                self.log(
                                    Level::Debug,
                                    format_args!(
                                        "requesting columns ({}): [{}] for slots: {start_slot}..{}",
                                        missing_column_indices.len(),
                                        missing_column_indices.iter().join(", "),
                                        start_slot + count,
                                    ),
                                );

                                match self.map_peer_custody_columns(
                                    missing_column_indices,
                                    &mut peers_to_request,
                                ) {
                                    Ok(peer_custody_columns_mapping) => {
                                        for (peer_id, columns) in peer_custody_columns_mapping {
                                            let batch = SyncBatch {
                                                target: SyncTarget::DataColumnSidecar,
                                                direction: SyncDirection::Back,
                                                peer_id,
                                                start_slot,
                                                count,
                                                response_received: false,
                                                retry_count: 0,
                                                // TODO(feature/fulu): handle error
                                                data_columns: ContiguousList::try_from_iter(
                                                    columns.into_iter(),
                                                )
                                                .map(Arc::new)
                                                .ok(),
                                            };

                                            self.log(
                                                Level::Debug,
                                                format_args!("back-sync batch built: {batch:?})"),
                                            );
                                            sync_batches.push(batch);
                                        }
                                    }
                                    Err(error) => {
                                        self.log(
                                            Level::Debug,
                                            format_args!("build_back_sync_batches: {error:?}"),
                                        );
                                    }
                                }
                            }
                        } else {
                            let batch = SyncBatch {
                                target: SyncTarget::BlobSidecar,
                                direction: SyncDirection::Back,
                                peer_id: *next_peer,
                                start_slot,
                                count,
                                response_received: false,
                                retry_count: 0,
                                data_columns: None,
                            };

                            self.log(
                                Level::Debug,
                                format_args!("back-sync batch built: {batch:?})"),
                            );

                            sync_batches.push(batch);
                        }
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
                // TODO(feature/eip7594)
                data_columns: None,
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
    pub fn build_forward_sync_batches(
        &mut self,
        config: &Config,
        current_slot: Slot,
        local_head_slot: Slot,
        local_finalized_slot: Slot,
    ) -> Result<Vec<SyncBatch<P>>> {
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
                } else if config
                    .phase_at_slot::<P>(local_head_slot)
                    .is_peerdas_activated()
                {
                    // with PeerDAS, we can't afford re-download an epoch range before local head
                    local_head_slot + 1
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
        let data_column_serve_range_slot =
            misc::data_column_serve_range_slot::<P>(config, current_slot);

        let mut peers_to_request = peers_to_sync.clone();
        let mut sync_batches = vec![];
        for (peer_id, index) in Self::peer_sync_batch_assignments(&peers_to_sync)
            .zip(0..)
            .take(batches_in_front)
        {
            let start_slot = sync_start_slot + slots_per_request * index;
            let count = remote_head_slot.saturating_sub(start_slot) + 1;
            let count = count.min(slots_per_request);

            max_slot = start_slot + count - 1;

            if config.phase_at_slot::<P>(start_slot).is_peerdas_activated() {
                if data_column_serve_range_slot < max_slot {
                    let missing_column_indices =
                        self.missing_column_indices_by_range(start_slot, count);

                    if !missing_column_indices.is_empty() {
                        self.log(
                            Level::Debug,
                            format_args!(
                                "requesting columns ({}): [{}] for slots: {start_slot}..={max_slot}",
                                missing_column_indices.len(),
                                missing_column_indices.iter().join(", "),
                            ),
                        );

                        match self
                            .map_peer_custody_columns(missing_column_indices, &mut peers_to_request)
                        {
                            Ok(peer_custody_columns_mapping) => {
                                for (peer_id, columns) in peer_custody_columns_mapping {
                                    sync_batches.push(SyncBatch {
                                        target: SyncTarget::DataColumnSidecar,
                                        direction: SyncDirection::Forward,
                                        peer_id,
                                        start_slot,
                                        count,
                                        response_received: false,
                                        retry_count: 0,
                                        // TODO(feature/fulu): handle error case
                                        data_columns: ContiguousList::try_from_iter(
                                            columns.into_iter(),
                                        )
                                        .map(Arc::new)
                                        .ok(),
                                    });
                                }
                            }
                            Err(error) => {
                                self.log(
                                    Level::Debug,
                                    format_args!("build_forward_sync_batches: {error:?}"),
                                );
                            }
                        }
                    }
                }

                // TODO(feature/eip7594): refactor SyncBatch to Enum instead of struct with options
                sync_batches.push(SyncBatch {
                    target: SyncTarget::Block,
                    direction: SyncDirection::Forward,
                    peer_id,
                    start_slot,
                    count,
                    response_received: false,
                    retry_count: 0,
                    data_columns: None,
                });

                if peers_to_request.is_empty() {
                    break;
                }
            } else {
                if blob_serve_range_slot < max_slot {
                    sync_batches.push(SyncBatch {
                        target: SyncTarget::BlobSidecar,
                        direction: SyncDirection::Forward,
                        peer_id,
                        start_slot,
                        count,
                        response_received: false,
                        retry_count: 0,
                        data_columns: None,
                    });
                }

                // TODO(feature/eip7594): refactor SyncBatch to Enum instead of struct with options
                sync_batches.push(SyncBatch {
                    target: SyncTarget::Block,
                    direction: SyncDirection::Forward,
                    peer_id,
                    start_slot,
                    count,
                    response_received: false,
                    retry_count: 0,
                    data_columns: None,
                });
            }
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
            && self.data_column_requests.ready_to_request_by_range()
    }

    pub fn ready_to_request_blob_by_root(
        &mut self,
        blob_identifier: &BlobIdentifier,
        peer_id: Option<PeerId>,
    ) -> bool {
        self.blob_requests
            .ready_to_request_by_root(blob_identifier, peer_id)
    }

    pub fn ready_to_request_block_by_root(
        &mut self,
        block_root: H256,
        peer_id: Option<PeerId>,
    ) -> bool {
        self.block_requests
            .ready_to_request_by_root(&block_root, peer_id)
    }

    pub fn ready_to_request_data_column_by_root(
        &mut self,
        data_column_identifier: &DataColumnIdentifier,
        peer_id: Option<PeerId>,
    ) -> bool {
        self.data_column_requests
            .ready_to_request_by_root(data_column_identifier, peer_id)
    }

    pub fn add_blob_request_by_range(&mut self, app_request_id: AppRequestId, batch: SyncBatch<P>) {
        self.log(
            Level::Debug,
            format_args!(
                "add blob request by range (app_request_id: {:?}, peer_id: {}, \
                range: {:?}, retries: {})",
                app_request_id,
                batch.peer_id,
                (batch.start_slot..(batch.start_slot + batch.count)),
                batch.retry_count,
            ),
        );

        self.blob_requests
            .add_request_by_range(app_request_id, batch)
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

    pub fn add_block_request_by_range(
        &mut self,
        app_request_id: AppRequestId,
        batch: SyncBatch<P>,
    ) {
        self.log(
            Level::Debug,
            format_args!(
                "add block request by range (app_request_id: {:?}, peer_id: {}, \
                range: {:?}, retries: {})",
                app_request_id,
                batch.peer_id,
                (batch.start_slot..(batch.start_slot + batch.count)),
                batch.retry_count,
            ),
        );

        self.block_requests
            .add_request_by_range(app_request_id, batch)
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

    pub fn add_data_columns_request_by_range(
        &mut self,
        app_request_id: AppRequestId,
        batch: SyncBatch<P>,
    ) {
        self.log(
            Level::Debug,
            format_args!(
                "add data column request by range (app_request_id: {:?}, peer_id: {}, range: {:?}, \
                retries: {}, columns: {:?})",
                app_request_id,
                batch.peer_id,
                (batch.start_slot..(batch.start_slot + batch.count)),
                batch.retry_count,
                batch.data_columns.as_ref().map(AsRef::as_ref),
            ),
        );

        self.data_column_requests
            .add_request_by_range(app_request_id, batch)
    }

    pub fn add_data_columns_request_by_root(
        &mut self,
        data_columns_by_root: DataColumnsByRootIdentifier<P>,
        peer_id: PeerId,
    ) -> Option<DataColumnsByRootIdentifier<P>> {
        let DataColumnsByRootIdentifier {
            block_root,
            columns,
        } = data_columns_by_root;

        let indices = columns
            .into_iter()
            .filter(|index| {
                self.data_column_requests.add_request_by_root(
                    DataColumnIdentifier {
                        block_root,
                        index: *index,
                    },
                    peer_id,
                )
            })
            .collect_vec();

        (!indices.is_empty()).then_some(DataColumnsByRootIdentifier {
            block_root,
            columns: ContiguousList::try_from(indices)
                .expect("columns indices per block should be no more than NUMBER_OF_COLUMNS"),
        })
    }

    pub fn random_peer(&self, use_black_list: bool) -> Option<PeerId> {
        let chain_id = self.chain_to_sync(use_black_list)?;

        let busy_peers = self
            .blob_requests
            .busy_peers()
            .chain(self.block_requests.busy_peers())
            .chain(self.data_column_requests.busy_peers())
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
        app_request_id: AppRequestId,
        request_direction: Option<SyncDirection>,
    ) {
        self.log(
            Level::Debug,
            format_args!(
                "request blob sidecars by range finished \
                (app_request_id: {app_request_id:?})",
            ),
        );

        if let Some((sync_batch, _)) = self.blob_requests.request_by_range_finished(app_request_id)
        {
            self.log(
                Level::Debug,
                format_args!(
                    "blob sidecars by range request stats: responses received: {}, count: {}, \
                    direction {request_direction:?}, retries: {}",
                    sync_batch.response_received, sync_batch.count, sync_batch.retry_count,
                ),
            );

            if request_direction == Some(SyncDirection::Back) && !sync_batch.response_received {
                self.retry_batch(app_request_id, sync_batch, self.random_peer(true));
            }
        }
    }

    pub fn blocks_by_range_request_finished(
        &mut self,
        controller: &RealController<P>,
        peer_id: PeerId,
        app_request_id: AppRequestId,
        request_direction: Option<SyncDirection>,
    ) {
        self.log(
            Level::Debug,
            format_args!("request blocks by range finished (app_request_id: {app_request_id:?})"),
        );

        if let Some((sync_batch, _)) = self
            .block_requests
            .request_by_range_finished(app_request_id)
        {
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

                self.retry_batch(app_request_id, sync_batch, self.random_peer(true));
            }
        }
    }

    pub fn data_columns_by_range_request_finished(
        &mut self,
        app_request_id: AppRequestId,
        request_direction: Option<SyncDirection>,
    ) {
        self.log(
            Level::Debug,
            format_args!(
                "request data columns by range finished (app_request_id: {app_request_id:?})"
            ),
        );

        if let Some((mut sync_batch, _)) = self
            .data_column_requests
            .request_by_range_finished(app_request_id)
        {
            self.log(
                Level::Debug,
                format_args!(
                    "data column sidecars by range request stats: responses received: {}, count: {}, \
                    direction {request_direction:?}, retries: {}",
                    sync_batch.response_received, sync_batch.count, sync_batch.retry_count,
                ),
            );

            if request_direction == Some(SyncDirection::Back) && !sync_batch.response_received {
                // Retry no more than 3 times, remove the peer
                if sync_batch.retry_count < 3 {
                    sync_batch.retry_count += 1;
                    let peer_id = sync_batch.peer_id;
                    self.retry_batch(app_request_id, sync_batch, Some(peer_id));
                } else {
                    self.retry_batch(app_request_id, sync_batch, None);
                }
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

    pub fn find_available_custodial_peers(&self) -> Vec<PeerId> {
        let busy_peers = self.busy_peers();

        self.peers_custodial
            .iter()
            .filter_map(|(peer_id, _)| (!busy_peers.contains(peer_id)).then_some(*peer_id))
            .collect()
    }

    fn find_peers_to_sync(&mut self, use_black_list: bool) -> Option<Vec<PeerId>> {
        self.find_chain_to_sync(use_black_list).map(|chain_id| {
            let peers_to_sync = self.chain_peers_shuffled(&chain_id, use_black_list);

            let busy_peers = self.busy_peers();

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
            if use_black_list {
                !self.back_sync_black_list.contains(&peer_id)
            } else {
                true
            }
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
            .map(|status| status.head_slot())
            .max()
    }

    fn peer_sync_batch_assignments(peers: &[PeerId]) -> impl Iterator<Item = PeerId> + '_ {
        core::iter::repeat_n(peers, BATCHES_PER_PEER)
            .flatten()
            .copied()
    }

    fn busy_peers(&self) -> HashSet<PeerId> {
        self.blob_requests
            .busy_peers()
            .chain(self.block_requests.busy_peers())
            .chain(self.data_column_requests.busy_peers())
            .collect()
    }

    fn update_peer_columns_custody(&mut self, peer_id: PeerId) {
        let custody_columns = (0..P::NumberOfColumns::U64)
            .filter(|column_index| {
                self.network_globals
                    .is_custody_peer_of(*column_index, &peer_id)
            })
            .collect();

        self.log(
            Level::Debug,
            format_args!("peer custody columns (peer: {peer_id}, columns: {custody_columns:?})"),
        );

        self.peers_custodial.insert(peer_id, custody_columns);
    }

    pub const fn is_local_head_not_progress(&self, local_head_slot: Slot) -> bool {
        local_head_slot <= self.last_sync_head
    }

    #[expect(clippy::unwrap_or_default)]
    pub fn missing_column_indices_by_root(
        &self,
        local_head_slot: Slot,
    ) -> HashMap<H256, HashSet<ColumnIndex>> {
        let sampling_count = self.network_globals.sampling_columns_count();
        let max_slot_ahead = 512 / sampling_count as u64;

        self.received_data_column_sidecars
            .iter()
            .filter_map(|entry| {
                (*entry.value() > local_head_slot
                    && *entry.value() < local_head_slot + max_slot_ahead)
                    .then_some((entry.key().block_root, entry.key().index))
            })
            .fold(HashMap::new(), |mut acc, (block_root, index)| {
                acc.entry(block_root)
                    .or_insert_with(HashSet::new)
                    .insert(index);

                acc
            })
            .into_iter()
            .filter_map(|(block_root, indices)| {
                (indices.len() != sampling_count).then(|| {
                    let missing = self
                        .network_globals
                        .sampling_columns()
                        .difference(&indices)
                        .copied()
                        .collect();

                    (block_root, missing)
                })
            })
            .collect()
    }

    pub fn missing_column_indices_by_range(
        &self,
        start_slot: Slot,
        count: u64,
    ) -> HashSet<ColumnIndex> {
        let mut missing_indices = HashSet::new();

        for slot in start_slot..start_slot.saturating_add(count) {
            let received_indices = self
                .received_data_column_sidecars
                .iter()
                .filter_map(|entry| (slot == *entry.value()).then_some(entry.key().index))
                .collect::<HashSet<_>>();

            missing_indices.extend(
                self.network_globals
                    .sampling_columns()
                    .difference(&received_indices),
            );
        }

        missing_indices
    }

    pub fn map_peer_custody_columns(
        &self,
        mut column_indices: HashSet<ColumnIndex>,
        peers_to_request: &mut Vec<PeerId>,
    ) -> Result<HashMap<PeerId, HashSet<ColumnIndex>>> {
        if column_indices.is_empty() {
            return Ok(HashMap::new());
        }

        if self.peers_custodial.is_empty() || peers_to_request.is_empty() {
            return Err(MapPeerCustodyError::NoAvailablePeers.into());
        }

        let mut peer_columns_mapping = HashMap::new();
        while !column_indices.is_empty() {
            // Find peer covering most remaining columns
            match self
                .peers_custodial
                .iter()
                .filter(|(peer, columns)| {
                    peers_to_request.contains(*peer)
                        && !columns.is_disjoint(&column_indices)
                        && !peer_columns_mapping.contains_key(*peer)
                })
                .min_by(|(_, columns_a), (_, columns_b)| {
                    let total_custody_a = columns_a.len();
                    let total_custody_b = columns_b.len();
                    let coverage_a = columns_a.intersection(&column_indices).count();
                    let coverage_b = columns_b.intersection(&column_indices).count();

                    // Prioritize peers with fewer total custody columns first, then maximize coverage
                    match total_custody_a.cmp(&total_custody_b) {
                        core::cmp::Ordering::Equal => coverage_b.cmp(&coverage_a),
                        other => other,
                    }
                }) {
                Some((peer, columns)) => {
                    let covered_by_peer = columns
                        .intersection(&column_indices)
                        .take(MAX_COLUMNS_ASSIGNED_PER_PEER)
                        .copied()
                        .collect::<HashSet<_>>();

                    if covered_by_peer.is_empty() {
                        break;
                    }

                    column_indices.retain(|col| !covered_by_peer.contains(col));
                    peer_columns_mapping.insert(*peer, covered_by_peer);
                }
                None => break,
            }
        }

        if peer_columns_mapping.is_empty() {
            return Err(MapPeerCustodyError::NoAvailablePeers.into());
        }

        // Remove assigned peers from
        peers_to_request.retain(|peer| !peer_columns_mapping.contains_key(peer));

        Ok(peer_columns_mapping)
    }

    pub fn expired_blob_range_batches(
        &mut self,
    ) -> impl Iterator<Item = (SyncBatch<P>, Instant)> + '_ {
        self.blob_requests.expired_range_batches()
    }

    pub fn expired_block_range_batches(
        &mut self,
    ) -> impl Iterator<Item = (SyncBatch<P>, Instant)> + '_ {
        self.block_requests.expired_range_batches()
    }

    pub fn expired_data_column_range_batches(
        &mut self,
    ) -> impl Iterator<Item = (SyncBatch<P>, Instant)> + '_ {
        self.data_column_requests.expired_range_batches()
    }

    pub fn cache_clear(&mut self) {
        self.blob_requests.cache_clear();
        self.block_requests.cache_clear();
        self.data_column_requests.cache_clear();
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
        self.data_column_requests.track_collection_metrics(metrics);
    }
}

#[derive(Debug, Error)]
enum MapPeerCustodyError {
    #[error("could not find available peers to request data column sidecars")]
    NoAvailablePeers,
}

#[cfg(test)]
impl<P: Preset> SyncManager<P> {
    pub fn add_blobs_by_range_busy_peer(&mut self, peer_id: PeerId) {
        self.blob_requests.add_request_by_range(
            AppRequestId::Application(1),
            SyncBatch {
                target: SyncTarget::BlobSidecar,
                direction: SyncDirection::Back,
                peer_id,
                start_slot: 0,
                count: 64,
                retry_count: 0,
                response_received: false,
                data_columns: None,
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
            AppRequestId::Application(2),
            SyncBatch {
                target: SyncTarget::Block,
                direction: SyncDirection::Back,
                peer_id,
                start_slot: 0,
                count: 64,
                retry_count: 0,
                response_received: false,
                data_columns: None,
            },
        );
    }

    pub fn add_blocks_by_root_busy_peer(&mut self, peer_id: PeerId) {
        self.block_requests
            .add_request_by_root(H256::zero(), peer_id);
    }

    pub fn add_data_columns_request_by_range_busy_peer(&mut self, peer_id: PeerId) {
        self.data_column_requests.add_request_by_range(
            AppRequestId::Application(3),
            SyncBatch {
                target: SyncTarget::DataColumnSidecar,
                direction: SyncDirection::Back,
                peer_id,
                start_slot: 16,
                count: 64,
                retry_count: 0,
                response_received: false,
                data_columns: ContiguousList::try_from(vec![0]).map(Arc::new).ok(),
            },
        )
    }

    pub fn add_data_columns_request_by_root_busy_peer(&mut self, peer_id: PeerId) {
        self.data_column_requests.add_request_by_root(
            DataColumnIdentifier {
                block_root: H256::zero(),
                index: 0,
            },
            peer_id,
        );
    }
}

#[cfg(test)]
mod tests {
    use eth2_libp2p::{rpc::StatusMessageV1, NetworkConfig};
    use slog::{o, Drain};
    use std::sync::Arc;
    use std_ext::ArcExt;
    use test_case::test_case;
    use types::{
        config::Config,
        phase0::primitives::H32,
        preset::{Mainnet, Minimal},
    };

    use super::*;

    pub fn build_log(level: slog::Level, enabled: bool) -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        if enabled {
            slog::Logger::root(drain.filter_level(level).fuse(), o!())
        } else {
            slog::Logger::root(drain.filter(|_| false).fuse(), o!())
        }
    }

    fn build_sync_manager<P: Preset>(chain_config: Arc<Config>) -> SyncManager<P> {
        let log = build_log(slog::Level::Debug, false);
        let network_config = Arc::new(NetworkConfig::default());
        let network_globals =
            NetworkGlobals::new_test_globals::<P>(chain_config, vec![], &log, network_config);
        let received_data_column_sidecars = Arc::new(DashMap::new());
        SyncManager::new(network_globals.into(), 100, received_data_column_sidecars)
    }

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
            (32, 16, SyncTarget::Block),
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
            (40, 8, SyncTarget::BlobSidecar),
            (40, 8, SyncTarget::Block),
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
            (0, 16, SyncTarget::Block),
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
            (20, 16, SyncTarget::Block),
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
        data_availability_serve_start_slot: Slot,
        head_slot: Slot,
        resulting_batches: impl IntoIterator<Item = (Slot, u64, SyncTarget)>,
    ) {
        let mut config = Config::minimal().rapid_upgrade();
        config.fulu_fork_epoch = 8;
        let config = Arc::new(config);

        let peer_status = StatusMessage::V1(StatusMessageV1 {
            fork_digest: H32::default(),
            finalized_root: H256::default(),
            finalized_epoch: 0,
            head_root: H256::default(),
            head_slot,
        });

        let mut sync_manager = build_sync_manager::<Minimal>(config.clone_arc());

        // Add 10 valid peers.
        // This will indirectly test that half of them are used for back-syncing (5 batches).
        for _ in 0..12 {
            sync_manager.add_peer(PeerId::random(), peer_status);
        }

        // Add one peer to a blacklist
        sync_manager.add_peer_to_back_sync_black_list(PeerId::random());

        // Have some peers busy
        sync_manager.add_blobs_by_range_busy_peer(PeerId::random());
        sync_manager.add_blobs_by_root_busy_peer(PeerId::random());
        sync_manager.add_blocks_by_range_busy_peer(PeerId::random());
        sync_manager.add_blocks_by_root_busy_peer(PeerId::random());
        sync_manager.add_data_columns_request_by_range_busy_peer(PeerId::random());
        sync_manager.add_data_columns_request_by_root_busy_peer(PeerId::random());

        let batches = sync_manager.build_back_sync_batches(
            &config,
            data_availability_serve_start_slot,
            head_slot,
            0,
        );

        itertools::assert_equal(
            batches
                .into_iter()
                .map(|batch| (batch.start_slot, batch.count, batch.target)),
            resulting_batches,
        );
    }

    #[test]
    fn test_build_forward_sync_batches_when_head_progresses() -> Result<()> {
        let config = Arc::new(Config::mainnet());
        let current_slot = 20_001;
        let local_head_slot = 3000;
        let local_finalized_slot = 1000;
        let slots_per_request = EPOCHS_PER_REQUEST * <Mainnet as Preset>::SlotsPerEpoch::U64;

        let peer_status = StatusMessage::V1(StatusMessageV1 {
            fork_digest: H32::default(),
            finalized_root: H256::default(),
            finalized_epoch: 248,
            head_root: H256::default(),
            head_slot: 20_000,
        });

        let mut sync_manager = build_sync_manager::<Mainnet>(config.clone_arc());

        sync_manager.add_peer(PeerId::random(), peer_status);

        for i in 0..50 {
            let batches = sync_manager.build_forward_sync_batches(
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
        let config = Arc::new(Config::mainnet());
        let current_slot = 20_001;
        let local_head_slot = 3000;
        let local_finalized_slot = 1000;
        let slots_per_request = EPOCHS_PER_REQUEST * <Mainnet as Preset>::SlotsPerEpoch::U64;

        let peer_status = StatusMessage::V1(StatusMessageV1 {
            fork_digest: H32::default(),
            finalized_root: H256::default(),
            finalized_epoch: 248,
            head_root: H256::default(),
            head_slot: 20_000,
        });

        let mut sync_manager = build_sync_manager::<Mainnet>(config.clone_arc());

        sync_manager.add_peer(PeerId::random(), peer_status);

        sync_manager.build_forward_sync_batches(
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
            sync_manager.build_forward_sync_batches(
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
            sync_manager.build_forward_sync_batches(
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

        sync_manager.build_forward_sync_batches(
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

    // Helper function to create a test SyncManager with custom custodial peers
    fn create_test_sync_manager_with_custody(
        peers_custodial: HashMap<PeerId, HashSet<ColumnIndex>>,
    ) -> SyncManager<Minimal> {
        let log = build_log(slog::Level::Debug, false);
        let chain_config = Arc::new(Config::minimal().rapid_upgrade());
        let network_config = Arc::new(NetworkConfig::default());
        let network_globals =
            NetworkGlobals::new_test_globals::<Minimal>(chain_config, vec![], &log, network_config);
        let received_data_column_sidecars = Arc::new(DashMap::new());
        let mut sync_manager =
            SyncManager::new(network_globals.into(), 100, received_data_column_sidecars);
        sync_manager.peers_custodial = peers_custodial;
        sync_manager
    }

    #[test]
    fn test_prioritizes_peers_with_fewer_custody_columns() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        // peer1 has 5 columns (heavy load)
        peers_custodial.insert(peer1, HashSet::from([0, 1, 2, 3, 4]));
        // peer2 has 2 columns (light load)
        peers_custodial.insert(peer2, HashSet::from([5, 6]));
        // peer3 has 1 column (lightest load)
        peers_custodial.insert(peer3, HashSet::from([7]));

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1, peer2, peer3];
        let column_indices = HashSet::from([0, 5, 7]); // Each peer can serve one of these

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // Should assign to peer3 first (lightest), then peer2, then peer1
        assert_eq!(result.len(), 3);
        assert!(result[&peer3].contains(&7)); // Lightest peer gets assigned
        assert!(result[&peer2].contains(&5)); // Second lightest
        assert!(result[&peer1].contains(&0)); // Heaviest peer gets assigned last
    }

    #[test]
    fn test_maximizes_coverage_within_same_load_tier() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        // Both peers have same number of total columns (3 each)
        peers_custodial.insert(peer1, HashSet::from([0, 1, 2]));
        peers_custodial.insert(peer2, HashSet::from([2, 3, 4])); // peer2 can cover 2 of requested columns

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1, peer2];
        let column_indices = HashSet::from([2, 3]); // peer2 can cover both, peer1 can cover only one

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // peer2 should be selected as it can cover more columns despite same total load
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&peer2));
        assert_eq!(result[&peer2], HashSet::from([2, 3]));
    }

    #[test]
    fn test_respects_max_columns_per_peer() {
        let peer1 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        // peer1 can custody many columns
        peers_custodial.insert(peer1, HashSet::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]));

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1];
        let column_indices = HashSet::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]); // Request all columns

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // Should not assign more than MAX_COLUMNS_ASSIGNED_PER_PEER
        assert_eq!(result.len(), 1);
        assert!(result[&peer1].len() <= MAX_COLUMNS_ASSIGNED_PER_PEER);
    }

    #[test]
    fn test_empty_column_indices_returns_empty_map() {
        let peer1 = PeerId::random();
        let mut peers_custodial = HashMap::new();
        peers_custodial.insert(peer1, HashSet::from([0, 1, 2]));

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1];
        let column_indices = HashSet::new(); // Empty request

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        assert!(result.is_empty());
    }

    #[test]
    fn test_no_available_peers_returns_error() {
        let sync_manager = create_test_sync_manager_with_custody(HashMap::new());
        let mut peers_to_request = vec![];
        let column_indices = HashSet::from([0, 1, 2]);

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect_err("no peers to request");

        assert!(matches!(
            result.downcast_ref(),
            Some(MapPeerCustodyError::NoAvailablePeers)
        ));
    }

    #[test]
    fn test_no_peers_can_serve_requested_columns() {
        let peer1 = PeerId::random();
        let mut peers_custodial = HashMap::new();
        peers_custodial.insert(peer1, HashSet::from([0, 1, 2])); // peer1 can't serve column 5

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1];
        let column_indices = HashSet::from([5, 6, 7]); // Columns peer1 can't serve

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect_err("no available custodial peers to request");

        assert!(matches!(
            result.downcast_ref(),
            Some(MapPeerCustodyError::NoAvailablePeers)
        ));
    }

    #[test]
    fn test_removes_assigned_peers_from_request_list() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        peers_custodial.insert(peer1, HashSet::from([0]));
        peers_custodial.insert(peer2, HashSet::from([1]));
        peers_custodial.insert(peer3, HashSet::from([2, 3, 4])); // peer3 not needed

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1, peer2, peer3];
        let column_indices = HashSet::from([0, 1]); // Only need peer1 and peer2

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // peer1 and peer2 should be assigned and removed from peers_to_request
        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&peer1));
        assert!(result.contains_key(&peer2));

        // Only peer3 should remain in peers_to_request
        assert_eq!(peers_to_request, vec![peer3]);
    }

    #[test]
    fn test_complex_load_balancing_scenario() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();
        let peer4 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        // peer1: heavy load (8 columns), can serve columns [0, 1, 2, 3]
        peers_custodial.insert(peer1, HashSet::from([0, 1, 2, 3, 10, 11, 12, 13]));
        // peer2: medium load (4 columns), can serve columns [1, 2, 4, 5]
        peers_custodial.insert(peer2, HashSet::from([1, 2, 4, 5]));
        // peer3: light load (2 columns), can serve columns [2, 6]
        peers_custodial.insert(peer3, HashSet::from([2, 6]));
        // peer4: lightest load (1 column), can serve column [7]
        peers_custodial.insert(peer4, HashSet::from([7]));

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1, peer2, peer3, peer4];
        let column_indices = HashSet::from([0, 1, 2, 4, 6, 7]);

        let result = sync_manager
            .map_peer_custody_columns(column_indices.clone(), &mut peers_to_request)
            .expect("custodial peers should be available");

        // Verify that lighter-loaded peers get assigned first
        // peer4 (1 column) should get column 7
        assert!(result[&peer4].contains(&7));

        // peer3 (2 columns) should get column 6 or 2
        assert!(result[&peer3].contains(&6) || result[&peer3].contains(&2));

        // peer2 (4 columns) should get some of the remaining columns
        assert!(result.contains_key(&peer2));

        // Verify all requested columns are assigned
        let all_assigned_columns: HashSet<ColumnIndex> = result
            .values()
            .flat_map(|columns| columns.iter())
            .copied()
            .collect();

        // All requested columns should be covered
        assert!(column_indices.is_subset(&all_assigned_columns));
    }

    #[test]
    fn test_peer_not_in_request_list_is_ignored() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        peers_custodial.insert(peer1, HashSet::from([0, 1])); // peer1 can serve but not in request list
        peers_custodial.insert(peer2, HashSet::from([0, 2])); // peer2 is in request list

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer2]; // Only peer2 is allowed
        let column_indices = HashSet::from([0, 1, 2]);

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // Only peer2 should be assigned (peer1 ignored despite being able to serve)
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&peer2));
        assert!(!result.contains_key(&peer1));
    }

    #[test]
    fn test_already_assigned_peer_is_skipped() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        peers_custodial.insert(peer1, HashSet::from([0, 1]));
        peers_custodial.insert(peer2, HashSet::from([1, 2]));

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1, peer2];
        let column_indices = HashSet::from([0, 1, 2]);

        let result = sync_manager
            .map_peer_custody_columns(column_indices.clone(), &mut peers_to_request)
            .expect("custodial peers should be available");

        // Each peer should only be assigned once, even if they could serve multiple columns
        let assigned_peers: HashSet<PeerId> = result.keys().copied().collect();
        assert_eq!(assigned_peers.len(), result.len()); // No duplicate peer assignments

        // Verify all columns are assigned
        let all_assigned_columns: HashSet<ColumnIndex> = result
            .values()
            .flat_map(|columns| columns.iter())
            .copied()
            .collect();
        assert_eq!(all_assigned_columns, column_indices);
    }

    #[test]
    fn test_equal_load_peers_prefer_better_coverage() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        // Both peers have same total load (3 columns each)
        peers_custodial.insert(peer1, HashSet::from([0, 10, 11])); // Can serve 1 requested column
        peers_custodial.insert(peer2, HashSet::from([1, 2, 12])); // Can serve 2 requested columns

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1, peer2];
        let column_indices = HashSet::from([0, 1, 2]); // peer2 has better coverage

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // peer2 should be selected first due to better coverage (same load)
        assert!(result.contains_key(&peer2));
        assert_eq!(result[&peer2], HashSet::from([1, 2]));
    }

    #[test]
    fn test_distributes_load_across_multiple_peers() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        // Graduated loads: 1, 2, 3 columns respectively
        peers_custodial.insert(peer1, HashSet::from([0])); // 1 column
        peers_custodial.insert(peer2, HashSet::from([1, 2])); // 2 columns
        peers_custodial.insert(peer3, HashSet::from([3, 4, 5])); // 3 columns

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1, peer2, peer3];
        let column_indices = HashSet::from([0, 1, 3]); // Each peer can serve one

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // All three peers should get assigned (peer1 first, then peer2, then peer3)
        assert_eq!(result.len(), 3);
        assert!(result[&peer1].contains(&0)); // Lightest load gets assigned first
        assert!(result[&peer2].contains(&1)); // Second lightest
        assert!(result[&peer3].contains(&3)); // Heaviest load gets assigned last
    }

    #[test]
    fn test_handles_overlapping_custody_efficiently() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        // peer1: light load, overlapping custody
        peers_custodial.insert(peer1, HashSet::from([0, 1])); // 2 columns
                                                              // peer2: heavy load, overlapping custody
        peers_custodial.insert(peer2, HashSet::from([0, 1, 2, 3, 4, 5])); // 6 columns

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1, peer2];
        let column_indices = HashSet::from([0, 1]);

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // peer1 should be selected due to lighter load, even though both can serve the columns
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&peer1));
        assert_eq!(result[&peer1], HashSet::from([0, 1]));
    }

    #[test]
    fn test_sequential_assignment_maintains_load_balance() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        peers_custodial.insert(peer1, HashSet::from([0, 1, 2, 10])); // 4 columns
        peers_custodial.insert(peer2, HashSet::from([3, 4, 11, 12])); // 4 columns
        peers_custodial.insert(peer3, HashSet::from([5, 6, 7, 8, 9, 13, 14, 15])); // 8 columns

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1, peer2, peer3];
        let column_indices = HashSet::from([0, 3, 5, 1, 4, 6]); // Multiple rounds of assignment

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // Should distribute across multiple peers, with lighter-loaded peers getting priority
        // peer1 and peer2 (4 columns each) should be preferred over peer3 (8 columns)
        let peer1_columns = result.get(&peer1).map(HashSet::len).unwrap_or(0);
        let peer2_columns = result.get(&peer2).map(HashSet::len).unwrap_or(0);
        let peer3_columns = result.get(&peer3).map(HashSet::len).unwrap_or(0);

        // Lighter loaded peers should get assignments first
        assert!(peer1_columns > 0 || peer2_columns > 0); // At least one of the lighter peers gets assigned

        // If peer3 gets assigned, it should be after peer1 and peer2 are considered
        if peer3_columns > 0 {
            // This indicates peer3 was needed, which is fine
            assert!(peer1_columns > 0 || peer2_columns > 0);
        }
    }

    #[test]
    fn test_partial_assignment_when_some_columns_cannot_be_served() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        peers_custodial.insert(peer1, HashSet::from([0, 1])); // Can serve 2 requested columns
        peers_custodial.insert(peer2, HashSet::from([2])); // Can serve 1 requested column

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1, peer2];
        let column_indices = HashSet::from([0, 1, 2, 99]); // Column 99 cannot be served

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // Should successfully assign the columns that can be served
        assert!(!result.is_empty());

        let all_assigned_columns: HashSet<ColumnIndex> = result
            .values()
            .flat_map(|columns| columns.iter())
            .copied()
            .collect();

        // Should contain the servable columns but not column 99
        assert!(all_assigned_columns.contains(&0));
        assert!(all_assigned_columns.contains(&1));
        assert!(all_assigned_columns.contains(&2));
        assert!(!all_assigned_columns.contains(&99));
    }

    #[test]
    fn test_single_peer_gets_multiple_columns_when_alone() {
        let peer1 = PeerId::random();

        let mut peers_custodial = HashMap::new();
        peers_custodial.insert(peer1, HashSet::from([0, 1, 2, 3, 4]));

        let sync_manager = create_test_sync_manager_with_custody(peers_custodial);
        let mut peers_to_request = vec![peer1];
        let column_indices = HashSet::from([0, 1, 2]);

        let result = sync_manager
            .map_peer_custody_columns(column_indices, &mut peers_to_request)
            .expect("custodial peers should be available");

        // Single peer should get all requested columns it can serve
        assert_eq!(result.len(), 1);
        assert_eq!(result[&peer1], HashSet::from([0, 1, 2]));
        assert!(peers_to_request.is_empty()); // Peer should be removed from request list
    }
}
