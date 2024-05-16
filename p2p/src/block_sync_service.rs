use core::{
    fmt::Debug,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use dashmap::DashMap;
use data_dumper::DataDumper;
use database::Database;
use eth1_api::RealController;
use eth2_libp2p::{PeerAction, PeerId, ReportSource};
use fork_choice_control::{PrefixableKey as _, StorageMode, SyncMessage};
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    future::Either,
    StreamExt as _,
};
use genesis::AnchorCheckpointProvider;
use helper_functions::misc;
use log::{debug, info, warn};
use prometheus_metrics::Metrics;
use ssz::SszReadDefault;
use std_ext::ArcExt as _;
use thiserror::Error;
use tokio::select;
use tokio_stream::wrappers::IntervalStream;
use types::{
    config::Config,
    deneb::containers::BlobIdentifier,
    eip7594::DataColumnIdentifier,
    phase0::primitives::{Slot, H256},
    preset::Preset,
    traits::SignedBeaconBlock as _,
};
use validator_statistics::ValidatorStatistics;

use crate::{
    back_sync::{
        BackSync, BackSyncDataBySlot, Data as BackSyncData, Error as BackSyncError, SyncCheckpoint,
    },
    messages::{ArchiverToSync, P2pToSync, SyncToApi, SyncToMetrics, SyncToP2p},
    misc::{PeerReportReason, RPCRequestType, RequestId},
    sync_manager::{SyncBatch, SyncManager, SyncTarget},
};

const LATEST_FINALIZED_BACK_SYNC_CHECKPOINT_KEY: &str = "latest_finalized_back_sync_checkpoint";
const NETWORK_EVENT_INTERVAL: Duration = Duration::from_secs(1);
const MISSED_SLOTS_TO_TRIGGER_SYNC: u64 = 2;

#[derive(Debug, Error)]
#[error("ran out of request IDs")]
struct Error;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SyncDirection {
    Forward,
    Back,
}

pub struct Channels<P: Preset> {
    pub fork_choice_to_sync_rx: Option<UnboundedReceiver<SyncMessage<P>>>,
    pub p2p_to_sync_rx: UnboundedReceiver<P2pToSync<P>>,
    pub sync_to_p2p_tx: UnboundedSender<SyncToP2p>,
    pub sync_to_api_tx: UnboundedSender<SyncToApi>,
    pub sync_to_metrics_tx: Option<UnboundedSender<SyncToMetrics>>,
}

pub struct BlockSyncService<P: Preset> {
    config: Arc<Config>,
    database: Option<Database>,
    sync_direction: SyncDirection,
    back_sync: Option<BackSync<P>>,
    anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    controller: RealController<P>,
    sync_manager: SyncManager,
    metrics: Option<Arc<Metrics>>,
    validator_statistics: Option<Arc<ValidatorStatistics>>,
    next_request_id: usize,
    slot: Slot,
    is_back_synced: bool,
    is_forward_synced: bool,
    is_exiting: Arc<AtomicBool>,
    received_blob_sidecars: Arc<DashMap<BlobIdentifier, Slot>>,
    received_block_roots: HashMap<H256, Slot>,
    data_dumper: Arc<DataDumper>,
    received_data_column_sidecars: HashMap<DataColumnIdentifier, Slot>,
    fork_choice_to_sync_rx: Option<UnboundedReceiver<SyncMessage<P>>>,
    p2p_to_sync_rx: UnboundedReceiver<P2pToSync<P>>,
    sync_to_p2p_tx: UnboundedSender<SyncToP2p>,
    sync_to_api_tx: UnboundedSender<SyncToApi>,
    sync_to_metrics_tx: Option<UnboundedSender<SyncToMetrics>>,
    archiver_to_sync_tx: Option<UnboundedSender<ArchiverToSync>>,
    archiver_to_sync_rx: Option<UnboundedReceiver<ArchiverToSync>>,
}

impl<P: Preset> Drop for BlockSyncService<P> {
    fn drop(&mut self) {
        self.is_exiting.store(true, Ordering::Relaxed)
    }
}

impl<P: Preset> BlockSyncService<P> {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Config>,
        db: Database,
        anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
        controller: RealController<P>,
        metrics: Option<Arc<Metrics>>,
        validator_statistics: Option<Arc<ValidatorStatistics>>,
        channels: Channels<P>,
        back_sync_enabled: bool,
        loaded_from_remote: bool,
        storage_mode: StorageMode,
        target_peers: usize,
        received_blob_sidecars: Arc<DashMap<BlobIdentifier, u64>>,
        data_dumper: Arc<DataDumper>,
    ) -> Result<Self> {
        let database;
        let back_sync;

        let (archiver_to_sync_tx, archiver_to_sync_rx) = if back_sync_enabled {
            if loaded_from_remote {
                let anchor_checkpoint = controller.anchor_block().as_ref().into();

                let latest_finalized_back_sync_checkpoint =
                    get_latest_finalized_back_sync_checkpoint(&db)?;

                // Checkpoint sync completed. Now we need to back-sync to one of the following:
                // - The previously stored latest finalized checkpoint (if the node was offline)
                // - Genesis, if the storage mode is set to Archive
                // - Config::min_epochs_for_block_request back, if the storage mode is Standard
                let back_sync_terminus =
                    latest_finalized_back_sync_checkpoint.unwrap_or_else(|| {
                        if storage_mode.is_archive() {
                            anchor_checkpoint_provider
                                .checkpoint()
                                .value
                                .block
                                .as_ref()
                                .into()
                        } else {
                            let terminus_epoch = controller.min_checked_block_availability_epoch();

                            SyncCheckpoint {
                                slot: misc::compute_start_slot_at_epoch::<P>(terminus_epoch),
                                // Options don't go along well with our SSZ implementation
                                // And also for compatibility reasons
                                block_root: H256::zero(),
                                parent_root: H256::zero(),
                            }
                        }
                    });

                let back_sync_process = BackSync::<P>::new(BackSyncData {
                    current: anchor_checkpoint,
                    high: anchor_checkpoint,
                    low: back_sync_terminus,
                });

                if !back_sync_process.is_finished() {
                    back_sync_process.save(&db)?;
                }

                if latest_finalized_back_sync_checkpoint.is_none() {
                    save_latest_finalized_back_sync_checkpoint(&db, anchor_checkpoint)?;
                }
            }

            back_sync = BackSync::load(&db)?;

            let (sync_tx, sync_rx) = futures::channel::mpsc::unbounded();

            database = Some(db);
            (Some(sync_tx), Some(sync_rx))
        } else {
            database = None;
            back_sync = None;
            (None, None)
        };

        let Channels {
            fork_choice_to_sync_rx,
            p2p_to_sync_rx,
            sync_to_p2p_tx,
            sync_to_api_tx,
            sync_to_metrics_tx,
        } = channels;

        // `is_back_synced` is set correctly only when back-sync is enabled. Otherwise it is set
        // to `true` and users can attempt to query historical data even after checkpoint sync.
        let is_back_synced = back_sync.is_none();
        let is_forward_synced = controller.is_forward_synced();
        let slot = controller.slot();

        let mut service = Self {
            config,
            database,
            sync_direction: SyncDirection::Forward,
            back_sync,
            anchor_checkpoint_provider,
            controller,
            sync_manager: SyncManager::new(target_peers),
            metrics,
            validator_statistics,
            next_request_id: 0,
            slot,
            is_back_synced,
            // Initialize `is_forward_synced` to `false`. This is needed to make
            // `BlockSyncService::set_forward_synced` subscribe to core topics on startup.
            is_forward_synced: false,
            is_exiting: Arc::new(AtomicBool::new(false)),
            received_blob_sidecars,
            received_block_roots: HashMap::new(),
            data_dumper,
            received_data_column_sidecars: HashMap::new(),
            fork_choice_to_sync_rx,
            p2p_to_sync_rx,
            sync_to_p2p_tx,
            sync_to_api_tx,
            sync_to_metrics_tx,
            archiver_to_sync_tx,
            archiver_to_sync_rx,
        };

        service.set_back_synced(is_back_synced);
        service.set_forward_synced(is_forward_synced)?;

        Ok(service)
    }

    #[expect(clippy::too_many_lines)]
    pub async fn run(mut self) -> Result<()> {
        let mut interval =
            IntervalStream::new(tokio::time::interval(NETWORK_EVENT_INTERVAL)).fuse();

        loop {
            select! {
                _ = interval.select_next_some() => {
                    self.request_blobs_and_blocks_if_ready()?;
                },

                message = match self.archiver_to_sync_rx.as_mut() {
                    Some(receiver) => Either::Left(receiver.select_next_some()),
                    None => Either::Right(futures::future::pending()),
                }, if self.archiver_to_sync_rx.is_some() => match message {
                    ArchiverToSync::BackSyncStatesArchived => {
                        debug!("received back-sync states archived message");

                        if let Some(back_sync) = self.back_sync.as_mut() {
                            if let Some(database) = self.database.as_ref() {
                                back_sync.remove(database)?;

                                debug!("finishing back-sync: {:?}", back_sync.data());

                                if let Some(sync) = BackSync::load(database)? {
                                    self.back_sync = Some(sync);
                                    self.try_to_spawn_back_sync_states_archiver()?;
                                    self.request_blobs_and_blocks_if_ready()?;
                                } else {
                                    self.set_back_synced(true);
                                }
                            }
                        }
                    }
                },

                message = match self.fork_choice_to_sync_rx.as_mut() {
                    Some(receiver) => Either::Left(receiver.select_next_some()),
                    None => Either::Right(futures::future::pending()),
                }, if self.fork_choice_to_sync_rx.is_some() => match message {
                    SyncMessage::Finalized(block) => {
                        if let Some(database) = &self.database {
                            let checkpoint = block.as_ref().into();

                            debug!("saving latest finalized back-sync checkpoint: {checkpoint:?}");

                            save_latest_finalized_back_sync_checkpoint(database, checkpoint)?;
                        }
                    }
                },

                message = self.p2p_to_sync_rx.select_next_some() => {
                    match message {
                        P2pToSync::Slot(slot) => {
                            self.slot = slot;
                            self.track_collection_metrics();

                            if let Some(metrics) = self.metrics.as_ref() {
                                self.sync_manager.track_collection_metrics(metrics);
                            }
                        }
                        P2pToSync::AddPeer(peer_id, status) => {
                            self.sync_manager.add_peer(peer_id, status);
                            self.request_blobs_and_blocks_if_ready()?;
                        }
                        P2pToSync::RemovePeer(peer_id) => {
                            let batches_to_retry = self.sync_manager.remove_peer(&peer_id);
                            self.retry_sync_batches(batches_to_retry)?;
                        }
                        P2pToSync::RequestFailed(peer_id) => {
                            if !self.is_forward_synced || !self.controller.is_back_synced() {
                                let batches_to_retry = self.sync_manager.remove_peer(&peer_id);
                                self.retry_sync_batches(batches_to_retry)?;
                            }
                        }
                        P2pToSync::StatusPeer(peer_id) => {
                            self.request_peer_status(peer_id)?;
                        }
                        P2pToSync::BlobsNeeded(identifiers, slot, peer_id) => {
                            self.request_needed_blob_sidecars(identifiers, slot, peer_id)?;
                        }
                        P2pToSync::BlockNeeded(block_root, peer_id) => {
                            self.request_needed_block(block_root, peer_id)?;
                        }
                        P2pToSync::DataColumnsNeeded(identifiers, slot, peer_id) => {
                            self.request_needed_data_columns(identifiers, slot, peer_id)?;
                        }
                        P2pToSync::GossipBlobSidecar(blob_sidecar, subnet_id, gossip_id) => {
                            self.data_dumper.dump_blob_sidecar(blob_sidecar.clone_arc());

                            let blob_identifier: BlobIdentifier = blob_sidecar.as_ref().into();
                            let blob_sidecar_slot = blob_sidecar.signed_block_header.message.slot;

                            self.register_new_received_blob_sidecar(blob_identifier, blob_sidecar_slot);

                            let block_seen = self
                                .received_block_roots
                                .contains_key(&blob_identifier.block_root);

                            self.controller.on_gossip_blob_sidecar(
                                blob_sidecar,
                                subnet_id,
                                gossip_id,
                                block_seen,
                            );
                        }
                        P2pToSync::RequestedBlobSidecar(blob_sidecar, peer_id, request_id, request_type) => {
                            let blob_identifier = blob_sidecar.as_ref().into();

                            self.sync_manager.record_received_blob_sidecar_response(blob_identifier, peer_id, request_id);

                            // Back sync does not issue BlobSidecarsByRoot requests
                            let request_direction = match request_type {
                                RPCRequestType::Root => SyncDirection::Forward,
                                RPCRequestType::Range => self
                                    .sync_manager
                                    .request_direction(request_id)
                                    .unwrap_or(self.sync_direction),
                            };

                            match request_direction {
                                SyncDirection::Forward => {
                                    let blob_sidecar_slot = blob_sidecar.signed_block_header.message.slot;

                                    if !self.controller.contains_block(blob_identifier.block_root)
                                        && self.register_new_received_blob_sidecar(blob_identifier, blob_sidecar_slot)
                                    {
                                        self.data_dumper.dump_blob_sidecar(blob_sidecar.clone_arc());

                                        let block_seen = self
                                            .received_block_roots
                                            .contains_key(&blob_identifier.block_root);

                                        self.controller
                                            .on_requested_blob_sidecar(blob_sidecar, block_seen, peer_id);
                                    }
                                }
                                SyncDirection::Back => {
                                    if let Some(back_sync) = self.back_sync.as_mut() {
                                        back_sync.push_blob_sidecar(blob_sidecar);
                                    }
                                }
                            }
                        }
                        P2pToSync::GossipBlock(beacon_block, peer_id, gossip_id) => {
                            let block_root = beacon_block.message().hash_tree_root();
                            let block_slot = beacon_block.message().slot();

                            if self.register_new_received_block(block_root, block_slot) {
                                self.data_dumper.dump_signed_beacon_block(beacon_block.clone_arc());

                                let block_slot_timestamp = misc::compute_timestamp_at_slot(
                                    self.controller.chain_config(),
                                    &self.controller.head_state().value(),
                                    block_slot,
                                );

                                if let Some(metrics) = self.metrics.as_ref() {
                                    metrics.observe_block_duration_to_slot(block_slot_timestamp);
                                }

                                debug!(
                                    "received beacon block as gossip (slot: {block_slot}, root: {block_root:?}, \
                                    peer_id: {peer_id})"
                                );

                                self.controller
                                    .on_gossip_block(beacon_block, gossip_id);
                            }
                        }
                        P2pToSync::RequestedBlock(block, peer_id, request_id, request_type) => {
                            let block_root = block.message().hash_tree_root();

                            self.sync_manager.record_received_block_response(block_root, peer_id, request_id);

                            // Back sync does not issue BeaconBlocksByRoot requests
                            let request_direction = match request_type {
                                RPCRequestType::Root => SyncDirection::Forward,
                                RPCRequestType::Range => self
                                    .sync_manager
                                    .request_direction(request_id)
                                    .unwrap_or(self.sync_direction),
                            };

                            match request_direction {
                                SyncDirection::Forward => {
                                    if self.register_new_received_block(block_root, block.message().slot()) {
                                        self.data_dumper.dump_signed_beacon_block(block.clone_arc());
                                        self.controller.on_requested_block(block, Some(peer_id));
                                    }
                                }
                                SyncDirection::Back => {
                                    if let Some(back_sync) = self.back_sync.as_mut() {
                                        back_sync.push_block(block);
                                    }
                                }
                            }
                        }
                        P2pToSync::GossipDataColumnSidecar(data_column_sidecar, subnet_id, gossip_id) => {
                            let data_column_identifier: DataColumnIdentifier = data_column_sidecar.as_ref().into();
                            let block_seen = self
                                .received_block_roots
                                .contains_key(&data_column_identifier.block_root);

                            self.controller.on_gossip_data_column_sidecar(
                                data_column_sidecar,
                                subnet_id,
                                gossip_id,
                                block_seen,
                            );
                        }
                        P2pToSync::RequestedDataColumnSidecar(data_column_sidecar, peer_id, request_id, request_type) => {
                            let data_column_identifier = data_column_sidecar.as_ref().into();

                            self.sync_manager.record_received_data_column_sidecar_response(data_column_identifier, peer_id, request_id);

                            // Back sync does not issue BlobSidecarsByRoot requests
                            let request_direction = match request_type {
                                RPCRequestType::Root => SyncDirection::Forward,
                                RPCRequestType::Range => self
                                    .sync_manager
                                    .request_direction(request_id)
                                    .unwrap_or(self.sync_direction),
                            };

                            match request_direction {
                                SyncDirection::Forward => {
                                    let data_column_sidecar_slot = data_column_sidecar.signed_block_header.message.slot;

                                    if self.register_new_received_data_column_sidecar(data_column_identifier, data_column_sidecar_slot) {
                                        let block_seen = self
                                            .received_block_roots
                                            .contains_key(&data_column_identifier.block_root);

                                        self.controller.on_requested_data_column_sidecar(data_column_sidecar, block_seen, peer_id);
                                    }
                                }
                                SyncDirection::Back => {
                                    if let Some(back_sync) = self.back_sync.as_mut() {
                                        back_sync.push_data_column_sidecar(data_column_sidecar);
                                    }
                                }
                            }
                        }
                        P2pToSync::BlobsByRangeRequestFinished(request_id) => {
                            let request_direction = self.sync_manager.request_direction(request_id);

                            self.sync_manager.blobs_by_range_request_finished(request_id, request_direction);

                            if request_direction == Some(SyncDirection::Back) {
                                self.check_back_sync_progress()?;
                            }

                            self.request_blobs_and_blocks_if_ready()?;
                        }
                        P2pToSync::BlocksByRangeRequestFinished(peer_id, request_id) => {
                            let request_direction = self.sync_manager.request_direction(request_id);

                            self.sync_manager.blocks_by_range_request_finished(
                                &self.controller,
                                peer_id,
                                request_id,
                                request_direction,
                            );

                            if request_direction == Some(SyncDirection::Back) {
                                self.check_back_sync_progress()?;
                            }

                            self.request_blobs_and_blocks_if_ready()?;
                        }
                        //TODO(feature/eip-7594)
                        P2pToSync::DataColumnsByRangeRequestFinished(request_id) => {
                            // self.sync_manager.blobs_by_range_request_finished(request_id);
                            // self.request_blobs_and_blocks_if_ready()?;
                        }
                        P2pToSync::FinalizedCheckpoint(finalized_checkpoint) => {
                            let start_of_epoch = misc::compute_start_slot_at_epoch::<P>(
                                finalized_checkpoint.epoch);

                            self.received_blob_sidecars.retain(|_, slot| *slot >= start_of_epoch);
                            self.received_block_roots.retain(|_, slot| *slot >= start_of_epoch);
                            self.received_data_column_sidecars.retain(|_, slot| *slot >= start_of_epoch);
                        }
                        P2pToSync::BlobSidecarRejected(blob_identifier) => {
                            // In case blob sidecar is not valid (e.g. someone spams fake blob sidecars)
                            // Grandine should not dismiss newer valid blob sidecars with the same blob identifier
                            self.received_blob_sidecars.remove(&blob_identifier);
                        }
                        P2pToSync::DataColumnSidecarRejected(data_column_identifier) => {
                            self.received_data_column_sidecars.remove(&data_column_identifier);
                        }
                        P2pToSync::Stop => {
                            SyncToApi::Stop.send(&self.sync_to_api_tx);

                            if let Some(sync_to_metrics_tx) = &self.sync_to_metrics_tx {
                                SyncToMetrics::Stop.send(sync_to_metrics_tx);
                            }

                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_back_sync_progress(&mut self) -> Result<()> {
        self.request_expired_blob_range_requests()?;
        self.request_expired_block_range_requests()?;
        self.request_expired_data_column_range_requests()?;

        // Check if batch has finished
        if !self.sync_manager.ready_to_request_by_range() {
            return Ok(());
        }

        let Some(back_sync) = self.back_sync.as_mut() else {
            return Ok(());
        };

        let Some(database) = self.database.as_ref() else {
            return Ok(());
        };

        if let Err(error) = back_sync.verify_blocks(&self.config, database, &self.controller) {
            warn!("error occurred while verifying back-sync blocks: {error:?}");

            if let Some(BackSyncError::FinalCheckpointMismatch::<P> { .. }) = error.downcast_ref() {
                back_sync.remove(database)?;
                self.back_sync = BackSync::load(database)?;
            }
        }

        if let Some(back_sync) = self.back_sync.as_mut() {
            back_sync.reset_batch();
        }

        self.try_to_spawn_back_sync_states_archiver()
    }

    pub fn try_to_spawn_back_sync_states_archiver(&mut self) -> Result<()> {
        if let Some(back_sync) = self.back_sync.as_mut() {
            if let Some(archiver_to_sync_tx) = self.archiver_to_sync_tx.as_ref() {
                back_sync.try_to_spawn_state_archiver(
                    self.controller.clone_arc(),
                    self.anchor_checkpoint_provider.clone(),
                    self.is_exiting.clone_arc(),
                    archiver_to_sync_tx.clone(),
                )?;
            }
        }

        Ok(())
    }

    pub fn retry_sync_batches(&mut self, batches: Vec<SyncBatch>) -> Result<()> {
        for batch in batches {
            let SyncBatch {
                target,
                direction,
                peer_id,
                mut start_slot,
                mut count,
                ..
            } = batch;

            let mut should_penalize_peer = true;

            if direction == SyncDirection::Back && target == SyncTarget::BlobSidecar {
                let blob_serve_range_slot =
                    misc::blob_serve_range_slot::<P>(self.controller.chain_config(), self.slot);

                if start_slot + count < blob_serve_range_slot {
                    debug!(
                        "skipping batch retry: blob back-sync batch is no longer relevant: \
                         {start_slot} + {count} < {blob_serve_range_slot}"
                    );

                    continue;
                }

                if start_slot < blob_serve_range_slot {
                    count = (start_slot + count)
                        .checked_sub(blob_serve_range_slot)
                        .unwrap_or(1);

                    start_slot = blob_serve_range_slot;
                    should_penalize_peer = false;
                }
            }

            let request_id = self.request_id()?;

            if should_penalize_peer {
                SyncToP2p::ReportPeer(
                    peer_id,
                    PeerAction::MidToleranceError,
                    ReportSource::SyncService,
                    PeerReportReason::ExpiredSyncBatch,
                )
                .send(&self.sync_to_p2p_tx);
            }

            let peer =
                self.sync_manager
                    .retry_batch(request_id, batch, direction == SyncDirection::Back);

            if let Some(peer_id) = peer {
                match target {
                    SyncTarget::BlobSidecar => {
                        SyncToP2p::RequestBlobsByRange(request_id, peer_id, start_slot, count)
                            .send(&self.sync_to_p2p_tx);
                    }
                    SyncTarget::Block => {
                        SyncToP2p::RequestBlocksByRange(request_id, peer_id, start_slot, count)
                            .send(&self.sync_to_p2p_tx);
                    }
                }
            }
        }

        Ok(())
    }

    fn request_expired_blob_range_requests(&mut self) -> Result<()> {
        let expired_batches = self
            .sync_manager
            .expired_blob_range_batches()
            .map(|(batch, _)| batch)
            .collect();

        self.retry_sync_batches(expired_batches)
    }

    fn request_expired_block_range_requests(&mut self) -> Result<()> {
        let expired_batches = self
            .sync_manager
            .expired_block_range_batches()
            .map(|(batch, _)| batch)
            .collect();

        self.retry_sync_batches(expired_batches)
    }

    fn request_expired_data_column_range_requests(&mut self) -> Result<()> {
        let expired_batches = self
            .sync_manager
            .expired_data_column_range_batches()
            .map(|(batch, _)| batch)
            .collect();

        self.retry_sync_batches(expired_batches)
    }

    fn request_blobs_and_blocks_if_ready(&mut self) -> Result<()> {
        self.request_expired_blob_range_requests()?;
        self.request_expired_block_range_requests()?;

        if !self.sync_manager.ready_to_request_by_range() {
            return Ok(());
        }

        let batches = match self.sync_direction {
            SyncDirection::Forward => {
                let snapshot = self.controller.snapshot();
                let head_slot = snapshot.head_slot();

                let local_finalized_slot =
                    misc::compute_start_slot_at_epoch::<P>(snapshot.finalized_epoch());

                if snapshot.is_forward_synced() {
                    self.set_forward_synced(true)?;

                    if self.slot.saturating_sub(head_slot) < MISSED_SLOTS_TO_TRIGGER_SYNC {
                        return Ok(());
                    }
                } else {
                    self.set_forward_synced(false)?;
                }

                self.sync_manager.build_forward_sync_batches::<P>(
                    self.controller.chain_config(),
                    self.slot,
                    head_slot,
                    local_finalized_slot,
                )?
            }
            SyncDirection::Back => {
                let blob_serve_range_slot =
                    misc::blob_serve_range_slot::<P>(self.controller.chain_config(), self.slot);

                self.back_sync
                    .as_ref()
                    .filter(|back_sync| !back_sync.is_finished())
                    .map(|back_sync| {
                        self.sync_manager.build_back_sync_batches::<P>(
                            blob_serve_range_slot,
                            back_sync.current_slot(),
                            // download one extra block for parent validation
                            back_sync.low_slot_with_parent(),
                        )
                    })
                    .unwrap_or_default()
            }
        };

        self.request_batches(batches)
    }

    fn request_batches(&mut self, batches: Vec<SyncBatch>) -> Result<()> {
        for batch in batches {
            let request_id = self.request_id()?;
            let SyncBatch {
                peer_id,
                start_slot,
                count,
                target,
                ..
            } = batch;

            match target {
                SyncTarget::BlobSidecar => {
                    self.sync_manager
                        .add_blob_request_by_range(request_id, batch);

                    SyncToP2p::RequestBlobsByRange(request_id, peer_id, start_slot, count)
                        .send(&self.sync_to_p2p_tx);
                }
                SyncTarget::Block => {
                    self.sync_manager
                        .add_block_request_by_range(request_id, batch);

                    SyncToP2p::RequestBlocksByRange(request_id, peer_id, start_slot, count)
                        .send(&self.sync_to_p2p_tx);
                }
            }
        }

        Ok(())
    }

    fn request_needed_blob_sidecars(
        &mut self,
        identifiers: Vec<BlobIdentifier>,
        slot: Slot,
        peer_id: Option<PeerId>,
    ) -> Result<()> {
        let blob_serve_slot = misc::blob_serve_range_slot::<P>(
            self.controller.chain_config(),
            self.controller.slot(),
        );

        if slot < blob_serve_slot {
            debug!(
                "Ignoring needed blob sidecar request: slot: {slot} < blob_serve_slot: {blob_serve_slot}"
            );
            return Ok(());
        }

        let identifiers = identifiers
            .into_iter()
            .filter(|blob_identifier| {
                !self.received_blob_sidecars.contains_key(blob_identifier)
                    && !self.controller.contains_block(blob_identifier.block_root)
            })
            .collect::<Vec<_>>();

        if identifiers.is_empty() {
            debug!(
                "cannot request BlobSidecarsByRoot: all requested blob sidecars have been received",
            );

            return Ok(());
        }

        let request_id = self.request_id()?;

        let Some(peer_id) = peer_id.or_else(|| self.sync_manager.random_peer(false)) else {
            return Ok(());
        };

        let blob_ids = self
            .sync_manager
            .add_blobs_request_by_root(identifiers, peer_id);

        if !blob_ids.is_empty() {
            SyncToP2p::RequestBlobsByRoot(request_id, peer_id, blob_ids).send(&self.sync_to_p2p_tx);
        }

        Ok(())
    }

    fn request_needed_block(&mut self, block_root: H256, peer_id: Option<PeerId>) -> Result<()> {
        if !self.is_forward_synced {
            return Ok(());
        }

        if !self
            .sync_manager
            .ready_to_request_block_by_root(block_root, peer_id)
        {
            return Ok(());
        }

        if self.received_block_roots.contains_key(&block_root) {
            debug!(
                "cannot request BeaconBlocksByRoot: requested block has been received:\
                 {block_root:?}"
            );

            return Ok(());
        }

        let request_id = self.request_id()?;

        let Some(peer_id) = peer_id.or_else(|| self.sync_manager.random_peer(false)) else {
            return Ok(());
        };

        if self
            .sync_manager
            .add_block_request_by_root(block_root, peer_id)
        {
            SyncToP2p::RequestBlockByRoot(request_id, peer_id, block_root)
                .send(&self.sync_to_p2p_tx);
        }

        Ok(())
    }

    fn request_needed_data_columns(
        &mut self,
        identifiers: Vec<DataColumnIdentifier>,
        slot: Slot,
        peer_id: Option<PeerId>,
    ) -> Result<()> {
        // TODO(feature/eip_7594): data_column_serve_slot check

        let Some(peer_id) = peer_id.or_else(|| self.sync_manager.random_peer(false)) else {
            return Ok(());
        };

        let identifiers = identifiers
            .into_iter()
            .filter(|identifier| !self.received_data_column_sidecars.contains_key(identifier))
            .collect::<Vec<_>>();

        if identifiers.is_empty() {
            debug!(
                "cannot request DataColumnSidecarsByRoot: all requested data column sidecars have been received",
            );

            return Ok(());
        }

        let request_id = self.request_id()?;

        let data_column_identifiers = self
            .sync_manager
            .add_data_columns_request_by_root(identifiers, peer_id);

        if !data_column_identifiers.is_empty() {
            SyncToP2p::RequestDataColumnsByRoot(request_id, peer_id, data_column_identifiers)
                .send(&self.sync_to_p2p_tx);
        }

        Ok(())
    }

    fn request_peer_status(&mut self, peer_id: PeerId) -> Result<()> {
        SyncToP2p::RequestPeerStatus(self.request_id()?, peer_id).send(&self.sync_to_p2p_tx);
        Ok(())
    }

    fn request_id(&mut self) -> Result<RequestId> {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).ok_or(Error)?;
        Ok(request_id)
    }

    fn set_back_synced(&mut self, is_back_synced: bool) {
        debug!("set back-synced: {is_back_synced}");

        let was_back_synced = self.is_back_synced;
        self.is_back_synced = is_back_synced;

        if was_back_synced != is_back_synced && is_back_synced {
            info!("back-sync completed");

            self.sync_manager.cache_clear();
            self.sync_direction = SyncDirection::Forward;
        }

        self.controller.on_back_sync_status(is_back_synced);
    }

    fn set_forward_synced(&mut self, is_forward_synced: bool) -> Result<()> {
        debug!("set forward synced: {is_forward_synced}");

        let was_forward_synced = self.is_forward_synced;
        self.is_forward_synced = is_forward_synced;

        if was_forward_synced && !is_forward_synced {
            // Stop back-sync and sync forward.
            if self.sync_direction == SyncDirection::Back {
                self.sync_direction = SyncDirection::Forward;
                self.sync_manager.cache_clear();
                self.request_blobs_and_blocks_if_ready()?;
            }
        }

        if !was_forward_synced && is_forward_synced {
            SyncToP2p::SubscribeToCoreTopics.send(&self.sync_to_p2p_tx);
            SyncToP2p::SubscribeToDataColumnTopics.send(&self.sync_to_p2p_tx);

            if self.back_sync.is_some() {
                self.received_block_roots = HashMap::new();
                self.received_blob_sidecars.clear();
                self.sync_direction = SyncDirection::Back;
                self.sync_manager.cache_clear();
                self.request_blobs_and_blocks_if_ready()?;
            }

            if let Some(validator_statistics) = self.validator_statistics.as_ref() {
                validator_statistics
                    .set_tracking_start(misc::compute_epoch_at_slot::<P>(self.controller.slot()));
            }
        }

        if was_forward_synced != is_forward_synced {
            SyncToApi::SyncStatus(is_forward_synced).send(&self.sync_to_api_tx);

            if let Some(sync_to_metrics_tx) = self.sync_to_metrics_tx.as_ref() {
                SyncToMetrics::SyncStatus(is_forward_synced).send(sync_to_metrics_tx);
            }
        }

        Ok(())
    }

    fn register_new_received_block(&mut self, block_root: H256, slot: Slot) -> bool {
        self.received_block_roots.insert(block_root, slot).is_none()
    }

    fn register_new_received_blob_sidecar(
        &self,
        blob_identifier: BlobIdentifier,
        slot: Slot,
    ) -> bool {
        self.received_blob_sidecars
            .insert(blob_identifier, slot)
            .is_none()
    }

    fn register_new_received_data_column_sidecar(
        &mut self,
        data_column_identifier: DataColumnIdentifier,
        slot: Slot,
    ) -> bool {
        self.received_data_column_sidecars
            .insert(data_column_identifier, slot)
            .is_none()
    }

    fn track_collection_metrics(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            let type_name = tynm::type_name::<Self>();

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "received_blob_sidecars",
                self.received_blob_sidecars.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "received_block_roots",
                self.received_block_roots.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "received_data_column_sidecars",
                self.received_data_column_sidecars.len(),
            );
        }
    }
}

fn get_latest_finalized_back_sync_checkpoint(
    database: &Database,
) -> Result<Option<SyncCheckpoint>> {
    fork_choice_control::get(database, LATEST_FINALIZED_BACK_SYNC_CHECKPOINT_KEY)
}

fn save_latest_finalized_back_sync_checkpoint(
    database: &Database,
    checkpoint: SyncCheckpoint,
) -> Result<()> {
    fork_choice_control::save(
        database,
        LATEST_FINALIZED_BACK_SYNC_CHECKPOINT_KEY,
        checkpoint,
    )
}

pub fn print_sync_database_info(database: &Database) -> Result<()> {
    info!(
        "latest finalized back-sync checkpoint: {:#?}",
        get_latest_finalized_back_sync_checkpoint(database)?,
    );

    let results = database.iterator_descending(..=BackSyncDataBySlot(Slot::MAX).to_string())?;

    for result in results {
        let (key_bytes, value_bytes) = result?;

        if !BackSyncDataBySlot::has_prefix(&key_bytes) {
            break;
        }

        let back_sync = BackSyncData::from_ssz_default(value_bytes)?;

        info!("{} : {back_sync:#?}", String::from_utf8_lossy(&key_bytes));
    }

    Ok(())
}
