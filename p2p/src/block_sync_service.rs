use core::{convert::Infallible as Never, fmt::Debug, time::Duration};
use std::sync::Arc;

use anyhow::Result;
use database::Database;
use eth1_api::RealController;
use eth2_libp2p::{rpc::StatusMessage, PeerId};
use features::Feature;
use fork_choice_control::SyncMessage;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    future::Either,
    StreamExt as _,
};
use genesis::AnchorCheckpointProvider;
use helper_functions::misc;
use log::{error, info};
use prometheus_metrics::Metrics;
use ssz::{SszReadDefault, SszWrite as _};
use std_ext::ArcExt as _;
use thiserror::Error;
use tokio::select;
use tokio_stream::wrappers::IntervalStream;
use types::{
    combined::SignedBeaconBlock,
    deneb::containers::BlobIdentifier,
    eip7594::DataColumnIdentifier,
    nonstandard::Phase,
    phase0::primitives::{Slot, H256},
    preset::Preset,
};

use crate::{
    back_sync::{BackSync, Data as BackSyncData, Error as BackSyncError, SyncCheckpoint},
    block_verification_pool::BlockVerificationPool,
    messages::{ArchiverToSync, P2pToSync, SyncToApi, SyncToMetrics, SyncToP2p},
    misc::RequestId,
    sync_manager::{SyncBatch, SyncManager, SyncTarget},
};

const LATEST_FINALIZED_BACK_SYNC_CHECKPOINT_KEY: &str = "latest_finalized_back_sync_checkpoint";
const NETWORK_EVENT_INTERVAL: Duration = Duration::from_secs(1);

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
    database: Option<Database>,
    sync_direction: SyncDirection,
    back_sync: Option<BackSync<P>>,
    anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    block_verification_pool: BlockVerificationPool<P>,
    controller: RealController<P>,
    sync_manager: SyncManager,
    metrics: Option<Arc<Metrics>>,
    next_request_id: usize,
    slot: Slot,
    is_back_synced: bool,
    is_forward_synced: bool,
    fork_choice_to_sync_rx: Option<UnboundedReceiver<SyncMessage<P>>>,
    p2p_to_sync_rx: UnboundedReceiver<P2pToSync<P>>,
    sync_to_p2p_tx: UnboundedSender<SyncToP2p>,
    sync_to_api_tx: UnboundedSender<SyncToApi>,
    sync_to_metrics_tx: Option<UnboundedSender<SyncToMetrics>>,
    archiver_to_sync_tx: Option<UnboundedSender<ArchiverToSync>>,
    archiver_to_sync_rx: Option<UnboundedReceiver<ArchiverToSync>>,
}

impl<P: Preset> BlockSyncService<P> {
    pub fn new(
        db: Database,
        anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
        controller: RealController<P>,
        metrics: Option<Arc<Metrics>>,
        channels: Channels<P>,
        back_sync_enabled: bool,
        loaded_from_remote: bool,
    ) -> Result<Self> {
        let database;
        let back_sync;
        let archiver_to_sync_tx;
        let archiver_to_sync_rx;

        if back_sync_enabled {
            if loaded_from_remote {
                let anchor_checkpoint = controller.anchor_block().as_ref().into();

                // Checkpoint sync happened, so we need to back sync to
                // previously stored latest finalized checkpoint or genesis.
                let back_sync_checkpoint = get_latest_finalized_back_sync_checkpoint(&db)?
                    .unwrap_or_else(|| {
                        anchor_checkpoint_provider
                            .checkpoint()
                            .value
                            .block
                            .as_ref()
                            .into()
                    });

                let back_sync_process = BackSync::<P>::new(BackSyncData::new(
                    anchor_checkpoint,
                    anchor_checkpoint,
                    back_sync_checkpoint,
                ));

                if !back_sync_process.is_finished() {
                    back_sync_process.save(&db)?;
                }
            }

            back_sync = BackSync::load(&db)?;

            let (sync_tx, sync_rx) = futures::channel::mpsc::unbounded();

            database = Some(db);
            archiver_to_sync_tx = Some(sync_tx);
            archiver_to_sync_rx = Some(sync_rx);
        } else {
            database = None;
            back_sync = None;
            archiver_to_sync_tx = None;
            archiver_to_sync_rx = None;
        };

        let slot = controller.slot();

        let Channels {
            fork_choice_to_sync_rx,
            p2p_to_sync_rx,
            sync_to_p2p_tx,
            sync_to_api_tx,
            sync_to_metrics_tx,
        } = channels;

        // `is_back_synced` is set correctly only when back sync is enabled. Otherwise it is set
        // to `true` and users can attempt to query historical data even after checkpoint sync.
        let is_back_synced = back_sync.is_none();
        let is_forward_synced = controller.is_forward_synced();

        let mut service = Self {
            database,
            sync_direction: SyncDirection::Forward,
            back_sync,
            anchor_checkpoint_provider,
            block_verification_pool: BlockVerificationPool::new(controller.clone_arc())?,
            controller,
            sync_manager: SyncManager::default(),
            metrics,
            next_request_id: 0,
            slot,
            is_back_synced,
            // Initialize `is_forward_synced` to `false`. This is needed to make
            // `BlockSyncService::set_forward_synced` subscribe to core topics on startup.
            is_forward_synced: false,
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

    #[allow(clippy::too_many_lines)]
    pub async fn run(mut self) -> Result<Never> {
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
                        features::log!(DebugP2p, "received back sync states archived message");

                        if let Some(back_sync) = self.back_sync.as_mut() {
                            if let Some(database) = self.database.as_ref() {
                                back_sync.finish(database)?;

                                features::log!(
                                    DebugP2p,
                                    "finishing back sync: {:?}",
                                    back_sync.data(),
                                );

                                if let Some(sync) = BackSync::load(database)? {
                                    self.back_sync = Some(sync);
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
                            features::log!(
                                DebugP2p,
                                "saving latest finalized back sync checkpoint: {checkpoint:?}",
                            );
                            save_latest_finalized_back_sync_checkpoint(database, checkpoint)?;
                        }
                    }
                },

                message = self.p2p_to_sync_rx.select_next_some() => {
                    match message {
                        P2pToSync::FinalizedEpoch(epoch) => {
                            if !Feature::DisableBlockVerificationPool.is_enabled() {
                                self.block_verification_pool.prune_outdated_blocks(epoch);
                            }
                        }
                        P2pToSync::HeadState(state) => {
                            if !Feature::DisableBlockVerificationPool.is_enabled() {
                                tokio::task::block_in_place(|| {
                                    self.block_verification_pool
                                        .verify_and_process_blocks(&state)
                                });
                            }
                        }
                        P2pToSync::Slot(slot) => {
                            self.slot = slot;

                            if let Some(metrics) = self.metrics.as_ref() {
                                self.sync_manager.track_collection_metrics(metrics);
                            }
                        }
                        P2pToSync::AddPeer(peer_id, status) => {
                            self.sync_manager.add_peer(peer_id, status);
                            self.request_peer_status_update(status)?;
                            self.request_blobs_and_blocks_if_ready()?;
                        }
                        P2pToSync::RemovePeer(peer_id) => {
                            let batches_to_retry = self.sync_manager.remove_peer(&peer_id);
                            self.retry_sync_batches(batches_to_retry)?;
                        }
                        P2pToSync::RequestFailed(peer_id) => {
                            if !self.is_forward_synced {
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
                        P2pToSync::RequestedBlobSidecar(blob_sidecar, block_seen, peer_id) => {
                            self.controller.on_requested_blob_sidecar(blob_sidecar, block_seen, peer_id);
                        }
                        P2pToSync::RequestedBlock((block, peer_id, request_id)) => {
                            match self
                                .sync_manager
                                .request_direction(request_id)
                                .unwrap_or(self.sync_direction)
                            {
                                SyncDirection::Forward => {
                                    if should_push_block_in_verification_pool(&block) {
                                        self.block_verification_pool.push(block);
                                    } else {
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
                        P2pToSync::RequestedDataColumnSidecar(data_column_sidecar, peer_id) => {
                            self.controller.on_requested_data_column_sidecar(data_column_sidecar, peer_id);
                        }
                        P2pToSync::BlobsByRangeRequestFinished(request_id) => {
                            self.sync_manager.blobs_by_range_request_finished(request_id);
                            self.request_blobs_and_blocks_if_ready()?;
                        }
                        P2pToSync::BlobsByRootChunkReceived(identifier, peer_id, request_id) => {
                            self.sync_manager.received_blob_sidecar_chunk(identifier, peer_id, request_id);
                            self.request_blobs_and_blocks_if_ready()?;
                        }
                        P2pToSync::BlocksByRangeRequestFinished(request_id) => {
                            let request_direction = self.sync_manager.request_direction(request_id);

                            self.sync_manager.blocks_by_range_request_finished(request_id);

                            if request_direction == Some(SyncDirection::Back) {
                                // aka batch finished
                                if self.sync_manager.ready_to_request_blocks_by_range() {
                                    if let Some(back_sync) = self.back_sync.as_mut() {
                                        if let Some(database) = self.database.as_ref() {
                                            if let Err(error) = back_sync.verify_blocks(
                                                database,
                                                &self.controller,
                                            ) {
                                                error!(
                                                    "error while verifying back sync blocks: \
                                                     {error:?}",
                                                );

                                                if let Some(
                                                    BackSyncError::FinalCheckpointMismatch { .. }
                                                ) = error.downcast_ref() {
                                                    back_sync.finish(database)?;
                                                    self.back_sync = BackSync::load(database)?;
                                                }
                                            }
                                        }

                                        self.try_to_spawn_back_sync_states_archiver()?;
                                    }
                                }
                            }

                            self.request_blobs_and_blocks_if_ready()?;
                        }
                        P2pToSync::BlockByRootRequestFinished(block_root) => {
                            self.sync_manager.block_by_root_request_finished(block_root);
                            self.request_blobs_and_blocks_if_ready()?;
                        }
                        P2pToSync::DataColumnsByRangeRequestFinished(request_id) => {
                            self.sync_manager.data_columns_by_range_request_finished(request_id);
                            self.request_blobs_and_blocks_if_ready()?;
                        }
                        P2pToSync::DataColumnsByRootChunkReceived(identifier, peer_id, request_id) => {
                            self.sync_manager.received_data_column_sidecar_chunk(identifier, peer_id, request_id);
                            self.request_blobs_and_blocks_if_ready()?;
                        }
                    }
                }
            }
        }
    }

    pub fn try_to_spawn_back_sync_states_archiver(&mut self) -> Result<()> {
        if let Some(back_sync) = self.back_sync.as_mut() {
            if let Some(archiver_to_sync_tx) = self.archiver_to_sync_tx.as_ref() {
                back_sync.try_to_spawn_state_archiver(
                    self.controller.clone_arc(),
                    self.anchor_checkpoint_provider.clone(),
                    archiver_to_sync_tx.clone(),
                )?;
            }
        }

        Ok(())
    }

    pub fn retry_sync_batches(&mut self, batches: Vec<SyncBatch>) -> Result<()> {
        for batch in batches {
            let request_id = self.request_id()?;
            let SyncBatch {
                target,
                start_slot,
                count,
                ref data_columns,
                ..
            } = batch;

            let peer = self.sync_manager.retry_batch(request_id, &batch);

            if let Some(peer_id) = peer {
                match target {
                    SyncTarget::DataColumnSidecar => {
                        let data_columns = data_columns.clone().unwrap_or_default();

                        SyncToP2p::RequestDataColumnsByRange(
                            request_id,
                            peer_id,
                            start_slot,
                            count,
                            data_columns,
                        )
                        .send(&self.sync_to_p2p_tx);
                    }
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
        self.request_expired_data_column_range_requests()?;

        if !self.sync_manager.ready_to_request_blocks_by_range() {
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

                    if head_slot >= self.slot {
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
            SyncDirection::Back => self
                .back_sync
                .as_ref()
                .filter(|back_sync| !back_sync.is_finished())
                .map(|back_sync| {
                    let current_slot = back_sync.current_slot();
                    let low_slot = back_sync.low_slot();

                    self.sync_manager
                        .build_back_sync_batches::<P>(current_slot, low_slot)
                })
                .unwrap_or_default(),
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
                ref data_columns,
                ..
            } = batch;

            match target {
                //TODO(feature/eip-7594)
                SyncTarget::DataColumnSidecar => {
                    let data_columns = data_columns.clone().unwrap_or_default();

                    self.sync_manager
                        .add_data_columns_request_by_range(request_id, batch);

                    SyncToP2p::RequestDataColumnsByRange(
                        request_id,
                        peer_id,
                        start_slot,
                        count,
                        data_columns,
                    )
                    .send(&self.sync_to_p2p_tx);
                }
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

    fn request_needed_data_columns(
        &mut self,
        identifiers: Vec<DataColumnIdentifier>,
        slot: Slot,
        peer_id: Option<PeerId>,
    ) -> Result<()> {
        let data_column_serve_range_slot = misc::data_column_serve_range_slot::<P>(
            self.controller.chain_config(),
            self.controller.slot(),
        );

        if slot < data_column_serve_range_slot {
            features::log!(
                DebugP2p,
                "Ignoring needed data column sidecar request: slot: {slot} < data_column_serve_range_slot: {data_column_serve_range_slot}"
            );
            return Ok(());
        }

        let request_id = self.request_id()?;

        let Some(peer_id) = peer_id.or_else(|| self.sync_manager.random_peer()) else {
            return Ok(());
        };

        let data_column_identifiers = self
            .sync_manager
            .add_data_columns_request_by_root(identifiers, peer_id);

        if !data_column_identifiers.is_empty() {
            SyncToP2p::RequestDataColumnsByRoot(request_id, peer_id, data_column_identifiers)
                .send(&self.sync_to_p2p_tx);
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
            features::log!(
                DebugP2p,
                "Ignoring needed blob sidecar request: slot: {slot} < blob_serve_slot: {blob_serve_slot}"
            );
            return Ok(());
        }

        let request_id = self.request_id()?;

        let Some(peer_id) = peer_id.or_else(|| self.sync_manager.random_peer()) else {
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

        let request_id = self.request_id()?;

        let Some(peer_id) = peer_id.or_else(|| self.sync_manager.random_peer()) else {
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

    fn request_peer_status(&mut self, peer_id: PeerId) -> Result<()> {
        SyncToP2p::RequestPeerStatus(self.request_id()?, peer_id).send(&self.sync_to_p2p_tx);
        Ok(())
    }

    fn request_peer_status_update(&mut self, status: StatusMessage) -> Result<()> {
        for peer_id in self.sync_manager.outdated_peers(status) {
            features::log!(DebugP2p, "Update outdated peer: {peer_id}");
            self.request_peer_status(peer_id)?;
        }

        Ok(())
    }

    fn request_id(&mut self) -> Result<RequestId> {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).ok_or(Error)?;
        Ok(request_id)
    }

    fn set_back_synced(&mut self, is_back_synced: bool) {
        features::log!(DebugP2p, "set back synced: {is_back_synced}");

        let was_back_synced = self.is_back_synced;
        self.is_back_synced = is_back_synced;

        if was_back_synced != is_back_synced && is_back_synced {
            info!("back sync completed");

            self.sync_manager.cache_clear();
            self.sync_direction = SyncDirection::Forward;
        }

        SyncToApi::BackSyncStatus(is_back_synced).send(&self.sync_to_api_tx);
    }

    fn set_forward_synced(&mut self, is_forward_synced: bool) -> Result<()> {
        features::log!(DebugP2p, "set forward synced: {is_forward_synced}");

        let was_forward_synced = self.is_forward_synced;
        self.is_forward_synced = is_forward_synced;

        if was_forward_synced && !is_forward_synced {
            // Stop back sync and sync forward.
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
                SyncToP2p::PruneReceivedBlocks.send(&self.sync_to_p2p_tx);
                self.sync_direction = SyncDirection::Back;
                self.sync_manager.cache_clear();
                self.request_blobs_and_blocks_if_ready()?;
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
}

fn should_push_block_in_verification_pool<P: Preset>(block: &SignedBeaconBlock<P>) -> bool {
    block.phase() == Phase::Phase0 && !Feature::DisableBlockVerificationPool.is_enabled()
}

fn get<V: SszReadDefault>(database: &Database, key: impl AsRef<[u8]>) -> Result<Option<V>> {
    database
        .get(key)?
        .map(V::from_ssz_default)
        .transpose()
        .map_err(Into::into)
}

fn get_latest_finalized_back_sync_checkpoint(
    database: &Database,
) -> Result<Option<SyncCheckpoint>> {
    get(database, LATEST_FINALIZED_BACK_SYNC_CHECKPOINT_KEY)
}

fn save_latest_finalized_back_sync_checkpoint(
    database: &Database,
    checkpoint: SyncCheckpoint,
) -> Result<()> {
    let bytes = checkpoint.to_ssz()?;
    database.put(LATEST_FINALIZED_BACK_SYNC_CHECKPOINT_KEY, bytes)
}
