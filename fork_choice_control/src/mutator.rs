// `Mutator::run` is executed in a background thread and performs all mutations on a uniquely owned
// copy of `Store` as an alternative to locking.
//
// Some of the earlier designs used `RwLock`s, but they caused all sorts of trouble. Switching from
// a read lock to a write lock must be done carefully to not introduce deadlocks or race conditions.
// `parking_lot` implements upgradable `RwLock`s, but they deadlock when 2 threads try to upgrade
// simultaneously (the other option would be to make one of them successfully lock, but no one seems
// to have proposed that).
//
// There is a number of alternate designs possible. This is just the first one that worked and
// fulfilled our requirements (see the comment in the `controller` module).
//
// The mutator's workload could be reduced by moving the handling of ignored and rejected objects to
// tasks as well, but that would complicate code and would most likely not improve performance much
// (in fact, the opposite may be true because `p2p_tx` would have to be cloned for each task).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{
        mpsc::{Receiver, Sender},
        Arc,
    },
    thread::Builder,
    time::Instant,
};

use anyhow::{anyhow, Error as AnyhowError, Result};
use arc_swap::ArcSwap;
use clock::{Tick, TickKind};
use drain_filter_polyfill::VecExt as _;
use eth2_libp2p::GossipId;
use execution_engine::{
    EngineGetBlobsParams, EngineGetBlobsV1Params, EngineGetBlobsV2Params, ExecutionEngine,
    PayloadStatusV1,
};
use fork_choice_store::{
    AggregateAndProofAction, ApplyBlockChanges, ApplyTickChanges, AttestationAction,
    AttestationItem, AttestationOrigin, AttestationValidationError, AttesterSlashingOrigin,
    BlobSidecarAction, BlobSidecarOrigin, BlockAction, BlockOrigin, ChainLink,
    DataColumnSidecarAction, DataColumnSidecarOrigin, Error, PayloadAction, StateCacheProcessor,
    Store, ValidAttestation,
};
use futures::channel::{mpsc::Sender as MultiSender, oneshot::Sender as OneshotSender};
use helper_functions::{accessors, misc, predicates, verifier::NullVerifier};
use itertools::{Either, Itertools as _};
use log::{debug, error, info, warn};
use num_traits::identities::Zero as _;
use prometheus_metrics::Metrics;
use pubkey_cache::PubkeyCache;
use ssz::SszHash as _;
use std_ext::ArcExt as _;
use typenum::Unsigned as _;
use types::{
    combined::{BeaconState, ExecutionPayloadParams, SignedBeaconBlock},
    deneb::containers::{BlobIdentifier, BlobSidecar},
    fulu::{
        containers::{DataColumnIdentifier, DataColumnSidecar, MatrixEntry},
        primitives::ColumnIndex,
    },
    nonstandard::{PayloadStatus, RelativeEpoch, ValidationOutcome},
    phase0::{
        containers::Checkpoint,
        primitives::{ExecutionBlockHash, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::{
    block_processor::BlockProcessor,
    events::{DependentRootsBundle, EventChannels},
    messages::{
        AttestationVerifierMessage, MutatorMessage, P2pMessage, PoolMessage, SubnetMessage,
        SyncMessage, ValidatorMessage,
    },
    misc::{
        BlockBlobAvailability, BlockDataColumnAvailability, Delayed, MutatorRejectionReason,
        PendingAggregateAndProof, PendingAttestation, PendingBlobSidecar, PendingBlock,
        PendingChainLink, PendingDataColumnSidecar, ProcessingTimings, ReorgSource,
        VerifyAggregateAndProofResult, VerifyAttestationResult, WaitingForCheckpointState,
    },
    storage::Storage,
    tasks::{
        AttestationTask, BlobSidecarTask, BlockAttestationsTask, BlockTask, CheckpointStateTask,
        DataColumnSidecarTask, PersistBlobSidecarsTask, PersistDataColumnSidecarsTask,
        PersistPubkeyCacheTask, PreprocessStateTask, ReconstructDataColumnSidecarsTask,
    },
    thread_pool::{Spawn, ThreadPool},
    unbounded_sink::UnboundedSink,
    wait::Wait,
};

const DATA_COLUMN_RETAIN_DURATION_IN_SLOTS: Slot = 2;

#[expect(clippy::struct_field_names)]
pub struct Mutator<P: Preset, E, W, TS, PS, LS, NS, SS, VS> {
    pubkey_cache: Arc<PubkeyCache>,
    store: Arc<Store<P, Storage<P>>>,
    store_snapshot: Arc<ArcSwap<Store<P, Storage<P>>>>,
    state_cache: Arc<StateCacheProcessor<P>>,
    block_processor: Arc<BlockProcessor<P>>,
    event_channels: Arc<EventChannels<P>>,
    execution_engine: E,
    delayed_until_blobs: HashMap<H256, PendingBlock<P>>,
    delayed_until_block: HashMap<H256, Delayed<P>>,
    // We previously ignored objects that would have to be delayed more than one slot. This was
    // based on the assumption that one slot is enough to account for clock differences between
    // nodes. However, this meant that if the application lagged enough to miss multiple slot
    // updates (not necessarily by its own fault), the fork choice store would start ignoring blocks
    // and make the application stop syncing.
    delayed_until_slot: BTreeMap<Slot, Delayed<P>>,
    // `Mutator.delayed_until_payload` is needed mainly to run optimistic sync test cases, but the
    // problem it solves can occur in normal operation as well. The execution layer may finish
    // validating the payload before the fork choice store processes the block containing it.
    delayed_until_payload: HashMap<ExecutionBlockHash, Vec<(PayloadStatusV1, Slot)>>,
    delayed_until_state: HashMap<(H256, Slot), Delayed<P>>,
    // The specification doesn't explicitly state it, but `Store.checkpoint_states` is effectively a
    // cache, as its contents can be recomputed at any time using data from other fields.
    //
    // Advancing a `BeaconState` through slots for each attestation independently results in a
    // massive slowdown. A naive implementation (one that matches `consensus-specs` exactly) could
    // avoid this by processing attestations sequentially and mutating `Store.checkpoint_states`
    // after each one. We cannot do this because we want to process attestations in parallel.
    // We previously solved this for attestations in blocks by extracting their targets and lazily
    // computing the checkpoint state for each target. Individual attestations received in quick
    // succession would still perform slot processing independently.
    waiting_for_checkpoint_states: HashMap<Checkpoint, WaitingForCheckpointState<P>>,
    storage: Arc<Storage<P>>,
    thread_pool: ThreadPool<P, E, W>,
    metrics: Option<Arc<Metrics>>,
    finished_loading_from_storage: bool,
    mutator_tx: Sender<MutatorMessage<P, W>>,
    mutator_rx: Receiver<MutatorMessage<P, W>>,
    attestation_verifier_tx: TS,
    p2p_tx: PS,
    pool_tx: LS,
    subnet_tx: NS,
    sync_tx: SS,
    validator_tx: VS,
}

impl<P, E, W, TS, PS, LS, NS, SS, VS> Mutator<P, E, W, TS, PS, LS, NS, SS, VS>
where
    P: Preset,
    E: ExecutionEngine<P> + Clone + Send + Sync + 'static,
    W: Wait,
    TS: UnboundedSink<AttestationVerifierMessage<P, W>>,
    PS: UnboundedSink<P2pMessage<P>>,
    LS: UnboundedSink<PoolMessage>,
    NS: UnboundedSink<SubnetMessage<W>>,
    SS: UnboundedSink<SyncMessage<P>>,
    VS: UnboundedSink<ValidatorMessage<P, W>>,
{
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        pubkey_cache: Arc<PubkeyCache>,
        store_snapshot: Arc<ArcSwap<Store<P, Storage<P>>>>,
        state_cache: Arc<StateCacheProcessor<P>>,
        block_processor: Arc<BlockProcessor<P>>,
        event_channels: Arc<EventChannels<P>>,
        execution_engine: E,
        storage: Arc<Storage<P>>,
        thread_pool: ThreadPool<P, E, W>,
        metrics: Option<Arc<Metrics>>,
        mutator_tx: Sender<MutatorMessage<P, W>>,
        mutator_rx: Receiver<MutatorMessage<P, W>>,
        attestation_verifier_tx: TS,
        p2p_tx: PS,
        pool_tx: LS,
        subnet_tx: NS,
        sync_tx: SS,
        validator_tx: VS,
    ) -> Self {
        Self {
            pubkey_cache,
            store: store_snapshot.load_full(),
            store_snapshot,
            state_cache,
            block_processor,
            event_channels,
            execution_engine,
            delayed_until_blobs: HashMap::new(),
            delayed_until_block: HashMap::new(),
            delayed_until_slot: BTreeMap::new(),
            delayed_until_payload: HashMap::new(),
            delayed_until_state: HashMap::new(),
            waiting_for_checkpoint_states: HashMap::new(),
            storage,
            thread_pool,
            metrics,
            finished_loading_from_storage: false,
            mutator_tx,
            mutator_rx,
            attestation_verifier_tx,
            p2p_tx,
            pool_tx,
            subnet_tx,
            sync_tx,
            validator_tx,
        }
    }

    #[expect(clippy::too_many_lines)]
    pub fn run(&mut self) -> Result<()> {
        loop {
            match self
                .mutator_rx
                .recv()
                .expect("sender in Controller is not dropped until mutator thread exits")
            {
                MutatorMessage::Tick { wait_group, tick } => self.handle_tick(&wait_group, tick)?,
                MutatorMessage::BackSyncStatus {
                    wait_group,
                    is_back_synced,
                } => self.handle_back_sync_status(wait_group, is_back_synced),
                MutatorMessage::Block {
                    wait_group,
                    result,
                    origin,
                    processing_timings,
                    block_root,
                } => {
                    self.handle_block(wait_group, result, origin, processing_timings, block_root)?
                }
                MutatorMessage::AggregateAndProof { wait_group, result } => {
                    self.handle_aggregate_and_proof(&wait_group, result)?
                }
                MutatorMessage::AggregateAndProofBatch {
                    wait_group,
                    results,
                } => self.handle_aggregate_and_proof_batch(&wait_group, results)?,
                MutatorMessage::Attestation { wait_group, result } => {
                    self.handle_attestation(&wait_group, result)?
                }
                MutatorMessage::AttestationBatch {
                    wait_group,
                    results,
                } => self.handle_attestation_batch(&wait_group, results)?,
                MutatorMessage::BlockAttestations {
                    wait_group,
                    results,
                } => self.handle_block_attestations(&wait_group, results)?,
                MutatorMessage::AttesterSlashing {
                    wait_group,
                    result,
                    origin,
                } => self.handle_attester_slashing(&wait_group, result, origin)?,
                MutatorMessage::BlobSidecar {
                    wait_group,
                    result,
                    origin,
                    blob_identifier,
                    block_seen,
                    submission_time,
                } => self.handle_blob_sidecar(
                    wait_group,
                    result,
                    origin,
                    blob_identifier,
                    block_seen,
                    submission_time,
                ),
                MutatorMessage::CheckpointState {
                    wait_group,
                    checkpoint,
                    checkpoint_state,
                } => self.handle_checkpoint_state(&wait_group, checkpoint, checkpoint_state)?,
                MutatorMessage::DataColumnSidecar {
                    wait_group,
                    result,
                    origin,
                    data_column_identifier,
                    block_seen,
                    submission_time,
                } => self.handle_data_column_sidecar(
                    wait_group,
                    result,
                    origin,
                    data_column_identifier,
                    block_seen,
                    submission_time,
                ),
                MutatorMessage::FinishedPersistingBlobSidecars {
                    wait_group,
                    persisted_blob_ids,
                } => {
                    self.handle_finish_persisting_blob_sidecars(wait_group, persisted_blob_ids);
                }
                MutatorMessage::FinishedPersistingDataColumnSidecars {
                    wait_group,
                    persisted_data_column_ids,
                    slot,
                } => {
                    self.handle_finish_persisting_data_column_sidecars(
                        wait_group,
                        persisted_data_column_ids,
                        slot,
                    );
                }
                MutatorMessage::PreprocessedBeaconState { state } => {
                    self.prepare_execution_payload_for_next_slot(&state);
                }
                MutatorMessage::NotifiedForkChoiceUpdate {
                    wait_group,
                    payload_status,
                } => self.handle_notified_forkchoice_update_result(&wait_group, &payload_status),
                MutatorMessage::NotifiedNewPayload {
                    wait_group,
                    beacon_block_root,
                    execution_block_hash,
                    payload_status,
                } => self.handle_notified_new_payload(
                    &wait_group,
                    beacon_block_root,
                    execution_block_hash,
                    payload_status,
                ),
                MutatorMessage::Stop { save_to_storage } => {
                    break self.handle_stop(save_to_storage);
                }
                MutatorMessage::StoreSamplingColumns { sampling_columns } => {
                    self.handle_store_sampling_columns(sampling_columns)
                }
                MutatorMessage::ReconstructedMissingColumns {
                    wait_group,
                    block_root,
                    full_matrix,
                } => {
                    self.handle_reconstructed_missing_columns(&wait_group, block_root, full_matrix)?
                }
            }
        }
    }

    pub fn process_unfinalized_blocks(
        &mut self,
        mut blocks: impl DoubleEndedIterator<Item = Result<Arc<SignedBeaconBlock<P>>>>,
    ) -> Result<()> {
        let wait_group = W::default();

        let Some(last_block) = blocks.next_back().transpose()? else {
            self.finished_loading_from_storage = true;
            return Ok(());
        };

        let head_slot = self
            .storage
            .checkpoint_state_slot()?
            .unwrap_or_else(|| last_block.message().slot());

        self.handle_tick(&wait_group, Tick::start_of_slot(head_slot))?;

        for result in blocks.chain(core::iter::once(Ok(last_block))) {
            let block = result?;
            let origin = BlockOrigin::Persisted;
            let processing_timings = ProcessingTimings::new();

            // There is no point in spawning `BlockTask`s to validate persisted blocks.
            // State transitions within a single fork must be performed sequentially.
            // Other validations may be performed in parallel, but they take very little time.
            let result = self
                .block_processor
                .validate_block(
                    &self.store,
                    &block,
                    origin.state_root_policy(),
                    origin.data_availability_policy(),
                    &self.execution_engine,
                    NullVerifier,
                )
                .into();

            let block_root = block.message().hash_tree_root();

            self.handle_block(
                wait_group.clone(),
                result,
                origin,
                processing_timings,
                block_root,
            )?;
        }

        self.finished_loading_from_storage = true;

        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    fn handle_tick(&mut self, wait_group: &W, tick: Tick) -> Result<()> {
        if tick.epoch::<P>() > self.store.current_epoch() {
            let checkpoint = self.store.unrealized_justified_checkpoint();

            if !self.store.contains_checkpoint_state(checkpoint) {
                debug!(
                    "tick waiting for checkpoint state \
                     (tick: {tick:?}, checkpoint: {checkpoint:?})",
                );

                let waiting = self
                    .waiting_for_checkpoint_states
                    .entry(checkpoint)
                    .or_default();

                let new = waiting.is_empty();

                waiting.ticks.push(tick);

                if new {
                    self.spawn_checkpoint_state_task(wait_group.clone(), checkpoint);
                }

                return Ok(());
            }
        }

        if tick.is_start_of_epoch::<P>() {
            self.execution_engine.exchange_capabilities();
        }

        // Query the execution engine for the current status of the head
        // if it is still optimistic 1 second before the next interval.
        if tick.is_end_of_interval() {
            let head = self.store.head();

            if head.is_optimistic() {
                if let Some(execution_payload) = head.block.as_ref().clone().execution_payload() {
                    let mut params = None;

                    if let Some(body) = head.block.message().body().post_electra() {
                        let versioned_hashes = body
                            .blob_kzg_commitments()
                            .iter()
                            .copied()
                            .map(misc::kzg_commitment_to_versioned_hash)
                            .collect();

                        params = Some(ExecutionPayloadParams::Electra {
                            versioned_hashes,
                            parent_beacon_block_root: head.block.message().parent_root(),
                            execution_requests: body.execution_requests().clone(),
                        });
                    } else if let Some(body) = head.block.message().body().post_deneb() {
                        let versioned_hashes = body
                            .blob_kzg_commitments()
                            .iter()
                            .copied()
                            .map(misc::kzg_commitment_to_versioned_hash)
                            .collect();

                        params = Some(ExecutionPayloadParams::Deneb {
                            versioned_hashes,
                            parent_beacon_block_root: head.block.message().parent_root(),
                        });
                    }

                    self.execution_engine.notify_new_payload(
                        head.block_root,
                        execution_payload,
                        params,
                        None,
                    )?;
                }
            }
        }

        let Some(changes) = self.store_mut().apply_tick(tick)? else {
            return Ok(());
        };

        if changes.is_finalized_checkpoint_updated() {
            self.archive_finalized(wait_group)?;
            self.prune_delayed_until_payload();
            self.persist_pubkey_cache(wait_group);

            let finalized_slot = self.store.finalized_slot();

            self.event_channels.prune_after_finalization(finalized_slot);

            if self.store.head().block.phase().is_peerdas_activated() {
                self.try_spawn_persist_data_columns_task(finalized_slot, wait_group.clone());
            }
        } else if changes.is_slot_updated()
            && self.store.head().block.phase().is_peerdas_activated()
        {
            self.try_spawn_persist_data_columns_task(
                self.store
                    .head()
                    .slot()
                    .saturating_sub(DATA_COLUMN_RETAIN_DURATION_IN_SLOTS),
                wait_group.clone(),
            )
        }

        self.update_store_snapshot();

        self.send_to_validator(ValidatorMessage::Tick(wait_group.clone(), tick));
        self.send_to_pool(PoolMessage::Tick(tick));

        if changes.is_slot_updated() {
            let slot = tick.slot;

            debug!("retrying objects delayed until slot {slot}");

            for delayed in self.take_delayed_until_slot(slot) {
                self.retry_delayed(delayed, wait_group);
            }

            self.send_to_pool(PoolMessage::Slot(slot));
            self.send_to_p2p(P2pMessage::Slot(slot));
            self.send_to_subnet_service(SubnetMessage::Slot(wait_group.clone(), slot));

            self.track_collection_metrics();
        }

        if changes.is_finalized_checkpoint_updated() {
            self.notify_about_finalized_checkpoint();
        }

        if let ApplyTickChanges::Reorganized { old_head, .. } = changes {
            self.notify_about_reorganization(wait_group.clone(), &old_head, ReorgSource::Tick);
            self.spawn_preprocess_head_state_for_next_slot_task();
        } else if self.store.tick().kind == TickKind::Attest {
            self.spawn_preprocess_head_state_for_next_slot_task();
        }

        if self.store.is_forward_synced() && misc::slots_since_epoch_start::<P>(tick.slot) == 0 {
            if tick.kind == TickKind::AttestFourth && self.store.is_back_synced() {
                self.prune_old_records()?;
            }

            if let Some(metrics) = self.metrics.as_ref() {
                Self::track_epoch_transition_metrics(
                    &self.store.head().state(&self.store),
                    metrics,
                );
            }
        }

        if tick.kind == TickKind::AggregateFourth {
            let store = &self.store;

            if let Some(state) = self.state_cache.existing_state_at_slot(
                store,
                store.head().block_root,
                store.slot() + 1,
            ) {
                self.prepare_execution_payload_for_next_slot(&state);
            }
        }

        Ok(())
    }

    fn handle_back_sync_status(&mut self, wait_group: W, is_back_synced: bool) {
        if self.store.is_back_synced() != is_back_synced {
            self.store_mut().set_back_synced(is_back_synced);
            self.update_store_snapshot();
        }

        drop(wait_group);
    }

    fn try_spawn_persist_data_columns_task(&mut self, slot: Slot, wait_group: W) {
        if self.storage.prune_storage_enabled() {
            return self.store_mut().prune_data_columns(slot);
        }

        self.spawn(PersistDataColumnSidecarsTask {
            slot,
            store_snapshot: self.owned_store(),
            storage: self.storage.clone_arc(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            metrics: self.metrics.clone(),
        });
    }

    #[expect(clippy::too_many_lines)]
    #[expect(clippy::cognitive_complexity)]
    fn handle_block(
        &mut self,
        wait_group: W,
        result: Box<Result<BlockAction<P>>>,
        origin: BlockOrigin,
        processing_timings: ProcessingTimings,
        block_root: H256,
    ) -> Result<()> {
        match *result {
            Ok(BlockAction::Accept(mut chain_link, attester_slashing_results)) => {
                let block_root = chain_link.block_root;
                let parent_root = chain_link.block.message().parent_root();

                if let Some(delayed) = self.delayed_until_block.get_mut(&block_root) {
                    if let Some((payload_status, _)) = delayed.payload_status.take() {
                        debug!(
                            "applying delayed payload status \
                            (payload_status: {payload_status:?}, beacon_block_root: {block_root:?})",
                        );

                        if let Some(valid_hash) = payload_status.latest_valid_hash {
                            if let Some(parent) = self.store.chain_link(parent_root) {
                                let parent_execution_block_hash =
                                    parent.block.execution_block_hash();

                                self.store_mut().update_chain_payload_statuses(
                                    valid_hash,
                                    parent_execution_block_hash,
                                );

                                self.update_store_snapshot();
                            }
                        }

                        if payload_status.status.is_valid() {
                            chain_link.payload_status = PayloadStatus::Valid;
                        }

                        if payload_status.status.is_invalid() {
                            self.reject_block(
                                Error::<P>::InvalidExecutionPayload.into(),
                                block_root,
                                origin,
                            );
                            return Ok(());
                        }
                    }
                }

                let pending_chain_link = PendingChainLink {
                    chain_link,
                    attester_slashing_results,
                    origin,
                    processing_timings,
                };

                self.accept_block(&wait_group, pending_chain_link)?;
            }
            Ok(BlockAction::Ignore(publishable)) => {
                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_block_validation_result_to_http_api(
                    sender,
                    Ok(ValidationOutcome::Ignore(publishable)),
                );
            }
            Ok(BlockAction::DelayUntilBlobs(block, state)) => {
                let processing_timings = processing_timings.delayed();

                let pending_block = PendingBlock {
                    block,
                    origin,
                    processing_timings,
                };

                if pending_block.block.phase().is_peerdas_activated() {
                    let block_data_column_availability = self.block_data_column_availability(
                        &pending_block.block,
                        self.delayed_until_state
                            .get(&(block_root, state.slot()))
                            .iter()
                            .flat_map(|delayed| delayed.data_column_sidecars.iter())
                            .map(|pending| pending.data_column_sidecar.as_ref()),
                    );

                    info!(
                        "availability for block: {:?} with origin: {:?} at slot: {}: {block_data_column_availability:?}",
                        pending_block.block.message().hash_tree_root(),
                        pending_block.origin,
                        pending_block.block.message().slot(),
                    );

                    match block_data_column_availability {
                        BlockDataColumnAvailability::Complete => {
                            self.retry_block(wait_group, pending_block);
                        }
                        BlockDataColumnAvailability::AnyPending => {
                            self.delay_block_until_blobs(block_root, pending_block);

                            self.take_delayed_until_state(block_root, state.slot())
                                .unwrap_or_default()
                                .data_column_sidecars
                                .into_iter()
                                .for_each(|pending_data_column| {
                                    self.retry_data_column_sidecar(
                                        wait_group.clone(),
                                        pending_data_column,
                                        Some(state.clone_arc()),
                                    );
                                });
                        }
                        BlockDataColumnAvailability::CompleteWithReconstruction => {
                            if let Some(gossip_id) = pending_block.origin.gossip_id() {
                                self.send_to_p2p(P2pMessage::Accept(gossip_id));
                            }

                            if self
                                .store
                                .indices_of_missing_data_columns(&pending_block.block)
                                .is_empty()
                            {
                                self.retry_block(wait_group, pending_block);
                            } else {
                                // TODO(peerdas-fulu): NEED REVIEW! if block proposed by itself, therefore all sampling
                                // columns should be arrived soon or later, so no need to trigger reconstruction.
                                if !matches!(pending_block.origin, BlockOrigin::Own)
                                    && !self.store.is_sidecars_construction_started(&block_root)
                                {
                                    self.handle_reconstructing_data_column_sidecars(
                                        wait_group,
                                        block_root,
                                        pending_block.block.message().slot(),
                                    );
                                }

                                self.delay_block_until_blobs(block_root, pending_block);
                            }
                        }
                        BlockDataColumnAvailability::Missing(missing_column_indices) => {
                            debug!(
                                "block delayed until sufficient data column sidecars are available \
                                 (missing columns: {missing_column_indices:?}, pending block root: {block_root:?})",
                            );

                            if let Some(gossip_id) = pending_block.origin.gossip_id() {
                                self.send_to_p2p(P2pMessage::Accept(gossip_id));
                            }

                            let pending_block = reply_delayed_block_validation_result(
                                pending_block,
                                Ok(ValidationOutcome::Ignore(false)),
                            );

                            if self.store.is_forward_synced()
                                && !self.store.has_requested_blobs_from_el(&block_root)
                                && !self.store.is_sidecars_construction_started(&block_root)
                            {
                                self.store_mut().mark_requested_blobs_from_el(
                                    block_root,
                                    pending_block.block.message().slot(),
                                );
                                self.update_store_snapshot();

                                let data_column_identifiers = missing_column_indices
                                    .into_iter()
                                    .map(|index| DataColumnIdentifier { block_root, index })
                                    .collect_vec();

                                self.request_blobs_from_execution_engine(
                                    EngineGetBlobsV2Params {
                                        block_or_sidecar: pending_block.block.clone_arc().into(),
                                        data_column_identifiers,
                                    }
                                    .into(),
                                );
                            }

                            self.delay_block_until_blobs(block_root, pending_block);
                        }
                        BlockDataColumnAvailability::Irrelevant => {
                            unreachable!("block without blobs should not be delayed until blobs")
                        }
                    }
                } else {
                    let block_blob_availability = self.block_blob_availability(
                        &pending_block.block,
                        self.delayed_until_state
                            .get(&(block_root, state.slot()))
                            .iter()
                            .flat_map(|delayed| delayed.blob_sidecars.iter())
                            .map(|pending_blob_sidecar| pending_blob_sidecar.blob_sidecar.as_ref()),
                    );

                    match block_blob_availability {
                        BlockBlobAvailability::Complete => {
                            self.retry_block(wait_group, pending_block);
                        }
                        BlockBlobAvailability::CompleteWithPending => {
                            self.delay_block_until_blobs(block_root, pending_block);

                            self.take_delayed_until_state(block_root, state.slot())
                                .unwrap_or_default()
                                .blob_sidecars
                                .into_iter()
                                .for_each(|pending_blob| {
                                    self.retry_blob_sidecar(
                                        wait_group.clone(),
                                        pending_blob,
                                        Some(state.clone_arc()),
                                    );
                                });
                        }
                        BlockBlobAvailability::Missing(missing_blob_indices) => {
                            debug!("block delayed until blobs: {pending_block:?}");

                            if let Some(gossip_id) = pending_block.origin.gossip_id() {
                                self.send_to_p2p(P2pMessage::Accept(gossip_id));
                            }

                            let pending_block = reply_delayed_block_validation_result(
                                pending_block,
                                Ok(ValidationOutcome::Ignore(false)),
                            );

                            let blob_identifiers = missing_blob_indices
                                .into_iter()
                                .map(|index| BlobIdentifier { block_root, index })
                                .collect_vec();

                            let peer_id = pending_block.origin.peer_id();

                            self.request_blobs_from_execution_engine(
                                EngineGetBlobsV1Params {
                                    block: pending_block.block.clone_arc(),
                                    blob_identifiers,
                                    peer_id,
                                }
                                .into(),
                            );

                            self.delay_block_until_blobs(block_root, pending_block);
                        }
                        BlockBlobAvailability::Irrelevant => {
                            unreachable!("block without blobs should not be delayed until blobs")
                        }
                    }
                }
            }
            Ok(BlockAction::DelayUntilParent(block)) => {
                let processing_timings = processing_timings.delayed();
                let parent_root = block.message().parent_root();

                let pending_block = PendingBlock {
                    block,
                    origin,
                    processing_timings,
                };

                if self.store.contains_block(parent_root) {
                    self.retry_block(wait_group, pending_block);
                } else {
                    let pending_block = reply_delayed_block_validation_result(
                        pending_block,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    debug!("block delayed until parent: {pending_block:?}");

                    let peer_id = pending_block.origin.peer_id();

                    self.send_to_p2p(P2pMessage::BlockNeeded(parent_root, peer_id));

                    self.delay_block_until_parent(pending_block);
                }
            }
            Ok(BlockAction::DelayUntilSlot(block)) => {
                let processing_timings = processing_timings.delayed();
                let slot = block.message().slot();

                let pending_block = PendingBlock {
                    block,
                    origin,
                    processing_timings,
                };

                if slot <= self.store.slot() {
                    self.retry_block(wait_group, pending_block);
                } else {
                    let pending_block = reply_delayed_block_validation_result(
                        pending_block,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    debug!("block delayed until slot: {pending_block:?}");

                    self.delay_block_until_slot(pending_block);
                }
            }
            Ok(BlockAction::WaitForJustifiedState(
                chain_link,
                attester_slashing_results,
                checkpoint,
            )) => {
                let processing_timings = processing_timings.delayed();
                let pending_chain_link = PendingChainLink {
                    chain_link,
                    attester_slashing_results,
                    origin,
                    processing_timings,
                };

                if self.store.contains_checkpoint_state(checkpoint) {
                    self.accept_block(&wait_group, pending_chain_link)?;
                } else {
                    debug!(
                        "block waiting for checkpoint state \
                         (block_root: {:?}, block: {:?}, checkpoint: {checkpoint:?})",
                        pending_chain_link.chain_link.block_root,
                        pending_chain_link.chain_link.block,
                    );

                    let waiting = self
                        .waiting_for_checkpoint_states
                        .entry(checkpoint)
                        .or_default();

                    let new = waiting.is_empty();

                    waiting.chain_links.push(pending_chain_link);

                    if new {
                        self.spawn_checkpoint_state_task(wait_group, checkpoint);
                    }
                }
            }
            Err(error) => self.reject_block(error, block_root, origin),
        }

        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    fn handle_aggregate_and_proof(
        &mut self,
        wait_group: &W,
        verify_result: VerifyAggregateAndProofResult<P>,
    ) -> Result<()> {
        let VerifyAggregateAndProofResult { result, origin } = verify_result;

        match result {
            Ok(AggregateAndProofAction::Accept {
                aggregate_and_proof,
                attesting_indices,
                is_subset_aggregate,
            }) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["accepted"]);
                }

                debug!(
                    "aggregate and proof accepted \
                     (aggregate_and_proof: {aggregate_and_proof:?}, origin: {origin:?})",
                );

                if origin.send_to_validator() {
                    let attestation = Arc::new(aggregate_and_proof.message().aggregate());

                    self.send_to_validator(ValidatorMessage::ValidAttestation(
                        wait_group.clone(),
                        attestation,
                    ));
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    if is_subset_aggregate {
                        self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                    } else {
                        self.send_to_p2p(P2pMessage::Accept(gossip_id));
                    }
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                let valid_attestation = ValidAttestation {
                    data: aggregate_and_proof.message().aggregate().data(),
                    attesting_indices,
                    is_from_block: false,
                };

                let old_head = self.store_mut().apply_attestation(valid_attestation)?;

                self.update_store_snapshot();

                if let Some(old_head) = old_head {
                    self.notify_about_reorganization(
                        wait_group.clone(),
                        &old_head,
                        ReorgSource::AggregateAndProof,
                    );

                    self.spawn_preprocess_head_state_for_next_slot_task();
                }
            }
            Ok(AggregateAndProofAction::Ignore) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["ignored"]);
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore(false)));
            }
            Ok(AggregateAndProofAction::DelayUntilBlock(aggregate_and_proof, block_root)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["delayed_until_block"]);
                }

                let pending_aggregate_and_proof = PendingAggregateAndProof {
                    aggregate_and_proof,
                    origin,
                };

                self.delay_aggregate_and_proof_until_block(
                    wait_group,
                    pending_aggregate_and_proof,
                    block_root,
                );
            }
            Ok(AggregateAndProofAction::DelayUntilSlot(aggregate_and_proof)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["delayed_until_slot"]);
                }

                let pending_aggregate_and_proof = PendingAggregateAndProof {
                    aggregate_and_proof,
                    origin,
                };

                self.delay_aggregate_and_proof_until_slot(wait_group, pending_aggregate_and_proof);
            }
            Ok(AggregateAndProofAction::WaitForTargetState(aggregate_and_proof)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["delayed_until_state"]);
                }

                let checkpoint = aggregate_and_proof.message().aggregate().data().target;

                let pending_aggregate_and_proof = PendingAggregateAndProof {
                    aggregate_and_proof,
                    origin,
                };

                if self.store.contains_checkpoint_state(checkpoint) {
                    self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
                } else {
                    let waiting = self
                        .waiting_for_checkpoint_states
                        .entry(checkpoint)
                        .or_default();

                    let new = waiting.is_empty();

                    waiting.aggregates.push(pending_aggregate_and_proof);

                    if new {
                        self.spawn_checkpoint_state_task(wait_group.clone(), checkpoint);
                    }
                }
            }
            Err(error) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["rejected"]);
                }

                if matches!(
                    error.downcast_ref::<Error<P>>(),
                    Some(Error::AggregatorNotInCommittee { .. }),
                ) {
                    debug!("aggregate and proof rejected (error: {error}, origin: {origin:?})");
                } else {
                    warn!("aggregate and proof rejected (error: {error}, origin: {origin:?})");
                }

                let (gossip_id, sender) = origin.split();

                if gossip_id.is_some() {
                    self.send_to_p2p(P2pMessage::Reject(
                        gossip_id,
                        MutatorRejectionReason::InvalidAggregateAndProof,
                    ));
                }

                reply_to_http_api(sender, Err(error));
            }
        }

        Ok(())
    }

    fn handle_aggregate_and_proof_batch(
        &mut self,
        wait_group: &W,
        results: Vec<VerifyAggregateAndProofResult<P>>,
    ) -> Result<()> {
        for result in results {
            self.handle_aggregate_and_proof(wait_group, result)?;
        }

        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    fn handle_attestation(
        &mut self,
        wait_group: &W,
        result: VerifyAttestationResult<P>,
    ) -> Result<()> {
        match result {
            Ok(AttestationAction::Accept {
                attestation,
                attesting_indices,
            }) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["accepted"]);
                }

                debug!("attestation accepted (attestation: {attestation:?})");

                if attestation.origin.should_generate_event() {
                    self.event_channels
                        .send_attestation_event(attestation.item.clone_arc());
                }

                if attestation.origin.send_to_validator() {
                    let attestation = attestation.item.clone_arc();

                    self.send_to_validator(ValidatorMessage::ValidAttestation(
                        wait_group.clone(),
                        attestation,
                    ));
                }

                let is_from_block = attestation.origin.is_from_block();

                let AttestationItem {
                    item: attestation,
                    origin,
                    ..
                } = attestation;

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Accept(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                let valid_attestation = ValidAttestation {
                    data: attestation.data(),
                    attesting_indices,
                    is_from_block,
                };

                let old_head = self.store_mut().apply_attestation(valid_attestation)?;

                self.update_store_snapshot();

                if let Some(old_head) = old_head {
                    self.notify_about_reorganization(
                        wait_group.clone(),
                        &old_head,
                        ReorgSource::Attestation,
                    );

                    self.spawn_preprocess_head_state_for_next_slot_task();
                }
            }
            Ok(AttestationAction::Ignore(attestation)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["ignored"]);
                }

                let (gossip_id, sender) = attestation.origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore(false)));
            }
            Ok(AttestationAction::DelayUntilBlock(attestation, block_root)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["delayed_until_block"]);
                }

                self.delay_attestation_until_block(wait_group, attestation, block_root);
            }
            Ok(AttestationAction::DelayUntilSlot(attestation)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["delayed_until_slot"]);
                }

                self.delay_attestation_until_slot(wait_group, attestation);
            }
            Ok(AttestationAction::WaitForTargetState(attestation)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["delayed_until_state"]);
                }

                let checkpoint = attestation.data().target;

                if self.store.contains_checkpoint_state(checkpoint) {
                    self.retry_attestation(wait_group.clone(), attestation);
                } else {
                    let waiting = self
                        .waiting_for_checkpoint_states
                        .entry(checkpoint)
                        .or_default();

                    let new = waiting.is_empty();

                    waiting.attestations.push(attestation);

                    if new {
                        self.spawn_checkpoint_state_task(wait_group.clone(), checkpoint);
                    }
                }
            }
            Err(error) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["rejected"]);
                }

                let source = error.to_string();
                warn!("attestation rejected (error: {error:?})",);

                let attestation = error.attestation();
                let (gossip_id, sender) = attestation.origin.split();

                if gossip_id.is_some() {
                    self.send_to_p2p(P2pMessage::Reject(
                        gossip_id,
                        MutatorRejectionReason::InvalidAttestation,
                    ));
                }

                reply_to_http_api(sender, Err(anyhow!(source)));
            }
        }

        Ok(())
    }

    fn handle_attestation_batch(
        &mut self,
        wait_group: &W,
        results: Vec<VerifyAttestationResult<P>>,
    ) -> Result<()> {
        for result in results {
            self.handle_attestation(wait_group, result)?;
        }

        Ok(())
    }

    fn handle_block_attestations(
        &mut self,
        wait_group: &W,
        results: Vec<
            Result<AttestationAction<P, GossipId>, AttestationValidationError<P, GossipId>>,
        >,
    ) -> Result<()> {
        let accepted = results
            .into_iter()
            .filter_map(|result| match result {
                Ok(AttestationAction::Accept {
                    attestation,
                    attesting_indices,
                }) => Some(ValidAttestation {
                    data: attestation.data(),
                    attesting_indices,
                    is_from_block: true,
                }),
                Ok(AttestationAction::Ignore(_)) => None,
                Ok(AttestationAction::DelayUntilBlock(attestation, block_root)) => {
                    self.delay_attestation_until_block(wait_group, attestation, block_root);
                    None
                }
                Ok(AttestationAction::DelayUntilSlot(attestation)) => {
                    self.delay_attestation_until_slot(wait_group, attestation);
                    None
                }
                Ok(AttestationAction::WaitForTargetState(pending_attestation)) => {
                    let checkpoint = pending_attestation.data().target;

                    if self.store.contains_checkpoint_state(checkpoint) {
                        self.retry_attestation(wait_group.clone(), pending_attestation)
                    } else {
                        let waiting = self
                            .waiting_for_checkpoint_states
                            .entry(checkpoint)
                            .or_default();

                        let new = waiting.is_empty();

                        waiting.attestations.push(pending_attestation);

                        if new {
                            self.spawn_checkpoint_state_task(wait_group.clone(), checkpoint);
                        }
                    }

                    None
                }
                Err(error) => {
                    warn!("block attestation rejected (error: {error})");
                    None
                }
            })
            .collect_vec();

        let old_head = self.store_mut().apply_attestation_batch(accepted)?;

        self.update_store_snapshot();

        if let Some(old_head) = old_head {
            self.notify_about_reorganization(
                wait_group.clone(),
                &old_head,
                ReorgSource::BlockAttestation,
            );

            self.spawn_preprocess_head_state_for_next_slot_task();
        }

        Ok(())
    }

    fn handle_attester_slashing(
        &mut self,
        wait_group: &W,
        result: Result<Vec<ValidatorIndex>>,
        origin: AttesterSlashingOrigin,
    ) -> Result<()> {
        match result {
            Ok(slashable_indices) => {
                let old_head = self
                    .store_mut()
                    .apply_attester_slashing(slashable_indices)?;

                self.update_store_snapshot();

                if let Some(old_head) = old_head {
                    self.notify_about_reorganization(
                        wait_group.clone(),
                        &old_head,
                        ReorgSource::AttesterSlashing,
                    );

                    self.spawn_preprocess_head_state_for_next_slot_task();
                }
            }
            Err(error) => debug!("attester slashing rejected (error: {error}, origin: {origin:?})"),
        }

        Ok(())
    }

    fn handle_blob_sidecar(
        &mut self,
        wait_group: W,
        result: Result<BlobSidecarAction<P>>,
        origin: BlobSidecarOrigin,
        blob_identifier: BlobIdentifier,
        block_seen: bool,
        submission_time: Instant,
    ) {
        match result {
            Ok(BlobSidecarAction::Accept(blob_sidecar)) => {
                if origin.is_from_el() {
                    self.send_to_p2p(P2pMessage::PublishBlobSidecar(blob_sidecar.clone_arc()));
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Accept(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                self.accept_blob_sidecar(&wait_group, &blob_sidecar);
            }
            Ok(BlobSidecarAction::Ignore(publishable)) => {
                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore(publishable)));
            }
            Ok(BlobSidecarAction::DelayUntilState(blob_sidecar, block_root)) => {
                let slot = blob_sidecar.signed_block_header.message.slot;

                let pending_blob_sidecar = PendingBlobSidecar {
                    blob_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if let Some(state) =
                    self.state_cache
                        .existing_state_at_slot(&self.store, block_root, slot)
                {
                    self.retry_blob_sidecar(wait_group, pending_blob_sidecar, Some(state));
                } else {
                    debug!(
                        "blob sidecar delayed until state at same slot is ready \
                         (blob_sidecar: {:?}, block_root: {block_root:?}, slot: {slot})",
                        pending_blob_sidecar.blob_sidecar,
                    );

                    let peer_id = pending_blob_sidecar.origin.peer_id();

                    self.send_to_p2p(P2pMessage::BlockNeeded(block_root, peer_id));

                    let pending_blob_sidecar = reply_delayed_blob_sidecar_validation_result(
                        pending_blob_sidecar,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    self.delay_blob_sidecar_until_state(pending_blob_sidecar, block_root);
                }
            }
            Ok(BlobSidecarAction::DelayUntilParent(blob_sidecar)) => {
                let parent_root = blob_sidecar.signed_block_header.message.parent_root;

                let pending_blob_sidecar = PendingBlobSidecar {
                    blob_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if self.store.contains_block(parent_root) {
                    self.retry_blob_sidecar(wait_group, pending_blob_sidecar, None);
                } else {
                    debug!("blob sidecar delayed until block parent: {parent_root:?}");

                    let peer_id = pending_blob_sidecar.origin.peer_id();

                    self.send_to_p2p(P2pMessage::BlockNeeded(parent_root, peer_id));

                    let pending_blob_sidecar = reply_delayed_blob_sidecar_validation_result(
                        pending_blob_sidecar,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    self.delay_blob_sidecar_until_parent(pending_blob_sidecar);
                }
            }
            Ok(BlobSidecarAction::DelayUntilSlot(blob_sidecar)) => {
                let slot = blob_sidecar.signed_block_header.message.slot;

                let pending_blob_sidecar = PendingBlobSidecar {
                    blob_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if slot <= self.store.slot() {
                    self.retry_blob_sidecar(wait_group, pending_blob_sidecar, None);
                } else {
                    debug!("blob sidecar delayed until slot: {slot}");

                    let pending_blob_sidecar = reply_delayed_blob_sidecar_validation_result(
                        pending_blob_sidecar,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    self.delay_blob_sidecar_until_slot(pending_blob_sidecar);
                }
            }
            Err(error) => {
                warn!("blob sidecar rejected (error: {error}, origin: {origin:?})");

                let (gossip_id, sender) = origin.split();

                self.send_to_p2p(P2pMessage::Reject(
                    gossip_id,
                    MutatorRejectionReason::InvalidBlobSidecar { blob_identifier },
                ));

                reply_to_http_api(sender, Err(error));
            }
        }
    }

    #[expect(clippy::too_many_lines)]
    fn handle_data_column_sidecar(
        &mut self,
        wait_group: W,
        result: Result<DataColumnSidecarAction<P>>,
        origin: DataColumnSidecarOrigin,
        data_column_identifier: DataColumnIdentifier,
        block_seen: bool,
        submission_time: Instant,
    ) {
        match result {
            Ok(DataColumnSidecarAction::Accept(data_column_sidecar)) => {
                if origin.is_from_el() {
                    self.send_to_p2p(P2pMessage::PublishDataColumnSidecar(
                        data_column_sidecar.clone_arc(),
                    ));
                }

                if !self.store.accepted_data_column_sidecar(
                    data_column_sidecar.signed_block_header.message,
                    data_column_sidecar.index,
                ) {
                    let block_root = data_column_sidecar
                        .signed_block_header
                        .message
                        .hash_tree_root();

                    if self.store.is_forward_synced()
                        && !matches!(
                            origin,
                            DataColumnSidecarOrigin::Own | DataColumnSidecarOrigin::ExecutionLayer
                        )
                        && !self.store.has_requested_blobs_from_el(&block_root)
                        && !self.store.is_sidecars_construction_started(&block_root)
                    {
                        self.store_mut()
                            .mark_requested_blobs_from_el(block_root, data_column_sidecar.slot());
                        self.update_store_snapshot();

                        let data_column_identifiers = self
                            .store
                            .sampling_columns()
                            .iter()
                            .map(|index| DataColumnIdentifier {
                                block_root,
                                index: *index,
                            })
                            .collect::<Vec<_>>();

                        self.request_blobs_from_execution_engine(
                            EngineGetBlobsV2Params {
                                block_or_sidecar: data_column_sidecar.clone_arc().into(),
                                data_column_identifiers,
                            }
                            .into(),
                        )
                    }

                    let (gossip_id, sender) = origin.split();

                    if let Some(gossip_id) = gossip_id {
                        self.send_to_p2p(P2pMessage::Accept(gossip_id));
                    }

                    reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                    self.accept_data_column_sidecar(&wait_group, &data_column_sidecar);
                }
            }
            Ok(DataColumnSidecarAction::Ignore(publishable)) => {
                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore(publishable)));
            }
            Ok(DataColumnSidecarAction::DelayUntilState(data_column_sidecar, block_root)) => {
                let slot = data_column_sidecar.signed_block_header.message.slot;

                let pending_data_column_sidecar = PendingDataColumnSidecar {
                    data_column_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if let Some(state) =
                    self.state_cache
                        .existing_state_at_slot(&self.store, block_root, slot)
                {
                    self.retry_data_column_sidecar(
                        wait_group,
                        pending_data_column_sidecar,
                        Some(state),
                    );
                } else {
                    debug!(
                        "data column sidecar delayed until state at same slot is ready \
                         (identifier: {data_column_identifier:?}, slot: {slot})",
                    );

                    let peer_id = pending_data_column_sidecar.origin.peer_id();

                    self.send_to_p2p(P2pMessage::BlockNeeded(block_root, peer_id));

                    let pending_data_column_sidecar =
                        reply_delayed_data_column_sidecar_validation_result(
                            pending_data_column_sidecar,
                            Ok(ValidationOutcome::Ignore(false)),
                        );

                    self.delay_data_column_sidecar_until_state(
                        pending_data_column_sidecar,
                        block_root,
                    );
                }
            }
            Ok(DataColumnSidecarAction::DelayUntilParent(data_column_sidecar)) => {
                let parent_root = data_column_sidecar.signed_block_header.message.parent_root;

                let pending_data_column_sidecar = PendingDataColumnSidecar {
                    data_column_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if self.store.contains_block(parent_root) {
                    self.retry_data_column_sidecar(wait_group, pending_data_column_sidecar, None);
                } else {
                    debug!("data column sidecar delayed until block parent: {parent_root:?}");

                    let peer_id = pending_data_column_sidecar.origin.peer_id();

                    self.send_to_p2p(P2pMessage::BlockNeeded(parent_root, peer_id));

                    let pending_data_column_sidecar =
                        reply_delayed_data_column_sidecar_validation_result(
                            pending_data_column_sidecar,
                            Ok(ValidationOutcome::Ignore(false)),
                        );

                    self.delay_data_column_sidecar_until_parent(pending_data_column_sidecar);
                }
            }
            Ok(DataColumnSidecarAction::DelayUntilSlot(data_column_sidecar)) => {
                let slot = data_column_sidecar.signed_block_header.message.slot;

                let pending_data_column_sidecar = PendingDataColumnSidecar {
                    data_column_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if slot <= self.store.slot() {
                    self.retry_data_column_sidecar(wait_group, pending_data_column_sidecar, None);
                } else {
                    debug!("data column sidecar delayed until slot: {slot}");

                    let pending_data_column_sidecar =
                        reply_delayed_data_column_sidecar_validation_result(
                            pending_data_column_sidecar,
                            Ok(ValidationOutcome::Ignore(false)),
                        );

                    self.delay_data_column_sidecar_until_slot(pending_data_column_sidecar);
                }
            }
            Err(error) => {
                warn!("data column sidecar rejected (error: {error}, origin: {origin:?})");

                let (gossip_id, sender) = origin.split();

                self.send_to_p2p(P2pMessage::Reject(
                    gossip_id,
                    MutatorRejectionReason::InvalidDataColumnSidecar {
                        data_column_identifier,
                    },
                ));

                reply_to_http_api(sender, Err(error));
            }
        }
    }

    fn handle_checkpoint_state(
        &mut self,
        wait_group: &W,
        checkpoint: Checkpoint,
        checkpoint_state: Option<Arc<BeaconState<P>>>,
    ) -> Result<()> {
        let Some(state) = checkpoint_state else {
            // The data required to compute the checkpoint state has been pruned.
            // The state and any objects waiting for it are no longer needed.
            // The objects waiting for it should have been pruned as well.
            // No further action is necessary.
            return Ok(());
        };

        let Some(waiting) = self.waiting_for_checkpoint_states.remove(&checkpoint) else {
            // The corresponding element in `Mutator.waiting_for_checkpoint_states` has been pruned.
            return Ok(());
        };

        self.store_mut().insert_checkpoint_state(checkpoint, state);

        // `Mutator::accept_block` also updates the snapshot, but only if the block isn't orphaned.
        self.update_store_snapshot();

        let WaitingForCheckpointState {
            ticks,
            chain_links,
            aggregates,
            attestations,
        } = waiting;

        for tick in ticks {
            self.retry_tick(wait_group, tick)?;
        }

        for pending_chain_link in chain_links {
            self.accept_block(wait_group, pending_chain_link)?;
        }

        for pending_aggregate_and_proof in aggregates {
            self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
        }

        // This spawns a separate task for each attestation.
        // Retrying them in batches did not improve performance during initial development.
        for pending_attestation in attestations {
            self.retry_attestation(wait_group.clone(), pending_attestation);
        }

        Ok(())
    }

    fn handle_finish_persisting_blob_sidecars(
        &mut self,
        wait_group: W,
        persisted_blob_ids: Vec<BlobIdentifier>,
    ) {
        self.store_mut().mark_persisted_blobs(persisted_blob_ids);

        self.update_store_snapshot();

        if self.store.has_unpersisted_blob_sidecars() {
            self.spawn(PersistBlobSidecarsTask {
                store_snapshot: self.owned_store(),
                storage: self.storage.clone_arc(),
                mutator_tx: self.owned_mutator_tx(),
                wait_group,
                metrics: self.metrics.clone(),
            });
        }
    }

    fn handle_finish_persisting_data_column_sidecars(
        &mut self,
        _wait_group: W,
        persisted_data_column_ids: Vec<DataColumnIdentifier>,
        slot: Slot,
    ) {
        self.store_mut()
            .mark_persisted_data_columns(persisted_data_column_ids);

        self.store_mut().prune_persisted_data_columns(slot);

        self.update_store_snapshot();
    }

    fn handle_reconstructing_data_column_sidecars(
        &mut self,
        wait_group: W,
        block_root: H256,
        slot: Slot,
    ) {
        self.store_mut()
            .mark_started_sidecars_construction(block_root, slot);
        self.update_store_snapshot();

        self.spawn(ReconstructDataColumnSidecarsTask {
            store_snapshot: self.owned_store(),
            storage: self.storage.clone_arc(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            block_root,
            metrics: self.metrics.clone(),
        });
    }

    fn handle_reconstructed_missing_columns(
        &mut self,
        wait_group: &W,
        block_root: H256,
        full_matrix: Vec<MatrixEntry<P>>,
    ) -> Result<()> {
        let Some(pending) = self.delayed_until_blobs.get(&block_root) else {
            return Ok(());
        };

        let missing_indices = self.store.indices_of_missing_data_columns(&pending.block);
        if missing_indices.is_empty() {
            return Ok(());
        }

        let timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.data_column_sidecar_computation.start_timer());

        let cells_and_kzg_proofs = eip_7594::construct_cells_and_kzg_proofs(full_matrix)?;

        let mut data_column_sidecars =
            eip_7594::construct_data_column_sidecars(&pending.block, &cells_and_kzg_proofs)?;

        prometheus_metrics::stop_and_record(timer);

        // > The following data column sidecars, where they exist, MUST be sent in (slot, column_index) order.
        data_column_sidecars.sort_by_key(|sidecar| (sidecar.slot(), sidecar.index));

        debug!(
            "storing data column sidecars from reconstruction (block: {block_root:?}, columns: {missing_indices:?})",
        );

        for data_column_sidecar in data_column_sidecars {
            if missing_indices.contains(&data_column_sidecar.index) {
                self.accept_data_column_sidecar(wait_group, &data_column_sidecar);

                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.reconstructed_columns.inc();
                }
            }

            if self.store.is_forward_synced() {
                self.send_to_p2p(P2pMessage::PublishDataColumnSidecar(data_column_sidecar));
            }
        }

        Ok(())
    }

    fn handle_notified_forkchoice_update_result(
        &mut self,
        wait_group: &W,
        payload_status: &PayloadStatusV1,
    ) {
        let Some(latest_valid_hash) = payload_status.latest_valid_hash else {
            return;
        };

        let old_head = self.store.head().clone();
        let head_was_optimistic = old_head.is_optimistic();

        self.store_mut()
            .update_chain_payload_statuses(latest_valid_hash, None);
        self.update_store_snapshot();

        self.handle_potential_head_change(wait_group, &old_head, head_was_optimistic);
    }

    fn handle_notified_new_payload(
        &mut self,
        wait_group: &W,
        beacon_block_root: H256,
        execution_block_hash: ExecutionBlockHash,
        payload_status: PayloadStatusV1,
    ) {
        if !self.store.contains_block(beacon_block_root) {
            self.delay_payload_status_until_block(beacon_block_root, payload_status);

            return;
        }

        let old_head = self.store.head().clone();
        let head_was_optimistic = old_head.is_optimistic();
        let latest_valid_hash = payload_status.latest_valid_hash;

        let mut payload_action = PayloadAction::Accept;

        if let Some(valid_hash) = latest_valid_hash {
            payload_action = self
                .store_mut()
                .update_chain_payload_statuses(valid_hash, Some(execution_block_hash));
        }

        let status = payload_status.status;

        if status.is_valid() {
            // According to the [Engine API specification], if the payload is valid,
            // `latest_valid_hash` must equal `execution_block_hash`.
            //
            // [Engine API specification]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#payload-validation
            if latest_valid_hash != Some(execution_block_hash) {
                warn!(
                    "execution engine returned inconsistent response \
                     (execution_block_hash: {execution_block_hash:?}, \
                     payload_status: {payload_status:?})",
                );
            }

            // The call to `Store::update_chain_payload_statuses` above will set the payload
            // statuses of the block and its ancestors to `PayloadStatus::Valid`.
        } else if status.is_invalid() {
            self.store_mut()
                .invalidate_block_and_descendant_payloads(beacon_block_root);
        } else {
            return;
        }

        match payload_action {
            PayloadAction::Accept => {}
            PayloadAction::DelayUntilBlock(hash) => {
                if !hash.is_zero() {
                    self.delayed_until_payload
                        .entry(hash)
                        .or_default()
                        .push((payload_status, self.store.slot()));
                }
            }
        }

        self.update_store_snapshot();

        // Do not send API events about optimistic blocks.
        // Vouch treats all head events as non-optimistic.
        if let Some(chain_link) = self
            .store
            .unfinalized_chain_link_by_execution_block_hash(execution_block_hash)
        {
            if chain_link.is_valid() {
                self.event_channels.send_block_event(
                    chain_link.slot(),
                    chain_link.block_root,
                    false,
                );
            }
        }

        self.handle_potential_head_change(wait_group, &old_head, head_was_optimistic);
    }

    fn handle_potential_head_change(
        &self,
        wait_group: &W,
        old_head: &ChainLink<P>,
        head_was_optimistic: bool,
    ) {
        let head = self.store.head();
        let head_changed = head.block_root != old_head.block_root;

        // Do not send API events about optimistic blocks.
        // Vouch treats all head events as non-optimistic.
        if !head_changed && head_was_optimistic && head.is_valid() {
            self.event_channels
                .send_head_event(head, |head| self.calculate_dependent_roots(head));

            // The call to `Store::notify_about_reorganization` below sends
            // a `ValidatorMessage::Head` message if the head changed.
            self.send_to_validator(ValidatorMessage::Head(wait_group.clone(), head.clone()));
        }

        if head_changed {
            self.notify_about_reorganization(
                wait_group.clone(),
                old_head,
                ReorgSource::PayloadResponse,
            );

            self.spawn_preprocess_head_state_for_next_slot_task();
        }
    }

    fn handle_stop(&self, save_to_storage: bool) -> Result<()> {
        // Send messages to services directly (i.e. not using wrapper methods)
        // to ensure the messages are sent unconditionally
        AttestationVerifierMessage::Stop.send(&self.attestation_verifier_tx);
        P2pMessage::Stop.send(&self.p2p_tx);
        PoolMessage::Stop.send(&self.pool_tx);
        SubnetMessage::Stop.send(&self.subnet_tx);
        ValidatorMessage::Stop.send(&self.validator_tx);

        self.execution_engine.stop();

        if save_to_storage {
            let slots = self.storage.append(
                self.store.unfinalized_canonical_chain(),
                self.store.finalized().iter(),
                &self.store,
            )?;

            info!(
                "chain saved (finalized blocks: {}, unfinalized blocks: {})",
                slots.finalized.len(),
                slots.unfinalized.len(),
            );

            debug!("appended block slots: {slots:?}");
        }

        Ok(())
    }

    fn handle_store_sampling_columns(&mut self, sampling_columns: HashSet<ColumnIndex>) {
        debug!(
            "storing index of column sidecars to sample: {sampling_columns:?} \
            for further data availability check",
        );

        self.store_mut().store_sampling_columns(sampling_columns);
        self.update_store_snapshot();
    }

    #[expect(clippy::cognitive_complexity)]
    #[expect(clippy::too_many_lines)]
    fn accept_block(
        &mut self,
        wait_group: &W,
        pending_chain_link: PendingChainLink<P>,
    ) -> Result<()> {
        let PendingChainLink {
            chain_link,
            attester_slashing_results,
            origin,
            processing_timings,
        } = pending_chain_link;

        let processing_timings = processing_timings.processing();
        let block_root = chain_link.block_root;
        let block = &chain_link.block;

        // Check if the block is already present in the store.
        // This is done here primarily to avoid spawning redundant `BlockAttestationsTask`s.
        if self.store.contains_block(block_root) {
            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                self.send_to_p2p(P2pMessage::Ignore(gossip_id));
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore(true)));

            return Ok(());
        }

        // A block may become orphaned while being processed.
        // The fork choice store is not designed to accommodate blocks like that.
        if block.message().slot() <= self.store.finalized_slot() {
            debug!(
                "block became orphaned while being processed \
                 (block_root: {block_root:?}, block: {block:?}, \
                  origin: {origin:?}, finalized slot: {})",
                self.store.finalized_slot(),
            );

            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                self.send_to_p2p(P2pMessage::Ignore(gossip_id));
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore(false)));

            return Ok(());
        }

        debug!("block accepted (block_root: {block_root:?}, block: {block:?}, origin: {origin:?})");

        let block_slot = chain_link.slot();

        if let Some(existing_link) = self.store.chain_link_before_or_at(block_slot) {
            if block_slot == existing_link.slot() {
                warn!(
                    "the store accepted a new block at slot {block_slot}, \
                    although it already contains one at the same slot on the canonical chain \
                    (existing canonical block: {:?}, new block: {:?})",
                    existing_link.block, chain_link.block,
                );
            }
        }

        let block = block.clone_arc();
        let is_valid = chain_link.is_valid();
        let changes = self.store_mut().apply_block(chain_link)?;
        let insertion_time = Instant::now();

        let unfinalized_states_in_memory = self.store.store_config().unfinalized_states_in_memory;
        let head_slot = self.store.head().slot();

        let block_epoch = misc::compute_epoch_at_slot::<P>(block_slot);
        let parent_epoch = self
            .store
            .chain_link(block.message().parent_root())
            .map(|chain_link| misc::compute_epoch_at_slot::<P>(chain_link.slot()));

        if parent_epoch
            .map(|epoch| epoch < block_epoch)
            .unwrap_or(true)
        {
            self.store.prune_state_cache(true);

            info!("unloading old beacon states (head slot: {head_slot})");

            let unloaded = self
                .store_mut()
                .unload_old_states(unfinalized_states_in_memory);

            let store = self.owned_store();
            let storage = self.storage.clone_arc();
            let wait_group = wait_group.clone();

            if !unloaded.is_empty() {
                Builder::new()
                .name("store-unloader".to_owned())
                .spawn(move || {
                    debug!("persisting unloaded old beacon states…");

                    let states_with_block_roots = unloaded
                        .iter()
                        .map(|chain_link| (chain_link.state(&store), chain_link.block_root));

                    match storage.append_states(states_with_block_roots) {
                        Ok(slots) => {
                            debug!(
                                "unloaded old beacon states persisted \
                                 (state slots: {slots:?})",
                            )
                        }
                        Err(error) => {
                            error!("persisting unloaded old beacon states to storage failed: {error:?}")
                        }
                    }

                    drop(wait_group);
                })?;
            }
        }

        let ProcessingTimings {
            delay_duration,
            submission_time,
            ..
        } = processing_timings;

        let insertion_duration = insertion_time.duration_since(submission_time);
        let processing_duration = insertion_duration.saturating_sub(delay_duration);

        features::log!(
            LogBlockProcessingTime,
            "block {block_root:?} inserted in {insertion_duration:?}, \
            processed in {processing_duration:?}",
        );

        if let Some(metrics) = self.metrics.as_ref() {
            metrics
                .block_insertion_times
                .observe(insertion_duration.as_secs_f64());

            metrics
                .block_processing_times
                .observe(processing_duration.as_secs_f64());
        }

        if let Some(hash) = block.execution_block_hash() {
            if let Some(payload_statuses) = self.delayed_until_payload.remove(&hash) {
                for (payload_status, _) in payload_statuses {
                    self.handle_notified_new_payload(wait_group, block_root, hash, payload_status);
                }
            }
        }

        // Do not send API events about optimistic blocks.
        // Vouch treats all head events as non-optimistic.
        if is_valid {
            self.event_channels
                .send_block_event(block_slot, block_root, false);
        }

        // TODO(Grandine Team): Performing the validation here results in the block being added to the
        //                      fork choice store even though it is already known to be invalid.
        //                      The validation should be in `Store::validate_block`,
        //                      but that makes it harder to retry payload statuses.
        //                      That is also why the message sending and task spawning was moved here.
        //                      One possible solution is to check `Mutator.delayed_until_payload` in
        //                      this method before calling `Store::apply_block`.
        // > - If `execution_payload` verification of block's parent by an execution node is *not*
        // >   complete:
        // >   - [REJECT] The block's parent (defined by `block.parent_root`) passes all validation
        // >     (excluding execution node verification of the `block.body.execution_payload`).
        // > - otherwise:
        // >   - [IGNORE] The block's parent (defined by `block.parent_root`) passes all validation
        // >     (including execution node verification of the `block.body.execution_payload`).
        if self
            .store
            .chain_link(block_root)
            .is_some_and(ChainLink::is_invalid)
        {
            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                self.send_to_p2p(P2pMessage::Ignore(gossip_id));
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore(false)));
        } else {
            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                self.send_to_p2p(P2pMessage::Accept(gossip_id));
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Accept));
        }

        self.maybe_spawn_block_attestations_task(wait_group, block_root, &block);

        if changes.is_finalized_checkpoint_updated() {
            self.archive_finalized(wait_group)?;
            self.prune_delayed_until_payload();
            self.persist_pubkey_cache(wait_group);

            let finalized_slot = self.store.finalized_slot();

            self.event_channels.prune_after_finalization(finalized_slot);

            if block.phase().is_peerdas_activated() {
                self.try_spawn_persist_data_columns_task(finalized_slot, wait_group.clone());
            }
        }

        // Call `Store::apply_attester_slashing` after `Store::archive_finalized` to reduce the
        // amount of work needed to update balances.
        let slashable_indices = attester_slashing_results
            .into_iter()
            .flat_map(|result| {
                let origin = AttesterSlashingOrigin::Block;

                result
                    .map_err(|error| {
                        debug!("attester slashing rejected (error: {error}, origin: {origin:?})")
                    })
                    .unwrap_or_default()
            })
            .collect_vec();

        if !slashable_indices.is_empty() {
            self.store_mut()
                .apply_attester_slashing(slashable_indices)?;
        }

        // The snapshot should be updated:
        // - After calling `Mutator::archive_finalized` because it mutates the store.
        // - Before spawning tasks to retry delayed objects or notifying other components to ensure
        //   that they cannot observe the store in an inconsistent state.
        self.update_store_snapshot();

        if let Some(objects) = self.take_delayed_until_block(block_root) {
            debug!("retrying objects delayed until block {block_root:?}");
            debug!(
                "retrying {} pending data column sidecars after block {block_root:?} imported",
                objects.data_column_sidecars.len(),
            );
            self.retry_delayed(objects, wait_group);
        }

        if changes.is_finalized_checkpoint_updated() {
            self.notify_about_finalized_checkpoint();
        }

        let pruned_gossip_ids = changes
            .is_finalized_checkpoint_updated()
            .then(|| {
                let delayed = self.prune_delayed_until_block();
                let delayed_until_blobs = self.prune_delayed_until_blobs();
                let waiting = self.prune_waiting_for_checkpoint_states();
                delayed
                    .into_iter()
                    .chain(delayed_until_blobs)
                    .chain(waiting)
            })
            .into_iter()
            .flatten();

        for gossip_id in pruned_gossip_ids {
            self.send_to_p2p(P2pMessage::Ignore(gossip_id));
        }

        match changes {
            ApplyBlockChanges::CanonicalChainExtended { .. } => {
                let new_head = self.store.head().clone();
                let state = new_head.state(&self.store);

                if let Some(metrics) = self.metrics.as_ref() {
                    Self::track_head_metrics(&new_head, metrics);
                }

                self.send_to_p2p(P2pMessage::HeadState(state));

                if new_head.is_valid() {
                    self.event_channels
                        .send_head_event(&new_head, |head| self.calculate_dependent_roots(head));

                    self.send_to_validator(ValidatorMessage::Head(
                        wait_group.clone(),
                        new_head.clone(),
                    ));
                }

                self.notify_forkchoice_updated(&new_head);
                self.maybe_spawn_preprocess_head_state_for_current_slot_task(block_slot);
                self.spawn_preprocess_head_state_for_next_slot_task();
            }
            ApplyBlockChanges::Reorganized { old_head, .. } => {
                self.notify_about_reorganization(wait_group.clone(), &old_head, ReorgSource::Block);
                self.maybe_spawn_preprocess_head_state_for_current_slot_task(block_slot);
                self.spawn_preprocess_head_state_for_next_slot_task();
            }
            ApplyBlockChanges::AlternateChainExtended { .. } => {}
        }

        let post_processing_duration = insertion_time.elapsed();

        features::log!(
            LogBlockProcessingTime,
            "block {block_root:?} post-processed in {post_processing_duration:?}",
        );

        if let Some(metrics) = self.metrics.as_ref() {
            metrics
                .block_post_processing_times
                .observe(post_processing_duration.as_secs_f64());
        }

        Ok(())
    }

    fn reject_block(&mut self, error: AnyhowError, block_root: H256, origin: BlockOrigin) {
        warn!("block rejected (error: {error}, block root: {block_root:?}, origin: {origin:?})");

        let sender = match origin {
            BlockOrigin::Gossip(gossip_id) => {
                self.send_to_p2p(P2pMessage::Reject(
                    Some(gossip_id),
                    MutatorRejectionReason::InvalidBlock,
                ));

                None
            }
            BlockOrigin::Api(sender) => sender,
            BlockOrigin::Requested(peer_id) => {
                if let Some(peer_id) = peer_id {
                    // During block sync (and especially during non-finality events)
                    // it's important to drop peers that send invalid blocks
                    self.send_to_p2p(P2pMessage::PenalizePeer(
                        peer_id,
                        MutatorRejectionReason::InvalidBlock,
                    ));
                }

                None
            }
            BlockOrigin::Own | BlockOrigin::Persisted => None,
        };

        self.store_mut().register_rejected_block(block_root);
        self.update_store_snapshot();

        reply_block_validation_result_to_http_api(sender, Err(error));
    }

    fn accept_blob_sidecar(&mut self, wait_group: &W, blob_sidecar: &Arc<BlobSidecar<P>>) {
        let block_root = blob_sidecar.signed_block_header.message.hash_tree_root();

        self.store_mut()
            .apply_blob_sidecar(blob_sidecar.clone_arc());

        self.update_store_snapshot();

        if let Some(pending_block) = self.take_delayed_until_blobs(block_root) {
            self.retry_block(wait_group.clone(), pending_block);
        }

        self.event_channels
            .send_blob_sidecar_event(block_root, blob_sidecar);

        if !self.storage.prune_storage_enabled() {
            self.spawn(PersistBlobSidecarsTask {
                store_snapshot: self.owned_store(),
                storage: self.storage.clone_arc(),
                mutator_tx: self.owned_mutator_tx(),
                wait_group: wait_group.clone(),
                metrics: self.metrics.clone(),
            });
        }
    }

    fn accept_data_column_sidecar(
        &mut self,
        wait_group: &W,
        data_column_sidecar: &Arc<DataColumnSidecar<P>>,
    ) {
        let block_root = data_column_sidecar
            .signed_block_header
            .message
            .hash_tree_root();

        self.store_mut()
            .apply_data_column_sidecar(data_column_sidecar.clone_arc());

        self.update_store_snapshot();

        let slot = data_column_sidecar.slot();
        let accepted_data_columns = self.store.accepted_data_column_sidecars_at_slot(slot);

        // There is no data columns by each root request, while syncing we batch by root requests
        // to respective custodial peers in `p2p/src/block_sync_service.rs::batch_request_missing_data_columns` method
        let should_retry_block = if self.store.is_sidecars_construction_started(&block_root)
            || (!self.store.is_forward_synced()
                && self.store.sampling_columns_count() * 2 < P::NumberOfColumns::USIZE)
        {
            accepted_data_columns == self.store.sampling_columns_count()
        } else {
            accepted_data_columns * 2 >= self.store.sampling_columns_count()
        };

        // During syncing, if we retry everytime when receiving a sidecar, this might spamming the
        // queue, leading to delaying other data column sidecar tasks
        if should_retry_block {
            if let Some(pending_block) = self.delayed_until_blobs.get(&block_root) {
                self.retry_block(wait_group.clone(), pending_block.clone());
            }
        }

        self.event_channels
            .send_data_column_sidecar_event(block_root, data_column_sidecar);
    }

    fn notify_about_finalized_checkpoint(&self) {
        let finalized_checkpoint = self.store.finalized_checkpoint();
        let justified_checkpoint = self.store.justified_checkpoint();
        let head = self.store.head();

        info!(
            "new finalized checkpoint \
             (epoch: {}, root: {:?}, head slot: {}, head root: {:?})",
            finalized_checkpoint.epoch,
            finalized_checkpoint.root,
            head.slot(),
            head.block_root,
        );

        self.send_to_p2p(P2pMessage::FinalizedCheckpoint(finalized_checkpoint));

        if let Some(metrics) = self.metrics.as_ref() {
            let state = head.state(&self.store);
            let previous_justified_checkpoint = state.previous_justified_checkpoint();

            metrics.set_beacon_current_justified_epoch(justified_checkpoint.epoch);
            metrics.set_beacon_finalized_epoch(finalized_checkpoint.epoch);
            metrics.set_beacon_previous_justified_epoch(previous_justified_checkpoint.epoch);
        }

        self.event_channels.send_finalized_checkpoint_event(
            head.block_root,
            finalized_checkpoint,
            head.is_optimistic(),
        );
    }

    fn notify_about_reorganization(
        &self,
        wait_group: W,
        old_head: &ChainLink<P>,
        reorg_source: ReorgSource,
    ) {
        let new_head = self.store.head().clone();

        self.event_channels
            .send_chain_reorg_event(&self.store, &new_head, old_head);

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.beacon_reorgs_total.inc();
        }

        info!(
            "chain reorganized (old head: {:?}, new head: {:?}), cause: {reorg_source:?}",
            old_head.block_root, new_head.block_root,
        );

        let state = new_head.state(&self.store);

        if let Some(metrics) = self.metrics.as_ref() {
            Self::track_head_metrics(&new_head, metrics);
        }

        self.send_to_p2p(P2pMessage::HeadState(state));

        if new_head.is_valid() {
            // Do not send API events about optimistic blocks.
            // Vouch treats all head events as non-optimistic.
            self.event_channels
                .send_head_event(&new_head, |head| self.calculate_dependent_roots(head));

            self.send_to_validator(ValidatorMessage::Head(wait_group, new_head.clone()));
        }

        self.notify_forkchoice_updated(&new_head);
    }

    fn request_blobs_from_execution_engine(&self, params: EngineGetBlobsParams<P>) {
        self.execution_engine.get_blobs(params);
    }

    fn notify_forkchoice_updated(&self, new_head: &ChainLink<P>) {
        let new_head_state = new_head.state(&self.store);

        let Some(state) = new_head_state.post_bellatrix() else {
            return;
        };

        if !predicates::is_merge_transition_complete(state) {
            return;
        }

        let safe_block_hash = self.store.safe_execution_payload_hash();
        let finalized_block_hash = self.store.finalized_execution_payload_hash();

        let head_block_hash = state.latest_execution_payload_header().block_hash();

        self.execution_engine.notify_forkchoice_updated(
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
            Either::Left(new_head.block.phase()),
            None,
        );
    }

    // This may even involve a DB lookup so it would be best
    // if we can avoid making it if no event listeners are present
    fn calculate_dependent_roots(&self, head: &ChainLink<P>) -> Result<DependentRootsBundle> {
        let state = head.state(&self.store);
        let current_epoch = accessors::get_current_epoch(&state);
        let previous_epoch = accessors::get_previous_epoch(&state);

        let current_duty_dependent_root =
            self.storage
                .dependent_root(&self.store, &state, current_epoch)?;

        let previous_duty_dependent_root =
            self.storage
                .dependent_root(&self.store, &state, previous_epoch)?;

        Ok(DependentRootsBundle {
            current_duty_dependent_root,
            previous_duty_dependent_root,
        })
    }

    fn delay_block_until_blobs(&mut self, beacon_block_root: H256, pending_block: PendingBlock<P>) {
        self.store_mut()
            .delay_block_at_slot(pending_block.block.message().slot(), beacon_block_root);
        self.update_store_snapshot();

        self.delayed_until_blobs
            .insert(beacon_block_root, pending_block);
    }

    fn delay_block_until_parent(&mut self, pending_block: PendingBlock<P>) {
        // Blocks produced by the application itself should never be delayed.
        assert!(!matches!(pending_block.origin, BlockOrigin::Own));

        self.delayed_until_block
            .entry(pending_block.block.message().parent_root())
            .or_default()
            .blocks
            .push(pending_block);
    }

    fn delay_aggregate_and_proof_until_block(
        &mut self,
        wait_group: &W,
        pending_aggregate_and_proof: PendingAggregateAndProof<P>,
        block_root: H256,
    ) {
        if self.store.contains_block(block_root) {
            self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
        } else {
            debug!(
                "aggregate and proof delayed until block \
                 (pending_aggregate_and_proof: {pending_aggregate_and_proof:?}, \
                  block_root: {block_root:?})",
            );

            let peer_id = pending_aggregate_and_proof
                .origin
                .gossip_id_ref()
                .map(|gossip_id| gossip_id.source);

            self.send_to_p2p(P2pMessage::BlockNeeded(block_root, peer_id));

            self.delayed_until_block
                .entry(block_root)
                .or_default()
                .aggregates
                .push(pending_aggregate_and_proof);
        }
    }

    fn delay_attestation_until_block(
        &mut self,
        wait_group: &W,
        pending_attestation: PendingAttestation<P>,
        block_root: H256,
    ) {
        if self.store.contains_block(block_root) {
            self.retry_attestation(wait_group.clone(), pending_attestation);
        } else {
            debug!(
                "attestation delayed until block \
                 (pending_attestation: {pending_attestation:?}, block_root: {block_root:?})",
            );

            let peer_id = pending_attestation
                .origin
                .gossip_id_ref()
                .map(|gossid_id| gossid_id.source);

            self.send_to_p2p(P2pMessage::BlockNeeded(block_root, peer_id));

            // Attestations produced by the application itself should never be delayed.
            assert!(!matches!(
                pending_attestation.origin,
                AttestationOrigin::Own(_),
            ));

            self.delayed_until_block
                .entry(block_root)
                .or_default()
                .attestations
                .push(pending_attestation);
        }
    }

    fn delay_payload_status_until_block(
        &mut self,
        beacon_block_root: H256,
        payload_status: PayloadStatusV1,
    ) {
        debug!(
            "payload status handling delayed until block \
             (payload_status: {payload_status:?}, beacon_block_root: {beacon_block_root:?})",
        );

        let pending_payload_status = (payload_status, self.store.head().slot());

        self.delayed_until_block
            .entry(beacon_block_root)
            .or_default()
            .payload_status = Some(pending_payload_status);
    }

    fn delay_block_until_slot(&mut self, pending_block: PendingBlock<P>) {
        // Requested blocks can also be delayed until a slot if the slot isn't updated on time.
        // Blocks produced by the application itself should never be delayed.
        assert!(!matches!(pending_block.origin, BlockOrigin::Own));

        self.delayed_until_slot
            .entry(pending_block.block.message().slot())
            .or_default()
            .blocks
            .push(pending_block);
    }

    fn delay_aggregate_and_proof_until_slot(
        &mut self,
        wait_group: &W,
        pending_aggregate_and_proof: PendingAggregateAndProof<P>,
    ) {
        let slot = pending_aggregate_and_proof
            .aggregate_and_proof
            .message()
            .aggregate()
            .data()
            .slot;

        if slot <= self.store.slot() {
            self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
        } else {
            debug!("aggregate and proof delayed until slot: {pending_aggregate_and_proof:?}");

            self.delayed_until_slot
                .entry(slot)
                .or_default()
                .aggregates
                .push(pending_aggregate_and_proof);
        }
    }

    fn delay_attestation_until_slot(
        &mut self,
        wait_group: &W,
        pending_attestation: PendingAttestation<P>,
    ) {
        let slot = pending_attestation.slot();

        if slot <= self.store.slot() {
            self.retry_attestation(wait_group.clone(), pending_attestation);
        } else {
            debug!("attestation delayed until slot: {pending_attestation:?}");

            // Attestations produced by the application itself should never be delayed.
            // Attestations included in blocks should never be delayed until a slot
            // because at least one slot must have passed since they were published.
            assert!(!matches!(
                pending_attestation.origin,
                AttestationOrigin::Own(_) | AttestationOrigin::Block(_),
            ));

            self.delayed_until_slot
                .entry(pending_attestation.slot())
                .or_default()
                .attestations
                .push(pending_attestation);
        }
    }

    fn delay_blob_sidecar_until_state(
        &mut self,
        pending_blob_sidecar: PendingBlobSidecar<P>,
        block_root: H256,
    ) {
        let slot = pending_blob_sidecar
            .blob_sidecar
            .signed_block_header
            .message
            .slot;

        self.delayed_until_state
            .entry((block_root, slot))
            .or_default()
            .blob_sidecars
            .push(pending_blob_sidecar);
    }

    fn delay_blob_sidecar_until_parent(&mut self, pending_blob_sidecar: PendingBlobSidecar<P>) {
        self.delayed_until_block
            .entry(
                pending_blob_sidecar
                    .blob_sidecar
                    .signed_block_header
                    .message
                    .parent_root,
            )
            .or_default()
            .blob_sidecars
            .push(pending_blob_sidecar);
    }

    fn delay_blob_sidecar_until_slot(&mut self, pending_blob_sidecar: PendingBlobSidecar<P>) {
        self.delayed_until_slot
            .entry(
                pending_blob_sidecar
                    .blob_sidecar
                    .signed_block_header
                    .message
                    .slot,
            )
            .or_default()
            .blob_sidecars
            .push(pending_blob_sidecar);
    }

    fn delay_data_column_sidecar_until_state(
        &mut self,
        pending_data_column_sidecar: PendingDataColumnSidecar<P>,
        block_root: H256,
    ) {
        let slot = pending_data_column_sidecar
            .data_column_sidecar
            .signed_block_header
            .message
            .slot;

        self.delayed_until_state
            .entry((block_root, slot))
            .or_default()
            .data_column_sidecars
            .push(pending_data_column_sidecar);
    }

    fn delay_data_column_sidecar_until_parent(
        &mut self,
        pending_data_column_sidecar: PendingDataColumnSidecar<P>,
    ) {
        self.delayed_until_block
            .entry(
                pending_data_column_sidecar
                    .data_column_sidecar
                    .signed_block_header
                    .message
                    .parent_root,
            )
            .or_default()
            .data_column_sidecars
            .push(pending_data_column_sidecar);
    }

    fn delay_data_column_sidecar_until_slot(
        &mut self,
        pending_data_column_sidecar: PendingDataColumnSidecar<P>,
    ) {
        self.delayed_until_slot
            .entry(
                pending_data_column_sidecar
                    .data_column_sidecar
                    .signed_block_header
                    .message
                    .slot,
            )
            .or_default()
            .data_column_sidecars
            .push(pending_data_column_sidecar);
    }

    fn take_delayed_until_blobs(&mut self, block_root: H256) -> Option<PendingBlock<P>> {
        self.delayed_until_blobs.remove(&block_root)
    }

    fn take_delayed_until_block(&mut self, block_root: H256) -> Option<Delayed<P>> {
        self.delayed_until_block.remove(&block_root)
    }

    fn take_delayed_until_slot(&mut self, slot: Slot) -> impl Iterator<Item = Delayed<P>> {
        match slot.checked_add(1) {
            Some(next_slot) => {
                let later = self.delayed_until_slot.split_off(&next_slot);
                core::mem::replace(&mut self.delayed_until_slot, later)
            }
            None => core::mem::take(&mut self.delayed_until_slot),
        }
        .into_values()
    }

    fn take_delayed_until_state(&mut self, block_root: H256, slot: Slot) -> Option<Delayed<P>> {
        self.delayed_until_state.remove(&(block_root, slot))
    }

    // `wait_group` is a reference not just to pass Clippy lints but for correctness as well.
    // The referenced value must not be dropped before the current message is handled.
    fn retry_delayed(&self, delayed: Delayed<P>, wait_group: &W) {
        let Delayed {
            blocks,
            // Delayed payload status update is applied before accepting block,
            // so a bit earlier than the other delayed items.
            payload_status: _,
            aggregates,
            attestations,
            blob_sidecars,
            data_column_sidecars,
        } = delayed;

        for pending_block in blocks {
            self.retry_block(wait_group.clone(), pending_block);
        }

        for pending_aggregate_and_proof in aggregates {
            self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
        }

        for pending_attestation in attestations {
            self.retry_attestation(wait_group.clone(), pending_attestation);
        }

        for pending_blob_sidecar in blob_sidecars {
            self.retry_blob_sidecar(wait_group.clone(), pending_blob_sidecar, None);
        }

        for pending_data_column_sidecar in data_column_sidecars {
            self.retry_data_column_sidecar(wait_group.clone(), pending_data_column_sidecar, None);
        }
    }

    fn retry_block(&self, wait_group: W, pending_block: PendingBlock<P>) {
        debug!("retrying delayed block: {pending_block:?}");

        let PendingBlock {
            block,
            origin,
            processing_timings,
        } = pending_block;

        let processing_timings = processing_timings.processing();

        self.spawn(BlockTask {
            store_snapshot: self.owned_store(),
            block_processor: self.block_processor.clone_arc(),
            execution_engine: self.execution_engine.clone(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            block,
            origin,
            processing_timings,
            metrics: self.metrics.clone(),
        });
    }

    fn retry_attestation(&self, wait_group: W, attestation: PendingAttestation<P>) {
        debug!("retrying delayed attestation: {attestation:?}");

        if attestation.verify_signatures() {
            self.send_to_attestation_verifier(AttestationVerifierMessage::Attestation {
                wait_group,
                attestation,
            });
        } else {
            self.spawn(AttestationTask {
                store_snapshot: self.owned_store(),
                mutator_tx: self.owned_mutator_tx(),
                wait_group,
                attestation,
                metrics: self.metrics.clone(),
            });
        }
    }

    fn retry_tick(&mut self, wait_group: &W, tick: Tick) -> Result<()> {
        debug!("retrying delayed tick: {tick:?}");

        self.handle_tick(wait_group, tick)
    }

    fn retry_aggregate_and_proof(
        &self,
        wait_group: W,
        pending_aggregate_and_proof: PendingAggregateAndProof<P>,
    ) {
        debug!("retrying delayed aggregate and proof: {pending_aggregate_and_proof:?}");

        let PendingAggregateAndProof {
            aggregate_and_proof,
            origin,
        } = pending_aggregate_and_proof;

        self.send_to_attestation_verifier(AttestationVerifierMessage::AggregateAndProof {
            wait_group,
            aggregate_and_proof,
            origin,
        });
    }

    fn retry_blob_sidecar(
        &self,
        wait_group: W,
        pending_blob_sidecar: PendingBlobSidecar<P>,
        state: Option<Arc<BeaconState<P>>>,
    ) {
        debug!("retrying delayed blob sidecar: {pending_blob_sidecar:?}");

        let PendingBlobSidecar {
            blob_sidecar,
            block_seen,
            origin,
            submission_time,
        } = pending_blob_sidecar;

        self.spawn(BlobSidecarTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            blob_sidecar,
            state,
            block_seen,
            origin,
            submission_time,
            metrics: self.metrics.clone(),
        });
    }

    fn retry_data_column_sidecar(
        &self,
        wait_group: W,
        pending_data_column_sidecar: PendingDataColumnSidecar<P>,
        state: Option<Arc<BeaconState<P>>>,
    ) {
        debug!("retrying delayed data column sidecar: {pending_data_column_sidecar:?}");

        let PendingDataColumnSidecar {
            data_column_sidecar,
            block_seen,
            origin,
            submission_time,
        } = pending_data_column_sidecar;

        self.spawn(DataColumnSidecarTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            data_column_sidecar,
            state,
            block_seen,
            origin,
            submission_time,
            metrics: self.metrics.clone(),
        });
    }

    fn prune_delayed_until_blobs(&mut self) -> Vec<GossipId> {
        let finalized_slot = self.store.finalized_slot();

        let mut gossip_ids = vec![];

        self.delayed_until_blobs.retain(|_, pending_block| {
            if pending_block.block.message().slot() > finalized_slot {
                return true;
            }

            if let Some(gossip_id) = pending_block.origin.gossip_id() {
                gossip_ids.push(gossip_id);
            }

            false
        });

        gossip_ids
    }

    // Some objects may be delayed until a block that is itself delayed.
    // If the latter is pruned, objects depending on it could be pruned as well.
    // We don't bother doing this. It's tricky to implement and might not even be worth it.
    //
    // It may be possible to prune delayed objects in a background thread.
    // We don't bother doing that either.
    fn prune_delayed_until_block(&mut self) -> Vec<GossipId> {
        let finalized_slot = self.store.finalized_slot();
        let previous_epoch = self.store.previous_epoch();

        let mut gossip_ids = vec![];

        // Use `drain_filter_polyfill` because `Vec::extract_if` is not stable as of Rust 1.82.0.
        self.delayed_until_block.retain(|_, delayed| {
            let Delayed {
                blocks,
                payload_status,
                aggregates,
                attestations,
                blob_sidecars,
                data_column_sidecars,
            } = delayed;

            gossip_ids.extend(
                blocks
                    .drain_filter(|pending| {
                        // The parent of a delayed block cannot be in a finalized slot.
                        pending.block.message().slot() - 1 <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            if let Some((_, slot)) = payload_status {
                if *slot <= finalized_slot {
                    payload_status.take();
                }
            }

            gossip_ids.extend(
                aggregates
                    .drain_filter(|pending| {
                        let epoch = pending
                            .aggregate_and_proof
                            .message()
                            .aggregate()
                            .data()
                            .target
                            .epoch;

                        epoch < previous_epoch
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                attestations
                    .drain_filter(|pending| {
                        let epoch = pending.data().target.epoch;

                        epoch < previous_epoch
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            // TODO(feature/deneb): Does the condition and comment apply to blob sidecars?
            gossip_ids.extend(
                blob_sidecars
                    .drain_filter(|pending| {
                        // The parent of a delayed block cannot be in a finalized slot.
                        pending.blob_sidecar.signed_block_header.message.slot - 1 <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                data_column_sidecars
                    .drain_filter(|pending| {
                        // The parent of a delayed block cannot be in a finalized slot.
                        pending.data_column_sidecar.signed_block_header.message.slot - 1
                            <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            !delayed.is_empty()
        });

        gossip_ids
    }

    fn prune_delayed_until_payload(&mut self) {
        let finalized_slot = self.store.finalized_slot();

        self.delayed_until_payload.retain(|_, statuses| {
            statuses.retain(|(_, slot)| *slot > finalized_slot);
            !statuses.is_empty()
        });
    }

    fn prune_waiting_for_checkpoint_states(&mut self) -> Vec<GossipId> {
        let finalized_epoch = self.store.finalized_epoch();

        let mut gossip_ids = vec![];

        // Use `HashMap::retain` because `HashMap::extract_if` is not stable as of Rust 1.82.0.
        self.waiting_for_checkpoint_states
            .retain(|target, waiting| {
                let prune = target.epoch < finalized_epoch;

                if prune {
                    let WaitingForCheckpointState {
                        ticks: _,
                        chain_links,
                        aggregates,
                        attestations,
                    } = waiting;

                    gossip_ids.extend(
                        core::mem::take(chain_links)
                            .into_iter()
                            .filter_map(|pending| pending.origin.gossip_id()),
                    );

                    gossip_ids.extend(
                        core::mem::take(aggregates)
                            .into_iter()
                            .filter_map(|pending| pending.origin.gossip_id()),
                    );

                    gossip_ids.extend(
                        core::mem::take(attestations)
                            .into_iter()
                            .filter_map(|pending| pending.origin.gossip_id()),
                    );
                }

                !prune
            });

        gossip_ids
    }

    // Attestations in blocks must be processed just like gossiped ones.
    // The docstring for `on_attestation` in the Fork Choice specification says:
    // > Run ``on_attestation`` upon receiving a new ``attestation`` from either within a
    // > block or directly on the wire.
    //
    // Also see <https://github.com/ethereum/consensus-specs/issues/1887#issuecomment-643522589>.
    fn maybe_spawn_block_attestations_task(
        &self,
        wait_group: &W,
        block_root: H256,
        block: &Arc<SignedBeaconBlock<P>>,
    ) {
        // `BlockAttestationsTask`s have a surprisingly large amount of overhead.
        // Avoid spawning them if possible.
        if block.message().body().attestations_len().is_zero() {
            return;
        }

        self.spawn(BlockAttestationsTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: wait_group.clone(),
            block_root,
            block: block.clone_arc(),
            metrics: self.metrics.clone(),
        });
    }

    fn prepare_execution_payload_for_next_slot(&self, next_slot_state: &BeaconState<P>) {
        let Some(state) = next_slot_state.post_bellatrix() else {
            return;
        };

        if !self.store.is_forward_synced() || !predicates::is_merge_transition_complete(state) {
            return;
        }

        let safe_block_hash = self.store.safe_execution_payload_hash();
        let finalized_block_hash = self.store.finalized_execution_payload_hash();

        self.send_to_validator(ValidatorMessage::PrepareExecutionPayload(
            state.slot(),
            safe_block_hash,
            finalized_block_hash,
        ));
    }

    fn spawn_checkpoint_state_task(&self, wait_group: W, checkpoint: Checkpoint) {
        self.spawn(CheckpointStateTask {
            store_snapshot: self.owned_store(),
            state_cache: self.state_cache.clone_arc(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            checkpoint,
            pubkey_cache: self.pubkey_cache.clone_arc(),
            metrics: self.metrics.clone(),
        });
    }

    fn maybe_spawn_preprocess_head_state_for_current_slot_task(&self, block_slot: Slot) {
        if !self.store.is_forward_synced() {
            return;
        }

        let current_tick = self.store.tick();

        if current_tick.slot == (block_slot + 1) && current_tick.is_before_attesting_interval() {
            debug!("spawn preprocess state task for current slot: {block_slot}: {current_tick:?}");

            self.spawn(PreprocessStateTask {
                store_snapshot: self.owned_store(),
                state_cache: self.state_cache.clone_arc(),
                mutator_tx: self.owned_mutator_tx(),
                head_block_root: self.store.head().block_root,
                next_slot: self.store.slot(),
                pubkey_cache: self.pubkey_cache.clone_arc(),
                metrics: self.metrics.clone(),
            })
        }
    }

    fn spawn_preprocess_head_state_for_next_slot_task(&self) {
        if !self.store.is_forward_synced() {
            return;
        }

        self.spawn(PreprocessStateTask {
            store_snapshot: self.owned_store(),
            state_cache: self.state_cache.clone_arc(),
            mutator_tx: self.owned_mutator_tx(),
            head_block_root: self.store.head().block_root,
            next_slot: self.store.slot() + 1,
            pubkey_cache: self.pubkey_cache.clone_arc(),
            metrics: self.metrics.clone(),
        })
    }

    fn spawn_pubkey_cache_persist_task(
        &self,
        pubkey_cache: Arc<PubkeyCache>,
        wait_group: W,
        state: Arc<BeaconState<P>>,
    ) {
        self.spawn(PersistPubkeyCacheTask {
            pubkey_cache,
            state,
            wait_group,
            metrics: self.metrics.clone(),
        })
    }

    fn archive_finalized(&mut self, wait_group: &W) -> Result<()> {
        if let Some(latest_archivable_index) = self.store.latest_archivable_index() {
            debug!("archiving finalized blocks and anchor state…");

            let store = self.owned_store();
            let storage = self.storage.clone_arc();
            let sync_tx = self.sync_tx.clone();
            let wait_group = wait_group.clone();
            let finished_loading_from_storage = self.finished_loading_from_storage;

            let mut archived = self.store_mut().archive_finalized(latest_archivable_index);
            archived.push_back(self.store.anchor().clone());

            let last_finalized_slot = self.store.last_finalized().slot();

            Builder::new()
                .name("store-archiver".to_owned())
                .spawn(move || {
                    debug!("saving finalized blocks and anchor state…");

                    match storage.append(core::iter::empty(), archived.iter(), &store) {
                        Ok(slots) => {
                            if let Some(chain_link) = archived.back() {
                                let finalized_block = chain_link.block.clone_arc();

                                if finished_loading_from_storage {
                                    SyncMessage::Finalized(finalized_block).send(&sync_tx);
                                }
                            }

                            debug!(
                                "finalized blocks and anchor state saved \
                                 (appended block slots: {slots:?})",
                            )
                        }
                        Err(error) => error!("saving to storage failed: {error:?}"),
                    }

                    debug!("removing unfinalized blocks");

                    if !storage.archive_storage_enabled() {
                        match storage.prune_unfinalized_blocks(last_finalized_slot) {
                            Ok(slots) => {
                                debug!(
                                    "unfinalized block pruning complete: pruned slots: {slots:?}"
                                );
                            }
                            Err(error) => error!("unfinalized block pruning failed: {error:?}"),
                        }
                    }

                    drop(wait_group);
                })?;
        }

        Ok(())
    }

    fn prune_old_records(&self) -> Result<()> {
        if self.storage.archive_storage_enabled() {
            return Ok(());
        }

        let storage = self.storage.clone_arc();
        let data_up_to_epoch = self
            .store
            .min_checked_data_availability_epoch(self.store.slot());
        let data_up_to_slot = misc::compute_start_slot_at_epoch::<P>(data_up_to_epoch);
        let blocks_up_to_epoch = self.store.min_checked_block_availability_epoch();
        let blocks_up_to_slot = misc::compute_start_slot_at_epoch::<P>(blocks_up_to_epoch);
        let data_phase = self
            .store
            .chain_config()
            .phase_at_slot::<P>(data_up_to_slot);

        Builder::new()
            .name("old-data-pruner".to_owned())
            .spawn(move || {
                if data_phase.is_peerdas_activated() {
                    debug!("pruning old data column sidecars from storage up to slot {data_up_to_slot}…");

                    match storage.prune_old_data_column_sidecars(data_up_to_slot) {
                        Ok(()) => {
                            debug!(
                                "pruned old data column sidecars from storage up to slot {data_up_to_slot}"
                            );
                        }
                        Err(error) => {
                            error!("pruning old data column sidecars from storage failed: {error:?}")
                        }
                    }
                } else {
                    debug!("pruning old blob sidecars from storage up to slot {data_up_to_slot}…");

                    match storage.prune_old_blob_sidecars(data_up_to_slot) {
                        Ok(()) => {
                            debug!(
                                "pruned old blob sidecars from storage up to slot {data_up_to_slot}"
                            );
                        }
                        Err(error) => {
                            error!("pruning old blob sidecars from storage failed: {error:?}")
                        }
                    }
                }

                debug!("pruning old blocks and states from storage up to slot {blocks_up_to_slot}…");

                match storage.prune_old_blocks_and_states(blocks_up_to_slot) {
                    Ok(()) => {
                        debug!(
                            "pruned old blocks and states from storage up to slot {blocks_up_to_slot}"
                        );
                    }
                    Err(error) => {
                        error!("pruning old blocks and states from storage failed: {error:?}")
                    }
                }

                debug!("pruning old state roots from storage up to slot {blocks_up_to_slot}…");

                match storage.prune_old_state_roots(blocks_up_to_slot) {
                    Ok(()) => {
                        debug!(
                            "pruned old state roots from storage up to slot {blocks_up_to_slot}"
                        );
                    }
                    Err(error) => {
                        error!("pruning old state roots from storage failed: {error:?}")
                    }
                }
            })?;

        Ok(())
    }

    fn persist_pubkey_cache(&self, wait_group: &W) {
        let store = &self.store;
        let chain_link = store.last_finalized();

        self.spawn_pubkey_cache_persist_task(
            self.pubkey_cache.clone_arc(),
            wait_group.clone(),
            chain_link.state(store),
        );
    }

    // This method should only be called when `Mutator.store` is in a consistent state.
    fn update_store_snapshot(&self) {
        // `ArcSwap::rcu` is not necessary here because there is only one thread mutating the store.
        self.store_snapshot.store(self.owned_store());
    }

    fn spawn(&self, task: impl Spawn<P, E, W>) {
        self.thread_pool.spawn(task);
    }

    fn store_mut(&mut self) -> &mut Store<P, Storage<P>> {
        self.store.make_mut()
    }

    // This uses `Mutator.store` instead of `Mutator.store_snapshot` for better performance.
    // `ArcSwap::load` and `ArcSwap::load_full` are surprisingly slow, to the point where it's
    // faster to clone a `Store` with all the `Arc`s inside it and allocate another `Arc`.
    //
    // As a result, this method should only be called when `Mutator.store` is in a consistent state.
    fn owned_store(&self) -> Arc<Store<P, Storage<P>>> {
        self.store.clone_arc()
    }

    fn owned_mutator_tx(&self) -> Sender<MutatorMessage<P, W>> {
        self.mutator_tx.clone()
    }

    fn send_to_attestation_verifier(&self, message: AttestationVerifierMessage<P, W>) {
        if self.finished_loading_from_storage {
            message.send(&self.attestation_verifier_tx);
        }
    }

    fn send_to_p2p(&self, message: P2pMessage<P>) {
        if self.finished_loading_from_storage {
            message.send(&self.p2p_tx);
        }
    }

    fn send_to_pool(&self, message: PoolMessage) {
        if self.finished_loading_from_storage {
            message.send(&self.pool_tx);
        }
    }

    fn send_to_subnet_service(&self, message: SubnetMessage<W>) {
        if self.finished_loading_from_storage {
            message.send(&self.subnet_tx);
        }
    }

    fn send_to_validator(&self, message: ValidatorMessage<P, W>) {
        if self.finished_loading_from_storage {
            message.send(&self.validator_tx);
        }
    }

    fn track_epoch_transition_metrics(head_state: &Arc<BeaconState<P>>, metrics: &Arc<Metrics>) {
        metrics.set_beacon_processed_deposits_total(head_state.eth1_deposit_index());
        metrics.set_validator_count(head_state.validators().len_usize());
        metrics.set_beacon_current_active_validators(
            accessors::get_active_validator_indices(head_state, RelativeEpoch::Current).count(),
        );
    }

    fn track_head_metrics(head: &ChainLink<P>, metrics: &Arc<Metrics>) {
        metrics.set_beacon_head_slot(head.slot());
    }

    #[expect(clippy::too_many_lines)]
    fn track_collection_metrics(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            let type_name = tynm::type_name::<Self>();

            let (high_priority_tasks, low_priority_tasks) = self.thread_pool.task_counts();

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_blobs",
                self.delayed_until_blobs.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block",
                self.delayed_until_block.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_blob_sidecars",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.blob_sidecars.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_blocks",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.blocks.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_attestations",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.attestations.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_aggregates",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.aggregates.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_payload",
                self.delayed_until_payload.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_slot",
                self.delayed_until_slot.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_slot_blocks",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.blocks.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_slot_attestations",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.attestations.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_slot_aggregates",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.aggregates.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_state",
                self.delayed_until_state.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "high_priority_tasks",
                high_priority_tasks,
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "low_priority_tasks",
                low_priority_tasks,
            );

            self.event_channels.track_collection_metrics(metrics);
            self.pubkey_cache.track_collection_metrics(metrics);
            self.store.track_collection_metrics(metrics);
        }
    }

    fn block_blob_availability<'blob>(
        &self,
        block: &SignedBeaconBlock<P>,
        pending_blobs_for_block: impl Iterator<Item = &'blob BlobSidecar<P>>,
    ) -> BlockBlobAvailability {
        let Some(body) = block.message().body().post_deneb() else {
            return BlockBlobAvailability::Irrelevant;
        };

        let missing_blob_indices = self.store.indices_of_missing_blobs(block);

        if missing_blob_indices.is_empty() {
            return BlockBlobAvailability::Complete;
        }

        let pending_missing_blobs = pending_blobs_for_block
            .filter(|blob_sidecar| missing_blob_indices.contains(&blob_sidecar.index))
            .collect_vec();

        let all_blobs_downloaded = body
            .blob_kzg_commitments()
            .into_iter()
            .zip(0..)
            .filter(|(_, index)| missing_blob_indices.contains(index))
            .all(|(block_commitment, index)| {
                pending_missing_blobs.iter().any(|blob_sidecar| {
                    blob_sidecar.index == index && blob_sidecar.kzg_commitment == *block_commitment
                })
            });

        if all_blobs_downloaded {
            return BlockBlobAvailability::CompleteWithPending;
        }

        BlockBlobAvailability::Missing(missing_blob_indices)
    }

    fn block_data_column_availability<'column>(
        &self,
        block: &SignedBeaconBlock<P>,
        mut pending_data_columns_for_block: impl Iterator<Item = &'column DataColumnSidecar<P>>,
    ) -> BlockDataColumnAvailability {
        let Some(body) = block.message().body().post_fulu() else {
            return BlockDataColumnAvailability::Irrelevant;
        };

        let missing_indices = self.store.indices_of_missing_data_columns(block);

        if missing_indices.is_empty() {
            return BlockDataColumnAvailability::Complete;
        }

        let any_pending_columns = pending_data_columns_for_block.any(|data_column_sidecar| {
            missing_indices.contains(&data_column_sidecar.index)
                && data_column_sidecar.kzg_commitments == *body.blob_kzg_commitments()
        });

        if any_pending_columns {
            return BlockDataColumnAvailability::AnyPending;
        }

        let available_columns_count = self
            .store
            .sampling_columns_count()
            .saturating_sub(missing_indices.len());

        if available_columns_count * 2 >= P::NumberOfColumns::USIZE
            && (self.store.is_forward_synced()
                || self.store.store_config().sync_with_reconstruction)
        {
            return BlockDataColumnAvailability::CompleteWithReconstruction;
        }

        BlockDataColumnAvailability::Missing(missing_indices)
    }
}

fn reply_to_http_api(
    sender: Option<OneshotSender<Result<ValidationOutcome>>>,
    reply: Result<ValidationOutcome>,
) {
    if let Some(sender) = sender {
        if let Err(reply) = sender.send(reply) {
            debug!("reply to HTTP API failed because the receiver was dropped: {reply:?}");
        }
    }
}

fn reply_block_validation_result_to_http_api(
    sender: Option<MultiSender<Result<ValidationOutcome>>>,
    reply: Result<ValidationOutcome>,
) {
    if let Some(mut sender) = sender {
        if let Err(reply) = sender.try_send(reply) {
            debug!("reply to HTTP API failed because the receiver was dropped: {reply:?}");
        }
    }
}

fn reply_delayed_block_validation_result<P: Preset>(
    pending_block: PendingBlock<P>,
    reply: Result<ValidationOutcome>,
) -> PendingBlock<P> {
    let PendingBlock {
        block,
        origin,
        processing_timings,
    } = pending_block;

    if let BlockOrigin::Api(Some(sender)) = origin {
        reply_block_validation_result_to_http_api(Some(sender), reply);

        PendingBlock {
            block,
            origin: BlockOrigin::Api(None),
            processing_timings,
        }
    } else {
        PendingBlock {
            block,
            origin,
            processing_timings,
        }
    }
}

fn reply_delayed_blob_sidecar_validation_result<P: Preset>(
    pending_blob_sidecar: PendingBlobSidecar<P>,
    reply: Result<ValidationOutcome>,
) -> PendingBlobSidecar<P> {
    let PendingBlobSidecar {
        blob_sidecar,
        block_seen,
        origin,
        submission_time,
    } = pending_blob_sidecar;

    if let BlobSidecarOrigin::Api(Some(sender)) = origin {
        reply_to_http_api(Some(sender), reply);

        PendingBlobSidecar {
            blob_sidecar,
            block_seen,
            origin: BlobSidecarOrigin::Api(None),
            submission_time,
        }
    } else {
        PendingBlobSidecar {
            blob_sidecar,
            block_seen,
            origin,
            submission_time,
        }
    }
}

fn reply_delayed_data_column_sidecar_validation_result<P: Preset>(
    pending_data_column_sidecar: PendingDataColumnSidecar<P>,
    reply: Result<ValidationOutcome>,
) -> PendingDataColumnSidecar<P> {
    let PendingDataColumnSidecar {
        data_column_sidecar,
        block_seen,
        origin,
        submission_time,
    } = pending_data_column_sidecar;

    if let DataColumnSidecarOrigin::Api(Some(sender)) = origin {
        reply_to_http_api(Some(sender), reply);

        PendingDataColumnSidecar {
            data_column_sidecar,
            block_seen,
            origin: DataColumnSidecarOrigin::Api(None),
            submission_time,
        }
    } else {
        PendingDataColumnSidecar {
            data_column_sidecar,
            block_seen,
            origin,
            submission_time,
        }
    }
}
