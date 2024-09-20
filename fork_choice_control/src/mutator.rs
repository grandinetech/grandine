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

use anyhow::Result;
use arc_swap::ArcSwap;
use clock::{Tick, TickKind};
use drain_filter_polyfill::VecExt as _;
use eth2_libp2p::GossipId;
use execution_engine::{ExecutionEngine, PayloadStatusV1};
use fork_choice_store::{
    AggregateAndProofAction, ApplyBlockChanges, ApplyTickChanges, AttestationAction,
    AttestationOrigin, AttesterSlashingOrigin, BlobSidecarAction, BlobSidecarOrigin, BlockAction,
    BlockOrigin, ChainLink, PayloadAction, Store, ValidAttestation,
};
use futures::channel::{mpsc::Sender as MultiSender, oneshot::Sender as OneshotSender};
use helper_functions::{accessors, misc, predicates, verifier::NullVerifier};
use itertools::{Either, Itertools as _};
use log::{debug, error, info, warn};
use prometheus_metrics::Metrics;
use ssz::SszHash as _;
use std_ext::ArcExt as _;
use typenum::Unsigned as _;
use types::{
    combined::{BeaconState, ExecutionPayloadParams, SignedBeaconBlock},
    deneb::containers::{BlobIdentifier, BlobSidecar},
    eip7594::{ColumnIndex, DataColumnIdentifier, DataColumnSidecar, NumberOfColumns},
    nonstandard::{RelativeEpoch, ValidationOutcome},
    phase0::{
        containers::Checkpoint,
        primitives::{ExecutionBlockHash, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use fork_choice_store::DataColumnSidecarAction;
use fork_choice_store::DataColumnSidecarOrigin;

use crate::{
    messages::{MutatorMessage, P2pMessage, SubnetMessage, SyncMessage, ValidatorMessage},
    misc::{
        Delayed, MutatorRejectionReason, PendingAggregateAndProof, PendingAttestation,
        PendingBlobSidecar, PendingBlock, PendingChainLink, PendingDataColumnSidecar,
        VerifyAggregateAndProofResult, VerifyAttestationResult, WaitingForCheckpointState,
    },
    state_cache::StateCache,
    storage::Storage,
    tasks::{
        AggregateAndProofTask, AttestationTask, BlobSidecarTask, BlockAttestationsTask, BlockTask,
        CheckpointStateTask, DataColumnSidecarTask, PersistBlobSidecarsTask,
        PersistDataColumnSidecarsTask, PreprocessStateTask,
    },
    thread_pool::{Spawn, ThreadPool},
    unbounded_sink::UnboundedSink,
    wait::Wait,
    ApiMessage, BlockEvent, ChainReorgEvent, FinalizedCheckpointEvent, HeadEvent,
};

#[allow(clippy::struct_field_names)]
pub struct Mutator<P: Preset, E, W, AS, PS, NS, SS, VS> {
    store: Arc<Store<P>>,
    store_snapshot: Arc<ArcSwap<Store<P>>>,
    state_cache: Arc<StateCache<P, W>>,
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
    mutator_tx: Sender<MutatorMessage<P, W>>,
    mutator_rx: Receiver<MutatorMessage<P, W>>,
    api_tx: AS,
    p2p_tx: PS,
    subnet_tx: NS,
    sync_tx: SS,
    validator_tx: VS,
}

impl<P, E, W, AS, PS, NS, SS, VS> Mutator<P, E, W, AS, PS, NS, SS, VS>
where
    P: Preset,
    E: ExecutionEngine<P> + Clone + Send + Sync + 'static,
    W: Wait,
    AS: UnboundedSink<ApiMessage<P>>,
    PS: UnboundedSink<P2pMessage<P>>,
    NS: UnboundedSink<SubnetMessage<W>>,
    SS: UnboundedSink<SyncMessage<P>>,
    VS: UnboundedSink<ValidatorMessage<P, W>>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store_snapshot: Arc<ArcSwap<Store<P>>>,
        state_cache: Arc<StateCache<P, W>>,
        execution_engine: E,
        storage: Arc<Storage<P>>,
        thread_pool: ThreadPool<P, E, W>,
        metrics: Option<Arc<Metrics>>,
        mutator_tx: Sender<MutatorMessage<P, W>>,
        mutator_rx: Receiver<MutatorMessage<P, W>>,
        api_tx: AS,
        p2p_tx: PS,
        subnet_tx: NS,
        sync_tx: SS,
        validator_tx: VS,
    ) -> Self {
        Self {
            store: store_snapshot.load_full(),
            store_snapshot,
            state_cache,
            execution_engine,
            delayed_until_blobs: HashMap::new(),
            delayed_until_block: HashMap::new(),
            delayed_until_slot: BTreeMap::new(),
            delayed_until_payload: HashMap::new(),
            waiting_for_checkpoint_states: HashMap::new(),
            storage,
            thread_pool,
            metrics,
            mutator_tx,
            mutator_rx,
            api_tx,
            p2p_tx,
            subnet_tx,
            sync_tx,
            validator_tx,
        }
    }

    pub fn run(&mut self) -> Result<()> {
        loop {
            match self
                .mutator_rx
                .recv()
                .expect("sender in Controller is not dropped until mutator thread exits")
            {
                MutatorMessage::Tick { wait_group, tick } => self.handle_tick(&wait_group, tick)?,
                MutatorMessage::Block {
                    wait_group,
                    result,
                    origin,
                    submission_time,
                    rejected_block_root,
                } => self.handle_block(
                    wait_group,
                    result,
                    origin,
                    submission_time,
                    rejected_block_root,
                )?,
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
                    block_seen,
                    origin,
                    submission_time,
                } => self.handle_blob_sidecar(
                    wait_group,
                    result,
                    block_seen,
                    origin,
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
                    submission_time,
                } => self.handle_data_column_sidecar(wait_group, result, origin, submission_time),
                MutatorMessage::FinishedPersistingBlobSidecars {
                    wait_group,
                    persisted_blob_ids,
                } => {
                    self.handle_finish_persisting_blob_sidecars(wait_group, persisted_blob_ids);
                }
                MutatorMessage::FinishedPersistingDataColumnSidecars {
                    wait_group,
                    persisted_data_column_ids,
                } => {
                    self.handle_finish_persisting_data_column_sidecars(
                        wait_group,
                        persisted_data_column_ids,
                    );
                }
                MutatorMessage::PreprocessedBeaconState { block_root, state } => {
                    self.handle_preprocessed_beacon_state(block_root, &state);
                }
                MutatorMessage::NotifiedForkChoiceUpdate {
                    wait_group,
                    payload_status,
                } => self.handle_notified_forkchoice_update_result(&wait_group, &payload_status),
                MutatorMessage::NotifiedNewPayload {
                    wait_group,
                    execution_block_hash,
                    payload_status,
                } => self.handle_notified_new_payload(
                    &wait_group,
                    execution_block_hash,
                    payload_status,
                ),
                MutatorMessage::Stop { save_to_storage } => {
                    break self.handle_stop(save_to_storage);
                }
                MutatorMessage::StoreCustodyColumns { custody_columns } => {
                    self.handle_store_custody_columns(custody_columns)
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
            let submission_time = Instant::now();

            // There is no point in spawning `BlockTask`s to validate persisted blocks.
            // State transitions within a single fork must be performed sequentially.
            // Other validations may be performed in parallel, but they take very little time.
            let result = self.store.validate_block(
                block.clone_arc(),
                origin.state_root_policy(),
                &self.execution_engine,
                NullVerifier,
            );

            let rejected_block_root = result.is_err().then(|| block.message().hash_tree_root());

            self.handle_block(
                wait_group.clone(),
                result,
                origin,
                submission_time,
                rejected_block_root,
            )?;
        }

        Ok(())
    }

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

        // Query the execution engine for the current status of the head
        // if it is still optimistic 1 second before the next interval.
        if tick.is_end_of_interval() {
            let head = self.store.head();

            if head.is_optimistic() {
                if let Some(execution_payload) = head.block.as_ref().clone().execution_payload() {
                    let mut params = None;

                    if let Some(body) = head.block.message().body().post_deneb() {
                        let versioned_hashes = body
                            .blob_kzg_commitments()
                            .iter()
                            .copied()
                            .map(helper_functions::misc::kzg_commitment_to_versioned_hash)
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
        }

        self.update_store_snapshot();

        ValidatorMessage::Tick(wait_group.clone(), tick).send(&self.validator_tx);

        if changes.is_slot_updated() {
            let slot = tick.slot;

            debug!("retrying objects delayed until slot {slot}");

            for delayed in self.take_delayed_until_slot(slot) {
                self.retry_delayed(delayed, wait_group);
            }

            P2pMessage::Slot(slot).send(&self.p2p_tx);
            SubnetMessage::Slot(wait_group.clone(), slot).send(&self.subnet_tx);

            self.track_collection_metrics();
        }

        if changes.is_finalized_checkpoint_updated() {
            self.notify_about_finalized_checkpoint();
        }

        if let ApplyTickChanges::Reorganized { old_head, .. } = changes {
            self.notify_about_reorganization(wait_group.clone(), &old_head);
            self.spawn_preprocess_head_state_for_next_slot_task();
        } else if self.store.tick().kind == TickKind::Attest {
            self.spawn_preprocess_head_state_for_next_slot_task();
        }

        if tick.kind == TickKind::AttestFourth
            && self.store.is_forward_synced()
            && misc::slots_since_epoch_start::<P>(tick.slot) == 0
        {
            self.prune_old_blob_sidecars()?;
        }

        if self.store.is_forward_synced() && misc::slots_since_epoch_start::<P>(tick.slot) == 0 {
            if tick.kind == TickKind::AttestFourth {
                self.prune_old_blob_sidecars()?;
            }

            if let Some(metrics) = self.metrics.as_ref() {
                Self::track_epoch_transition_metrics(
                    &self.store.head().state(&self.store),
                    metrics,
                );
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn handle_block(
        &mut self,
        wait_group: W,
        result: Result<BlockAction<P>>,
        origin: BlockOrigin,
        submission_time: Instant,
        rejected_block_root: Option<H256>,
    ) -> Result<()> {
        match result {
            Ok(BlockAction::Accept(chain_link, attester_slashing_results)) => {
                let pending_chain_link = PendingChainLink {
                    chain_link,
                    attester_slashing_results,
                    origin,
                    submission_time,
                };

                self.accept_block(&wait_group, pending_chain_link)?;
            }
            Ok(BlockAction::Ignore) => {
                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    P2pMessage::Ignore(gossip_id).send(&self.p2p_tx);
                }

                reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore));
            }
            Ok(BlockAction::DelayUntilBlobs(block)) => {
                let slot = block.message().slot();
                let block_root = block.message().hash_tree_root();

                let pending_block = PendingBlock {
                    block,
                    origin,
                    submission_time,
                };

                if self
                    .store
                    .chain_config()
                    .is_eip7594_fork(misc::compute_epoch_at_slot::<P>(slot))
                {
                    let parent = self
                        .store
                        .chain_link(pending_block.block.message().parent_root())
                        .expect("block data availability check should be done after block parent presence check");

                    let missing_column_indices =
                        self.store.indices_of_missing_data_columns(&parent.block);

                    if missing_column_indices.len() * 2 < NumberOfColumns::USIZE
                        || !self.store.is_forward_synced()
                    {
                        self.retry_block(wait_group, pending_block);
                    } else {
                        info!(
                            "block delayed until parent has sufficient data columns \
                             (column indices: {missing_column_indices:?}, pending block root: {block_root:?})",
                        );

                        if let Some(gossip_id) = pending_block.origin.gossip_id() {
                            P2pMessage::Accept(gossip_id).send(&self.p2p_tx);
                        }

                        let column_ids = missing_column_indices
                            .into_iter()
                            .map(|index| DataColumnIdentifier { block_root, index })
                            .collect_vec();

                        let peer_id = pending_block.origin.peer_id();

                        P2pMessage::DataColumnsNeeded(column_ids, slot, peer_id).send(&self.p2p_tx);

                        self.delay_block_until_blobs(block_root, pending_block);
                    }
                } else {
                    let missing_blob_indices =
                        self.store.indices_of_missing_blobs(&pending_block.block);

                    if missing_blob_indices.is_empty() {
                        self.retry_block(wait_group, pending_block);
                    } else {
                        debug!("block delayed until blobs: {pending_block:?}");

                        if let Some(gossip_id) = pending_block.origin.gossip_id() {
                            P2pMessage::Accept(gossip_id).send(&self.p2p_tx);
                        }

                        let blob_ids = missing_blob_indices
                            .into_iter()
                            .map(|index| BlobIdentifier { block_root, index })
                            .collect_vec();

                        let peer_id = pending_block.origin.peer_id();

                        P2pMessage::BlobsNeeded(blob_ids, slot, peer_id).send(&self.p2p_tx);

                        self.delay_block_until_blobs(block_root, pending_block);
                    }
                }
            }
            Ok(BlockAction::DelayUntilParent(block)) => {
                let parent_root = block.message().parent_root();

                let pending_block = PendingBlock {
                    block,
                    origin,
                    submission_time,
                };

                if self.store.contains_block(parent_root) {
                    self.retry_block(wait_group, pending_block);
                } else {
                    debug!("block delayed until parent: {pending_block:?}");

                    let peer_id = pending_block.origin.peer_id();

                    P2pMessage::BlockNeeded(parent_root, peer_id).send(&self.p2p_tx);

                    self.delay_block_until_parent(pending_block);
                }
            }
            Ok(BlockAction::DelayUntilSlot(block)) => {
                let slot = block.message().slot();

                let pending_block = PendingBlock {
                    block,
                    origin,
                    submission_time,
                };

                if slot <= self.store.slot() {
                    self.retry_block(wait_group, pending_block);
                } else {
                    debug!("block delayed until slot: {pending_block:?}");

                    self.delay_block_until_slot(pending_block);
                }
            }
            Ok(BlockAction::WaitForJustifiedState(
                chain_link,
                attester_slashing_results,
                checkpoint,
            )) => {
                let pending_chain_link = PendingChainLink {
                    chain_link,
                    attester_slashing_results,
                    origin,
                    submission_time,
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
            Err(error) => {
                warn!("block rejected (error: {error}, origin: {origin:?})");

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    P2pMessage::Reject(gossip_id, MutatorRejectionReason::InvalidBlock)
                        .send(&self.p2p_tx);
                }

                if let Some(block_root) = rejected_block_root {
                    self.store_mut().register_rejected_block(block_root);
                    self.update_store_snapshot();
                }

                reply_block_validation_result_to_http_api(sender, Err(error));
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
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
                is_superset,
            }) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["accepted"]);
                }

                debug!(
                    "aggregate and proof accepted \
                     (aggregate_and_proof: {aggregate_and_proof:?}, origin: {origin:?})",
                );

                if origin.send_to_validator() {
                    let attestation = Arc::new(aggregate_and_proof.message.aggregate.clone());

                    ValidatorMessage::ValidAttestation(wait_group.clone(), attestation)
                        .send(&self.validator_tx);
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    if is_superset {
                        P2pMessage::Accept(gossip_id).send(&self.p2p_tx);
                    } else {
                        P2pMessage::Ignore(gossip_id).send(&self.p2p_tx);
                    }
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                let valid_attestation = ValidAttestation {
                    data: aggregate_and_proof.message.aggregate.data,
                    attesting_indices,
                    is_from_block: false,
                };

                let old_head = self.store_mut().apply_attestation(valid_attestation)?;

                self.update_store_snapshot();

                if let Some(old_head) = old_head {
                    self.notify_about_reorganization(wait_group.clone(), &old_head);
                    self.spawn_preprocess_head_state_for_next_slot_task();
                }
            }
            Ok(AggregateAndProofAction::Ignore) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["ignored"]);
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    P2pMessage::Ignore(gossip_id).send(&self.p2p_tx);
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore));
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

                let checkpoint = aggregate_and_proof.message.aggregate.data.target;

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

                warn!("aggregate and proof rejected (error: {error}, origin: {origin:?})");

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    P2pMessage::Reject(gossip_id, MutatorRejectionReason::InvalidAggregateAndProof)
                        .send(&self.p2p_tx);
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

    #[allow(clippy::too_many_lines)]
    fn handle_attestation(
        &mut self,
        wait_group: &W,
        verify_result: VerifyAttestationResult<P>,
    ) -> Result<()> {
        let VerifyAttestationResult { result, origin } = verify_result;

        match result {
            Ok(AttestationAction::Accept {
                attestation,
                attesting_indices,
            }) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["accepted"]);
                }

                debug!("attestation accepted (attestation: {attestation:?}, origin: {origin:?})");

                if origin.should_generate_event() {
                    ApiMessage::AttestationEvent(attestation.clone_arc()).send(&self.api_tx);
                }

                if origin.send_to_validator() {
                    let attestation = attestation.clone_arc();

                    ValidatorMessage::ValidAttestation(wait_group.clone(), attestation)
                        .send(&self.validator_tx);
                }

                let is_from_block = origin.is_from_block();
                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    P2pMessage::Accept(gossip_id).send(&self.p2p_tx);
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                let valid_attestation = ValidAttestation {
                    data: attestation.data,
                    attesting_indices,
                    is_from_block,
                };

                let old_head = self.store_mut().apply_attestation(valid_attestation)?;

                self.update_store_snapshot();

                if let Some(old_head) = old_head {
                    self.notify_about_reorganization(wait_group.clone(), &old_head);
                    self.spawn_preprocess_head_state_for_next_slot_task();
                }
            }
            Ok(AttestationAction::Ignore) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["ignored"]);
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    P2pMessage::Ignore(gossip_id).send(&self.p2p_tx);
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore));
            }
            Ok(AttestationAction::DelayUntilBlock(attestation, block_root)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["delayed_until_block"]);
                }

                let pending_attestation = PendingAttestation {
                    attestation,
                    origin,
                };

                self.delay_attestation_until_block(wait_group, pending_attestation, block_root);
            }
            Ok(AttestationAction::DelayUntilSlot(attestation)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["delayed_until_slot"]);
                }

                let pending_attestation = PendingAttestation {
                    attestation,
                    origin,
                };

                self.delay_attestation_until_slot(wait_group, pending_attestation);
            }
            Ok(AttestationAction::WaitForTargetState(attestation)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["delayed_until_state"]);
                }

                let checkpoint = attestation.data.target;

                let pending_attestation = PendingAttestation {
                    attestation,
                    origin,
                };

                if self.store.contains_checkpoint_state(checkpoint) {
                    self.retry_attestation(wait_group.clone(), pending_attestation);
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
            }
            Err(error) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["rejected"]);
                }

                warn!("attestation rejected (error: {error}, origin: {origin:?})");

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    P2pMessage::Reject(gossip_id, MutatorRejectionReason::InvalidAttestation)
                        .send(&self.p2p_tx);
                }

                reply_to_http_api(sender, Err(error));
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
        results: Vec<Result<AttestationAction<P>>>,
    ) -> Result<()> {
        let accepted = results
            .into_iter()
            .filter_map(|result| match result {
                Ok(AttestationAction::Accept {
                    attestation,
                    attesting_indices,
                }) => Some(ValidAttestation {
                    data: attestation.data,
                    attesting_indices,
                    is_from_block: true,
                }),
                Ok(AttestationAction::Ignore) => None,
                Ok(AttestationAction::DelayUntilBlock(attestation, block_root)) => {
                    self.delay_attestation_until_block(
                        wait_group,
                        PendingAttestation {
                            attestation,
                            origin: AttestationOrigin::Block,
                        },
                        block_root,
                    );
                    None
                }
                Ok(AttestationAction::DelayUntilSlot(attestation)) => {
                    self.delay_attestation_until_slot(
                        wait_group,
                        PendingAttestation {
                            attestation,
                            origin: AttestationOrigin::Block,
                        },
                    );
                    None
                }
                Ok(AttestationAction::WaitForTargetState(attestation)) => {
                    let checkpoint = attestation.data.target;

                    let pending_attestation = PendingAttestation {
                        attestation,
                        origin: AttestationOrigin::Block,
                    };

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
                    let origin = AttestationOrigin::<GossipId>::Block;
                    warn!("attestation rejected (error: {error}, origin: {origin:?})");
                    None
                }
            })
            .collect_vec();

        let old_head = self.store_mut().apply_attestation_batch(accepted)?;

        self.update_store_snapshot();

        if let Some(old_head) = old_head {
            self.notify_about_reorganization(wait_group.clone(), &old_head);
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
                    self.notify_about_reorganization(wait_group.clone(), &old_head);
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
        block_seen: bool,
        origin: BlobSidecarOrigin,
        submission_time: Instant,
    ) {
        match result {
            Ok(BlobSidecarAction::Accept(blob_sidecar)) => {
                if let Some(gossip_id) = origin.gossip_id() {
                    P2pMessage::Accept(gossip_id).send(&self.p2p_tx);
                }

                self.accept_blob_sidecar(&wait_group, blob_sidecar);
            }
            Ok(BlobSidecarAction::Ignore) => {
                if let Some(gossip_id) = origin.gossip_id() {
                    P2pMessage::Ignore(gossip_id).send(&self.p2p_tx);
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
                    self.retry_blob_sidecar(wait_group, pending_blob_sidecar);
                } else {
                    debug!("blob sidecar delayed until block parent: {parent_root:?}");

                    let peer_id = pending_blob_sidecar.origin.peer_id();

                    P2pMessage::BlockNeeded(parent_root, peer_id).send(&self.p2p_tx);

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
                    self.retry_blob_sidecar(wait_group, pending_blob_sidecar);
                } else {
                    debug!("blob sidecar delayed until slot: {slot}");

                    self.delay_blob_sidecar_until_slot(pending_blob_sidecar);
                }
            }
            Err(error) => {
                warn!("blob sidecar rejected (error: {error}, origin: {origin:?})");

                if let Some(gossip_id) = origin.gossip_id() {
                    P2pMessage::Reject(gossip_id, MutatorRejectionReason::InvalidBlobSidecar)
                        .send(&self.p2p_tx);
                }
            }
        }
    }

    fn handle_data_column_sidecar(
        &mut self,
        wait_group: W,
        result: Result<DataColumnSidecarAction<P>>,
        origin: DataColumnSidecarOrigin,
        submission_time: Instant,
    ) {
        match result {
            Ok(DataColumnSidecarAction::Accept(data_column_sidecar)) => {
                if let Some(gossip_id) = origin.gossip_id() {
                    P2pMessage::Accept(gossip_id).send(&self.p2p_tx);
                }
                
                self.accept_data_column_sidecar(&wait_group, data_column_sidecar);
            }
            Ok(DataColumnSidecarAction::Ignore) => {
                if let Some(gossip_id) = origin.gossip_id() {
                    P2pMessage::Ignore(gossip_id).send(&self.p2p_tx);
                }
            }
            Ok(DataColumnSidecarAction::DelayUntilParent(data_column_sidecar)) => {
                let parent_root = data_column_sidecar.signed_block_header.message.parent_root;

                let pending_data_column_sidecar = PendingDataColumnSidecar {
                    data_column_sidecar,
                    origin,
                    submission_time,
                };

                if self.store.contains_block(parent_root) {
                    self.retry_data_column_sidecar(wait_group, pending_data_column_sidecar);
                } else {
                    debug!("data column sidecar delayed until block parent: {parent_root:?}");

                    let peer_id = pending_data_column_sidecar.origin.peer_id();

                    P2pMessage::BlockNeeded(parent_root, peer_id).send(&self.p2p_tx);

                    self.delay_data_column_sidecar_until_parent(pending_data_column_sidecar);
                }
            }
            Ok(DataColumnSidecarAction::DelayUntilSlot(data_column_sidecar)) => {
                let slot = data_column_sidecar.signed_block_header.message.slot;

                let pending_data_column_sidecar = PendingDataColumnSidecar {
                    data_column_sidecar,
                    origin,
                    submission_time,
                };

                if slot <= self.store.slot() {
                    self.retry_data_column_sidecar(wait_group, pending_data_column_sidecar);
                } else {
                    debug!("data column sidecar delayed until slot: {slot}");

                    self.delay_data_column_sidecar_until_slot(pending_data_column_sidecar);
                }
            }
            Err(error) => {
                warn!("data column sidecar rejected (error: {error}, origin: {origin:?})");

                if let Some(gossip_id) = origin.gossip_id() {
                    P2pMessage::Reject(gossip_id, MutatorRejectionReason::InvalidBlobSidecar)
                        .send(&self.p2p_tx);
                }
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
        wait_group: W,
        persisted_data_column_ids: Vec<DataColumnIdentifier>,
    ) {
        self.store_mut()
            .mark_persisted_data_columns(persisted_data_column_ids);

        self.update_store_snapshot();

        if self.store.has_unpersisted_data_column_sidecars() {
            self.spawn(PersistDataColumnSidecarsTask {
                store_snapshot: self.owned_store(),
                storage: self.storage.clone_arc(),
                mutator_tx: self.owned_mutator_tx(),
                wait_group,
                metrics: self.metrics.clone(),
            });
        }
    }

    fn handle_preprocessed_beacon_state(&mut self, block_root: H256, state: &Arc<BeaconState<P>>) {
        self.store_mut()
            .insert_preprocessed_state(block_root, state.clone_arc());
        self.update_store_snapshot();

        self.prepare_execution_payload_for_next_slot(state);
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
        execution_block_hash: ExecutionBlockHash,
        payload_status: PayloadStatusV1,
    ) {
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
            // The call to `Store::update_chain_payload_statuses` above will set the payload
            // statuses of the block and its descendants to `PayloadStatus::Invalid`,
            // but only if `latest_valid_hash` is present.
            if latest_valid_hash.is_none() || latest_valid_hash == Some(ExecutionBlockHash::zero())
            {
                payload_action = self
                    .store_mut()
                    .invalidate_block_and_descendant_payload_statuses(execution_block_hash);
            }
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
                ApiMessage::BlockEvent(BlockEvent {
                    slot: chain_link.slot(),
                    block: chain_link.block_root,
                    execution_optimistic: false,
                })
                .send(&self.api_tx);
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
        if (head_changed || head_was_optimistic) && head.is_valid() {
            match HeadEvent::new(&self.storage, &self.store, head) {
                Ok(event) => ApiMessage::Head(event).send(&self.api_tx),
                Err(error) => warn!("{error:#}"),
            }

            if !head_changed {
                // The call to `Store::notify_about_reorganization` below sends
                // a `ValidatorMessage::Head` message if the head changed.
                ValidatorMessage::Head(wait_group.clone(), head.clone()).send(&self.validator_tx);
            }
        }

        if head_changed {
            self.notify_about_reorganization(wait_group.clone(), old_head);
            self.spawn_preprocess_head_state_for_next_slot_task();
        }
    }

    fn handle_stop(&self, save_to_storage: bool) -> Result<()> {
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

    fn handle_store_custody_columns(&mut self, custody_columns: HashSet<ColumnIndex>) {
        info!("storing custody columns: {custody_columns:?} for further data availability check");

        self.store_mut()
            .store_custody_columns(custody_columns.into());
    }

    #[allow(clippy::cognitive_complexity)]
    #[allow(clippy::too_many_lines)]
    fn accept_block(
        &mut self,
        wait_group: &W,
        pending_chain_link: PendingChainLink<P>,
    ) -> Result<()> {
        let PendingChainLink {
            chain_link,
            attester_slashing_results,
            origin,
            submission_time,
        } = pending_chain_link;

        let block_root = chain_link.block_root;
        let block = &chain_link.block;

        // Check if the block is already present in the store.
        // This is done here primarily to avoid spawning redundant `BlockAttestationsTask`s.
        if self.store.contains_block(block_root) {
            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                P2pMessage::Ignore(gossip_id).send(&self.p2p_tx);
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore));

            return Ok(());
        }

        // A block may become orphaned while being processed.
        // The fork choice store is not designed to accomodate blocks like that.
        if block.message().slot() <= self.store.finalized_slot() {
            debug!(
                "block became orphaned while being processed \
                 (block_root: {block_root:?}, block: {block:?}, \
                  origin: {origin:?}, finalized slot: {})",
                self.store.finalized_slot(),
            );

            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                P2pMessage::Ignore(gossip_id).send(&self.p2p_tx);
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore));

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

        if misc::is_epoch_start::<P>(head_slot) {
            info!("unloading old beacon states (head slot: {head_slot})");

            self.store_mut()
                .unload_old_states(unfinalized_states_in_memory);
        }

        let processing_duration = insertion_time.duration_since(submission_time);

        features::log!(
            LogBlockProcessingTime,
            "block {block_root:?} processed in {processing_duration:?}",
        );

        if let Some(metrics) = self.metrics.as_ref() {
            metrics
                .block_processing_times
                .observe(processing_duration.as_secs_f64());
        }

        if let Some(hash) = block.execution_block_hash() {
            if let Some(payload_statuses) = self.delayed_until_payload.remove(&hash) {
                for (payload_status, _) in payload_statuses {
                    self.handle_notified_new_payload(wait_group, hash, payload_status);
                }
            }
        }

        // Do not send API events about optimistic blocks.
        // Vouch treats all head events as non-optimistic.
        if is_valid {
            ApiMessage::BlockEvent(BlockEvent {
                slot: block_slot,
                block: block_root,
                execution_optimistic: false,
            })
            .send(&self.api_tx);
        }

        // TODO(Grandine Team): Performing the validation here results in the block being added to the
        //                      fork choice store even though it is already known to be invalid.
        //                      The validation should be in `Store::validate_block`,
        //                      but that makes it harder to retry payload statuses.
        //                      That is also why the message sending and task spawning was moved here.
        //                      One possible solution is to check `Mutator.delayed_until_payload` in
        //                      this method before calling `Store::apply_block`.
        // > - If `exection_payload` verification of block's parent by an execution node is *not*
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
                P2pMessage::Ignore(gossip_id).send(&self.p2p_tx);
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore));
        } else {
            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                P2pMessage::Accept(gossip_id).send(&self.p2p_tx);
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Accept));
        }

        self.maybe_spawn_block_attestations_task(wait_group, &block);

        if changes.is_finalized_checkpoint_updated() {
            self.archive_finalized(wait_group)?;
            self.prune_delayed_until_payload();
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
            self.retry_delayed(objects, wait_group);
        }

        if changes.is_finalized_checkpoint_updated() {
            self.notify_about_finalized_checkpoint();
        }

        let pruned_gossip_ids = changes
            .is_finalized_checkpoint_updated()
            .then(|| {
                let delayed = self.prune_delayed_until_block();
                let waiting = self.prune_waiting_for_checkpoint_states();
                delayed.into_iter().chain(waiting)
            })
            .into_iter()
            .flatten();

        for gossip_id in pruned_gossip_ids {
            P2pMessage::Ignore(gossip_id).send(&self.p2p_tx);
        }

        match changes {
            ApplyBlockChanges::CanonicalChainExtended { .. } => {
                let new_head = self.store.head().clone();
                let state = new_head.state(&self.store);

                if let Some(metrics) = self.metrics.as_ref() {
                    Self::track_head_metrics(&new_head, metrics);
                }

                P2pMessage::HeadState(state).send(&self.p2p_tx);

                // Do not send API events about optimistic blocks.
                // Vouch treats all head events as non-optimistic.
                if new_head.is_valid() {
                    match HeadEvent::new(&self.storage, &self.store, &new_head) {
                        Ok(event) => ApiMessage::Head(event).send(&self.api_tx),
                        Err(error) => warn!("{error:#}"),
                    }

                    ValidatorMessage::Head(wait_group.clone(), new_head.clone())
                        .send(&self.validator_tx);
                }

                self.notify_forkchoice_updated(&new_head);
                self.spawn_preprocess_head_state_for_next_slot_task();
            }
            ApplyBlockChanges::Reorganized { old_head, .. } => {
                self.notify_about_reorganization(wait_group.clone(), &old_head);
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

    fn accept_blob_sidecar(&mut self, wait_group: &W, blob_sidecar: Arc<BlobSidecar<P>>) {
        let old_head = self.store.head().clone();
        let head_was_optimistic = old_head.is_optimistic();
        let block_root = blob_sidecar.signed_block_header.message.hash_tree_root();

        self.store_mut().apply_blob_sidecar(blob_sidecar);

        self.update_store_snapshot();

        if let Some(pending_block) = self.delayed_until_blobs.get(&block_root) {
            self.retry_block(wait_group.clone(), pending_block.clone());
        }

        self.spawn(PersistBlobSidecarsTask {
            store_snapshot: self.owned_store(),
            storage: self.storage.clone_arc(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: wait_group.clone(),
            metrics: self.metrics.clone(),
        });

        self.handle_potential_head_change(wait_group, &old_head, head_was_optimistic);
    }

    fn accept_data_column_sidecar(
        &mut self,
        wait_group: &W,
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    ) {
        let old_head = self.store.head().clone();
        let head_was_optimistic = old_head.is_optimistic();
        let block_root = data_column_sidecar
            .signed_block_header
            .message
            .hash_tree_root();

        self.store_mut()
            .apply_data_column_sidecar(data_column_sidecar);

        self.update_store_snapshot();

        if let Some(pending_block) = self.delayed_until_blobs.get(&block_root) {
            self.retry_block(wait_group.clone(), pending_block.clone());
        }

        self.spawn(PersistDataColumnSidecarsTask {
            store_snapshot: self.owned_store(),
            storage: self.storage.clone_arc(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: wait_group.clone(),
            metrics: self.metrics.clone(),
        });

        self.handle_potential_head_change(wait_group, &old_head, head_was_optimistic);
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

        P2pMessage::FinalizedCheckpoint(finalized_checkpoint).send(&self.p2p_tx);

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.set_justified_epoch(justified_checkpoint.epoch);
            metrics.set_finalized_epoch(finalized_checkpoint.epoch);
        }

        ValidatorMessage::FinalizedEth1Data(
            self.store
                .last_finalized()
                .state(&self.store)
                .eth1_deposit_index(),
        )
        .send(&self.validator_tx);

        ApiMessage::FinalizedCheckpoint(FinalizedCheckpointEvent {
            block: head.block_root,
            state: finalized_checkpoint.root,
            epoch: finalized_checkpoint.epoch,
            execution_optimistic: head.is_optimistic(),
        })
        .send(&self.api_tx);
    }

    fn notify_about_reorganization(&self, wait_group: W, old_head: &ChainLink<P>) {
        let new_head = self.store.head().clone();
        let event = ChainReorgEvent::new(&self.store, old_head);

        ApiMessage::ChainReorgEvent(event).send(&self.api_tx);

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.beacon_reorgs_total.inc();
        }

        info!(
            "chain reorganized (old head: {:?}, new head: {:?})",
            old_head.block_root, new_head.block_root,
        );

        let state = new_head.state(&self.store);

        if let Some(metrics) = self.metrics.as_ref() {
            Self::track_head_metrics(&new_head, metrics);
        }

        P2pMessage::HeadState(state).send(&self.p2p_tx);

        if new_head.is_valid() {
            ValidatorMessage::Head(wait_group, new_head.clone()).send(&self.validator_tx);
        }

        self.notify_forkchoice_updated(&new_head);
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

        if !new_head.is_valid() {
            let head_block_hash = state.latest_execution_payload_header().block_hash();

            self.execution_engine.notify_forkchoice_updated(
                head_block_hash,
                safe_block_hash,
                finalized_block_hash,
                Either::Left(new_head.block.phase()),
                None,
            );
        }
    }

    fn delay_block_until_blobs(&mut self, beacon_block_root: H256, pending_block: PendingBlock<P>) {
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

            P2pMessage::BlockNeeded(block_root, peer_id).send(&self.p2p_tx);

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

            P2pMessage::BlockNeeded(block_root, peer_id).send(&self.p2p_tx);

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
            .message
            .aggregate
            .data
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
        let slot = pending_attestation.attestation.data.slot;

        if slot <= self.store.slot() {
            self.retry_attestation(wait_group.clone(), pending_attestation);
        } else {
            debug!("attestation delayed until slot: {pending_attestation:?}");

            // Attestations produced by the application itself should never be delayed.
            // Attestations included in blocks should never be delayed until a slot
            // because at least one slot must have passed since they were published.
            assert!(!matches!(
                pending_attestation.origin,
                AttestationOrigin::Own(_) | AttestationOrigin::Block,
            ));

            self.delayed_until_slot
                .entry(pending_attestation.attestation.data.slot)
                .or_default()
                .attestations
                .push(pending_attestation);
        }
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

    // `wait_group` is a reference not just to pass Clippy lints but for correctness as well.
    // The referenced value must not be dropped before the current message is handled.
    fn retry_delayed(&self, delayed: Delayed<P>, wait_group: &W) {
        let Delayed {
            blocks,
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
            self.retry_blob_sidecar(wait_group.clone(), pending_blob_sidecar);
        }

        for pending_data_column_sidecar in data_column_sidecars {
            self.retry_data_column_sidecar(wait_group.clone(), pending_data_column_sidecar);
        }
    }

    fn retry_block(&self, wait_group: W, pending_block: PendingBlock<P>) {
        debug!("retrying delayed block: {pending_block:?}");

        let PendingBlock {
            block,
            origin,
            submission_time,
        } = pending_block;

        self.spawn(BlockTask {
            store_snapshot: self.owned_store(),
            execution_engine: self.execution_engine.clone(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            block,
            origin,
            submission_time,
            metrics: self.metrics.clone(),
        });
    }

    fn retry_attestation(&self, wait_group: W, pending_attestation: PendingAttestation<P>) {
        debug!("retrying delayed attestation: {pending_attestation:?}");

        let PendingAttestation {
            attestation,
            origin,
        } = pending_attestation;

        if let Some(subnet_id) = origin.subnet_id() {
            if let Some(gossip_id) = origin.gossip_id_ref() {
                P2pMessage::ReverifyGossipAttestation(attestation, subnet_id, gossip_id.clone())
                    .send(&self.p2p_tx);
                return;
            }
        }

        self.spawn(AttestationTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            attestation,
            origin,
            metrics: self.metrics.clone(),
        });
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

        self.spawn(AggregateAndProofTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            aggregate_and_proof,
            origin,
            metrics: self.metrics.clone(),
        });
    }

    fn retry_blob_sidecar(&self, wait_group: W, pending_blob_sidecar: PendingBlobSidecar<P>) {
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
    ) {
        debug!("retrying delayed data column sidecar: {pending_data_column_sidecar:?}");

        let PendingDataColumnSidecar {
            data_column_sidecar,
            origin,
            submission_time,
        } = pending_data_column_sidecar;

        self.spawn(DataColumnSidecarTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            data_column_sidecar,
            origin,
            submission_time,
            metrics: self.metrics.clone(),
        });
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

        // Use `drain_filter_polyfill` because `Vec::extract_if` is not stable as of Rust 1.77.2.
        self.delayed_until_block.retain(|_, delayed| {
            let Delayed {
                blocks,
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

            gossip_ids.extend(
                aggregates
                    .drain_filter(|pending| {
                        let epoch = pending
                            .aggregate_and_proof
                            .message
                            .aggregate
                            .data
                            .target
                            .epoch;

                        epoch < previous_epoch
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                attestations
                    .drain_filter(|pending| {
                        let epoch = pending.attestation.data.target.epoch;

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

        // Use `HashMap::retain` because `HashMap::extract_if` is not stable as of Rust 1.77.2.
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
        block: &Arc<SignedBeaconBlock<P>>,
    ) {
        // `BlockAttestationsTask`s have a surprisingly large amount of overhead.
        // Avoid spawning them if possible.
        if block.message().body().attestations().is_empty() {
            return;
        }

        self.spawn(BlockAttestationsTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: wait_group.clone(),
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

        ValidatorMessage::PrepareExecutionPayload(
            state.slot(),
            safe_block_hash,
            finalized_block_hash,
        )
        .send(&self.validator_tx);
    }

    fn spawn_checkpoint_state_task(&self, wait_group: W, checkpoint: Checkpoint) {
        self.spawn(CheckpointStateTask {
            state_cache: self.state_cache.clone_arc(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            checkpoint,
            metrics: self.metrics.clone(),
        });
    }

    fn spawn_preprocess_head_state_for_next_slot_task(&self) {
        if !self.store.is_forward_synced() {
            return;
        }

        self.spawn(PreprocessStateTask {
            state_cache: self.state_cache.clone_arc(),
            head_block_root: self.store.head().block_root,
            next_slot: self.store.slot() + 1,
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

            let mut archived = self.store_mut().archive_finalized(latest_archivable_index);
            archived.push_back(self.store.anchor().clone());

            Builder::new()
                .name("store-archiver".to_owned())
                .spawn(move || {
                    debug!("saving finalized blocks and anchor state…");

                    match storage.append(core::iter::empty(), archived.iter(), &store) {
                        Ok(slots) => {
                            if let Some(chain_link) = archived.back() {
                                let finalized_block = chain_link.block.clone_arc();
                                SyncMessage::Finalized(finalized_block).send(&sync_tx);
                            }

                            debug!(
                                "finalized blocks and anchor state saved \
                                 (appended block slots: {slots:?})",
                            )
                        }
                        Err(error) => error!("saving to storage failed: {error:?}"),
                    }

                    drop(wait_group);
                })?;
        }

        Ok(())
    }

    fn prune_old_blob_sidecars(&self) -> Result<()> {
        let storage = self.storage.clone_arc();
        let current_epoch = misc::compute_epoch_at_slot::<P>(self.store.slot());
        let up_to_epoch = current_epoch.saturating_sub(
            self.store
                .chain_config()
                .min_epochs_for_blob_sidecars_requests,
        );
        let up_to_slot = misc::compute_start_slot_at_epoch::<P>(up_to_epoch);

        Builder::new()
            .name("old-blob-pruner".to_owned())
            .spawn(move || {
                debug!("pruning old blob sidecards from storage up to slot {up_to_slot}…");

                match storage.prune_old_blob_sidecars(up_to_slot) {
                    Ok(()) => {
                        debug!("pruned old blob sidecards from storage up to slot {up_to_slot}");
                    }
                    Err(error) => {
                        error!("pruning old blob sidecards from storage failed: {error:?}")
                    }
                }
            })?;

        Ok(())
    }

    // This method should only be called when `Mutator.store` is in a consistent state.
    fn update_store_snapshot(&self) {
        // `ArcSwap::rcu` is not necessary here because there is only one thread mutating the store.
        self.store_snapshot.store(self.owned_store());
    }

    fn spawn(&self, task: impl Spawn<P, E, W>) {
        self.thread_pool.spawn(task);
    }

    fn store_mut(&mut self) -> &mut Store<P> {
        self.store.make_mut()
    }

    // This uses `Mutator.store` instead of `Mutator.store_snapshot` for better performance.
    // `ArcSwap::load` and `ArcSwap::load_full` are surprisingly slow, to the point where it's
    // faster to clone a `Store` with all the `Arc`s inside it and allocate another `Arc`.
    //
    // As a result, this method should only be called when `Mutator.store` is in a consistent state.
    fn owned_store(&self) -> Arc<Store<P>> {
        self.store.clone_arc()
    }

    fn owned_mutator_tx(&self) -> Sender<MutatorMessage<P, W>> {
        self.mutator_tx.clone()
    }

    fn track_epoch_transition_metrics(head_state: &Arc<BeaconState<P>>, metrics: &Arc<Metrics>) {
        metrics.set_processed_deposits(head_state.eth1_deposit_index());
        metrics.set_validator_count(head_state.validators().len_usize());
        metrics.set_active_validators(
            accessors::get_active_validator_indices(head_state, RelativeEpoch::Current).count(),
        );
    }

    fn track_head_metrics(head: &ChainLink<P>, metrics: &Arc<Metrics>) {
        metrics.set_slot(head.slot());
    }

    fn track_collection_metrics(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            let type_name = tynm::type_name::<Self>();

            let (high_priority_tasks, low_priority_tasks) = self.thread_pool.task_counts();

            metrics.set_collection_length(
                &type_name,
                "delayed_until_block",
                self.delayed_until_block.len(),
            );

            metrics.set_collection_length(
                &type_name,
                "delayed_until_block_blocks",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.blocks.len())
                    .sum(),
            );

            metrics.set_collection_length(
                &type_name,
                "delayed_until_block_attestations",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.attestations.len())
                    .sum(),
            );

            metrics.set_collection_length(
                &type_name,
                "delayed_until_block_aggregates",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.aggregates.len())
                    .sum(),
            );

            metrics.set_collection_length(
                &type_name,
                "delayed_until_slot",
                self.delayed_until_slot.len(),
            );

            metrics.set_collection_length(
                &type_name,
                "delayed_until_slot_blocks",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.blocks.len())
                    .sum(),
            );

            metrics.set_collection_length(
                &type_name,
                "delayed_until_slot_attestations",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.attestations.len())
                    .sum(),
            );

            metrics.set_collection_length(
                &type_name,
                "delayed_until_slot_aggregates",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.aggregates.len())
                    .sum(),
            );

            metrics.set_collection_length(&type_name, "high_priority_tasks", high_priority_tasks);
            metrics.set_collection_length(&type_name, "low_priority_tasks", low_priority_tasks);

            self.store.track_collection_metrics(metrics);
        }
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
