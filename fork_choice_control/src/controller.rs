// Instead of mutating `Store` directly, the `on_*` methods spawn tasks that do so in the
// background. Query methods operate on a recent but potentially out-of-date snapshot of `Store`.
// All of this serves to accomplish 3 things:
// - Independent blocks and attestations can be processed in parallel.
// - Query methods do not need to wait.
// - The `on_*` methods return quickly and can thus be called from `async` tasks.
//
// The downside is that submitting the same object multiple times in quick succession will result in
// it being processed multiple times in parallel redundantly.

use core::panic::AssertUnwindSafe;
use std::{
    sync::{mpsc::Sender, Arc},
    thread::{Builder, JoinHandle},
    time::Instant,
};

use anyhow::{Context as _, Result};
use arc_swap::{ArcSwap, Guard};
use clock::Tick;
use eth2_libp2p::{GossipId, PeerId};
use execution_engine::{ExecutionEngine, PayloadStatusV1};
use fork_choice_store::{
    AggregateAndProofOrigin, AttestationItem, AttestationOrigin, AttesterSlashingOrigin,
    BlobSidecarOrigin, BlockOrigin, StateCacheProcessor, Store, StoreConfig,
};
use futures::channel::{mpsc::Sender as MultiSender, oneshot::Sender as OneshotSender};
use genesis::AnchorCheckpointProvider;
use http_api_utils::EventChannels;
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use thiserror::Error;
use types::{
    combined::{
        Attestation, AttesterSlashing, BeaconState, SignedAggregateAndProof, SignedBeaconBlock,
    },
    config::Config as ChainConfig,
    deneb::containers::BlobSidecar,
    nonstandard::ValidationOutcome,
    phase0::primitives::{ExecutionBlockHash, Slot, SubnetId},
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::{
    block_processor::BlockProcessor,
    messages::{
        AttestationVerifierMessage, MutatorMessage, P2pMessage, PoolMessage, SubnetMessage,
        SyncMessage, ValidatorMessage,
    },
    misc::{VerifyAggregateAndProofResult, VerifyAttestationResult},
    mutator::Mutator,
    storage::Storage,
    tasks::{
        AggregateAndProofTask, AttestationTask, AttesterSlashingTask, BlobSidecarTask, BlockTask,
        BlockVerifyForGossipTask,
    },
    thread_pool::{Spawn, ThreadPool},
    unbounded_sink::UnboundedSink,
    wait::Wait,
};

pub struct Controller<P: Preset, E, A, W: Wait> {
    // The latest consistent snapshot of the store.
    store_snapshot: Arc<ArcSwap<Store<P>>>,
    block_processor: Arc<BlockProcessor<P>>,
    execution_engine: E,
    state_cache: Arc<StateCacheProcessor<P>>,
    storage: Arc<Storage<P>>,
    thread_pool: ThreadPool<P, E, W>,
    wait_group: W::Swappable,
    metrics: Option<Arc<Metrics>>,
    mutator_tx: Sender<MutatorMessage<P, W>>,
    attestation_verifier_tx: A,
}

impl<P: Preset, E, A, W: Wait> Drop for Controller<P, E, A, W> {
    fn drop(&mut self) {
        let save_to_storage = !std::thread::panicking();
        MutatorMessage::Stop { save_to_storage }.send(&self.mutator_tx);
    }
}

impl<P, E, A, W> Controller<P, E, A, W>
where
    P: Preset,
    E: ExecutionEngine<P> + Clone + Send + Sync + 'static,
    A: UnboundedSink<AttestationVerifierMessage<P, W>>,
    W: Wait,
{
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        chain_config: Arc<ChainConfig>,
        store_config: StoreConfig,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
        tick: Tick,
        event_channels: Arc<EventChannels>,
        execution_engine: E,
        metrics: Option<Arc<Metrics>>,
        attestation_verifier_tx: A, // impl UnboundedSink<AttestationVerifierMessage<P, W>>,
        p2p_tx: impl UnboundedSink<P2pMessage<P>>,
        pool_tx: impl UnboundedSink<PoolMessage>,
        subnet_tx: impl UnboundedSink<SubnetMessage<W>>,
        sync_tx: impl UnboundedSink<SyncMessage<P>>,
        validator_tx: impl UnboundedSink<ValidatorMessage<P, W>>,
        storage: Arc<Storage<P>>,
        unfinalized_blocks: impl DoubleEndedIterator<Item = Result<Arc<SignedBeaconBlock<P>>>>,
    ) -> Result<(Arc<Self>, MutatorHandle<P, W>)> {
        let finished_initial_forward_sync = anchor_block.message().slot() >= tick.slot;

        let mut store = Store::new(
            chain_config.clone_arc(),
            store_config,
            anchor_block,
            anchor_state,
            finished_initial_forward_sync,
        );

        store.apply_tick(tick)?;

        let state_cache = store.state_cache();
        let store_snapshot = Arc::new(ArcSwap::from_pointee(store));
        let thread_pool = ThreadPool::new()?;
        let (mutator_tx, mutator_rx) = std::sync::mpsc::channel();

        let block_processor = Arc::new(BlockProcessor::new(chain_config, state_cache.clone_arc()));

        let mut mutator = Mutator::new(
            store_snapshot.clone_arc(),
            state_cache.clone_arc(),
            block_processor.clone_arc(),
            event_channels,
            execution_engine.clone(),
            storage.clone_arc(),
            thread_pool.clone(),
            metrics.clone(),
            mutator_tx.clone(),
            mutator_rx,
            attestation_verifier_tx.clone(),
            p2p_tx,
            pool_tx,
            subnet_tx,
            sync_tx,
            validator_tx,
        );

        mutator.process_unfinalized_blocks(unfinalized_blocks)?;

        let join_handle = Builder::new().name("store-mutator".to_owned()).spawn(|| {
            // The closure should be unwind safe.
            // The synchronization primitives used by the mutator are unlikely to panic.
            // The instance of `Store` used by the mutator may become inconsistent but cannot be
            // observed because the shared snapshot is only updated with values that are consistent.
            std::panic::catch_unwind(AssertUnwindSafe(move || mutator.run()))
                .map_err(panics::payload_into_error)
                .context(Error::MutatorPanicked)?
                .context(Error::MutatorFailed)
        })?;

        let controller = Arc::new(Self {
            store_snapshot,
            block_processor,
            execution_engine,
            state_cache,
            storage,
            thread_pool,
            wait_group: W::Swappable::default(),
            metrics,
            mutator_tx: mutator_tx.clone(),
            attestation_verifier_tx,
        });

        let mutator_handle = MutatorHandle {
            join_handle: Some(join_handle),
            mutator_tx,
        };

        Ok((controller, mutator_handle))
    }

    pub fn chain_config(&self) -> &Arc<ChainConfig> {
        self.storage().config()
    }

    // This should be called at the start of every tick.
    // More or less frequent calls are allowed but may worsen performance and quality of the head.
    // According to the Fork Choice specification, `on_tick` should be called every second,
    // but doing so would be redundant. The fork choice rule does not need a precise timestamp.
    pub fn on_tick(&self, tick: Tick) {
        // Don't spawn a new task because it would have very little to do.
        // Don't check if the tick is newer because `Store` will have to do it anyway.
        // Assume that sending to an unbounded channel never blocks.
        MutatorMessage::Tick {
            wait_group: self.owned_wait_group(),
            tick,
        }
        .send(&self.mutator_tx)
    }

    pub fn on_gossip_block(&self, block: Arc<SignedBeaconBlock<P>>, gossip_id: GossipId) {
        self.spawn_block_task(block, BlockOrigin::Gossip(gossip_id))
    }

    pub fn on_requested_block(&self, block: Arc<SignedBeaconBlock<P>>, peer_id: Option<PeerId>) {
        self.spawn_block_task(block, BlockOrigin::Requested(peer_id))
    }

    pub fn on_own_block(&self, wait_group: W, block: Arc<SignedBeaconBlock<P>>) {
        self.spawn_block_task_with_wait_group(wait_group, block, BlockOrigin::Own)
    }

    pub fn on_own_blob_sidecar(&self, wait_group: W, blob_sidecar: Arc<BlobSidecar<P>>) {
        self.spawn_blob_sidecar_task_with_wait_group(
            wait_group,
            blob_sidecar,
            true,
            BlobSidecarOrigin::Own,
        )
    }

    pub fn on_api_blob_sidecar(
        &self,
        blob_sidecar: Arc<BlobSidecar<P>>,
        sender: Option<OneshotSender<Result<ValidationOutcome>>>,
    ) {
        self.spawn_blob_sidecar_task(blob_sidecar, true, BlobSidecarOrigin::Api(sender))
    }

    pub fn on_api_block(
        &self,
        block: Arc<SignedBeaconBlock<P>>,
        sender: MultiSender<Result<ValidationOutcome>>,
    ) {
        self.spawn_block_task(block, BlockOrigin::Api(Some(sender)))
    }

    pub fn on_api_block_for_gossip(
        &self,
        block: Arc<SignedBeaconBlock<P>>,
        sender: MultiSender<Result<ValidationOutcome>>,
    ) {
        self.spawn(BlockVerifyForGossipTask {
            store_snapshot: self.owned_store_snapshot(),
            block_processor: self.block_processor.clone_arc(),
            wait_group: self.owned_wait_group(),
            block,
            sender,
        })
    }

    pub fn on_notified_fork_choice_update(&self, payload_status: PayloadStatusV1) {
        MutatorMessage::NotifiedForkChoiceUpdate {
            wait_group: self.owned_wait_group(),
            payload_status,
        }
        .send(&self.mutator_tx);
    }

    pub fn on_notified_new_payload(
        &self,
        execution_block_hash: ExecutionBlockHash,
        payload_status: PayloadStatusV1,
    ) {
        MutatorMessage::NotifiedNewPayload {
            wait_group: self.owned_wait_group(),
            execution_block_hash,
            payload_status,
        }
        .send(&self.mutator_tx);
    }

    pub fn on_api_aggregate_and_proof(
        &self,
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
        sender: OneshotSender<Result<ValidationOutcome>>,
    ) {
        AttestationVerifierMessage::AggregateAndProof {
            wait_group: self.owned_wait_group(),
            aggregate_and_proof,
            origin: AggregateAndProofOrigin::Api(sender),
        }
        .send(&self.attestation_verifier_tx);
    }

    pub fn on_api_singular_attestation(
        &self,
        attestation: Arc<Attestation<P>>,
        subnet_id: SubnetId,
        sender: OneshotSender<Result<ValidationOutcome>>,
    ) {
        AttestationVerifierMessage::Attestation {
            wait_group: self.owned_wait_group(),
            attestation: AttestationItem::unverified(
                attestation,
                AttestationOrigin::Api(subnet_id, sender),
            ),
        }
        .send(&self.attestation_verifier_tx);
    }

    pub fn on_gossip_aggregate_and_proof(
        &self,
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
        gossip_id: GossipId,
    ) {
        AttestationVerifierMessage::AggregateAndProof {
            wait_group: self.owned_wait_group(),
            aggregate_and_proof,
            origin: AggregateAndProofOrigin::Gossip(gossip_id),
        }
        .send(&self.attestation_verifier_tx);
    }

    pub fn on_gossip_singular_attestation(
        &self,
        attestation: Arc<Attestation<P>>,
        subnet_id: SubnetId,
        gossip_id: GossipId,
    ) {
        AttestationVerifierMessage::Attestation {
            wait_group: self.owned_wait_group(),
            attestation: AttestationItem::unverified(
                attestation,
                AttestationOrigin::Gossip(subnet_id, gossip_id),
            ),
        }
        .send(&self.attestation_verifier_tx);
    }

    pub fn on_aggregate_and_proof(
        &self,
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
        origin: AggregateAndProofOrigin<GossipId>,
    ) {
        self.spawn(AggregateAndProofTask {
            store_snapshot: self.owned_store_snapshot(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: self.owned_wait_group(),
            aggregate_and_proof,
            origin,
            metrics: self.metrics.clone(),
        })
    }

    pub fn on_singular_attestation(&self, attestation: AttestationItem<P, GossipId>) {
        self.spawn(AttestationTask {
            store_snapshot: self.owned_store_snapshot(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: self.owned_wait_group(),
            attestation,
            metrics: self.metrics.clone(),
        })
    }

    pub fn on_aggregate_and_proof_batch(&self, results: Vec<VerifyAggregateAndProofResult<P>>) {
        if results.is_empty() {
            return;
        }

        MutatorMessage::AggregateAndProofBatch {
            wait_group: self.owned_wait_group(),
            results,
        }
        .send(&self.mutator_tx)
    }

    pub fn on_attestation_batch(&self, results: Vec<VerifyAttestationResult<P>>) {
        if results.is_empty() {
            return;
        }

        MutatorMessage::AttestationBatch {
            wait_group: self.owned_wait_group(),
            results,
        }
        .send(&self.mutator_tx)
    }

    pub fn on_gossip_attester_slashing(&self, attester_slashing: Box<AttesterSlashing<P>>) {
        self.spawn(AttesterSlashingTask {
            store_snapshot: self.owned_store_snapshot(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: self.owned_wait_group(),
            attester_slashing,
            origin: AttesterSlashingOrigin::Gossip,
            metrics: self.metrics.clone(),
        })
    }

    pub fn on_own_attester_slashing(&self, attester_slashing: Box<AttesterSlashing<P>>) {
        self.spawn(AttesterSlashingTask {
            store_snapshot: self.owned_store_snapshot(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: self.owned_wait_group(),
            attester_slashing,
            origin: AttesterSlashingOrigin::Own,
            metrics: self.metrics.clone(),
        })
    }

    pub fn on_gossip_blob_sidecar(
        &self,
        blob_sidecar: Arc<BlobSidecar<P>>,
        subnet_id: SubnetId,
        gossip_id: GossipId,
        block_seen: bool,
    ) {
        self.spawn_blob_sidecar_task(
            blob_sidecar,
            block_seen,
            BlobSidecarOrigin::Gossip(subnet_id, gossip_id),
        )
    }

    pub fn on_requested_blob_sidecar(
        &self,
        blob_sidecar: Arc<BlobSidecar<P>>,
        block_seen: bool,
        peer_id: PeerId,
    ) {
        self.spawn(BlobSidecarTask {
            store_snapshot: self.owned_store_snapshot(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: self.owned_wait_group(),
            blob_sidecar,
            block_seen,
            origin: BlobSidecarOrigin::Requested(peer_id),
            submission_time: Instant::now(),
            metrics: self.metrics.clone(),
        })
    }

    pub fn store_back_sync_blocks(
        &self,
        blocks: impl IntoIterator<Item = Arc<SignedBeaconBlock<P>>>,
    ) -> Result<()> {
        self.storage.store_back_sync_blocks(blocks)
    }

    pub fn archive_back_sync_states(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
    ) -> Result<()> {
        self.storage
            .archive_back_sync_states(start_slot, end_slot, anchor_checkpoint_provider)
    }

    fn spawn_blob_sidecar_task(
        &self,
        blob_sidecar: Arc<BlobSidecar<P>>,
        block_seen: bool,
        origin: BlobSidecarOrigin,
    ) {
        self.spawn_blob_sidecar_task_with_wait_group(
            self.owned_wait_group(),
            blob_sidecar,
            block_seen,
            origin,
        )
    }

    fn spawn_blob_sidecar_task_with_wait_group(
        &self,
        wait_group: W,
        blob_sidecar: Arc<BlobSidecar<P>>,
        block_seen: bool,
        origin: BlobSidecarOrigin,
    ) {
        self.spawn(BlobSidecarTask {
            store_snapshot: self.owned_store_snapshot(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            blob_sidecar,
            block_seen,
            origin,
            submission_time: Instant::now(),
            metrics: self.metrics.clone(),
        })
    }

    fn spawn_block_task(&self, block: Arc<SignedBeaconBlock<P>>, origin: BlockOrigin) {
        self.spawn_block_task_with_wait_group(self.owned_wait_group(), block, origin)
    }

    fn spawn_block_task_with_wait_group(
        &self,
        wait_group: W,
        block: Arc<SignedBeaconBlock<P>>,
        origin: BlockOrigin,
    ) {
        self.spawn(BlockTask {
            store_snapshot: self.owned_store_snapshot(),
            block_processor: self.block_processor.clone_arc(),
            execution_engine: self.execution_engine.clone(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            block,
            origin,
            submission_time: Instant::now(),
            metrics: self.metrics.clone(),
        })
    }

    pub(crate) fn spawn(&self, task: impl Spawn<P, E, W>) {
        self.thread_pool.spawn(task);
    }

    pub const fn block_processor(&self) -> &Arc<BlockProcessor<P>> {
        &self.block_processor
    }

    pub(crate) const fn state_cache(&self) -> &Arc<StateCacheProcessor<P>> {
        &self.state_cache
    }

    pub fn store_config(&self) -> StoreConfig {
        self.store_snapshot().store_config()
    }

    pub(crate) fn store_snapshot(&self) -> Guard<Arc<Store<P>>> {
        self.store_snapshot.load()
    }

    pub(crate) fn owned_store_snapshot(&self) -> Arc<Store<P>> {
        self.store_snapshot.load_full()
    }

    pub(crate) fn storage(&self) -> &Storage<P> {
        &self.storage
    }

    pub(crate) const fn wait_group(&self) -> &W::Swappable {
        &self.wait_group
    }

    pub(crate) fn owned_wait_group(&self) -> W {
        Wait::load_and_clone(&self.wait_group)
    }

    pub(crate) fn owned_mutator_tx(&self) -> Sender<MutatorMessage<P, W>> {
        self.mutator_tx.clone()
    }
}

/// A wrapper over [`JoinHandle`] that can be used to wait for the mutator thread to finish.
///
/// We previously used [`std::process::exit`] to terminate the process when the mutator thread
/// failed. This makes tests and benchmarks less verbose but seems to lose buffered log messages.
///
/// In normal operation the mutator thread should be joined explicitly using
/// [`MutatorHandle::join`]. Tests and benchmarks may drop [`MutatorHandle`],
/// at which point the mutator thread will be joined implicitly.
pub struct MutatorHandle<P: Preset, W> {
    join_handle: Option<JoinHandle<Result<()>>>,
    mutator_tx: Sender<MutatorMessage<P, W>>,
}

impl<P: Preset, W> Drop for MutatorHandle<P, W> {
    fn drop(&mut self) {
        // Stop the mutator thread to avoid a deadlock if the corresponding `Controller` hasn't been
        // dropped yet. This only matters in tests and benchmarks. In normal operation `Controller`
        // and `MutatorHandle` are owned by different tasks, so their drop order is independent.
        self.stop();

        let result = self.join_internal();

        if !std::thread::panicking() {
            result.expect("mutator thread should succeed when joined implicitly")
        }
    }
}

impl<P: Preset, W> MutatorHandle<P, W> {
    pub fn join(mut self) -> Result<()> {
        self.join_internal()
    }

    fn stop(&self) {
        let save_to_storage = !std::thread::panicking();
        MutatorMessage::Stop { save_to_storage }.send(&self.mutator_tx);
    }

    fn join_internal(&mut self) -> Result<()> {
        // Don't use `Option::expect` here.
        // `MutatorHandle::join_internal` is called twice in normal operation.
        match self.join_handle.take() {
            Some(join_handle) => join_handle
                .join()
                .expect("mutator thread handles panics internally"),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("mutator panicked")]
    MutatorPanicked,
    #[error("mutator failed")]
    MutatorFailed,
}
