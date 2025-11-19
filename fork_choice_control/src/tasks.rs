use core::panic::AssertUnwindSafe;
use std::{
    sync::{mpsc::Sender, Arc},
    time::Instant,
};

use anyhow::Result;
use eth2_libp2p::GossipId;
use execution_engine::{ExecutionEngine, NullExecutionEngine};
use features::Feature;
use fork_choice_store::{
    AggregateAndProofOrigin, AttestationItem, AttestationOrigin, AttesterSlashingOrigin,
    BlobSidecarOrigin, BlockAction, BlockOrigin, DataColumnSidecarAction, DataColumnSidecarOrigin,
    StateCacheProcessor, Store,
};
use futures::channel::mpsc::Sender as MultiSender;
use helper_functions::{
    accessors, misc,
    verifier::{MultiVerifier, NullVerifier},
};
use logging::{debug_with_peers, warn_with_peers};
use prometheus_metrics::Metrics;
use pubkey_cache::PubkeyCache;
use ssz::SszHash as _;
use tracing::{instrument, Span};
use types::{
    combined::{
        AttesterSlashing, BeaconState as CombinedBeaconState, SignedAggregateAndProof,
        SignedBeaconBlock,
    },
    config::Config,
    deneb::containers::{BlobIdentifier, BlobSidecar},
    fulu::containers::{DataColumnIdentifier, DataColumnSidecar},
    nonstandard::{RelativeEpoch, ValidationOutcome},
    phase0::{
        containers::Checkpoint,
        primitives::{Slot, H256},
    },
    preset::Preset,
    traits::{BeaconState, SignedBeaconBlock as _},
};

use crate::{
    block_processor::BlockProcessor,
    messages::MutatorMessage,
    misc::{ProcessingTimings, VerifyAggregateAndProofResult},
    state_at_slot_cache::StateAtSlotCache,
    storage::Storage,
};

pub trait Run {
    fn run(self);

    fn run_and_handle_panics(self)
    where
        Self: Sized,
    {
        // All tasks should be unwind safe.
        // Running a task consumes it, making it impossible to observe any invalid state.
        std::panic::catch_unwind(AssertUnwindSafe(|| self.run())).unwrap_or_else(panics::log)
    }
}

// TODO(Grandine Team): Now that the time measuring logic has become permanent, consider refactoring
//                      the tasks to contain `*Pending` structs instead of duplicating their fields.

pub struct BlockTask<P: Preset, E, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub block_processor: Arc<BlockProcessor<P>>,
    pub execution_engine: E,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub block: Arc<SignedBeaconBlock<P>>,
    pub origin: BlockOrigin,
    pub processing_timings: ProcessingTimings,
    pub metrics: Option<Arc<Metrics>>,
    pub tracing_span: Span,
}

impl<P: Preset, E: ExecutionEngine<P> + Send, W> Run for BlockTask<P, E, W> {
    #[instrument(
        skip_all,
        name = "BlockTask::run",
        parent = &self.tracing_span,
        fields(
            origin = ?&self.origin,
            slot = self.block.message().slot()
        ),
    )]
    fn run(self) {
        let Self {
            store_snapshot,
            block_processor,
            execution_engine,
            mutator_tx,
            wait_group,
            block,
            origin,
            processing_timings,
            metrics,
            tracing_span,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(&metrics.fc_block_task_times, origin.as_ref())
        });

        // TODO(Grandine Team): Consider moving the `match` into `Store`.
        let result = match origin {
            BlockOrigin::Gossip(_) | BlockOrigin::Requested(_) | BlockOrigin::Api(_) => {
                block_processor.validate_block(
                    &store_snapshot,
                    &block,
                    origin.state_root_policy(),
                    origin.data_availability_policy(),
                    execution_engine,
                    MultiVerifier::default(),
                )
            }
            BlockOrigin::Own => {
                if Feature::TrustOwnBlockSignatures.is_enabled() {
                    block_processor.validate_block(
                        &store_snapshot,
                        &block,
                        origin.state_root_policy(),
                        origin.data_availability_policy(),
                        execution_engine,
                        NullVerifier,
                    )
                } else {
                    block_processor.validate_block(
                        &store_snapshot,
                        &block,
                        origin.state_root_policy(),
                        origin.data_availability_policy(),
                        execution_engine,
                        MultiVerifier::default(),
                    )
                }
            }
            BlockOrigin::Persisted => block_processor.validate_block(
                &store_snapshot,
                &block,
                origin.state_root_policy(),
                origin.data_availability_policy(),
                NullExecutionEngine,
                NullVerifier,
            ),
        };

        // TODO: reduce number of block root computations across the app
        let block_root = block.message().hash_tree_root();

        MutatorMessage::Block {
            wait_group,
            result: result.into(),
            origin,
            processing_timings,
            block_root,
            tracing_span,
        }
        .send(&mutator_tx);
    }
}

pub struct BlockVerifyForGossipTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub block_processor: Arc<BlockProcessor<P>>,
    pub wait_group: W,
    pub block: Arc<SignedBeaconBlock<P>>,
    pub sender: MultiSender<Result<ValidationOutcome>>,
}

impl<P: Preset, W> Run for BlockVerifyForGossipTask<P, W> {
    #[instrument(
        skip_all,
        name = "BlockVerifyForGossipTask::run",
        level = "debug",
        fields(
            slot = self.block.message().slot()
        ),
    )]
    fn run(self) {
        let Self {
            store_snapshot,
            block_processor,
            wait_group,
            block,
            mut sender,
        } = self;

        let validation_outcome = block_processor
            .validate_block_for_gossip(&store_snapshot, &block)
            .map(|block_action| match block_action {
                Some(BlockAction::Accept(_, _)) | None => ValidationOutcome::Accept,
                Some(BlockAction::Ignore(publishable)) => ValidationOutcome::Ignore(publishable),
                Some(_) => ValidationOutcome::Ignore(false),
            });

        if let Err(reply) = sender.try_send(validation_outcome) {
            debug_with_peers!(
                "reply to HTTP API failed because the receiver was dropped: {reply:?}"
            );
        }

        drop(wait_group);
    }
}

pub struct AggregateAndProofTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
    pub origin: AggregateAndProofOrigin<GossipId>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for AggregateAndProofTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "AggregateAndProofTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            aggregate_and_proof,
            origin,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(
                &metrics.fc_aggregate_and_proof_task_times,
                origin.as_ref(),
            )
        });

        let result =
            store_snapshot.validate_aggregate_and_proof(aggregate_and_proof, &origin, false);

        let result = VerifyAggregateAndProofResult { result, origin };

        MutatorMessage::AggregateAndProof { wait_group, result }.send(&mutator_tx);
    }
}

pub struct AttestationTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub attestation: AttestationItem<P, GossipId>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for AttestationTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "AttestationTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            attestation,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(
                &metrics.fc_attestation_task_times,
                attestation.origin.as_ref(),
            )
        });

        let result = store_snapshot.validate_attestation(attestation, false);

        MutatorMessage::Attestation { wait_group, result }.send(&mutator_tx);
    }
}

// TODO(Grandine Team): Merge this with `BlockTask` and benchmark.
pub struct BlockAttestationsTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub block_root: H256,
    pub block: Arc<SignedBeaconBlock<P>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for BlockAttestationsTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "BlockAttestationTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            block_root,
            block,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_block_attestation_task_times.start_timer());

        // TODO(Grandine Team): Consider turning the pipeline into a new method in `Store`.
        let results = block
            .message()
            .body()
            .combined_attestations()
            .map(|attestation| {
                store_snapshot.validate_attestation(
                    AttestationItem::verified(
                        Arc::new(attestation),
                        AttestationOrigin::Block(block_root),
                    ),
                    true,
                )
            })
            .collect();

        MutatorMessage::BlockAttestations {
            wait_group,
            results,
        }
        .send(&mutator_tx);
    }
}

pub struct AttesterSlashingTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub attester_slashing: Box<AttesterSlashing<P>>,
    pub origin: AttesterSlashingOrigin,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for AttesterSlashingTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "AttesterSlashingTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            attester_slashing,
            origin,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_attester_slashing_task_times.start_timer());

        let result = store_snapshot.validate_attester_slashing(&*attester_slashing, origin);

        MutatorMessage::AttesterSlashing {
            wait_group,
            result,
            origin,
        }
        .send(&mutator_tx);
    }
}

pub struct BlobSidecarTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub blob_sidecar: Arc<BlobSidecar<P>>,
    pub state: Option<Arc<CombinedBeaconState<P>>>,
    pub block_seen: bool,
    pub origin: BlobSidecarOrigin,
    pub submission_time: Instant,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for BlobSidecarTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "BlobSidecarTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            blob_sidecar,
            state,
            block_seen,
            origin,
            submission_time,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_blob_sidecar_task_times.start_timer());

        let block_root = blob_sidecar.signed_block_header.message.hash_tree_root();
        let index = blob_sidecar.index;
        let blob_identifier = BlobIdentifier { block_root, index };

        let result = store_snapshot.validate_blob_sidecar(blob_sidecar, state, block_seen, &origin);

        MutatorMessage::BlobSidecar {
            wait_group,
            result,
            origin,
            blob_identifier,
            block_seen,
            submission_time,
        }
        .send(&mutator_tx);
    }
}

pub struct DataColumnSidecarTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub data_column_sidecar: Arc<DataColumnSidecar<P>>,
    pub state: Option<Arc<CombinedBeaconState<P>>>,
    pub block_seen: bool,
    pub origin: DataColumnSidecarOrigin,
    pub submission_time: Instant,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for DataColumnSidecarTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "DataColumnSidecarTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            data_column_sidecar,
            state,
            block_seen,
            origin,
            submission_time,
            metrics,
        } = self;

        let block_root = data_column_sidecar
            .signed_block_header
            .message
            .hash_tree_root();

        let _data_column_sidecar_verification_timer = metrics
            .as_ref()
            .map(|metrics| metrics.data_column_sidecar_verification_times.start_timer());

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_data_column_sidecar_task_times.start_timer());

        let index = data_column_sidecar.index;
        let data_column_identifier = DataColumnIdentifier { block_root, index };

        let result = store_snapshot.validate_data_column_sidecar(
            data_column_sidecar,
            state,
            block_seen,
            &origin,
            metrics.as_ref(),
        );

        if result.is_err() {
            if let Some(metrics) = metrics.as_ref() {
                metrics.data_column_sidecars_submitted_for_processing.inc();
            }
        }

        if let Ok(DataColumnSidecarAction::Accept(_)) = result {
            if let Some(metrics) = metrics.as_ref() {
                metrics.data_column_sidecars_submitted_for_processing.inc();
                metrics.verified_gossip_data_column_sidecar.inc();
            }
        }

        MutatorMessage::DataColumnSidecar {
            wait_group,
            result,
            origin,
            data_column_identifier,
            block_seen,
            submission_time,
        }
        .send(&mutator_tx);
    }
}

pub struct RetryDataColumnSidecarTask<P: Preset, W> {
    pub task: DataColumnSidecarTask<P, W>,
}

impl<P: Preset, W> Run for RetryDataColumnSidecarTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "RetryDataColumnSidecarTask::run")]
    fn run(self) {
        self.task.run()
    }
}

pub struct PersistBlobSidecarsTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub storage: Arc<Storage<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PersistBlobSidecarsTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PersistBlobSidecarTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            storage,
            mutator_tx,
            wait_group,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_blob_sidecar_persist_task_times.start_timer());

        let blob_sidecars = store_snapshot.unpersisted_blob_sidecars();

        match storage.append_blob_sidecars(blob_sidecars) {
            Ok(persisted_blob_ids) => {
                MutatorMessage::FinishedPersistingBlobSidecars {
                    wait_group,
                    persisted_blob_ids,
                }
                .send(&mutator_tx);
            }
            Err(error) => {
                warn_with_peers!("failed to persist blob sidecars to storage: {error:?}");
            }
        }
    }
}

pub struct PersistDataColumnSidecarsTask<P: Preset, W> {
    pub slot: Slot,
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub storage: Arc<Storage<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PersistDataColumnSidecarsTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PersistDataColumnSidecarTask::run")]
    fn run(self) {
        let Self {
            slot,
            storage,
            store_snapshot,
            mutator_tx,
            wait_group,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            metrics
                .fc_data_column_sidecar_persist_task_times
                .start_timer()
        });

        let data_column_sidecars = store_snapshot.unpersisted_data_column_sidecars();

        match storage.append_data_column_sidecars(data_column_sidecars) {
            Ok(persisted_data_column_ids) => {
                MutatorMessage::FinishedPersistingDataColumnSidecars {
                    wait_group,
                    persisted_data_column_ids,
                    slot,
                }
                .send(&mutator_tx);
            }
            Err(error) => {
                warn_with_peers!("failed to persist data column sidecars to storage: {error:?}");
            }
        }
    }
}

pub struct CheckpointStateTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub state_cache: Arc<StateCacheProcessor<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub checkpoint: Checkpoint,
    pub pubkey_cache: Arc<PubkeyCache>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for CheckpointStateTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "CheckpointStateTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            state_cache,
            mutator_tx,
            wait_group,
            checkpoint,
            pubkey_cache,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_checkpoint_state_task_times.start_timer());

        let Checkpoint { epoch, root } = checkpoint;
        let slot = misc::compute_start_slot_at_epoch::<P>(epoch);

        let checkpoint_state = match state_cache.try_state_at_slot(
            &pubkey_cache,
            &store_snapshot,
            root,
            slot,
            store_snapshot.is_forward_synced(),
        ) {
            Ok(state) => state,
            Err(error) => {
                warn_with_peers!("failed to compute checkpoint state: {error:?}");
                return;
            }
        };

        MutatorMessage::CheckpointState {
            wait_group,
            checkpoint,
            checkpoint_state,
        }
        .send(&mutator_tx);
    }
}

pub struct PreprocessStateTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub state_cache: Arc<StateCacheProcessor<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub head_block_root: H256,
    pub next_slot: Slot,
    pub pubkey_cache: Arc<PubkeyCache>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PreprocessStateTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PreprocessStateTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            state_cache,
            mutator_tx,
            head_block_root,
            next_slot,
            pubkey_cache,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_preprocess_state_task_times.start_timer());

        match state_cache.state_at_slot_quiet(
            &pubkey_cache,
            &store_snapshot,
            head_block_root,
            next_slot,
        ) {
            Ok(state) => {
                if let Err(error) =
                    initialize_preprocessed_state_cache(store_snapshot.chain_config(), &state)
                {
                    warn_with_peers!(
                        "failed to initialize preprocessed state's cache values: {error:?}"
                    );
                }

                MutatorMessage::PreprocessedBeaconState { state }.send(&mutator_tx);
            }
            Err(error) => {
                warn_with_peers!("failed to preprocess beacon state for the next slot: {error:?}");
            }
        }
    }
}

pub struct PersistPubkeyCacheTask<P: Preset, W> {
    pub pubkey_cache: Arc<PubkeyCache>,
    pub state: Arc<CombinedBeaconState<P>>,
    pub wait_group: W,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PersistPubkeyCacheTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PersistPubkeyCacheTask::run")]
    fn run(self) {
        let Self {
            pubkey_cache,
            state,
            wait_group,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_persist_pubkey_cache_task_times.start_timer());

        if let Err(error) = pubkey_cache.persist(&state) {
            warn_with_peers!("failed to persist pubkey cache to disk: {error:?}");
        }

        drop(wait_group);
    }
}

fn initialize_preprocessed_state_cache<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
) -> Result<()> {
    accessors::get_or_try_init_beacon_proposer_index(config, state, false)?;
    accessors::get_or_init_active_validator_indices_shuffled(state, RelativeEpoch::Current, false);
    accessors::get_or_init_active_validator_indices_shuffled(state, RelativeEpoch::Next, false);
    accessors::get_or_init_total_active_balance(state, false);
    accessors::get_or_init_validator_indices(state, false);

    Ok(())
}

pub struct StateAtSlotCacheFlushTask<P: Preset> {
    pub state_at_slot_cache: Arc<StateAtSlotCache<P>>,
}

impl<P: Preset> Run for StateAtSlotCacheFlushTask<P> {
    #[instrument(skip_all, level = "debug", name = "StateAtSlotCacheFlushTask::run")]
    fn run(self) {
        let Self {
            state_at_slot_cache,
        } = self;

        if let Err(error) = state_at_slot_cache.flush() {
            warn_with_peers!("failed to flush state at slot cache: {error:?}");
        }
    }
}
