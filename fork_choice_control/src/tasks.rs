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
    AggregateAndProofOrigin, AttestationOrigin, AttesterSlashingOrigin, BlobSidecarOrigin,
    BlockOrigin, DataColumnSidecarOrigin, Store,
};
use helper_functions::{
    accessors, misc,
    verifier::{MultiVerifier, NullVerifier, VerifierOption},
};
use log::warn;
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use types::{
    combined::SignedBeaconBlock,
    deneb::containers::BlobSidecar,
    eip7594::DataColumnSidecar,
    nonstandard::RelativeEpoch,
    phase0::{
        containers::{Attestation, AttesterSlashing, Checkpoint, SignedAggregateAndProof},
        primitives::{Slot, H256},
    },
    preset::Preset,
    traits::{BeaconState, SignedBeaconBlock as _},
};

use crate::{
    messages::MutatorMessage,
    misc::{VerifyAggregateAndProofResult, VerifyAttestationResult},
    state_cache::StateCache,
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
    pub store_snapshot: Arc<Store<P>>,
    pub execution_engine: E,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub block: Arc<SignedBeaconBlock<P>>,
    pub origin: BlockOrigin,
    pub submission_time: Instant,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, E: ExecutionEngine<P> + Send, W> Run for BlockTask<P, E, W> {
    fn run(self) {
        let Self {
            store_snapshot,
            execution_engine,
            mutator_tx,
            wait_group,
            block,
            origin,
            submission_time,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(&metrics.fc_block_task_times, origin.as_ref())
        });

        let block_arc = block.clone_arc();

        // TODO(Grandine Team): Consider moving the `match` into `Store`.
        let result = match origin {
            BlockOrigin::Gossip(_) | BlockOrigin::Requested(_) | BlockOrigin::Api(_) => {
                store_snapshot.validate_block(
                    block,
                    origin.state_root_policy(),
                    execution_engine,
                    MultiVerifier::default(),
                )
            }
            BlockOrigin::SemiVerified => store_snapshot.validate_block(
                block,
                origin.state_root_policy(),
                execution_engine,
                MultiVerifier::new([VerifierOption::SkipBlockBaseSignatures]),
            ),
            BlockOrigin::Own => {
                if Feature::TrustOwnBlockSignatures.is_enabled() {
                    store_snapshot.validate_block(
                        block,
                        origin.state_root_policy(),
                        execution_engine,
                        NullVerifier,
                    )
                } else {
                    store_snapshot.validate_block(
                        block,
                        origin.state_root_policy(),
                        execution_engine,
                        MultiVerifier::default(),
                    )
                }
            }
            BlockOrigin::Persisted => store_snapshot.validate_block(
                block,
                origin.state_root_policy(),
                NullExecutionEngine,
                NullVerifier,
            ),
        };

        let rejected_block_root = result
            .is_err()
            .then(|| block_arc.message().hash_tree_root());

        MutatorMessage::Block {
            wait_group,
            result,
            origin,
            submission_time,
            rejected_block_root,
        }
        .send(&mutator_tx);
    }
}

pub struct AggregateAndProofTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub aggregate_and_proof: Box<SignedAggregateAndProof<P>>,
    pub origin: AggregateAndProofOrigin<GossipId>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for AggregateAndProofTask<P, W> {
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

        let result = store_snapshot.validate_aggregate_and_proof(aggregate_and_proof, &origin);
        let result = VerifyAggregateAndProofResult { result, origin };

        MutatorMessage::AggregateAndProof { wait_group, result }.send(&mutator_tx);
    }
}

pub struct AttestationTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub attestation: Arc<Attestation<P>>,
    pub origin: AttestationOrigin<GossipId>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for AttestationTask<P, W> {
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            attestation,
            origin,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(&metrics.fc_attestation_task_times, origin.as_ref())
        });

        let result = store_snapshot.validate_attestation(attestation, &origin);
        let result = VerifyAttestationResult { result, origin };

        MutatorMessage::Attestation { wait_group, result }.send(&mutator_tx);
    }
}

// TODO(Grandine Team): Merge this with `BlockTask` and benchmark.
pub struct BlockAttestationsTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub block: Arc<SignedBeaconBlock<P>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for BlockAttestationsTask<P, W> {
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
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
            .attestations()
            .iter()
            .map(|attestation| {
                let attestation = Arc::new(attestation.clone());
                let origin = AttestationOrigin::<GossipId>::Block;
                store_snapshot.validate_attestation(attestation, &origin)
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
    pub store_snapshot: Arc<Store<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub attester_slashing: Box<AttesterSlashing<P>>,
    pub origin: AttesterSlashingOrigin,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for AttesterSlashingTask<P, W> {
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

        let result = store_snapshot.validate_attester_slashing(&attester_slashing, origin);

        MutatorMessage::AttesterSlashing {
            wait_group,
            result,
            origin,
        }
        .send(&mutator_tx);
    }
}

pub struct BlobSidecarTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub blob_sidecar: Arc<BlobSidecar<P>>,
    pub block_seen: bool,
    pub origin: BlobSidecarOrigin,
    pub submission_time: Instant,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for BlobSidecarTask<P, W> {
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            blob_sidecar,
            block_seen,
            origin,
            submission_time,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_blob_sidecar_task_times.start_timer());

        let result = store_snapshot.validate_blob_sidecar(
            blob_sidecar,
            block_seen,
            &origin,
            MultiVerifier::default(),
        );

        MutatorMessage::BlobSidecar {
            wait_group,
            result,
            block_seen,
            origin,
            submission_time,
        }
        .send(&mutator_tx);
    }
}

pub struct DataColumnSidecarTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub data_column_sidecar: Arc<DataColumnSidecar<P>>,
    pub origin: DataColumnSidecarOrigin,
    pub submission_time: Instant,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for DataColumnSidecarTask<P, W> {
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            data_column_sidecar,
            origin,
            submission_time,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_data_column_sidecar_task_times.start_timer());

        let result = store_snapshot.validate_data_column_sidecar(
            data_column_sidecar,
            &origin,
            store_snapshot.slot(),
            MultiVerifier::default(),
            &metrics,
        );

        MutatorMessage::DataColumnSidecar {
            wait_group,
            result,
            origin,
            submission_time,
        }
        .send(&mutator_tx);
    }
}

pub struct PersistBlobSidecarsTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P>>,
    pub storage: Arc<Storage<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PersistBlobSidecarsTask<P, W> {
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
                warn!("failed to persist blob sidecars to storage: {error:?}");
            }
        }
    }
}

pub struct PersistDataColumnSidecarsTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P>>,
    pub storage: Arc<Storage<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PersistDataColumnSidecarsTask<P, W> {
    fn run(self) {
        let Self {
            store_snapshot,
            storage,
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
                }
                .send(&mutator_tx);
            }
            Err(error) => {
                warn!("failed to persist data column sidecars to storage: {error:?}");
            }
        }
    }
}

pub struct CheckpointStateTask<P: Preset, W> {
    pub state_cache: Arc<StateCache<P, W>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub checkpoint: Checkpoint,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for CheckpointStateTask<P, W> {
    fn run(self) {
        let Self {
            state_cache,
            mutator_tx,
            wait_group,
            checkpoint,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_checkpoint_state_task_times.start_timer());

        let Checkpoint { epoch, root } = checkpoint;
        let slot = misc::compute_start_slot_at_epoch::<P>(epoch);

        let checkpoint_state = match state_cache.try_state_at_slot(root, slot) {
            Ok(state) => state,
            Err(error) => {
                warn!("failed to compute checkpoint state: {error:?}");
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
    pub state_cache: Arc<StateCache<P, W>>,
    pub head_block_root: H256,
    pub next_slot: Slot,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PreprocessStateTask<P, W> {
    fn run(self) {
        let Self {
            state_cache,
            head_block_root,
            next_slot,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_preprocess_state_task_times.start_timer());

        match state_cache.state_at_slot_quiet(head_block_root, next_slot) {
            Ok(state) => {
                if let Err(error) = initialize_preprocessed_state_cache(&state) {
                    warn!("failed to initialize preprocessed state's cache values: {error:?}");
                }
            }
            Err(error) => {
                warn!("failed to preprocess beacon state for the next slot: {error:?}");
            }
        }
    }
}

fn initialize_preprocessed_state_cache<P: Preset>(state: &impl BeaconState<P>) -> Result<()> {
    accessors::get_or_try_init_beacon_proposer_index(state, false)?;
    accessors::get_or_init_active_validator_indices_shuffled(state, RelativeEpoch::Current, false);
    accessors::get_or_init_active_validator_indices_shuffled(state, RelativeEpoch::Next, false);
    accessors::get_or_init_total_active_balance(state, false);
    accessors::get_or_init_validator_indices(state, false);

    Ok(())
}
