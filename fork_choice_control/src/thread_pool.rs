// We use a custom thread pool for several reasons:
// - Prioritizing certain tasks improves performance.
//   Rayon has limited support for priorities in the form of `spawn` and `spawn_fifo`.
// - Rayon is prone to stack overflows due to the way it runs tasks.
// - It should make it easier to implement batched signature verification in the fork choice store.
//
// Low priority tasks will starve if there are enough high priority tasks to occupy all workers.
// This could be prevented in several ways:
// - Dedicate some threads to low priority tasks.
// - Randomly skip high priority tasks depending on task counts.
// - Represent priorities with numbers and add some randomness to them.
// - Store task submission times and give very old tasks a higher priority.

use std::{collections::VecDeque, sync::Arc, thread::Builder, time::Instant};

use anyhow::Result;
use derivative::Derivative;
use derive_more::From;
use execution_engine::ExecutionEngine;
use log::debug;
use parking_lot::{Condvar, Mutex};
use ssz::SszHash as _;
use std_ext::ArcExt as _;
use types::{preset::Preset, traits::SignedBeaconBlock as _};

use crate::{
    tasks::{
        AggregateAndProofTask, AttestationTask, AttesterSlashingTask, BlobSidecarTask,
        BlockAttestationsTask, BlockTask, BlockVerifyForGossipTask, CheckpointStateTask,
        PersistBlobSidecarsTask, PreprocessStateTask, Run,
    },
    wait::Wait,
};

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ThreadPool<P: Preset, E, W> {
    shared: Arc<Shared<P, E, W>>,
}

impl<P: Preset, E, W> Drop for ThreadPool<P, E, W> {
    fn drop(&mut self) {
        self.shared.critical.lock().done = true;
        self.shared.condvar.notify_all();
    }
}

impl<P: Preset, E, W> ThreadPool<P, E, W> {
    pub fn new() -> Result<Self>
    where
        E: ExecutionEngine<P> + Send + 'static,
        W: Wait,
    {
        let shared = Arc::new(Shared::default());

        for index in 0..num_cpus::get() {
            let shared = shared.clone_arc();

            Builder::new()
                .name(format!("store-worker-{index}"))
                .spawn(move || run_worker(&shared))?;
        }

        Ok(Self { shared })
    }

    pub fn spawn(&self, task: impl Spawn<P, E, W>) {
        task.spawn(&mut self.shared.critical.lock());
        self.shared.condvar.notify_one();
    }

    pub fn task_counts(&self) -> (usize, usize) {
        let critical = self.shared.critical.lock();
        let high = critical.high_priority_tasks.len();
        let low = critical.low_priority_tasks.len();
        (high, low)
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
struct Shared<P: Preset, E, W> {
    critical: Mutex<Critical<P, E, W>>,
    condvar: Condvar,
}

// `done` and fields holding tasks must be inside the `Mutex` to avoid race conditions.
// This remains true even with thread-safe collections like `crossbeam_queue::SegQueue`.
#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Critical<P: Preset, E, W> {
    done: bool,
    // `VecDeque` is faster than both `LinkedList` and `crossbeam_queue::SegQueue`. The downside of
    // `VecDeque` is that it never automatically shrinks, so the application may hold on to a large
    // allocation permanently. An unrolled linked list (other than `crossbeam_queue::SegQueue`)
    // might be the best of both worlds.
    high_priority_tasks: VecDeque<HighPriorityTask<P, E, W>>,
    low_priority_tasks: VecDeque<LowPriorityTask<P, W>>,
}

// TODO(feature/deneb): Figure out if `BlobSidecarTask` should be a high priority task.
#[derive(From)]
enum HighPriorityTask<P: Preset, E, W> {
    Block(BlockTask<P, E, W>),
    BlockForGossip(BlockVerifyForGossipTask<P, W>),
    BlobSidecar(BlobSidecarTask<P, W>),
    // `CheckpointStateTask` is a high priority task to prevent attestation tasks from delaying
    // processing of blocks that are waiting for checkpoint states. However, this may result in a
    // `CheckpointStateTask` being prioritized when it's only needed to verify attestations.
    CheckpointState(CheckpointStateTask<P, W>),
    PreprocessState(PreprocessStateTask<P, W>),
}

impl<P: Preset, E: ExecutionEngine<P> + Send, W> Run for HighPriorityTask<P, E, W> {
    fn run(self) {
        match self {
            Self::Block(task) => task.run(),
            Self::BlockForGossip(task) => task.run(),
            Self::BlobSidecar(task) => task.run(),
            Self::CheckpointState(task) => task.run(),
            Self::PreprocessState(task) => task.run(),
        }
    }
}

impl<P: Preset, E, W> HighPriorityTask<P, E, W> {
    pub fn task_name(&self) -> String {
        match self {
            Self::Block(task) => format!(
                "BlockTask (block root: {:?}, slot: {})",
                task.block.hash_tree_root(),
                task.block.message().slot(),
            ),
            Self::BlockForGossip(task) => format!(
                "BlockVerifyForGossipTask (block root: {:?}, slot: {})",
                task.block.hash_tree_root(),
                task.block.message().slot(),
            ),
            Self::BlobSidecar(task) => format!(
                "BlobSidecarTask (block root: {:?}, index: {}, slot: {})",
                task.blob_sidecar
                    .signed_block_header
                    .message
                    .hash_tree_root(),
                task.blob_sidecar.index,
                task.blob_sidecar.signed_block_header.message.slot,
            ),
            Self::CheckpointState(task) => {
                format!("CheckpointStateTask (checkpoint: {:?})", task.checkpoint)
            }
            Self::PreprocessState(task) => format!(
                "PreprocessStateTask (head block root: {:?}, next slot: {})",
                task.head_block_root, task.next_slot
            ),
        }
    }
}

#[derive(From)]
enum LowPriorityTask<P: Preset, W> {
    AggregateAndProof(AggregateAndProofTask<P, W>),
    Attestation(AttestationTask<P, W>),
    BlockAttestations(BlockAttestationsTask<P, W>),
    AttesterSlashing(AttesterSlashingTask<P, W>),
    PersistBlobSidecarsTask(PersistBlobSidecarsTask<P, W>),
}

impl<P: Preset, W> Run for LowPriorityTask<P, W> {
    fn run(self) {
        match self {
            Self::AggregateAndProof(task) => task.run(),
            Self::Attestation(task) => task.run(),
            Self::BlockAttestations(task) => task.run(),
            Self::AttesterSlashing(task) => task.run(),
            Self::PersistBlobSidecarsTask(task) => task.run(),
        }
    }
}

impl<P: Preset, W> LowPriorityTask<P, W> {
    pub fn task_name(&self) -> String {
        match self {
            Self::AggregateAndProof(task) => format!(
                "AggregateAndProofTask (aggregate and proof: {:?}, origin: {:?})",
                task.aggregate_and_proof, task.origin,
            ),
            Self::Attestation(task) => {
                format!("AttestationTask (attestation item: {:?})", task.attestation,)
            }
            Self::BlockAttestations(task) => format!(
                "BlockAttestationsTask (block root: {:?}, slot: {})",
                task.block.hash_tree_root(),
                task.block.message().slot(),
            ),
            Self::AttesterSlashing(task) => format!(
                "AttesterSlashingTask (attester slashing: {:?})",
                task.attester_slashing
            ),
            Self::PersistBlobSidecarsTask(_task) => "PersistBlobSidecarsTask".into(),
        }
    }
}

pub trait Spawn<P: Preset, E, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>);
}

impl<P: Preset, E, W> Spawn<P, E, W> for BlockTask<P, E, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>) {
        critical.high_priority_tasks.push_back(self.into())
    }
}

impl<P: Preset, E, W> Spawn<P, E, W> for BlockVerifyForGossipTask<P, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>) {
        critical.high_priority_tasks.push_back(self.into())
    }
}

impl<P: Preset, E, W> Spawn<P, E, W> for BlobSidecarTask<P, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>) {
        critical.high_priority_tasks.push_back(self.into())
    }
}

impl<P: Preset, E, W> Spawn<P, E, W> for CheckpointStateTask<P, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>) {
        critical.high_priority_tasks.push_back(self.into())
    }
}

impl<P: Preset, E, W> Spawn<P, E, W> for PreprocessStateTask<P, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>) {
        critical.high_priority_tasks.push_back(self.into())
    }
}

impl<P: Preset, E, W> Spawn<P, E, W> for AggregateAndProofTask<P, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>) {
        critical.low_priority_tasks.push_back(self.into())
    }
}

impl<P: Preset, E, W> Spawn<P, E, W> for AttestationTask<P, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>) {
        critical.low_priority_tasks.push_back(self.into())
    }
}

impl<P: Preset, E, W> Spawn<P, E, W> for BlockAttestationsTask<P, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>) {
        critical.low_priority_tasks.push_back(self.into())
    }
}

impl<P: Preset, E, W> Spawn<P, E, W> for AttesterSlashingTask<P, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>) {
        critical.low_priority_tasks.push_back(self.into())
    }
}

impl<P: Preset, E, W> Spawn<P, E, W> for PersistBlobSidecarsTask<P, W> {
    fn spawn(self, critical: &mut Critical<P, E, W>) {
        critical.low_priority_tasks.push_back(self.into())
    }
}

fn run_worker<P: Preset, E: ExecutionEngine<P> + Send, W>(shared: &Shared<P, E, W>) {
    debug!("thread {} starting", thread_name());

    'outer: loop {
        let mut critical = shared.critical.lock();

        loop {
            if critical.done {
                break 'outer;
            }

            if let Some(task) = critical.high_priority_tasks.pop_front() {
                drop(critical);

                let started_at = Instant::now();

                debug!(
                    "thread {} starting high priority task {}",
                    thread_name(),
                    task.task_name(),
                );

                task.run_and_handle_panics();

                debug!(
                    "thread {} finished high priority task in {} ms",
                    thread_name(),
                    started_at.elapsed().as_millis()
                );

                continue 'outer;
            }

            if let Some(task) = critical.low_priority_tasks.pop_front() {
                drop(critical);

                let started_at = Instant::now();

                debug!(
                    "thread {} starting low priority task {}",
                    thread_name(),
                    task.task_name()
                );

                task.run_and_handle_panics();

                debug!(
                    "thread {} finished low priority task in {} ms",
                    thread_name(),
                    started_at.elapsed().as_millis()
                );

                continue 'outer;
            }

            shared.condvar.wait(&mut critical);
        }
    }

    debug!("thread {} stopping", thread_name());
}

// Keeping the `Thread` and its name around as locals in `run_worker` seems to add a small amount of
// overhead. This function lets us keep the logging without penalizing the case when it's disabled.
fn thread_name() -> String {
    std::thread::current()
        .name()
        .expect("ThreadPool::new gives every worker thread a name")
        .to_owned()
}
