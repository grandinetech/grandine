use core::num::NonZeroUsize;
use std::{
    collections::VecDeque,
    sync::Arc,
    thread::{Builder, available_parallelism},
};

use anyhow::Result;
use parking_lot::Mutex;
use std_ext::ArcExt as _;

type Work = Box<dyn FnOnce() + Send + 'static>;

/// Thread pool for archival work.
///
/// The pool starts with no workers, spawns one per submission until it reaches the cap, and lets
/// workers exit once the queue drains. Queued tasks own a snapshot of the store for as long as
/// they wait, so the queue is bounded too: a submission that arrives with the queue full runs the
/// work on the calling thread instead of enqueueing it. That caps live snapshots at
/// `max_workers + max_queued` and turns a storage backlog into backpressure on the submitter,
/// rather than into a queue that grows with every finalization.
#[derive(Clone)]
pub struct ArchivalPool(Arc<Pool>);

impl Default for ArchivalPool {
    fn default() -> Self {
        let cores = available_parallelism().map_or(1, NonZeroUsize::get);

        Self::with_max_workers((cores / 2).max(1))
    }
}

impl ArchivalPool {
    fn with_max_workers(max_workers: usize) -> Self {
        Self::with_limits(max_workers, max_workers)
    }

    fn with_limits(max_workers: usize, max_queued: usize) -> Self {
        Self(Arc::new(Pool {
            state: Mutex::new(State {
                queue: VecDeque::new(),
                workers: 0,
            }),
            max_workers,
            max_queued,
        }))
    }

    pub fn submit(&self, work: impl FnOnce() + Send + 'static) -> Result<()> {
        self.0.submit(Box::new(work))
    }

    #[cfg(test)]
    fn workers(&self) -> usize {
        self.0.state.lock().workers
    }
}

struct State {
    queue: VecDeque<Work>,
    workers: usize,
}

struct Pool {
    state: Mutex<State>,
    max_workers: usize,
    max_queued: usize,
}

impl Pool {
    /// The worker is spawned before the task is enqueued and the lock is held across both, so a
    /// failed spawn leaves nothing behind and a fresh worker cannot retire before it sees the task
    /// that spawned it.
    fn submit(self: &Arc<Self>, work: Work) -> Result<()> {
        let mut state = self.state.lock();

        if state.workers < self.max_workers {
            self.spawn_worker()?;

            state.workers = state.workers.saturating_add(1);
        }

        if state.queue.len() >= self.max_queued {
            drop(state);

            work();

            return Ok(());
        }

        state.queue.push_back(work);

        Ok(())
    }

    /// Spawns a worker without touching [`State::workers`]. Callers hold the state lock and
    /// account for the slot themselves.
    fn spawn_worker(self: &Arc<Self>) -> Result<()> {
        let pool = self.clone_arc();

        Builder::new()
            .name("archiver".to_owned())
            .spawn(move || Worker::new(pool).run())?;

        Ok(())
    }
}

/// A live worker, counted in [`State::workers`] until it is dropped.
///
/// Retiring happens under the same lock that observes the empty queue, so a task pushed by a
/// submitter that saw this worker still alive is always picked up before the worker exits. The
/// `Drop` impl covers the remaining case: a task that panics unwinds out of [`Worker::run`],
/// abandoning both the slot and whatever is still queued behind it.
struct Worker {
    pool: Arc<Pool>,
    retired: bool,
}

impl Drop for Worker {
    fn drop(&mut self) {
        if self.retired {
            return;
        }

        let mut state = self.pool.state.lock();

        // Nothing else will drain the queue: submitters only spawn while below the cap, and this
        // slot is still counted. Hand it to a replacement instead of releasing it, or the queued
        // tasks - each holding a store snapshot alive - wait for the next submission.
        if !state.queue.is_empty() && self.pool.spawn_worker().is_ok() {
            return;
        }

        state.workers = state.workers.saturating_sub(1);
    }
}

impl Worker {
    const fn new(pool: Arc<Pool>) -> Self {
        Self {
            pool,
            retired: false,
        }
    }

    fn run(mut self) {
        while let Some(work) = self.take_work() {
            work();
        }
    }

    fn take_work(&mut self) -> Option<Work> {
        let mut state = self.pool.state.lock();

        let work = state.queue.pop_front();

        if work.is_none() {
            state.workers = state.workers.saturating_sub(1);
            self.retired = true;
        }

        work
    }
}

#[cfg(test)]
mod tests {
    use core::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use std::{
        sync::{Barrier, mpsc},
        thread,
        time::Instant,
    };

    use super::*;

    const RETIREMENT_TIMEOUT: Duration = Duration::from_secs(10);

    fn wait_for_retirement(pool: &ArchivalPool) {
        let deadline = Instant::now()
            .checked_add(RETIREMENT_TIMEOUT)
            .expect("the deadline is a few seconds away");

        while pool.workers() > 0 {
            assert!(
                Instant::now() < deadline,
                "workers must retire once the queue drains",
            );

            thread::yield_now();
        }
    }

    #[test]
    fn all_submitted_work_runs_and_the_worker_count_stays_within_the_cap() -> Result<()> {
        const MAX_WORKERS: usize = 3;
        const TASKS: usize = 64;

        let pool = ArchivalPool::with_limits(MAX_WORKERS, TASKS);
        let (sender, receiver) = mpsc::channel();
        let running = Arc::new(AtomicUsize::new(0));

        for task in 0..TASKS {
            let sender = sender.clone();
            let running = running.clone_arc();

            pool.submit(move || {
                let concurrent = running.fetch_add(1, Ordering::SeqCst);

                thread::yield_now();

                running.fetch_sub(1, Ordering::SeqCst);

                sender
                    .send((task, concurrent))
                    .expect("the receiver is still alive");
            })?;
        }

        drop(sender);

        let mut completed = receiver.iter().collect::<Vec<_>>();

        for (task, concurrent) in &completed {
            assert!(
                *concurrent < MAX_WORKERS,
                "task {task} ran with {concurrent} other tasks already running",
            );
        }

        completed.sort_unstable();

        assert_eq!(
            completed
                .into_iter()
                .map(|(task, _)| task)
                .collect::<Vec<_>>(),
            (0..TASKS).collect::<Vec<_>>(),
        );

        Ok(())
    }

    #[test]
    fn the_pool_downscales_after_the_queue_drains() -> Result<()> {
        const MAX_WORKERS: usize = 4;
        const TASKS: usize = 32;

        let pool = ArchivalPool::with_max_workers(MAX_WORKERS);
        let (sender, receiver) = mpsc::channel();

        for _ in 0..TASKS {
            let sender = sender.clone();

            pool.submit(move || sender.send(()).expect("the receiver is still alive"))?;
        }

        drop(sender);

        assert_eq!(receiver.iter().count(), TASKS);

        // The last task sends before its worker looks at the queue again, so workers may still be
        // retiring when `recv` returns.
        wait_for_retirement(&pool);

        // A pool that downscaled to nothing still accepts work.
        let (sender, receiver) = mpsc::channel();

        pool.submit(move || sender.send(()).expect("the receiver is still alive"))?;

        assert_eq!(receiver.recv()?, ());

        Ok(())
    }

    #[test]
    fn work_submitted_from_several_threads_is_not_dropped() {
        const SUBMITTERS: usize = 8;
        const TASKS_PER_SUBMITTER: usize = 32;

        let pool = ArchivalPool::with_max_workers(3);
        let (sender, receiver) = mpsc::channel();
        let barrier = Barrier::new(SUBMITTERS);

        thread::scope(|scope| {
            for submitter in 0..SUBMITTERS {
                let pool = &pool;
                let barrier = &barrier;
                let sender = sender.clone();

                scope.spawn(move || {
                    barrier.wait();

                    for task in 0..TASKS_PER_SUBMITTER {
                        let sender = sender.clone();

                        pool.submit(move || {
                            sender
                                .send((submitter, task))
                                .expect("the receiver is still alive")
                        })
                        .expect("submitting must succeed");
                    }
                });
            }
        });

        drop(sender);

        let mut completed = receiver.iter().collect::<Vec<_>>();

        completed.sort_unstable();

        let expected = (0..SUBMITTERS)
            .flat_map(|submitter| (0..TASKS_PER_SUBMITTER).map(move |task| (submitter, task)))
            .collect::<Vec<_>>();

        assert_eq!(completed, expected);
    }

    #[test]
    fn a_panicking_task_does_not_consume_a_worker_slot() -> Result<()> {
        let pool = ArchivalPool::with_max_workers(1);

        // The panic is expected, so its backtrace would only be noise in the test output.
        let hook = std::panic::take_hook();

        std::panic::set_hook(Box::new(|_| ()));

        for _ in 0..3 {
            pool.submit(|| panic!("archival work panicked"))?;

            wait_for_retirement(&pool);
        }

        std::panic::set_hook(hook);

        // A slot leaked by any of the panics would leave the pool at its cap with no live worker,
        // so this task would never run.
        let (sender, receiver) = mpsc::channel();

        pool.submit(move || sender.send(()).expect("the receiver is still alive"))?;

        assert_eq!(receiver.recv_timeout(RETIREMENT_TIMEOUT)?, ());

        Ok(())
    }

    #[test]
    fn a_panicking_task_does_not_strand_the_work_queued_behind_it() -> Result<()> {
        let pool = ArchivalPool::with_max_workers(1);

        // The panic is expected, so its backtrace would only be noise in the test output.
        let hook = std::panic::take_hook();

        std::panic::set_hook(Box::new(|_| ()));

        let (release_sender, release_receiver) = mpsc::channel();
        let entered = Arc::new(Barrier::new(2));
        let task_entered = entered.clone_arc();

        pool.submit(move || {
            task_entered.wait();

            release_receiver.recv().expect("the sender is still alive");

            panic!("archival work panicked");
        })?;

        // The only worker is now inside the panicking task, so the next task is queued behind it
        // rather than picked up by a worker of its own.
        entered.wait();

        let (sender, receiver) = mpsc::channel();

        pool.submit(move || sender.send(()).expect("the receiver is still alive"))?;

        release_sender.send(())?;

        assert_eq!(receiver.recv_timeout(RETIREMENT_TIMEOUT)?, ());

        std::panic::set_hook(hook);

        Ok(())
    }

    #[test]
    fn a_submission_that_finds_the_queue_full_runs_the_work_itself() -> Result<()> {
        // The cap on workers bounds concurrency, not the snapshots the queue keeps alive. With a
        // queue of one, the third submission has nowhere to wait, so it must run on the submitter
        // rather than growing the backlog.
        let pool = ArchivalPool::with_limits(1, 1);
        let (release_sender, release_receiver) = mpsc::channel::<()>();
        let (started_sender, started_receiver) = mpsc::channel();
        let (sender, receiver) = mpsc::channel();

        // Occupies the only worker until it is released, so nothing drains the queue meanwhile.
        pool.submit(move || {
            started_sender
                .send(())
                .expect("the receiver is still alive");

            release_receiver
                .recv()
                .expect("the sender is dropped only after this task is released");
        })?;

        started_receiver.recv()?;

        let queued = sender.clone();

        // Fills the queue.
        pool.submit(move || queued.send("queued").expect("the receiver is still alive"))?;

        let inline = sender.clone();
        let submitter = thread::current().id();
        let (thread_sender, thread_receiver) = mpsc::channel();

        // Finds the queue full, so it runs here rather than waiting behind the task above.
        pool.submit(move || {
            thread_sender
                .send(thread::current().id())
                .expect("the receiver is still alive");

            inline.send("inline").expect("the receiver is still alive");
        })?;

        assert_eq!(
            thread_receiver.recv()?,
            submitter,
            "a submission made with the queue full runs on the calling thread",
        );

        drop(release_sender);
        drop(sender);

        let mut completed = receiver.iter().collect::<Vec<_>>();

        completed.sort_unstable();

        assert_eq!(completed, ["inline", "queued"]);

        Ok(())
    }

    #[test]
    fn the_default_cap_is_half_the_cores_and_at_least_one() {
        let cores = available_parallelism().map_or(1, NonZeroUsize::get);

        assert_eq!(ArchivalPool::default().0.max_workers, (cores / 2).max(1));
        assert!(ArchivalPool::default().0.max_workers > 0);
    }
}
