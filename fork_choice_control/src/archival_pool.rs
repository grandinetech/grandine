use core::{num::NonZeroUsize, panic::AssertUnwindSafe};
use std::{
    collections::VecDeque,
    sync::Arc,
    thread::{Builder, available_parallelism},
};

use anyhow::Result;
use logging::warn_with_peers;
use parking_lot::Mutex;
use std_ext::ArcExt as _;

type Work = Box<dyn FnOnce() + Send + 'static>;

pub struct ArchivalPool(Arc<Pool>);

impl Default for ArchivalPool {
    fn default() -> Self {
        let cores = available_parallelism().map_or(1, NonZeroUsize::get);

        Self::with_max_workers((cores / 2).max(1))
    }
}

impl ArchivalPool {
    fn with_max_workers(max_workers: usize) -> Self {
        Self(Arc::new(Pool {
            state: Mutex::new(State {
                queue: VecDeque::new(),
                workers: 0,
            }),
            max_workers,
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
}

impl Pool {
    fn submit(self: &Arc<Self>, work: Work) -> Result<()> {
        let mut state = self.state.lock();

        if state.workers < self.max_workers {
            match self.spawn_worker() {
                Ok(()) => state.workers = state.workers.saturating_add(1),
                Err(error) if state.workers == 0 => return Err(error),
                Err(error) => warn_with_peers!("failed to spawn archival worker: {error:?}"),
            }
        }

        state.queue.push_back(work);

        Ok(())
    }

    fn spawn_worker(self: &Arc<Self>) -> Result<()> {
        let pool = self.clone_arc();

        Builder::new()
            .name("archiver".to_owned())
            .spawn(move || pool.run())?;

        Ok(())
    }

    fn run(&self) {
        while let Some(work) = self.take_work() {
            std::panic::catch_unwind(AssertUnwindSafe(work)).unwrap_or_else(panics::log);
        }
    }

    fn take_work(&self) -> Option<Work> {
        let mut state = self.state.lock();

        let work = state.queue.pop_front();

        if work.is_none() {
            state.workers = state.workers.saturating_sub(1);
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

        let pool = ArchivalPool::with_max_workers(MAX_WORKERS);
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

        for _ in 0..3 {
            pool.submit(|| panic!("archival work panicked"))?;

            wait_for_retirement(&pool);
        }

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

        Ok(())
    }

    #[test]
    fn a_submission_made_while_every_worker_is_busy_neither_blocks_nor_runs_on_the_submitter()
    -> Result<()> {
        // The cap on workers bounds concurrency, not the queue. The only submitter is the mutator,
        // so submissions that arrive with every worker busy have to queue: blocking would stall
        // the node behind storage, and running the work here would stall it just as thoroughly.
        let pool = ArchivalPool::with_max_workers(1);
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

        pool.submit(move || queued.send("queued").expect("the receiver is still alive"))?;

        let backlogged = sender.clone();
        let submitter = thread::current().id();
        let (thread_sender, thread_receiver) = mpsc::channel();

        // Returns rather than waiting behind the two tasks above, which are still not runnable.
        pool.submit(move || {
            thread_sender
                .send(thread::current().id())
                .expect("the receiver is still alive");

            backlogged
                .send("backlogged")
                .expect("the receiver is still alive");
        })?;

        drop(release_sender);
        drop(sender);

        assert_ne!(
            thread_receiver.recv()?,
            submitter,
            "no submission runs on the calling thread",
        );

        let mut completed = receiver.iter().collect::<Vec<_>>();

        completed.sort_unstable();

        assert_eq!(completed, ["backlogged", "queued"]);

        Ok(())
    }

    #[test]
    fn the_default_cap_is_half_the_cores_and_at_least_one() {
        let cores = available_parallelism().map_or(1, NonZeroUsize::get);

        assert_eq!(ArchivalPool::default().0.max_workers, (cores / 2).max(1));
        assert!(ArchivalPool::default().0.max_workers > 0);
    }
}
