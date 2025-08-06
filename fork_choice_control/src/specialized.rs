use core::ops::DerefMut as _;
use std::sync::Arc;

use clock::Tick;
use crossbeam_utils::sync::WaitGroup;
use dashmap::DashMap;
use database::Database;
use execution_engine::{ExecutionEngine, NullExecutionEngine};
use fork_choice_store::StoreConfig;
use futures::sink::Drain;
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use tap::Pipe as _;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config as ChainConfig,
    phase0::primitives::Slot,
    preset::Preset,
};

use crate::{
    controller::{Controller, MutatorHandle},
    events::EventChannels,
    messages::{AttestationVerifierMessage, P2pMessage},
    storage::{Storage, DEFAULT_ARCHIVAL_EPOCH_INTERVAL},
    unbounded_sink::UnboundedSink,
    StorageMode,
};

#[cfg(test)]
use std::sync::Mutex;

#[cfg(test)]
use ::{
    execution_engine::MockExecutionEngine,
    fork_choice_store::{AttestationItem, AttestationOrigin},
    types::combined::Attestation,
};

#[cfg(test)]
use crate::tasks::AttestationTask;

pub type AttestationVerifierDrain<P> = Drain<AttestationVerifierMessage<P, WaitGroup>>;

pub type AdHocBenchController<P> =
    Controller<P, NullExecutionEngine, AttestationVerifierDrain<P>, WaitGroup>;

pub type BenchController<P> =
    Controller<P, NullExecutionEngine, AttestationVerifierDrain<P>, WaitGroup>;

#[cfg(test)]
pub type TestController<P> =
    Controller<P, TestExecutionEngine<P>, AttestationVerifierDrain<P>, WaitGroup>;

#[cfg(test)]
pub type TestExecutionEngine<P> = Arc<Mutex<MockExecutionEngine<P>>>;

impl<P, E, A> Controller<P, E, A, WaitGroup>
where
    P: Preset,
    E: ExecutionEngine<P> + Clone + Send + Sync + 'static,
    A: UnboundedSink<AttestationVerifierMessage<P, WaitGroup>>,
{
    pub fn on_slot(&self, slot: Slot) {
        self.on_tick(Tick::start_of_slot(slot));
    }

    /// Waits until currently spawned tasks are completed.
    ///
    /// If the mutator spawns new tasks while handling messages from old ones,
    /// this waits until the new tasks are completed too.
    ///
    /// This is intended for use in tests and benchmarks.
    /// [`WaitGroup`] is not used in normal operation because it adds some overhead.
    pub fn wait_for_tasks(&self) {
        let wait_group = self
            .wait_group()
            .lock()
            .expect("Store.wait_group mutex is poisoned")
            .deref_mut()
            .pipe(core::mem::take);

        wait_group.wait()
    }
}

impl<P, E> Controller<P, E, AttestationVerifierDrain<P>, WaitGroup>
where
    P: Preset,
    E: ExecutionEngine<P> + Clone + Send + Sync + 'static,
{
    #[expect(clippy::too_many_arguments)]
    fn new_internal(
        chain_config: Arc<ChainConfig>,
        store_config: StoreConfig,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
        database: Database,
        execution_engine: E,
        metrics: Option<Arc<Metrics>>,
        p2p_tx: impl UnboundedSink<P2pMessage<P>>,
    ) -> (Arc<Self>, MutatorHandle<P, WaitGroup>) {
        let tick = Tick::block_proposal(&anchor_block);

        let storage = Arc::new(Storage::new(
            chain_config.clone_arc(),
            database,
            DEFAULT_ARCHIVAL_EPOCH_INTERVAL,
            StorageMode::Standard,
        ));

        let event_channels = Arc::new(EventChannels::default());

        Self::new(
            chain_config,
            store_config,
            anchor_block,
            anchor_state,
            tick,
            event_channels,
            execution_engine,
            metrics,
            futures::sink::drain(),
            p2p_tx,
            futures::sink::drain(),
            futures::sink::drain(),
            futures::sink::drain(),
            futures::sink::drain(),
            storage,
            core::iter::empty(),
            true,
            [].into(),
            Arc::new(DashMap::new()),
        )
        .expect("Controller::new should not fail in tests and benchmarks")
    }
}

impl<P: Preset> AdHocBenchController<P> {
    pub fn with_p2p_tx(
        chain_config: Arc<ChainConfig>,
        store_config: StoreConfig,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
        database: Database,
        p2p_tx: impl UnboundedSink<P2pMessage<P>>,
    ) -> (Arc<Self>, MutatorHandle<P, WaitGroup>) {
        Self::new_internal(
            chain_config,
            store_config,
            anchor_block,
            anchor_state,
            database,
            NullExecutionEngine,
            None,
            p2p_tx,
        )
    }
}

impl<P: Preset> BenchController<P> {
    #[must_use]
    pub fn quiet(
        chain_config: Arc<ChainConfig>,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
    ) -> (Arc<Self>, MutatorHandle<P, WaitGroup>) {
        Self::new_internal(
            chain_config,
            StoreConfig::default(),
            anchor_block,
            anchor_state,
            Database::in_memory(),
            NullExecutionEngine,
            None,
            futures::sink::drain(),
        )
    }
}

#[cfg(test)]
impl<P: Preset> TestController<P> {
    #[cfg(feature = "eth2-cache")]
    pub(crate) fn quiet(
        chain_config: Arc<ChainConfig>,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
    ) -> (Arc<Self>, MutatorHandle<P, WaitGroup>) {
        Self::with_p2p_tx(
            chain_config,
            anchor_block,
            anchor_state,
            Arc::new(Mutex::new(MockExecutionEngine::new(true, false, None))),
            futures::sink::drain(),
        )
    }

    pub(crate) fn with_p2p_tx(
        chain_config: Arc<ChainConfig>,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
        execution_engine: TestExecutionEngine<P>,
        p2p_tx: impl UnboundedSink<P2pMessage<P>>,
    ) -> (Arc<Self>, MutatorHandle<P, WaitGroup>) {
        let store_config = StoreConfig::aggressive(&chain_config);

        Self::new_internal(
            chain_config,
            store_config,
            anchor_block,
            anchor_state,
            Database::in_memory(),
            execution_engine,
            None,
            p2p_tx,
        )
    }

    pub(crate) fn on_test_attestation(&self, attestation: Arc<Attestation<P>>) {
        self.spawn(AttestationTask {
            store_snapshot: self.owned_store_snapshot(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: self.owned_wait_group(),
            attestation: AttestationItem::unverified(attestation, AttestationOrigin::Test),
            metrics: None,
        })
    }
}
