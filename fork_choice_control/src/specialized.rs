use core::ops::DerefMut as _;
use std::sync::Arc;

use clock::Tick;
use crossbeam_utils::sync::WaitGroup;
use execution_engine::{
    ExecutionEngine, NullExecutionEngine, PayloadStatusV1, PayloadValidationStatus,
};
use fork_choice_store::StoreConfig;
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use tap::Pipe as _;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config as ChainConfig,
    phase0::primitives::{ExecutionBlockHash, Slot},
    preset::Preset,
};

use crate::{
    controller::{Controller, MutatorHandle},
    messages::P2pMessage,
    storage::Storage,
    unbounded_sink::UnboundedSink,
};

#[cfg(test)]
use std::sync::Mutex;

#[cfg(test)]
use ::{
    execution_engine::MockExecutionEngine, fork_choice_store::AttestationOrigin,
    types::phase0::containers::Attestation,
};

#[cfg(test)]
use crate::tasks::AttestationTask;

pub type AdHocBenchController<P> = Controller<P, NullExecutionEngine, WaitGroup>;

pub type BenchController<P> = Controller<P, NullExecutionEngine, WaitGroup>;

#[cfg(test)]
pub type TestController<P> = Controller<P, TestExecutionEngine, WaitGroup>;

#[cfg(test)]
pub type TestExecutionEngine = Arc<Mutex<MockExecutionEngine>>;

impl<P, E> Controller<P, E, WaitGroup>
where
    P: Preset,
    E: ExecutionEngine<P> + Clone + Send + Sync + 'static,
{
    pub fn on_slot(&self, slot: Slot) {
        self.on_tick(Tick::start_of_slot(slot));
    }

    pub fn on_notified_valid_payload(&self, execution_block_hash: ExecutionBlockHash) {
        let payload_status = PayloadStatusV1 {
            status: PayloadValidationStatus::Valid,
            // According to the [Engine API specification], if the payload is valid,
            // `latest_valid_hash` must equal `execution_block_hash`.
            //
            // [Engine API specification]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#payload-validation
            latest_valid_hash: Some(execution_block_hash),
            validation_error: None,
        };

        self.on_notified_new_payload(execution_block_hash, payload_status)
    }

    pub fn on_notified_invalid_payload(
        &self,
        execution_block_hash: ExecutionBlockHash,
        latest_valid_hash: Option<ExecutionBlockHash>,
    ) {
        let payload_status = PayloadStatusV1 {
            status: PayloadValidationStatus::Invalid,
            latest_valid_hash,
            validation_error: None,
        };

        self.on_notified_new_payload(execution_block_hash, payload_status)
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

    fn new_internal(
        chain_config: Arc<ChainConfig>,
        store_config: StoreConfig,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
        execution_engine: E,
        metrics: Option<Arc<Metrics>>,
        p2p_tx: impl UnboundedSink<P2pMessage<P>>,
    ) -> (Arc<Self>, MutatorHandle<P, WaitGroup>) {
        let tick = Tick::block_proposal(&anchor_block);

        Self::new(
            chain_config.clone_arc(),
            store_config,
            anchor_block,
            anchor_state,
            tick,
            execution_engine,
            metrics,
            futures::sink::drain(),
            p2p_tx,
            futures::sink::drain(),
            futures::sink::drain(),
            futures::sink::drain(),
            Arc::new(Storage::in_memory(chain_config)),
            core::iter::empty(),
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
        p2p_tx: impl UnboundedSink<P2pMessage<P>>,
    ) -> (Arc<Self>, MutatorHandle<P, WaitGroup>) {
        Self::new_internal(
            chain_config,
            store_config,
            anchor_block,
            anchor_state,
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
            NullExecutionEngine,
            None,
            futures::sink::drain(),
        )
    }
}

#[cfg(test)]
impl<P: Preset> TestController<P> {
    pub(crate) fn quiet(
        chain_config: Arc<ChainConfig>,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
    ) -> (Arc<Self>, MutatorHandle<P, WaitGroup>) {
        Self::with_p2p_tx(
            chain_config,
            anchor_block,
            anchor_state,
            Arc::new(Mutex::new(MockExecutionEngine::new(true, false))),
            futures::sink::drain(),
        )
    }

    pub(crate) fn with_p2p_tx(
        chain_config: Arc<ChainConfig>,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
        execution_engine: TestExecutionEngine,
        p2p_tx: impl UnboundedSink<P2pMessage<P>>,
    ) -> (Arc<Self>, MutatorHandle<P, WaitGroup>) {
        let store_config = StoreConfig::minimal(&chain_config);

        Self::new_internal(
            chain_config,
            store_config,
            anchor_block,
            anchor_state,
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
            attestation,
            origin: AttestationOrigin::Test,
            metrics: None,
        })
    }
}
