use core::ops::Range;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clock::Tick;
use crossbeam_utils::sync::WaitGroup;
use eth2_libp2p::GossipId;
use execution_engine::{
    BlockOrDataColumnSidecar, EngineGetBlobsParams, EngineGetBlobsV1Params, EngineGetBlobsV2Params,
    ExecutionServiceMessage, MockExecutionEngine, PayloadStatusV1, PayloadValidationStatus,
};
use fork_choice_store::{AttestationItem, AttestationOrigin};
use futures::channel::mpsc::UnboundedReceiver;
use helper_functions::misc;
use std_ext::ArcExt as _;
use types::{
    combined::{Attestation, AttesterSlashing, BeaconState, SignedBeaconBlock},
    config::Config,
    deneb::containers::{BlobIdentifier, BlobSidecar},
    nonstandard::{PayloadStatus, Phase, TimedPowBlock},
    phase0::{
        containers::Checkpoint,
        primitives::{Epoch, ExecutionBlockHash, Slot, UnixSeconds, ValidatorIndex, H256},
    },
    preset::{Minimal, Preset},
    traits::SignedBeaconBlock as _,
};
use unwrap_none::UnwrapNone as _;

use crate::{
    controller::MutatorHandle,
    messages::P2pMessage,
    queries::BlockWithRoot,
    specialized::{TestController, TestExecutionEngine},
};

pub struct Context<P: Preset> {
    controller: Option<Arc<TestController<P>>>,
    #[expect(
        dead_code,
        reason = "Keep the `MutatorHandle` around to avoid joining the mutator thread prematurely."
    )]
    mutator_handle: MutatorHandle<P, WaitGroup>,
    execution_engine: TestExecutionEngine<P>,
    p2p_rx: UnboundedReceiver<P2pMessage<P>>,
    service_rx: UnboundedReceiver<ExecutionServiceMessage<P>>,
}

impl<P: Preset> Drop for Context<P> {
    fn drop(&mut self) {
        self.controller
            .take()
            .expect("Self.controller is only taken in Drop::drop");

        if !std::thread::panicking() {
            self.next_p2p_message().unwrap_none();
        }
    }
}

impl<P: Preset> Context<P> {
    fn with_config(config: Config) -> Result<Self> {
        let config = Arc::new(config);
        let (genesis_state, _) = factory::min_genesis_state(&config)?;
        let genesis_block = Arc::new(genesis::beacon_block(&genesis_state));
        Ok(Self::new(config, genesis_block, genesis_state, true))
    }

    #[must_use]
    pub fn new(
        config: Arc<Config>,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
        optimistic_merge_block_validation: bool,
    ) -> Self {
        let (service_tx, service_rx) = futures::channel::mpsc::unbounded();

        let execution_engine = Arc::new(Mutex::new(MockExecutionEngine::new(
            true,
            optimistic_merge_block_validation,
            Some(service_tx),
        )));

        let (p2p_tx, p2p_rx) = futures::channel::mpsc::unbounded();

        let (controller, mutator_handle) = TestController::with_p2p_tx(
            config,
            anchor_block,
            anchor_state,
            execution_engine.clone_arc(),
            p2p_tx,
        );

        Self {
            controller: Some(controller),
            mutator_handle,
            p2p_rx,
            service_rx,
            execution_engine,
        }
    }

    #[must_use]
    pub fn unfinalized_states_in_memory(&self) -> u64 {
        self.controller()
            .store_config()
            .unfinalized_states_in_memory
    }

    #[must_use]
    pub fn genesis(&self) -> (Arc<SignedBeaconBlock<P>>, Arc<BeaconState<P>>) {
        let chain_link = self
            .controller()
            .genesis()
            .expect("store was created using genesis as the anchor");

        let state = self.controller().state_by_chain_link(&chain_link);

        (chain_link.block, state)
    }

    #[must_use]
    pub fn anchor_block(&self) -> Arc<SignedBeaconBlock<P>> {
        self.controller().anchor_block()
    }

    #[must_use]
    pub fn anchor_state(&self) -> Arc<BeaconState<P>> {
        self.controller().anchor_state()
    }

    #[must_use]
    pub fn justified_state(&self) -> Arc<BeaconState<P>> {
        self.controller()
            .justified_state()
            .expect("justified block should be present in the store")
            .value
    }

    #[must_use]
    pub fn last_finalized_state(&self) -> Arc<BeaconState<P>> {
        self.controller().last_finalized_state().value
    }

    // The `graffiti` parameters are needed for two reasons:
    // - To make otherwise identical blocks distinct.
    // - To break ties the desired way.

    #[must_use]
    pub fn empty_block(
        &self,
        pre_state: &Arc<BeaconState<P>>,
        slot: Slot,
        graffiti: H256,
    ) -> (Arc<SignedBeaconBlock<P>>, Arc<BeaconState<P>>) {
        factory::empty_block(self.config(), pre_state.clone_arc(), slot, graffiti)
            .expect("block should be constructed successfully")
    }

    #[must_use]
    pub fn block_with_payload(
        &self,
        pre_state: &Arc<BeaconState<P>>,
        slot: Slot,
        graffiti: H256,
        execution_block_hash: ExecutionBlockHash,
    ) -> (Arc<SignedBeaconBlock<P>>, Arc<BeaconState<P>>) {
        let execution_payload =
            factory::execution_payload(self.config(), pre_state, slot, execution_block_hash)
                .expect("execution payload should be constructed successfully");

        factory::block_with_payload(
            self.config(),
            pre_state.clone_arc(),
            slot,
            graffiti,
            execution_payload,
        )
        .expect("block should be constructed successfully")
    }

    #[must_use]
    pub fn block_justifying_previous_epoch(
        &self,
        pre_state: &Arc<BeaconState<P>>,
        epoch: Epoch,
        graffiti: H256,
    ) -> (Arc<SignedBeaconBlock<P>>, Arc<BeaconState<P>>) {
        let pre_state = pre_state.clone_arc();

        factory::block_justifying_previous_epoch(self.config(), pre_state, epoch, graffiti)
            .expect("block should be constructed successfully")
    }

    #[must_use]
    pub fn block_justifying_current_epoch(
        &self,
        pre_state: &Arc<BeaconState<P>>,
        epoch: Epoch,
        graffiti: H256,
    ) -> (Arc<SignedBeaconBlock<P>>, Arc<BeaconState<P>>) {
        let pre_state = pre_state.clone_arc();

        factory::block_justifying_current_epoch(self.config(), pre_state, epoch, graffiti, None)
            .expect("block should be constructed successfully")
    }

    #[must_use]
    pub fn block_with_payload_justifying_current_epoch(
        &self,
        pre_state: &Arc<BeaconState<P>>,
        epoch: Epoch,
        graffiti: H256,
        execution_block_hash: ExecutionBlockHash,
    ) -> (Arc<SignedBeaconBlock<P>>, Arc<BeaconState<P>>) {
        let pre_state = pre_state.clone_arc();

        let execution_payload = factory::execution_payload(
            self.config(),
            &pre_state,
            start_of_epoch(epoch + 1) - 1,
            execution_block_hash,
        )
        .expect("execution payload should be constructed successfully");

        factory::block_justifying_current_epoch(
            self.config(),
            pre_state,
            epoch,
            graffiti,
            Some(execution_payload),
        )
        .expect("block should be constructed successfully")
    }

    pub fn on_tick(&mut self, tick: Tick) {
        let old_slot = self.controller().slot();
        let new_slot = tick.slot;

        self.controller().on_tick(tick);
        self.controller().wait_for_tasks();

        // Some artifacts, like blob sidecars, require current slot state for validation.
        let _unused = self.controller().preprocessed_state_at_current_slot();

        if old_slot < new_slot {
            assert!(matches!(
                self.next_p2p_message(),
                Some(P2pMessage::Slot(slot)) if slot == new_slot,
            ));
        }
    }

    pub fn on_slot(&mut self, new_slot: Slot) {
        let old_slot = self.controller().slot();

        self.controller().on_slot(new_slot);
        self.controller().wait_for_tasks();

        if old_slot < new_slot {
            assert!(matches!(
                self.next_p2p_message(),
                Some(P2pMessage::Slot(slot)) if slot == new_slot,
            ));
        }
    }

    pub fn on_blob_sidecar(&mut self, blob_sidecar: BlobSidecar<P>) -> Option<P2pMessage<P>> {
        let subnet_id = misc::compute_subnet_for_blob_sidecar(self.config(), &blob_sidecar);

        self.controller().on_gossip_blob_sidecar(
            Arc::new(blob_sidecar),
            subnet_id,
            GossipId::default(),
            true,
        );

        self.controller().wait_for_tasks();
        self.next_p2p_message()
    }

    pub fn on_acceptable_block(&mut self, block: &Arc<SignedBeaconBlock<P>>) {
        assert!(matches!(self.on_block(block), Some(P2pMessage::Accept(_))));
    }

    pub fn on_ignorable_block(&mut self, block: &Arc<SignedBeaconBlock<P>>) {
        assert!(matches!(self.on_block(block), Some(P2pMessage::Ignore(_))));
    }

    pub fn on_valid_block(&mut self, block: &Arc<SignedBeaconBlock<P>>) {
        assert!(matches!(
            self.on_block(block),
            Some(P2pMessage::Accept(_) | P2pMessage::Ignore(_)),
        ));
    }

    pub fn on_invalid_block(&mut self, block: &Arc<SignedBeaconBlock<P>>) {
        assert!(matches!(
            self.on_block(block),
            Some(P2pMessage::Ignore(_) | P2pMessage::Reject(_, _)) | None,
        ));
    }

    pub fn on_block_with_missing_blobs(
        &mut self,
        block: &Arc<SignedBeaconBlock<P>>,
        blob_count: usize,
    ) {
        // If an optimistic beacon block is not accepted by the fork choice,
        // then it will not be propagated in gossipsub before it is fully validated (e.g. block arrives before blob).
        self.on_valid_block(block);

        let block_root = block.message().hash_tree_root();

        match self.next_execution_service_message() {
            Some(ExecutionServiceMessage::GetBlobs(params)) => match params {
                EngineGetBlobsParams::V1(EngineGetBlobsV1Params {
                    block: block_with_missing_blobs,
                    blob_identifiers,
                    peer_id: _,
                }) => {
                    let expected_identifiers = (0..blob_count)
                        .map(|index| BlobIdentifier {
                            block_root,
                            index: index.try_into().expect("usize should fit to u64"),
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(blob_identifiers, expected_identifiers);
                    assert_eq!(block_with_missing_blobs, *block);
                }
                EngineGetBlobsParams::V2(EngineGetBlobsV2Params {
                    block_or_sidecar,
                    data_column_identifiers,
                }) => {
                    assert!(data_column_identifiers
                        .iter()
                        .all(|id| id.block_root == block_root));
                    assert!(!data_column_identifiers.is_empty());

                    match block_or_sidecar {
                        BlockOrDataColumnSidecar::Block(block_with_missing_blobs) => {
                            assert_eq!(block_with_missing_blobs, *block)
                        }
                        BlockOrDataColumnSidecar::Sidecar(data_column_sidecar) => {
                            assert_eq!(data_column_sidecar.signed_block_header, block.to_header())
                        }
                    }
                }
            },
            _ => panic!("ExecutionServiceMessage::GetBlobs expected"),
        }
    }

    pub fn on_acceptable_singular_attestation(
        &mut self,
        state: &Arc<BeaconState<P>>,
        epoch: Epoch,
        validator_index: ValidatorIndex,
    ) {
        assert!(matches!(
            self.on_singular_attestation(state, epoch, validator_index),
            Some(P2pMessage::Accept(_)),
        ));
    }

    pub fn on_ignorable_singular_attestation(
        &mut self,
        state: &Arc<BeaconState<P>>,
        epoch: Epoch,
        validator_index: ValidatorIndex,
    ) {
        assert!(matches!(
            self.on_singular_attestation(state, epoch, validator_index),
            Some(P2pMessage::Ignore(_)),
        ));
    }

    pub fn on_merge_block(&self, block_hash: ExecutionBlockHash, timed_pow_block: TimedPowBlock) {
        self.execution_engine
            .lock()
            .expect("execution engine mutex is poisoned")
            .insert_pow_block(block_hash, timed_pow_block);
    }

    pub fn on_notified_new_payload(
        &self,
        beacon_block_root: H256,
        block_hash: ExecutionBlockHash,
        payload_status: PayloadStatusV1,
    ) {
        self.controller()
            .on_notified_new_payload(beacon_block_root, block_hash, payload_status);
        self.controller().wait_for_tasks();
    }

    pub fn on_test_attestation(&mut self, attestation: Attestation<P>) {
        self.controller().on_test_attestation(Arc::new(attestation));
        self.controller().wait_for_tasks();
        self.next_p2p_message().unwrap_none();
    }

    pub fn on_attester_slashing(&mut self, attester_slashing: AttesterSlashing<P>) {
        self.controller()
            .on_gossip_attester_slashing(Box::new(attester_slashing));
        self.controller().wait_for_tasks();
        self.next_p2p_message().unwrap_none();
    }

    pub fn on_notified_valid_payload(&self, block: &SignedBeaconBlock<P>) {
        let execution_block_hash = Self::execution_block_hash(block);

        self.on_notified_new_payload(
            block.message().hash_tree_root(),
            execution_block_hash,
            PayloadStatusV1 {
                status: PayloadValidationStatus::Valid,
                // According to the [Engine API specification], if the payload is valid,
                // `latest_valid_hash` must equal `execution_block_hash`.
                //
                // [Engine API specification]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#payload-validation
                latest_valid_hash: Some(execution_block_hash),
                validation_error: None,
            },
        );
    }

    pub fn on_notified_invalid_payload(
        &self,
        block: &SignedBeaconBlock<P>,
        latest_valid_block: Option<&SignedBeaconBlock<P>>,
    ) {
        self.on_notified_new_payload(
            block.message().hash_tree_root(),
            Self::execution_block_hash(block),
            PayloadStatusV1 {
                status: PayloadValidationStatus::Invalid,
                latest_valid_hash: latest_valid_block.map(Self::execution_block_hash),
                validation_error: None,
            },
        );
    }

    pub fn blocks_by_range(&self, range: Range<Slot>) -> Result<Vec<BlockWithRoot<P>>> {
        self.controller().blocks_by_range(range)
    }

    pub fn assert_genesis_time(&self, expected_time: UnixSeconds) {
        assert_eq!(self.controller().genesis_time(), expected_time);
    }

    pub fn assert_tick(&self, expected_tick: Tick) {
        assert_eq!(self.controller().tick(), expected_tick);
    }

    pub fn assert_justified_checkpoint(&self, expected_checkpoint: Checkpoint) {
        assert_eq!(
            self.controller().justified_checkpoint(),
            expected_checkpoint,
        );
    }

    pub fn assert_finalized_checkpoint(&self, expected_checkpoint: Checkpoint) {
        assert_eq!(
            self.controller().finalized_checkpoint(),
            expected_checkpoint,
        );
    }

    pub fn assert_proposer_boost_root(&self, expected_root: H256) {
        assert_eq!(self.controller().proposer_boost_root(), expected_root);
    }

    pub fn assert_head(&self, expected_head_slot: Slot, expected_head_root: H256) {
        let head = self.controller().head().value;

        assert_eq!(head.block_root, expected_head_root);
        assert_eq!(head.slot(), expected_head_slot);
    }

    pub fn assert_status(&self, expected_status: Status<P>) {
        // In normal operation making multiple calls to `Controller` could result in computations
        // being done based on different snapshots of `Store`, leading to inconsistent results.
        // This is not a problem here because the `Controller` is not accessed by any other thread
        // and we wait for tasks to complete after each call that could mutate the `Store`.
        assert_eq!(
            self.controller().head_block().value.as_ref(),
            expected_status.head,
        );
        assert_eq!(
            self.controller().attesting_balance(),
            expected_status
                .attesting_validators
                .map(|count| count * P::MAX_EFFECTIVE_BALANCE),
        );
        assert_eq!(
            self.controller().justified_epoch(),
            expected_status.store_justified_epoch,
        );
        assert_eq!(
            self.controller().finalized_epoch(),
            expected_status.store_finalized_epoch,
        );
        assert_eq!(
            self.controller().fork_count_viable(),
            expected_status.fork_count_viable,
        );
        assert_eq!(
            self.controller().fork_count_total(),
            expected_status.fork_count_total,
        );
        assert_eq!(
            self.controller()
                .finalized_block_count()
                .expect("no storage errors should occur"),
            expected_status.finalized_block_count,
        );
        assert_eq!(
            self.controller().unfinalized_block_count_in_fork(),
            expected_status.unfinalized_block_count_in_fork,
        );
        assert_eq!(
            self.controller().unfinalized_block_count_total(),
            expected_status.unfinalized_block_count_total,
        );
    }

    pub fn assert_payload_status(
        &self,
        block: &SignedBeaconBlock<P>,
        expected_payload_status: Option<PayloadStatus>,
    ) {
        assert_eq!(
            self.controller()
                .payload_status(block.message().hash_tree_root()),
            expected_payload_status,
        );
    }

    pub fn assert_optimistic(&self, block: &SignedBeaconBlock<P>, expected_optimistic: bool) {
        assert_eq!(
            self.controller()
                .check_block_root(block.message().hash_tree_root())
                .expect("no storage errors should occur")
                .expect("block should be present in the store")
                .status
                .is_optimistic(),
            expected_optimistic,
        );
    }

    pub fn assert_forward_synced(&self, expected_forward_synced: bool) {
        assert_eq!(
            self.controller().is_forward_synced(),
            expected_forward_synced,
        );
    }

    pub fn assert_head_notification_sent(&mut self) {
        assert!(matches!(
            self.next_p2p_message_verbose(),
            Some(P2pMessage::HeadState(_)),
        ));
    }

    fn config(&self) -> &Config {
        self.controller().chain_config()
    }

    fn controller(&self) -> &TestController<P> {
        self.controller
            .as_ref()
            .expect("Self.controller is only taken in Drop::drop")
    }

    // Taking `block` by reference is unconventional but makes the call sites look consistent.
    fn on_block(&mut self, block: &Arc<SignedBeaconBlock<P>>) -> Option<P2pMessage<P>> {
        self.controller()
            .on_gossip_block(block.clone_arc(), GossipId::default());
        self.controller().wait_for_tasks();
        self.next_p2p_message()
    }

    fn on_singular_attestation(
        &mut self,
        state: &Arc<BeaconState<P>>,
        epoch: Epoch,
        validator_index: ValidatorIndex,
    ) -> Option<P2pMessage<P>> {
        let (attestation, subnet_id) =
            factory::singular_attestation(self.config(), state.clone_arc(), epoch, validator_index)
                .expect("attestation should be constructed successfully");

        self.controller()
            .on_singular_attestation(AttestationItem::unverified(
                Arc::new(attestation),
                AttestationOrigin::Gossip(subnet_id, GossipId::default()),
            ));

        self.controller().wait_for_tasks();

        self.next_p2p_message()
    }

    fn next_execution_service_message(&mut self) -> Option<ExecutionServiceMessage<P>> {
        self.service_rx.try_next().ok().flatten()
    }

    fn next_p2p_message(&mut self) -> Option<P2pMessage<P>> {
        loop {
            let option = self.next_p2p_message_verbose();

            if let Some(
                P2pMessage::FinalizedCheckpoint(_) | P2pMessage::HeadState(_) | P2pMessage::Stop,
            ) = option
            {
                continue;
            }

            return option;
        }
    }

    fn next_p2p_message_verbose(&mut self) -> Option<P2pMessage<P>> {
        self.p2p_rx.try_next().ok().flatten()
    }

    fn execution_block_hash(block: &SignedBeaconBlock<P>) -> ExecutionBlockHash {
        block
            .execution_block_hash()
            .expect("block should be post-Bellatrix")
    }
}

// This cannot be done with a default type parameter because they are not used for type inference.
// See:
// - <https://github.com/rust-lang/rust/issues/27336>
// - <https://old.reddit.com/r/rust/comments/azqo9c/hey_rustaceans_got_an_easy_question_ask_here/eicgce8/>
impl Context<Minimal> {
    pub fn minimal() -> Self {
        Self::with_config(Config::minimal()).expect("minimal configuration is valid")
    }

    pub fn bellatrix_minimal() -> Self {
        Self::with_config(Config::minimal().start_and_stay_in(Phase::Bellatrix))
            .expect("minimal configuration modified to start in Bellatrix is valid")
    }
}

#[derive(Clone, Copy)]
pub struct Status<'block, P: Preset> {
    pub head: &'block SignedBeaconBlock<P>,
    pub attesting_validators: Option<u64>,
    pub store_justified_epoch: Epoch,
    pub store_finalized_epoch: Epoch,
    pub fork_count_viable: usize,
    pub fork_count_total: usize,
    pub finalized_block_count: usize,
    pub unfinalized_block_count_in_fork: usize,
    pub unfinalized_block_count_total: usize,
}

pub fn epoch_at_slot(slot: Slot) -> Epoch {
    misc::compute_epoch_at_slot::<Minimal>(slot)
}

pub const fn start_of_epoch(epoch: Epoch) -> Slot {
    misc::compute_start_slot_at_epoch::<Minimal>(epoch)
}

pub fn is_at_start_of_epoch(block: &SignedBeaconBlock<Minimal>) -> bool {
    misc::is_epoch_start::<Minimal>(block.message().slot())
}
