use std::{
    collections::HashSet,
    sync::{mpsc::Sender, Arc},
    time::Instant,
};

use anyhow::Result;
use clock::Tick;
use eth2_libp2p::{GossipId, PeerId};
use execution_engine::PayloadStatusV1;
use fork_choice_store::{
    AttestationAction, AttesterSlashingOrigin, BlobSidecarAction, BlobSidecarOrigin, BlockAction,
    BlockOrigin, ChainLink, DataColumnSidecarOrigin, Store,
};
use helper_functions::{accessors, misc};
use log::debug;
use serde::Serialize;
use tap::Pipe as _;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    deneb::containers::BlobIdentifier,
    eip7594::{ColumnIndex, DataColumnIdentifier},
    phase0::{
        containers::{Attestation, Checkpoint},
        primitives::{
            DepositIndex, Epoch, ExecutionBlockHash, Slot, SubnetId, ValidatorIndex, H256,
        },
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::{
    misc::{MutatorRejectionReason, VerifyAggregateAndProofResult, VerifyAttestationResult},
    storage::Storage,
    unbounded_sink::UnboundedSink,
};
use fork_choice_store::DataColumnSidecarAction;

#[cfg(test)]
use core::fmt::Debug;

#[cfg(test)]
use educe::Educe;

// Attestations cannot result in delayed objects being retried, but a `wait_group` field is still
// needed in the attestation variants to make `Controller::wait_for_tasks` work.
pub enum MutatorMessage<P: Preset, W> {
    Tick {
        wait_group: W,
        tick: Tick,
    },
    Block {
        wait_group: W,
        result: Result<BlockAction<P>>,
        origin: BlockOrigin,
        submission_time: Instant,
        rejected_block_root: Option<H256>,
    },
    AggregateAndProof {
        wait_group: W,
        result: VerifyAggregateAndProofResult<P>,
    },
    AggregateAndProofBatch {
        wait_group: W,
        results: Vec<VerifyAggregateAndProofResult<P>>,
    },
    Attestation {
        wait_group: W,
        result: VerifyAttestationResult<P>,
    },
    AttestationBatch {
        wait_group: W,
        results: Vec<VerifyAttestationResult<P>>,
    },
    BlockAttestations {
        wait_group: W,
        results: Vec<Result<AttestationAction<P>>>,
    },
    AttesterSlashing {
        wait_group: W,
        result: Result<Vec<ValidatorIndex>>,
        origin: AttesterSlashingOrigin,
    },
    BlobSidecar {
        wait_group: W,
        result: Result<BlobSidecarAction<P>>,
        origin: BlobSidecarOrigin,
        block_seen: bool,
        submission_time: Instant,
    },
    CheckpointState {
        wait_group: W,
        // `checkpoint` can be computed from the checkpoint state using
        // `helper_functions::accessors::get_current_epoch` and
        // `helper_functions::accessors::latest_block_root`, but the latter may involve hashing.
        checkpoint: Checkpoint,
        checkpoint_state: Option<Arc<BeaconState<P>>>,
    },
    DataColumnSidecar {
        wait_group: W,
        result: Result<DataColumnSidecarAction<P>>,
        origin: DataColumnSidecarOrigin,
        submission_time: Instant,
    },
    FinishedPersistingBlobSidecars {
        wait_group: W,
        persisted_blob_ids: Vec<BlobIdentifier>,
    },
    FinishedPersistingDataColumnSidecars {
        wait_group: W,
        persisted_data_column_ids: Vec<DataColumnIdentifier>,
    },
    PreprocessedBeaconState {
        block_root: H256,
        state: Arc<BeaconState<P>>,
    },
    NotifiedForkChoiceUpdate {
        wait_group: W,
        payload_status: PayloadStatusV1,
    },
    NotifiedNewPayload {
        wait_group: W,
        execution_block_hash: ExecutionBlockHash,
        payload_status: PayloadStatusV1,
    },
    // Dropping `Controller.mutator_tx` is not enough to stop the mutator thread because `Mutator`
    // itself keeps a sender in `Mutator.mutator_tx` for spawning tasks.
    //
    // The sender could instead be wrapped in an `Arc` and some other primitive, allowing
    // `Controller` to stop the mutator thread by swapping it out or dropping it. However, that
    // would force the mutator to process messages from all currently running tasks before stopping.
    //
    // It doesn't make sense for this to have a `wait_group` field because this is only sent when
    // the corresponding `Controller` is dropped. There is no way to call
    // `Controller::wait_for_tasks` after that.
    Stop {
        save_to_storage: bool,
    },
    StoreCustodyColumns {
        custody_columns: HashSet<ColumnIndex>,
    },
}

impl<P: Preset, W> MutatorMessage<P, W> {
    pub(crate) fn send(self, tx: &Sender<Self>) {
        // Don't log the value because it can contain entire `BeaconState`s.
        if tx.send(self).is_err() {
            // This can happen if the mutator thread exits early due to failure or if a task
            // is completed after the `Controller` is dropped and stops the mutator thread.
            debug!("send to mutator failed because the receiver was dropped");
        }
    }
}

#[derive(Serialize)]
#[serde(bound = "")]
#[cfg_attr(test, derive(Educe))]
#[cfg_attr(test, educe(Debug))]
pub enum P2pMessage<P: Preset> {
    Slot(Slot),
    Accept(GossipId),
    Ignore(GossipId),
    Reject(GossipId, MutatorRejectionReason),
    BlockNeeded(H256, Option<PeerId>),
    BlobsNeeded(Vec<BlobIdentifier>, Slot, Option<PeerId>),
    DataColumnsNeeded(Vec<DataColumnIdentifier>, Slot, Option<PeerId>),
    FinalizedCheckpoint(Checkpoint),
    HeadState(#[cfg_attr(test, educe(Debug(ignore)))] Arc<BeaconState<P>>),
    ReverifyGossipAttestation(Arc<Attestation<P>>, SubnetId, GossipId),
}

impl<P: Preset> P2pMessage<P> {
    pub(crate) fn send(self, tx: &impl UnboundedSink<Self>) {
        // Don't log the value because it can contain entire `BeaconState`s.
        if tx.unbounded_send(self).is_err() {
            debug!("send to p2p failed because the receiver was dropped");
        }
    }
}

pub enum ValidatorMessage<P: Preset, W> {
    Tick(W, Tick),
    FinalizedEth1Data(DepositIndex),
    Head(W, ChainLink<P>),
    ValidAttestation(W, Arc<Attestation<P>>),
    PrepareExecutionPayload(Slot, ExecutionBlockHash, ExecutionBlockHash),
}

impl<P: Preset, W> ValidatorMessage<P, W> {
    pub(crate) fn send(self, tx: &impl UnboundedSink<Self>) {
        // Don't log the value because it can contain entire `BeaconState`s.
        if tx.unbounded_send(self).is_err() {
            debug!("send to validator failed because the receiver was dropped");
        }
    }
}

#[derive(Debug)]
pub enum ApiMessage<P: Preset> {
    AttestationEvent(Arc<Attestation<P>>),
    BlockEvent(BlockEvent),
    ChainReorgEvent(ChainReorgEvent),
    FinalizedCheckpoint(FinalizedCheckpointEvent),
    Head(HeadEvent),
}

impl<P: Preset> ApiMessage<P> {
    pub(crate) fn send(self, tx: &impl UnboundedSink<Self>) {
        if let Err(message) = tx.unbounded_send(self) {
            debug!("send to HTTP API failed because the receiver was dropped: {message:?}");
        }
    }
}

pub enum SubnetMessage<W> {
    Slot(W, Slot),
}

impl<W> SubnetMessage<W> {
    pub(crate) fn send(self, tx: &impl UnboundedSink<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to subnet service failed because the receiver was dropped");
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(bound = "")]
pub enum SyncMessage<P: Preset> {
    Finalized(Arc<SignedBeaconBlock<P>>),
}

impl<P: Preset> SyncMessage<P> {
    pub(crate) fn send(self, tx: &impl UnboundedSink<Self>) {
        if let Err(message) = tx.unbounded_send(self) {
            debug!(
                "send to block sync service failed because the receiver was dropped: {message:?}"
            );
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BlockEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub block: H256,
    pub execution_optimistic: bool,
}

#[derive(Debug, Serialize)]
pub struct ChainReorgEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub depth: u64,
    pub old_head_block: H256,
    pub new_head_block: H256,
    pub old_head_state: H256,
    pub new_head_state: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
    pub execution_optimistic: bool,
}

impl ChainReorgEvent {
    // The [Eth Beacon Node API specification] does not make it clear how `slot`, `depth`, and
    // `epoch` should be computed. We try to match the behavior of Lighthouse.
    //
    // [Eth Beacon Node API specification]: https://ethereum.github.io/beacon-APIs/
    #[must_use]
    pub fn new<P: Preset>(store: &Store<P>, old_head: &ChainLink<P>) -> Self {
        let new_head = store.head();
        let old_slot = old_head.slot();
        let new_slot = new_head.slot();

        let depth = store
            .common_ancestor(old_head.block_root, new_head.block_root)
            .map(ChainLink::slot)
            .unwrap_or_else(|| {
                // A reorganization may be triggered by an alternate chain being finalized.
                // The old block will no longer be present in `store` if that happens.
                // Default to the old finalized slot like Lighthouse does.
                // A proper solution may require significant changes to `Mutator`.
                old_head
                    .state(store)
                    .finalized_checkpoint()
                    .epoch
                    .pipe(misc::compute_start_slot_at_epoch::<P>)
            })
            .abs_diff(old_slot);

        Self {
            slot: new_slot,
            depth,
            old_head_block: old_head.block_root,
            new_head_block: new_head.block_root,
            old_head_state: old_head.block.message().state_root(),
            new_head_state: new_head.block.message().state_root(),
            epoch: misc::compute_epoch_at_slot::<P>(new_slot),
            execution_optimistic: new_head.is_optimistic(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FinalizedCheckpointEvent {
    pub block: H256,
    pub state: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
    pub execution_optimistic: bool,
}

#[derive(Debug, Serialize)]
pub struct HeadEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub block: H256,
    pub state: H256,
    pub epoch_transition: bool,
    pub previous_duty_dependent_root: H256,
    pub current_duty_dependent_root: H256,
    pub execution_optimistic: bool,
}

impl HeadEvent {
    pub fn new<P: Preset>(
        storage: &Storage<P>,
        store: &Store<P>,
        head: &ChainLink<P>,
    ) -> Result<Self> {
        let slot = head.slot();
        let state = head.state(store);
        let previous_epoch = accessors::get_previous_epoch(&state);
        let current_epoch = accessors::get_current_epoch(&state);
        let dependent_root = |epoch| storage.dependent_root(store, &state, epoch);

        Ok(Self {
            slot,
            block: head.block_root,
            state: head.block.message().state_root(),
            epoch_transition: misc::is_epoch_start::<P>(slot),
            previous_duty_dependent_root: dependent_root(previous_epoch)?,
            current_duty_dependent_root: dependent_root(current_epoch)?,
            execution_optimistic: head.is_optimistic(),
        })
    }
}
