#![allow(
    clippy::allow_attributes,
    reason = "allow_attributes lint trigger from some derive macros. \
              See <https://github.com/rust-lang/rust-clippy/issues/13349>."
)]
use std::{
    sync::{mpsc::Sender, Arc},
    time::Instant,
};

use anyhow::Result;
use clock::Tick;
use eth2_libp2p::{GossipId, PeerId};
use execution_engine::PayloadStatusV1;
use fork_choice_store::{
    AggregateAndProofOrigin, AttestationAction, AttestationItem, AttestationValidationError,
    AttesterSlashingOrigin, BlobSidecarAction, BlobSidecarOrigin, BlockAction, BlockOrigin,
    ChainLink,
};
use log::debug;
use serde::Serialize;
use types::{
    combined::{Attestation, BeaconState, SignedAggregateAndProof, SignedBeaconBlock},
    deneb::containers::BlobIdentifier,
    phase0::{
        containers::Checkpoint,
        primitives::{DepositIndex, ExecutionBlockHash, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
};

use crate::{
    misc::{MutatorRejectionReason, VerifyAggregateAndProofResult, VerifyAttestationResult},
    unbounded_sink::UnboundedSink,
};

#[cfg(test)]
use core::fmt::Debug;

#[cfg(test)]
use derivative::Derivative;

pub enum AttestationVerifierMessage<P: Preset, W> {
    AggregateAndProof {
        wait_group: W,
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
        origin: AggregateAndProofOrigin<GossipId>,
    },
    Attestation {
        wait_group: W,
        attestation: AttestationItem<P, GossipId>,
    },
}

impl<P: Preset, W> AttestationVerifierMessage<P, W> {
    pub fn send(self, tx: &impl UnboundedSink<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to attestation verifier failed because the receiver was dropped");
        }
    }
}

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
        results:
            Vec<Result<AttestationAction<P, GossipId>, AttestationValidationError<P, GossipId>>>,
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
    FinishedPersistingBlobSidecars {
        wait_group: W,
        persisted_blob_ids: Vec<BlobIdentifier>,
    },
    PreprocessedBeaconState {
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
#[cfg_attr(test, derive(Derivative))]
#[cfg_attr(test, derivative(Debug(bound = "")))]
pub enum P2pMessage<P: Preset> {
    Slot(Slot),
    Accept(GossipId),
    Ignore(GossipId),
    Reject(GossipId, MutatorRejectionReason),
    BlockNeeded(H256, Option<PeerId>),
    BlobsNeeded(Vec<BlobIdentifier>, Slot, Option<PeerId>),
    FinalizedCheckpoint(Checkpoint),
    HeadState(#[cfg_attr(test, derivative(Debug = "ignore"))] Arc<BeaconState<P>>),
}

impl<P: Preset> P2pMessage<P> {
    pub(crate) fn send(self, tx: &impl UnboundedSink<Self>) {
        // Don't log the value because it can contain entire `BeaconState`s.
        if tx.unbounded_send(self).is_err() {
            debug!("send to p2p failed because the receiver was dropped");
        }
    }
}

pub enum PoolMessage {
    Slot(Slot),
    Tick(Tick),
}

impl PoolMessage {
    pub(crate) fn send(self, tx: &impl UnboundedSink<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to operation pools failed because the receiver was dropped");
        }
    }
}

pub enum ValidatorMessage<P: Preset, W> {
    Tick(W, Tick),
    FinalizedEth1Data(DepositIndex, Option<DepositIndex>),
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
