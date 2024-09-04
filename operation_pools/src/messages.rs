use eth2_libp2p::GossipId;
use futures::channel::mpsc::UnboundedSender;
use tracing::debug;
use serde::Serialize;
use types::{
    altair::containers::SyncCommitteeMessage, capella::containers::SignedBlsToExecutionChange,
};

use crate::misc::PoolRejectionReason;

#[derive(Serialize)]
pub enum PoolToP2pMessage {
    Accept(GossipId),
    Ignore(GossipId),
    Reject(GossipId, PoolRejectionReason),
    PublishSignedBlsToExecutionChange(Box<SignedBlsToExecutionChange>),
}

impl PoolToP2pMessage {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if let Err(message) = tx.unbounded_send(self) {
            debug!("send to p2p failed because the receiver was dropped: {message:?}");
        }
    }
}

pub enum PoolToLivenessMessage {
    SyncCommitteeMessage(SyncCommitteeMessage),
}

impl PoolToLivenessMessage {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if let Err(message) = tx.unbounded_send(self) {
            debug!("send to liveness tracker failed because the receiver was dropped: {message:?}");
        }
    }
}

pub enum PoolToApiMessage {
    SignedBlsToExecutionChange(Box<SignedBlsToExecutionChange>),
}

impl PoolToApiMessage {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if let Err(message) = tx.unbounded_send(self) {
            debug!("send to HTTP API failed because the receiver was dropped: {message:?}");
        }
    }
}
