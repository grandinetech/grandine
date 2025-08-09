use eth2_libp2p::GossipId;
use futures::channel::mpsc::UnboundedSender;
use logging::debug_with_peers;
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
            debug_with_peers!("send to p2p failed because the receiver was dropped: {message:?}");
        }
    }
}

pub enum PoolToLivenessMessage {
    SyncCommitteeMessage(SyncCommitteeMessage),
}

impl PoolToLivenessMessage {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if let Err(message) = tx.unbounded_send(self) {
            debug_with_peers!("send to liveness tracker failed because the receiver was dropped: {message:?}");
        }
    }
}
