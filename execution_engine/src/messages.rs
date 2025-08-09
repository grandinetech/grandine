use std::sync::Arc;

use anyhow::Result;
use either::Either;
use eth2_libp2p::PeerId;
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use logging::debug_with_peers;
use types::{
    combined::{ExecutionPayload, ExecutionPayloadParams, SignedBeaconBlock},
    deneb::containers::BlobIdentifier,
    nonstandard::Phase,
    phase0::primitives::{ExecutionBlockHash, H256},
    preset::Preset,
};

use crate::{PayloadAttributes, PayloadId, PayloadStatusV1};

pub enum ExecutionServiceMessage<P: Preset> {
    ExchangeCapabilities,
    GetBlobs {
        block: Arc<SignedBeaconBlock<P>>,
        blob_identifiers: Vec<BlobIdentifier>,
        peer_id: Option<PeerId>,
    },
    NotifyForkchoiceUpdated {
        head_eth1_block_hash: ExecutionBlockHash,
        safe_eth1_block_hash: ExecutionBlockHash,
        finalized_eth1_block_hash: ExecutionBlockHash,
        payload_attributes: Either<Phase, PayloadAttributes<P>>,
        sender: Option<Sender<Option<PayloadId>>>,
    },
    NotifyNewPayload {
        beacon_block_root: H256,
        payload: Box<ExecutionPayload<P>>,
        params: Option<ExecutionPayloadParams<P>>,
        sender: Option<Sender<Result<PayloadStatusV1>>>,
    },
    Stop,
}

impl<P: Preset> ExecutionServiceMessage<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug_with_peers!("send to execution service failed because the receiver was dropped");
        }
    }
}
