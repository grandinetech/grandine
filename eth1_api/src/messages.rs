use anyhow::Result;
use either::Either;
use execution_engine::{PayloadAttributes, PayloadId, PayloadStatusV1};
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use tracing::debug;
use types::{
    combined::{ExecutionPayload, ExecutionPayloadParams},
    nonstandard::Phase,
    phase0::primitives::{ExecutionBlockHash, H256},
    preset::Preset,
};

pub enum ExecutionServiceMessage<P: Preset> {
    NotifyForkchoiceUpdated {
        head_eth1_block_hash: ExecutionBlockHash,
        safe_eth1_block_hash: ExecutionBlockHash,
        finalized_eth1_block_hash: ExecutionBlockHash,
        payload_attributes: Either<Phase, PayloadAttributes<P>>,
        sender: Option<Sender<Option<PayloadId>>>,
    },
    NotifyNewPayload {
        beacon_block_root: H256,
        payload: ExecutionPayload<P>,
        params: Option<ExecutionPayloadParams>,
        sender: Option<Sender<Result<PayloadStatusV1>>>,
    },
}

impl<P: Preset> ExecutionServiceMessage<P> {
    pub(crate) fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to execution service failed because the receiver was dropped");
        }
    }
}

pub struct Eth1Metrics {
    pub eth1_connection_data: Eth1ConnectionData,
    pub sync_eth1_fallback_configured: bool,
}

#[derive(Copy, Clone, Default)]
pub struct Eth1ConnectionData {
    pub sync_eth1_connected: bool,
    pub sync_eth1_fallback_connected: bool,
}

pub enum Eth1ApiToMetrics {
    Eth1Connection(Eth1ConnectionData),
}

impl Eth1ApiToMetrics {
    pub(crate) fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to metrics service failed because the receiver was dropped");
        }
    }
}
