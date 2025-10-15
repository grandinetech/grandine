use eth2_libp2p::PeerId;
use execution_engine::EngineGetBlobsParams;
use futures::channel::mpsc::UnboundedSender;
use log::debug;
use serde::Serialize;
use types::{
    deneb::containers::BlobIdentifier, fulu::containers::DataColumnsByRootIdentifier,
    phase0::primitives::Slot, preset::Preset,
};

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

pub enum Eth1ApiToBlobFetcher<P: Preset> {
    GetBlobs(EngineGetBlobsParams<P>),
    Stop,
}

impl<P: Preset> Eth1ApiToBlobFetcher<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to blob fetcher failed because the receiver was dropped");
        }
    }
}

#[derive(Debug, Serialize)]
pub enum BlobFetcherToP2p<P: Preset> {
    BlobsNeeded(Vec<BlobIdentifier>, Slot, Option<PeerId>),
    DataColumnsNeeded(DataColumnsByRootIdentifier<P>, Slot),
}

impl<P: Preset> BlobFetcherToP2p<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to p2p failed because the receiver was dropped");
        }
    }
}
