use std::sync::Arc;

use eth2_libp2p::PeerId;
use futures::channel::mpsc::UnboundedSender;
use log::debug;
use serde::Serialize;
use types::{
    combined::SignedBeaconBlock, deneb::containers::BlobIdentifier, phase0::primitives::Slot,
    preset::Preset,
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
    GetBlobs {
        block: Arc<SignedBeaconBlock<P>>,
        blob_identifiers: Vec<BlobIdentifier>,
        peer_id: Option<PeerId>,
    },
}

impl<P: Preset> Eth1ApiToBlobFetcher<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to blob fetcher failed because the receiver was dropped");
        }
    }
}

#[derive(Serialize)]
pub enum BlobFetcherToP2p {
    BlobsNeeded(Vec<BlobIdentifier>, Slot, Option<PeerId>),
}

impl BlobFetcherToP2p {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to p2p failed because the receiver was dropped");
        }
    }
}
