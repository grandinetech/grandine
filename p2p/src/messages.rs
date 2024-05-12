use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use bls::PublicKeyBytes;
use eth2_libp2p::{
    rpc::{GoodbyeReason, StatusMessage},
    types::{EnrForkId, GossipKind},
    GossipId, GossipTopic, MessageAcceptance, NetworkEvent, PeerAction, PeerId, PeerRequestId,
    PubsubMessage, ReportSource, Request, Response, Subnet, SubnetDiscovery,
};
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use log::debug;
use operation_pools::PoolRejectionReason;
use serde::Serialize;
use types::{
    altair::containers::{SignedContributionAndProof, SyncCommitteeMessage},
    combined::{Attestation, AttesterSlashing, SignedAggregateAndProof, SignedBeaconBlock},
    deneb::containers::{BlobIdentifier, BlobSidecar},
    nonstandard::Phase,
    phase0::{
        containers::{ProposerSlashing, SignedVoluntaryExit},
        primitives::{Epoch, ForkDigest, Slot, SubnetId, ValidatorIndex, H256},
    },
    preset::Preset,
};

use crate::{
    misc::{
        AttestationSubnetActions, BeaconCommitteeSubscription, PeerReportReason, RequestId,
        SyncCommitteeSubnetAction, SyncCommitteeSubscription,
    },
    network_api::{NodeIdentity, NodePeer, NodePeerCount, NodePeersQuery},
};

pub enum P2pToSync<P: Preset> {
    Slot(Slot),
    AddPeer(PeerId, StatusMessage),
    RemovePeer(PeerId),
    StatusPeer(PeerId),
    BlobsNeeded(Vec<BlobIdentifier>, Slot, Option<PeerId>),
    BlockNeeded(H256, Option<PeerId>),
    RequestedBlobSidecar(Arc<BlobSidecar<P>>, bool, PeerId),
    RequestedBlock((Arc<SignedBeaconBlock<P>>, PeerId, RequestId)),
    BlobsByRangeRequestFinished(RequestId),
    BlobsByRootChunkReceived(BlobIdentifier, PeerId, RequestId),
    BlocksByRangeRequestFinished(RequestId),
    BlockByRootRequestFinished(H256),
    DataColumnsByRangeRequestFinished(RequestId),
    RequestFailed(PeerId),
}

impl<P: Preset> P2pToSync<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to block sync service failed because the receiver was dropped");
        }
    }
}

#[derive(Serialize)]
#[serde(bound = "")]
pub enum ApiToP2p<P: Preset> {
    PublishBeaconBlock(Arc<SignedBeaconBlock<P>>),
    PublishBlobSidecar(Arc<BlobSidecar<P>>),
    PublishSingularAttestation(Arc<Attestation<P>>, SubnetId),
    PublishAggregateAndProof(Arc<SignedAggregateAndProof<P>>),
    PublishSyncCommitteeMessage(Box<(SubnetId, SyncCommitteeMessage)>),
    PublishProposerSlashing(Box<ProposerSlashing>),
    PublishAttesterSlashing(Box<AttesterSlashing<P>>),
    PublishVoluntaryExit(Box<SignedVoluntaryExit>),
    RequestIdentity(#[serde(skip)] Sender<NodeIdentity>),
    RequestPeer(PeerId, #[serde(skip)] Sender<Option<NodePeer>>),
    RequestPeerCount(#[serde(skip)] Sender<NodePeerCount>),
    RequestPeers(
        #[serde(skip)] NodePeersQuery,
        #[serde(skip)] Sender<Vec<NodePeer>>,
    ),
}

impl<P: Preset> ApiToP2p<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to p2p failed because the receiver was dropped");
        }
    }
}

pub enum SyncToApi {
    SyncStatus(bool),
    BackSyncStatus(bool),
}

impl SyncToApi {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to HTTP API failed because the receiver was dropped");
        }
    }
}

pub enum SyncToMetrics {
    SyncStatus(bool),
}

impl SyncToMetrics {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to metrics failed because the receiver was dropped");
        }
    }
}

pub enum SyncToP2p {
    PruneReceivedBlocks,
    ReportPeer(PeerId, PeerAction, ReportSource, PeerReportReason),
    RequestBlobsByRange(RequestId, PeerId, Slot, u64),
    RequestBlobsByRoot(RequestId, PeerId, Vec<BlobIdentifier>),
    RequestBlocksByRange(RequestId, PeerId, Slot, u64),
    RequestBlockByRoot(RequestId, PeerId, H256),
    RequestPeerStatus(RequestId, PeerId),
    SubscribeToCoreTopics,
}

impl SyncToP2p {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to p2p failed because the receiver was dropped");
        }
    }
}

pub enum ArchiverToSync {
    BackSyncStatesArchived,
}

impl ArchiverToSync {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to block sync service failed because the receiver was dropped");
        }
    }
}

#[derive(Serialize)]
#[serde(bound = "")]
pub enum ValidatorToP2p<P: Preset> {
    Accept(GossipId),
    Ignore(GossipId),
    Reject(GossipId, PoolRejectionReason),
    PublishBeaconBlock(Arc<SignedBeaconBlock<P>>),
    PublishBlobSidecar(Arc<BlobSidecar<P>>),
    PublishSingularAttestation(Arc<Attestation<P>>, SubnetId),
    PublishAggregateAndProof(Arc<SignedAggregateAndProof<P>>),
    PublishSyncCommitteeMessage(Box<(SubnetId, SyncCommitteeMessage)>),
    PublishContributionAndProof(Box<SignedContributionAndProof<P>>),
}

impl<P: Preset> ValidatorToP2p<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to p2p failed because the receiver was dropped");
        }
    }
}

pub enum P2pToValidator<P: Preset> {
    AttesterSlashing(Box<AttesterSlashing<P>>, GossipId),
    ProposerSlashing(Box<ProposerSlashing>, GossipId),
    VoluntaryExit(Box<SignedVoluntaryExit>, GossipId),
}

impl<P: Preset> P2pToValidator<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to validator failed because the receiver was dropped");
        }
    }
}

pub enum P2pToSlasher<P: Preset> {
    Attestation(Arc<Attestation<P>>),
    Block(Arc<SignedBeaconBlock<P>>),
}

impl<P: Preset> P2pToSlasher<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to slasher failed because the receiver was dropped");
        }
    }
}

pub enum ServiceInboundMessage<P: Preset> {
    DiscoverSubnetPeers(Vec<SubnetDiscovery>),
    GoodbyePeer(PeerId, GoodbyeReason, ReportSource),
    Publish(PubsubMessage<P>),
    ReportPeer(PeerId, PeerAction, ReportSource, &'static str),
    ReportMessageValidationResult(GossipId, MessageAcceptance),
    SendRequest(PeerId, RequestId, Request),
    SendResponse(PeerId, PeerRequestId, Box<Response<P>>),
    Subscribe(GossipTopic),
    SubscribeKind(GossipKind),
    SubscribeNewForkTopics(Phase, ForkDigest),
    Unsubscribe(GossipTopic),
    UnsubscribeFromForkTopicsExcept(ForkDigest),
    UpdateEnrSubnet(Subnet, bool),
    UpdateFork(EnrForkId),
    UpdateGossipsubParameters(u64, Slot),
}

impl<P: Preset> ServiceInboundMessage<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to network service failed because the receiver was dropped");
        }
    }
}

pub enum ServiceOutboundMessage<P: Preset> {
    NetworkEvent(NetworkEvent<RequestId, P>),
}

impl<P: Preset> ServiceOutboundMessage<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send from network service failed because the receiver was dropped");
        }
    }
}

#[derive(Serialize)]
pub enum SubnetServiceToP2p {
    // Use `BTreeMap` to make serialization deterministic for snapshot testing.
    // `Vec` would work too and would be slightly faster.
    UpdateAttestationSubnets(AttestationSubnetActions),
    UpdateSyncCommitteeSubnets(BTreeMap<SubnetId, SyncCommitteeSubnetAction>),
}

impl SubnetServiceToP2p {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to p2p failed because the receiver was dropped");
        }
    }
}

pub enum ToSubnetService {
    SetRegisteredValidators(Vec<PublicKeyBytes>, Vec<ValidatorIndex>),
    UpdateBeaconCommitteeSubscriptions(Slot, Vec<BeaconCommitteeSubscription>, Sender<Result<()>>),
    UpdateSyncCommitteeSubscriptions(Epoch, Vec<SyncCommitteeSubscription>),
}

impl ToSubnetService {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to subnet service failed because the receiver was dropped");
        }
    }
}
