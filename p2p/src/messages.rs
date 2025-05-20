use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use bls::PublicKeyBytes;
use eth2_libp2p::{
    rpc::{GoodbyeReason, RequestId as IncomingRequestId, RequestType, StatusMessage},
    types::{EnrForkId, GossipKind},
    GossipId, GossipTopic, MessageAcceptance, NetworkEvent, PeerAction, PeerId, PeerRequestId,
    PubsubMessage, ReportSource, Response, Subnet, SubnetDiscovery,
};
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use log::debug;
use operation_pools::PoolRejectionReason;
use serde::Serialize;
use ssz::ContiguousList;
use types::{
    altair::containers::{SignedContributionAndProof, SyncCommitteeMessage},
    combined::{Attestation, AttesterSlashing, SignedAggregateAndProof, SignedBeaconBlock},
    deneb::containers::{BlobIdentifier, BlobSidecar},
    fulu::{
        consts::NumberOfColumns,
        containers::{DataColumnIdentifier, DataColumnSidecar, DataColumnsByRootIdentifier},
        primitives::ColumnIndex,
    },
    nonstandard::Phase,
    phase0::{
        containers::{Checkpoint, ProposerSlashing, SignedVoluntaryExit},
        primitives::{Epoch, ForkDigest, Slot, SubnetId, ValidatorIndex, H256},
    },
    preset::Preset,
};

use crate::{
    misc::{
        AttestationSubnetActions, BeaconCommitteeSubscription, PeerReportReason, RPCRequestType,
        RequestId, SyncCommitteeSubnetAction, SyncCommitteeSubscription,
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
    DataColumnsNeeded(DataColumnsByRootIdentifier, Slot),
    RequestedBlobSidecar(Arc<BlobSidecar<P>>, PeerId, RequestId, RPCRequestType),
    RequestedBlock(Arc<SignedBeaconBlock<P>>, PeerId, RequestId, RPCRequestType),
    RequestedDataColumnSidecar(Arc<DataColumnSidecar<P>>, PeerId, RequestId, RPCRequestType),
    BlobsByRangeRequestFinished(RequestId),
    BlocksByRangeRequestFinished(PeerId, RequestId),
    DataColumnsByRangeRequestFinished(RequestId),
    RequestFailed(PeerId),
    FinalizedCheckpoint(Checkpoint),
    GossipBlobSidecar(Arc<BlobSidecar<P>>, SubnetId, GossipId),
    GossipBlock(Arc<SignedBeaconBlock<P>>, PeerId, GossipId),
    GossipDataColumnSidecar(Arc<DataColumnSidecar<P>>, SubnetId, GossipId),
    BlobSidecarRejected(BlobIdentifier),
    DataColumnSidecarRejected(DataColumnIdentifier),
    PeerCgcUpdated(PeerId),
    Stop,
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
    PublishDataColumnSidecar(Arc<DataColumnSidecar<P>>),
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
    Stop,
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
    Stop,
}

impl SyncToMetrics {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to metrics failed because the receiver was dropped");
        }
    }
}

pub enum SyncToP2p {
    ReportPeer(PeerId, PeerAction, ReportSource, PeerReportReason),
    RequestBlobsByRange(RequestId, PeerId, Slot, u64),
    RequestBlobsByRoot(RequestId, PeerId, Vec<BlobIdentifier>),
    RequestBlocksByRange(RequestId, PeerId, Slot, u64),
    RequestBlockByRoot(RequestId, PeerId, H256),
    RequestDataColumnsByRange(
        RequestId,
        PeerId,
        Slot,
        u64,
        Arc<ContiguousList<ColumnIndex, NumberOfColumns>>,
    ),
    RequestDataColumnsByRoot(RequestId, PeerId, Vec<DataColumnsByRootIdentifier>),
    RequestPeerStatus(RequestId, PeerId),
    SubscribeToCoreTopics,
    UpdateEarliestAvailableSlot(Slot),
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
    PublishDataColumnSidecar(Arc<DataColumnSidecar<P>>),
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
    AttemptToUpdateCustodyGroupCount(u64),
    DiscoverSubnetPeers(Vec<SubnetDiscovery>),
    GoodbyePeer(PeerId, GoodbyeReason, ReportSource),
    Publish(PubsubMessage<P>),
    ReportPeer(PeerId, PeerAction, ReportSource, &'static str),
    ReportMessageValidationResult(GossipId, MessageAcceptance),
    SendRequest(PeerId, RequestId, RequestType<P>),
    SendResponse(PeerId, PeerRequestId, IncomingRequestId, Box<Response<P>>),
    Subscribe(GossipTopic),
    SubscribeKind(GossipKind),
    SubscribeNewForkTopics(Phase, ForkDigest),
    Unsubscribe(GossipTopic),
    UnsubscribeFromForkTopicsExcept(ForkDigest),
    UpdateCustodyRequirements(Epoch, u64),
    UpdateEnrSubnet(Subnet, bool),
    UpdateFork(EnrForkId),
    UpdateGossipsubParameters(u64, Slot),
    UpdateNextForkDigest(ForkDigest, Epoch),
    Stop,
}

impl<P: Preset> ServiceInboundMessage<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        // panic if network thread is no longer running
        tx.unbounded_send(self)
            .expect("send to network service failed because the receiver was dropped");
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
    AttemptToUpdateCustodyGroupCount(u64),
    UpdateAttestationSubnets(AttestationSubnetActions),
    UpdateCustodyRequirements(Epoch, u64),
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
    AttemptToUpdateCustodyGroupCount(u64),
    SetRegisteredValidators(Vec<PublicKeyBytes>, Vec<ValidatorIndex>),
    UpdateBeaconCommitteeSubscriptions(Slot, Vec<BeaconCommitteeSubscription>, Sender<Result<()>>),
    UpdateCustodyRequirements(Epoch, u64),
    UpdateSyncCommitteeSubscriptions(Epoch, Vec<SyncCommitteeSubscription>),
}

impl ToSubnetService {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send to subnet service failed because the receiver was dropped");
        }
    }
}
