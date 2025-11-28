use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use bls::PublicKeyBytes;
use eth2_libp2p::{
    rpc::{GoodbyeReason, InboundRequestId, RequestType, RpcErrorResponse, StatusMessage},
    service::api_types::AppRequestId,
    types::{EnrForkId, GossipKind},
    GossipId, GossipTopic, MessageAcceptance, NetworkEvent, PeerAction, PeerId, PubsubMessage,
    ReportSource, Response, Subnet, SubnetDiscovery,
};
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use logging::debug_with_peers;
use operation_pools::PoolRejectionReason;
use serde::Serialize;
use ssz::ContiguousList;
use types::{
    altair::containers::{SignedContributionAndProof, SyncCommitteeMessage},
    combined::{
        Attestation, AttesterSlashing, DataColumnSidecar, SignedAggregateAndProof,
        SignedBeaconBlock,
    },
    deneb::containers::{BlobIdentifier, BlobSidecar},
    fulu::{
        containers::{DataColumnIdentifier, DataColumnsByRootIdentifier},
        primitives::ColumnIndex,
    },
    gloas::containers::{
        PayloadAttestationMessage, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
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
    DataColumnsNeeded(DataColumnsByRootIdentifier<P>, Slot),
    RequestedBlobSidecar(Arc<BlobSidecar<P>>, PeerId, AppRequestId, RPCRequestType),
    RequestedBlock(
        Arc<SignedBeaconBlock<P>>,
        PeerId,
        AppRequestId,
        RPCRequestType,
    ),
    RequestedDataColumnSidecar(
        Arc<DataColumnSidecar<P>>,
        PeerId,
        AppRequestId,
        RPCRequestType,
    ),
    RequestedExecutionPayloadEnvelope(
        Arc<SignedExecutionPayloadEnvelope<P>>,
        PeerId,
        AppRequestId,
        RPCRequestType,
    ),
    BlobsByRangeRequestFinished(AppRequestId),
    BlocksByRangeRequestFinished(PeerId, AppRequestId),
    DataColumnsByRangeRequestFinished(AppRequestId),
    ExecutionPayloadEnvelopesByRangeRequestFinished(PeerId, AppRequestId),
    RequestFailed(PeerId),
    FinalizedCheckpoint(Checkpoint),
    GossipBlobSidecar(Arc<BlobSidecar<P>>, SubnetId, GossipId),
    GossipBlock(Arc<SignedBeaconBlock<P>>, PeerId, GossipId),
    GossipDataColumnSidecar(Arc<DataColumnSidecar<P>>, SubnetId, GossipId),
    BlobSidecarRejected(BlobIdentifier),
    DataColumnSidecarRejected(DataColumnIdentifier),
    PeerCgcUpdated(PeerId),
    RequestCustodyGroupBackfill(HashSet<u64>, Slot),
    Stop,
}

impl<P: Preset> P2pToSync<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug_with_peers!("send to block sync service failed because the receiver was dropped");
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(bound = "")]
pub enum ApiToP2p<P: Preset> {
    PublishBeaconBlock(Arc<SignedBeaconBlock<P>>),
    PublishBlobSidecar(Arc<BlobSidecar<P>>),
    PublishDataColumnSidecar(Arc<DataColumnSidecar<P>>),
    PublishSingularAttestation(Arc<Attestation<P>>, SubnetId),
    PublishAggregateAndProof(Arc<SignedAggregateAndProof<P>>),
    PublishSyncCommitteeMessage(Box<(SubnetId, SyncCommitteeMessage)>),
    PublishPayloadBid(Arc<SignedExecutionPayloadBid>),
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
            debug_with_peers!("send to p2p failed because the receiver was dropped");
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
            debug_with_peers!("send to HTTP API failed because the receiver was dropped");
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
            debug_with_peers!("send to metrics failed because the receiver was dropped");
        }
    }
}

#[derive(Debug)]
pub enum SyncToP2p<P: Preset> {
    ReportPeer(PeerId, PeerAction, ReportSource, PeerReportReason),
    RequestBlobsByRange(AppRequestId, PeerId, Slot, u64),
    RequestBlobsByRoot(AppRequestId, PeerId, Vec<BlobIdentifier>),
    RequestBlocksByRange(AppRequestId, PeerId, Slot, u64),
    RequestBlockByRoot(AppRequestId, PeerId, H256),
    RequestDataColumnsByRange(
        AppRequestId,
        PeerId,
        Slot,
        u64,
        Arc<ContiguousList<ColumnIndex, P::NumberOfColumns>>,
    ),
    RequestExecutionPayloadEnvelopesByRange(AppRequestId, PeerId, Slot, u64),
    RequestExecutionPayloadEnvelopesByRoot(AppRequestId, PeerId, Vec<H256>),
    RequestDataColumnsByRoot(AppRequestId, PeerId, Vec<DataColumnsByRootIdentifier<P>>),
    RequestPeerStatus(AppRequestId, PeerId),
    SubscribeToCoreTopics,
    UpdateEarliestAvailableSlot(Slot),
}

impl<P: Preset> SyncToP2p<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug_with_peers!("send to p2p failed because the receiver was dropped");
        }
    }
}

pub enum ArchiverToSync {
    BackSyncStatesArchived,
}

impl ArchiverToSync {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug_with_peers!("send to block sync service failed because the receiver was dropped");
        }
    }
}

pub enum BlockSyncServiceMessage {
    RequestData,
}

impl BlockSyncServiceMessage {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug_with_peers!("send to block sync service failed because the receiver was dropped");
        }
    }
}

#[derive(Debug, Serialize)]
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
    PublishPayloadAttestation(Arc<PayloadAttestationMessage>),
    UpdateDataColumnSubnets(u64),
}

impl<P: Preset> ValidatorToP2p<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug_with_peers!("send to p2p failed because the receiver was dropped");
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
            debug_with_peers!("send to validator failed because the receiver was dropped");
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
            debug_with_peers!("send to slasher failed because the receiver was dropped");
        }
    }
}

#[derive(Debug)]
pub enum ServiceInboundMessage<P: Preset> {
    DiscoverSubnetPeers(Vec<SubnetDiscovery>),
    GoodbyePeer(PeerId, GoodbyeReason, ReportSource),
    Publish(PubsubMessage<P>),
    ReportPeer(PeerId, PeerAction, ReportSource, &'static str),
    ReportMessageValidationResult(GossipId, MessageAcceptance),
    SendErrorResponse(PeerId, InboundRequestId, RpcErrorResponse, &'static str),
    SendRequest(PeerId, AppRequestId, RequestType<P>),
    SendResponse(PeerId, InboundRequestId, Box<Response<P>>),
    Subscribe(GossipTopic),
    SubscribeKind(GossipKind),
    SubscribeNewForkTopics(Phase, ForkDigest),
    Unsubscribe(GossipTopic),
    UnsubscribeFromForkTopicsExcept(ForkDigest),
    UpdateDataColumnSubnets(u64),
    UpdateEnrCgc(u64),
    UpdateEnrSubnet(Subnet, bool),
    UpdateFork(EnrForkId),
    UpdateGossipsubParameters(u64, Slot),
    UpdateNextForkDigest(ForkDigest),
    Stop,
}

impl<P: Preset> ServiceInboundMessage<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        // panic if network thread is no longer running
        tx.unbounded_send(self)
            .expect("send to network service failed because the receiver was dropped");
    }
}

#[derive(Debug)]
pub enum ServiceOutboundMessage<P: Preset> {
    NetworkEvent(NetworkEvent<P>),
}

impl<P: Preset> ServiceOutboundMessage<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug_with_peers!("send from network service failed because the receiver was dropped");
        }
    }
}

#[derive(Debug, Serialize)]
pub enum SubnetServiceToP2p {
    // Use `BTreeMap` to make serialization deterministic for snapshot testing.
    // `Vec` would work too and would be slightly faster.
    UpdateAttestationSubnets(AttestationSubnetActions),
    UpdateSyncCommitteeSubnets(BTreeMap<SubnetId, SyncCommitteeSubnetAction>),
}

impl SubnetServiceToP2p {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug_with_peers!("send to p2p failed because the receiver was dropped");
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
            debug_with_peers!("send to subnet service failed because the receiver was dropped");
        }
    }
}
