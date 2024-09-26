use core::{cmp::Ordering, convert::Infallible as Never, fmt::Display, time::Duration};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::Instant,
};

use anyhow::{bail, Result};
use dedicated_executor::DedicatedExecutor;
use enum_iterator::Sequence as _;
use eth1_api::RealController;
use eth2_libp2p::{
    rpc::{
        methods::{
            BlobsByRangeRequest, BlobsByRootRequest, BlocksByRangeRequest, BlocksByRootRequest,
            DataColumnsByRangeRequest, DataColumnsByRootRequest, MaxRequestDataColumnSidecars,
        },
        GoodbyeReason, StatusMessage,
    },
    service::Network as Service,
    types::{core_topics_to_subscribe, EnrForkId, ForkContext, GossipEncoding},
    Context, GossipId, GossipTopic, MessageAcceptance, MessageId, NetworkConfig, NetworkEvent,
    NetworkGlobals, PeerAction, PeerId, PeerRequestId, PubsubMessage, ReportSource, Request,
    Response, ShutdownReason, Subnet, SubnetDiscovery, SyncInfo, SyncStatus, TaskExecutor,
};
use fork_choice_control::P2pMessage;
use futures::{
    channel::mpsc::{self, Receiver, UnboundedReceiver, UnboundedSender},
    future::FutureExt as _,
    select,
    stream::StreamExt as _,
};
use helper_functions::misc;
use log::{debug, error, log, warn, Level};
use operation_pools::{BlsToExecutionChangePool, Origin, PoolToP2pMessage, SyncCommitteeAggPool};
use prometheus_client::registry::Registry;
use prometheus_metrics::Metrics;
use rand::seq::SliceRandom;
use rand::thread_rng;
use slog::{o, Drain as _, Logger};
use slog_stdlog::StdLog;
use ssz::ContiguousList;
use std_ext::ArcExt as _;
use thiserror::Error;
use typenum::Unsigned as _;
use types::{
    altair::containers::{SignedContributionAndProof, SyncCommitteeMessage},
    capella::containers::SignedBlsToExecutionChange,
    combined::SignedBeaconBlock,
    deneb::containers::{BlobIdentifier, BlobSidecar},
    eip7594::{ColumnIndex, DataColumnIdentifier, DataColumnSidecar},
    nonstandard::{Phase, WithStatus},
    phase0::{
        consts::{FAR_FUTURE_EPOCH, GENESIS_EPOCH},
        containers::{
            Attestation, AttesterSlashing, ProposerSlashing, SignedAggregateAndProof,
            SignedVoluntaryExit,
        },
        primitives::{Epoch, ForkDigest, NodeId, Slot, SubnetId, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::{
    messages::{
        ApiToP2p, P2pToAttestationVerifier, P2pToSlasher, P2pToSync, P2pToValidator,
        ServiceInboundMessage, ServiceOutboundMessage, SubnetServiceToP2p, SyncToP2p,
        ValidatorToP2p,
    },
    misc::{AttestationSubnetActions, RequestId, SubnetPeerDiscovery, SyncCommitteeSubnetAction},
    upnp::PortMappings,
};

const MAX_FOR_DOS_PREVENTION: u64 = 64;

/// Number of slots before a new phase to subscribe to its topics.
///
/// The number 5 was chosen arbitrarily.
/// The behavior is specified in the [Networking specification] but the exact number is not:
/// > In advance of the fork, a node SHOULD subscribe to the post-fork variants of the topics.
///
/// Lighthouse uses the number 2 with no explanation why:
/// - <https://github.com/sigp/lighthouse/blob/bf533c8e42cc73c35730e285c21df8add0195369/beacon_node/network/src/service.rs#L42>
/// - <https://github.com/sigp/lighthouse/pull/2532>
///
/// [Networking specification]: https://github.com/ethereum/consensus-specs/blob/9839ed49346a85f95af4f8b0cb9c4d98b2308af8/specs/altair/p2p-interface.md#transitioning-the-gossip
const NEW_PHASE_TOPICS_ADVANCE_SLOTS: u64 = 5;

/// Number of epochs to remain subscribed to the topics of previous phases as defined in:
/// <https://github.com/ethereum/consensus-specs/blob/9839ed49346a85f95af4f8b0cb9c4d98b2308af8/specs/altair/p2p-interface.md#transitioning-the-gossip>
const OLD_PHASE_TOPICS_REMAIN_EPOCHS: u64 = 2;

pub struct Channels<P: Preset> {
    pub api_to_p2p_rx: UnboundedReceiver<ApiToP2p<P>>,
    pub fork_choice_to_p2p_rx: UnboundedReceiver<P2pMessage<P>>,
    pub pool_to_p2p_rx: UnboundedReceiver<PoolToP2pMessage>,
    pub p2p_to_attestation_verifier_tx: UnboundedSender<P2pToAttestationVerifier<P>>,
    pub p2p_to_sync_tx: UnboundedSender<P2pToSync<P>>,
    pub p2p_to_validator_tx: UnboundedSender<P2pToValidator<P>>,
    pub sync_to_p2p_rx: UnboundedReceiver<SyncToP2p>,
    pub validator_to_p2p_rx: UnboundedReceiver<ValidatorToP2p<P>>,
    pub network_to_slasher_tx: Option<UnboundedSender<P2pToSlasher<P>>>,
    pub subnet_service_to_p2p_rx: UnboundedReceiver<SubnetServiceToP2p>,
}

#[allow(clippy::struct_field_names)]
pub struct Network<P: Preset> {
    network_globals: Arc<NetworkGlobals>,
    received_blob_sidecars: HashMap<BlobIdentifier, Slot>,
    received_block_roots: HashMap<H256, Slot>,
    received_data_column_sidecars: HashMap<DataColumnIdentifier, Slot>,
    controller: RealController<P>,
    channels: Channels<P>,
    dedicated_executor: Arc<DedicatedExecutor>,
    sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P>>,
    bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
    // TODO(Grandine Team): Is there a good reason to keep the `ForkContext` around?
    //                      The current fork can be determined from `Network.controller`
    //                      (or whatever replaces it). Fork digests can easily be computed from a
    //                      state obtained from one of the controllers.
    fork_context: Arc<ForkContext>,
    metrics: Option<Arc<Metrics>>,
    network_to_service_tx: UnboundedSender<ServiceInboundMessage<P>>,
    service_to_network_rx: UnboundedReceiver<ServiceOutboundMessage<P>>,
    shutdown_rx: Receiver<ShutdownReason>,
    target_peers: usize,
    #[allow(dead_code)]
    port_mappings: Option<PortMappings>,
}

impl<P: Preset> Network<P> {
    #[must_use]
    pub const fn network_globals(&self) -> &Arc<NetworkGlobals> {
        &self.network_globals
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        network_config: &NetworkConfig,
        controller: RealController<P>,
        slot: Slot,
        channels: Channels<P>,
        dedicated_executor: Arc<DedicatedExecutor>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P>>,
        bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
        metrics: Option<Arc<Metrics>>,
        libp2p_registry: Option<&mut Registry>,
    ) -> Result<Self> {
        let chain_config = controller.chain_config().as_ref();
        let head_state = controller.head_state().value;

        let fork_context = Arc::new(ForkContext::new::<P>(
            chain_config,
            slot,
            head_state.genesis_validators_root(),
        ));

        let enr_fork_id = Self::enr_fork_id(&controller, &fork_context, slot);
        let logger = Logger::root(StdLog.fuse(), o!());
        let (shutdown_tx, shutdown_rx) = futures::channel::mpsc::channel(1);
        let executor = TaskExecutor::new(logger.clone(), shutdown_tx);

        let context = Context {
            config: network_config,
            enr_fork_id,
            fork_context: fork_context.clone_arc(),
            libp2p_registry,
        };

        // Box the future to pass `clippy::large_futures`.
        let (service, network_globals) =
            Box::pin(Service::new(chain_config, executor, context, &logger)).await?;

        let mut port_mappings = None;

        if network_config.upnp_enabled && !network_config.disable_discovery {
            match PortMappings::new(network_config) {
                Ok(mappings) => port_mappings = Some(mappings),
                Err(error) => warn!("error while initializing UPnP: {error}"),
            }
        }

        let (network_to_service_tx, network_to_service_rx) = mpsc::unbounded();
        let (service_to_network_tx, service_to_network_rx) = mpsc::unbounded();

        run_network_service(service, network_to_service_rx, service_to_network_tx);

        let network = Self {
            network_globals,
            received_blob_sidecars: HashMap::new(),
            received_block_roots: HashMap::new(),
            received_data_column_sidecars: HashMap::new(),
            controller,
            channels,
            dedicated_executor,
            sync_committee_agg_pool,
            bls_to_execution_change_pool,
            fork_context,
            metrics,
            network_to_service_tx,
            service_to_network_rx,
            shutdown_rx,
            target_peers: network_config.target_peers,
            port_mappings,
        };

        Ok(network)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn run(mut self) -> Result<Never> {
        loop {
            select! {
                message = self.service_to_network_rx.select_next_some() => {
                    match message {
                        ServiceOutboundMessage::NetworkEvent(network_event) => {
                            self.handle_network_event(network_event)
                        }
                    }
                },

                message = self.channels.api_to_p2p_rx.select_next_some() => {
                    let success = match message {
                        ApiToP2p::PublishBeaconBlock(beacon_block) => {
                            self.publish_beacon_block(beacon_block);
                            true
                        },
                        ApiToP2p::PublishBlobSidecar(blob_sidecar) => {
                            self.publish_blob_sidecar(blob_sidecar);
                            true
                        },
                        ApiToP2p::PublishDataColumnSidecars(data_column_sidecars) => {
                            self.publish_data_column_sidecars(data_column_sidecars);
                            true
                        },
                        ApiToP2p::PublishAggregateAndProof(aggregate_and_proof) => {
                            self.publish_aggregate_and_proof(aggregate_and_proof);
                            true
                        }
                        ApiToP2p::PublishSingularAttestation(attestation, subnet_id) => {
                            self.publish_singular_attestation(attestation, subnet_id);
                            true
                        }
                        ApiToP2p::PublishSyncCommitteeMessage(message) => {
                            self.publish_sync_committee_message(message);
                            true
                        }
                        ApiToP2p::RequestIdentity(receiver) => {
                            receiver.send(self.node_identity()).is_ok()
                        },
                        ApiToP2p::RequestPeer(peer_id, receiver) => {
                            receiver.send(self.node_peer(&peer_id)).is_ok()
                        },
                        ApiToP2p::RequestPeerCount(receiver) => {
                            receiver.send(self.node_peer_count()).is_ok()
                        },
                        ApiToP2p::RequestPeers(query, receiver) => {
                            receiver.send(self.node_peers(&query)).is_ok()
                        },
                    };

                    if !success {
                        debug!("send to HTTP API failed because the receiver was dropped");
                    }
                },

                message = self.channels.pool_to_p2p_rx.select_next_some() => {
                    match message {
                        PoolToP2pMessage::Accept(gossip_id) => {
                            self.report_outcome(gossip_id, MessageAcceptance::Accept);
                        },
                        PoolToP2pMessage::Ignore(gossip_id) => {
                            self.report_outcome(gossip_id, MessageAcceptance::Ignore);
                        },
                        PoolToP2pMessage::Reject(gossip_id, pool_rejection_reason) => {
                            self.report_outcome(gossip_id.clone(), MessageAcceptance::Reject);
                            self.report_peer(
                                gossip_id.source,
                                PeerAction::LowToleranceError,
                                ReportSource::Processor,
                                pool_rejection_reason,
                            );
                        },
                        PoolToP2pMessage::PublishSignedBlsToExecutionChange(signed_bls_to_execution_change) => {
                            self.publish_signed_bls_to_execution_change(signed_bls_to_execution_change);
                        },
                    }
                },

                message = self.channels.fork_choice_to_p2p_rx.select_next_some() => {
                    match message {
                        P2pMessage::Slot(slot) => {
                            self.on_slot(slot);
                            self.track_collection_metrics();
                        }
                        P2pMessage::Accept(gossip_id) => {
                            self.report_outcome(gossip_id, MessageAcceptance::Accept);
                        }
                        P2pMessage::Ignore(gossip_id) => {
                            self.report_outcome(gossip_id, MessageAcceptance::Ignore);
                        }
                        P2pMessage::Reject(gossip_id, mutator_rejection_reason) => {
                            self.report_outcome(gossip_id.clone(), MessageAcceptance::Reject);
                            self.report_peer(
                                gossip_id.source,
                                PeerAction::LowToleranceError,
                                ReportSource::Processor,
                                mutator_rejection_reason,
                            );
                        }
                        P2pMessage::BlobsNeeded(identifiers, slot, peer_id) => {
                            if let Some(peer_id) = peer_id {
                                self.log(
                                    Level::Debug,
                                    format_args!("blobs needed: {identifiers:?} from {peer_id}"),
                                );
                            } else {
                                self.log(
                                    Level::Debug,
                                    format_args!("blobs needed: {identifiers:?}"),
                                );
                            }

                            let peer_id = self.ensure_peer_connected(peer_id);

                            P2pToSync::BlobsNeeded(identifiers, slot, peer_id)
                                .send(&self.channels.p2p_to_sync_tx);
                        }
                        P2pMessage::DataColumnsNeeded(identifiers, slot, peer_id) => {
                            if let Some(peer_id) = peer_id {
                                self.log(
                                    Level::Debug,
                                    format_args!("data columns needed: {identifiers:?} from {peer_id}"),
                                );
                            } else {
                                self.log(
                                    Level::Debug,
                                    format_args!("data columns needed: {identifiers:?}"),
                                );
                            }

                            let peer_id = self.ensure_peer_connected(peer_id);

                            P2pToSync::DataColumnsNeeded(identifiers, slot, peer_id)
                                .send(&self.channels.p2p_to_sync_tx);
                        }
                        P2pMessage::BlockNeeded(root, peer_id) => {
                            if let Some(peer_id) = peer_id {
                                self.log(
                                    Level::Debug,
                                    format_args!("block needed: {root:?} from {peer_id}"),
                                );
                            } else {
                                self.log(
                                    Level::Debug,
                                    format_args!("block needed: {root:?}"),
                                );
                            }

                            let peer_id = self.ensure_peer_connected(peer_id);

                            P2pToSync::BlockNeeded(root, peer_id)
                                .send(&self.channels.p2p_to_sync_tx);
                        }
                        P2pMessage::FinalizedCheckpoint(finalized_checkpoint) => {
                            self.prune_received_blob_sidecars(finalized_checkpoint.epoch);
                            self.prune_received_block_roots(finalized_checkpoint.epoch);
                            self.prune_received_data_column_sidecars(finalized_checkpoint.epoch);

                            P2pToSync::FinalizedEpoch(self.controller.finalized_epoch()).send(&self.channels.p2p_to_sync_tx);
                        }
                        P2pMessage::HeadState(state) => {
                            P2pToSync::HeadState(state).send(&self.channels.p2p_to_sync_tx);
                        }
                        P2pMessage::ReverifyGossipAttestation(attestation, subnet_id, gossip_id) => {
                            P2pToAttestationVerifier::GossipAttestation(attestation, subnet_id, gossip_id)
                                .send(&self.channels.p2p_to_attestation_verifier_tx);
                        }
                    }
                },

                message = self.channels.validator_to_p2p_rx.select_next_some() => {
                    match message {
                        ValidatorToP2p::Accept(gossip_id) => {
                            self.report_outcome(gossip_id, MessageAcceptance::Accept);
                        }
                        ValidatorToP2p::Ignore(gossip_id) => {
                            self.report_outcome(gossip_id, MessageAcceptance::Ignore);
                        }
                        ValidatorToP2p::Reject(gossip_id, pool_rejection_reason) => {
                            self.report_outcome(gossip_id.clone(), MessageAcceptance::Reject);
                            self.report_peer(
                                gossip_id.source,
                                PeerAction::LowToleranceError,
                                ReportSource::Processor,
                                pool_rejection_reason,
                            );
                        }
                        ValidatorToP2p::PublishBeaconBlock(beacon_block) => {
                            self.publish_beacon_block(beacon_block);
                        }
                        ValidatorToP2p::PublishBlobSidecar(blob_sidecar) => {
                            self.publish_blob_sidecar(blob_sidecar);
                        }
                        ValidatorToP2p::PublishDataColumnSidecars(data_column_sidecars) => {
                            self.publish_data_column_sidecars(data_column_sidecars);
                        }
                        ValidatorToP2p::PublishSingularAttestation(attestation, subnet_id) => {
                            self.publish_singular_attestation(attestation, subnet_id);
                        }
                        ValidatorToP2p::PublishAggregateAndProof(aggregate_and_proof) => {
                            self.publish_aggregate_and_proof(aggregate_and_proof);
                        }
                        ValidatorToP2p::PublishProposerSlashing(proposer_slashing) => {
                            self.publish_proposer_slashing(proposer_slashing);
                        }
                        ValidatorToP2p::PublishAttesterSlashing(attester_slashing) => {
                            self.publish_attester_slashing(attester_slashing);
                        }
                        ValidatorToP2p::PublishVoluntaryExit(voluntary_exit) => {
                            self.publish_voluntary_exit(voluntary_exit);
                        }
                        ValidatorToP2p::PublishSyncCommitteeMessage(message) => {
                            self.publish_sync_committee_message(message);
                        }
                        ValidatorToP2p::PublishContributionAndProof(contribution_and_proof) => {
                            self.publish_contribution_and_proof(contribution_and_proof);
                        }
                    }
                },

                message = self.channels.sync_to_p2p_rx.select_next_some() => {
                    match message {
                        SyncToP2p::RequestBlobsByRange(request_id, peer_id, start_slot, count) => {
                            self.request_blobs_by_range(request_id, peer_id, start_slot, count);
                        }
                        SyncToP2p::RequestBlobsByRoot(request_id, peer_id, identifiers) => {
                            self.request_blobs_by_root(request_id, peer_id, identifiers);
                        }
                        SyncToP2p::RequestBlocksByRange(request_id, peer_id, start_slot, count) => {
                            self.request_blocks_by_range(request_id, peer_id, start_slot, count);
                        }
                        SyncToP2p::RequestBlockByRoot(request_id, peer_id, block_root) => {
                            self.request_block_by_root(request_id, peer_id, block_root);
                        }
                        SyncToP2p::RequestDataColumnsByRoot(request_id, peer_id, identifiers) => {
                            self.request_data_columns_by_root(request_id, peer_id, identifiers);
                        }
                        SyncToP2p::RequestDataColumnsByRange(request_id, peer_id, start_slot, count) => {
                            self.request_data_columns_by_range(request_id, peer_id, start_slot, count);
                        }
                        SyncToP2p::RequestPeerStatus(request_id, peer_id) => {
                            self.request_peer_status(request_id, peer_id);
                        }
                        SyncToP2p::SubscribeToCoreTopics => {
                            self.subscribe_to_core_topics();
                        }
                        SyncToP2p::SubscribeToDataColumnTopics => {
                            self.subscribe_to_data_column_topics();
                        }
                        SyncToP2p::PruneReceivedBlocks => {
                            self.received_block_roots = HashMap::new();
                        }
                    }
                },

                message = self.channels.subnet_service_to_p2p_rx.select_next_some() => {
                    match message {
                        SubnetServiceToP2p::UpdateAttestationSubnets(actions) => {
                            self.update_attestation_subnets(actions);
                        }
                        SubnetServiceToP2p::UpdateSyncCommitteeSubnets(actions) => {
                            self.update_sync_committee_subnets(actions);
                        }
                    }
                },

                shutdown_reason = self.shutdown_rx.select_next_some() => match shutdown_reason {
                    ShutdownReason::Failure(message) => {
                        bail!("eth2_libp2p initiated shutdown: {message}");
                    }
                }
            }
        }
    }

    fn on_slot(&self, slot: Slot) {
        P2pToSync::Slot(slot).send(&self.channels.p2p_to_sync_tx);

        let chain_config = self.controller.chain_config();
        let phase_by_slot = chain_config.phase_at_slot::<P>(slot);
        let phase_by_state = self.fork_context.current_fork();

        self.fork_context.update_current_fork(phase_by_slot);

        if phase_by_slot != phase_by_state {
            self.log(
                Level::Info,
                format_args!("switching from {phase_by_state} to {phase_by_slot}"),
            );

            let new_enr_fork_id = Self::enr_fork_id(&self.controller, &self.fork_context, slot);

            ServiceInboundMessage::UpdateForkVersion(new_enr_fork_id)
                .send(&self.network_to_service_tx);
        }

        // Subscribe to the topics of the next phase.
        if let Some(next_phase) = chain_config.next_phase_at_slot::<P>(slot) {
            let next_phase_slot = chain_config
                .fork_slot::<P>(next_phase)
                .expect("Config::next_phase_at_slot ensures that the phase is enabled");

            if slot + NEW_PHASE_TOPICS_ADVANCE_SLOTS == next_phase_slot {
                if let Some(fork_digest) = self.fork_context.to_context_bytes(next_phase) {
                    self.log(
                        Level::Info,
                        format_args!("subscribing to new topics from {next_phase}"),
                    );

                    ServiceInboundMessage::SubscribeNewForkTopics(next_phase, fork_digest)
                        .send(&self.network_to_service_tx);
                }
            }
        }

        if Some(phase_by_slot) > Phase::first() && misc::is_epoch_start::<P>(slot) {
            let epoch = misc::compute_epoch_at_slot::<P>(slot);

            // Unsubscribe from the topics of previous phases.
            if chain_config.fork_epoch(phase_by_slot) + OLD_PHASE_TOPICS_REMAIN_EPOCHS == epoch {
                if let Some(fork_digest) = self.fork_context.to_context_bytes(phase_by_slot) {
                    self.log(Level::Info, "unsubscribing from old topics");

                    ServiceInboundMessage::UnsubscribeFromForkTopicsExcept(fork_digest)
                        .send(&self.network_to_service_tx);
                }
            }
        }
    }

    // See <https://github.com/ethereum/consensus-specs/blob/9839ed49346a85f95af4f8b0cb9c4d98b2308af8/specs/phase0/p2p-interface.md#eth2-field>.
    #[must_use]
    pub fn enr_fork_id(
        controller: &RealController<P>,
        fork_context: &Arc<ForkContext>,
        slot: Slot,
    ) -> EnrForkId {
        let chain_config = controller.chain_config().as_ref();

        let next_fork_version;
        let next_fork_epoch;

        if let Some(next_phase) = chain_config.next_phase_at_slot::<P>(slot) {
            next_fork_version = chain_config.version(next_phase);
            next_fork_epoch = chain_config.fork_epoch(next_phase);
        } else {
            // > If no future fork is planned,
            // > set `next_fork_version = current_fork_version` to signal this fact
            //
            // > `current_fork_version` is the fork version at the node's current epoch defined \
            // > by the wall-clock time (not necessarily the epoch to which the node is sync)
            next_fork_version = chain_config.version(chain_config.phase_at_slot::<P>(slot));
            // > If no future fork is planned,
            // > set `next_fork_epoch = FAR_FUTURE_EPOCH` to signal this fact
            next_fork_epoch = FAR_FUTURE_EPOCH;
        }

        EnrForkId {
            fork_digest: fork_digest(fork_context),
            next_fork_version,
            next_fork_epoch,
        }
    }

    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId::from_be_bytes(self.network_globals.local_enr().node_id().raw())
    }

    #[must_use]
    pub fn get_custodial_peers(&self, column_index: ColumnIndex) -> Vec<PeerId> {
        self.network_globals()
            .custody_peers_for_column(column_index)
    }

    #[must_use]
    pub fn get_random_custodial_peer(&self, column_index: ColumnIndex) -> Option<PeerId> {
        self.get_custodial_peers(column_index)
            .choose(&mut thread_rng())
            .cloned()
    }

    fn publish_beacon_block(&self, beacon_block: Arc<SignedBeaconBlock<P>>) {
        self.log(
            Level::Debug,
            format_args!("publishing beacon block: {beacon_block:?}"),
        );

        self.publish(PubsubMessage::BeaconBlock(beacon_block));
    }

    fn publish_blob_sidecar(&self, blob_sidecar: Arc<BlobSidecar<P>>) {
        let subnet_id = misc::compute_subnet_for_blob_sidecar(blob_sidecar.index);
        let blob_identifier: BlobIdentifier = blob_sidecar.as_ref().into();

        self.log(
            Level::Debug,
            format_args!("publishing blob sidecar: {blob_identifier:?}, subnet_id: {subnet_id}"),
        );

        self.publish(PubsubMessage::BlobSidecar(Box::new((
            subnet_id,
            blob_sidecar,
        ))));
    }

    fn publish_data_column_sidecars(&self, data_column_sidecars: Vec<Arc<DataColumnSidecar<P>>>) {
        let messages = data_column_sidecars
            .into_iter()
            .map(|data_column_sidecar| {
                PubsubMessage::DataColumnSidecar(Box::new((
                    misc::compute_subnet_for_data_column_sidecar(data_column_sidecar.index),
                    data_column_sidecar,
                )))
            })
            .collect::<Vec<_>>();

        self.log(
            Level::Debug,
            format_args!("publishing data column sidecars: {messages:?}"),
        );

        self.publish_batch(messages);
    }

    fn publish_singular_attestation(&self, attestation: Arc<Attestation<P>>, subnet_id: SubnetId) {
        if attestation.aggregation_bits.count_ones() != 1 {
            self.log(
                Level::Error,
                format_args!(
                    "attempted to publish singular attestation \
                     with invalid number of participants: {attestation:?}",
                ),
            );
            return;
        }

        self.log(
            Level::Debug,
            format_args!(
                "publishing singular attestation \
                 (attestation: {attestation:?}, subnet_id: {subnet_id})",
            ),
        );

        self.publish(PubsubMessage::Attestation(subnet_id, attestation));
    }

    fn publish_aggregate_and_proof(&self, aggregate_and_proof: Box<SignedAggregateAndProof<P>>) {
        if aggregate_and_proof
            .message
            .aggregate
            .aggregation_bits
            .not_any()
        {
            self.log(
                Level::Error,
                format_args!(
                    "attempted to publish aggregate and proof with no participants: \
                     {aggregate_and_proof:?}",
                ),
            );
            return;
        }

        self.log(
            Level::Debug,
            format_args!("publishing aggregate and proof: {aggregate_and_proof:?}"),
        );

        self.publish(PubsubMessage::AggregateAndProofAttestation(
            aggregate_and_proof,
        ));
    }

    fn publish_proposer_slashing(&self, slashing: Box<ProposerSlashing>) {
        self.log(
            Level::Debug,
            format_args!("publishing proposer slashing: {slashing:?}"),
        );

        self.publish(PubsubMessage::ProposerSlashing(slashing));
    }

    fn publish_attester_slashing(&self, slashing: Box<AttesterSlashing<P>>) {
        self.log(
            Level::Debug,
            format_args!("publishing attester slashing: {slashing:?}"),
        );

        self.publish(PubsubMessage::AttesterSlashing(slashing));
    }

    fn publish_voluntary_exit(&self, voluntary_exit: Box<SignedVoluntaryExit>) {
        self.log(
            Level::Debug,
            format_args!("publishing voluntary exit: {voluntary_exit:?}"),
        );

        self.publish(PubsubMessage::VoluntaryExit(voluntary_exit));
    }

    fn publish_sync_committee_message(&self, message: Box<(SubnetId, SyncCommitteeMessage)>) {
        self.log(
            Level::Debug,
            format_args!("publishing sync committee message: {message:?}"),
        );

        self.publish(PubsubMessage::SyncCommitteeMessage(message));
    }

    fn publish_contribution_and_proof(
        &self,
        contribution_and_proof: Box<SignedContributionAndProof<P>>,
    ) {
        if contribution_and_proof
            .message
            .contribution
            .aggregation_bits
            .none()
        {
            self.log(
                Level::Error,
                format_args!(
                    "attempted to publish sync committee contribution \
                     and proof with no participants: {contribution_and_proof:?}",
                ),
            );
            return;
        }

        self.log(
            Level::Debug,
            format_args!(
                "publishing sync committee contribution and proof: {contribution_and_proof:?}",
            ),
        );

        self.publish(PubsubMessage::SignedContributionAndProof(
            contribution_and_proof,
        ));
    }

    fn publish_signed_bls_to_execution_change(
        &self,
        signed_bls_to_execution_change: Box<SignedBlsToExecutionChange>,
    ) {
        self.log(
            Level::Debug,
            format_args!(
                "publishing signed bls to execution change: {signed_bls_to_execution_change:?}",
            ),
        );

        self.publish(PubsubMessage::BlsToExecutionChange(
            signed_bls_to_execution_change,
        ));
    }

    fn update_attestation_subnets(&self, subnet_actions: AttestationSubnetActions) {
        let chain_config = self.controller.chain_config();
        let current_slot = self.controller.slot();

        let AttestationSubnetActions {
            discoveries,
            enr,
            subscriptions,
        } = subnet_actions;

        let subnet_discoveries = discoveries
            .into_iter()
            .map(|discovery| {
                let SubnetPeerDiscovery {
                    subnet_id,
                    expiration,
                } = discovery;

                let min_ttl = match expiration {
                    Some(expiration) => {
                        let time_diff = expiration.saturating_sub(current_slot)
                            * chain_config.seconds_per_slot.get();
                        Instant::now().checked_add(Duration::from_secs(time_diff))
                    }
                    None => None,
                };

                SubnetDiscovery {
                    subnet: Subnet::Attestation(subnet_id),
                    min_ttl,
                }
            })
            .collect();

        ServiceInboundMessage::DiscoverSubnetPeers(subnet_discoveries)
            .send(&self.network_to_service_tx);

        for (subnet_id, subscribe) in subscriptions {
            let subnet = Subnet::Attestation(subnet_id);

            if subscribe {
                self.log(
                    Level::Debug,
                    format_args!("subscribing to attestation subnet (subnet_id: {subnet_id})"),
                );

                // TODO(Grandine Team): The Honest Validator specification says:
                //                      > *Note*: When preparing for a hard fork, a validator must
                //                      > select and subscribe to random subnets of the future
                //                      > fork versioning at least
                //                      > `EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION` epochs in
                //                      > advance of the fork.
                if let Some(topic) = self.subnet_gossip_topic(subnet) {
                    ServiceInboundMessage::Subscribe(topic).send(&self.network_to_service_tx);
                }
            } else {
                self.log(
                    Level::Debug,
                    format_args!("unsubscribing from attestation subnet {subnet_id}"),
                );

                if let Some(topic) = self.subnet_gossip_topic(subnet) {
                    ServiceInboundMessage::Unsubscribe(topic).send(&self.network_to_service_tx);
                }
            }
        }

        for (subnet_id, add_to_enr) in enr {
            let subnet = Subnet::Attestation(subnet_id);

            if add_to_enr {
                self.log(
                    Level::Debug,
                    format_args!("adding attestation subnet to ENR (subnet_id: {subnet_id})"),
                );
            } else {
                self.log(
                    Level::Debug,
                    format_args!("removing attestation subnet from ENR (subnet_id: {subnet_id})"),
                );
            }

            ServiceInboundMessage::UpdateEnrSubnet(subnet, add_to_enr)
                .send(&self.network_to_service_tx);
        }
    }

    fn update_sync_committee_subnets(
        &self,
        actions: BTreeMap<SubnetId, SyncCommitteeSubnetAction>,
    ) {
        let subnet_discoveries = actions
            .iter()
            .filter(|(_, action)| {
                matches!(
                    action,
                    SyncCommitteeSubnetAction::Subscribe | SyncCommitteeSubnetAction::DiscoverPeers,
                )
            })
            .map(|(subnet_id, _)| SubnetDiscovery {
                subnet: Subnet::SyncCommittee(*subnet_id),
                min_ttl: None,
            })
            .collect();

        ServiceInboundMessage::DiscoverSubnetPeers(subnet_discoveries)
            .send(&self.network_to_service_tx);

        for (subnet_id, action) in actions {
            let subnet = Subnet::SyncCommittee(subnet_id);

            match action {
                SyncCommitteeSubnetAction::Subscribe => {
                    self.log(
                        Level::Debug,
                        format_args!("subscribing to sync committee subnet {subnet_id}"),
                    );

                    // TODO(Grandine Team): Does it make sense to use the Phase 0 digest here?
                    if let Some(topic) = self.subnet_gossip_topic(subnet) {
                        ServiceInboundMessage::Subscribe(topic).send(&self.network_to_service_tx);
                    }

                    ServiceInboundMessage::UpdateEnrSubnet(subnet, true)
                        .send(&self.network_to_service_tx);
                }
                SyncCommitteeSubnetAction::DiscoverPeers => {
                    self.log(
                        Level::Debug,
                        format_args!("discovering peers in sync committee subnet {subnet_id}"),
                    );
                }
                SyncCommitteeSubnetAction::Unsubscribe => {
                    self.log(
                        Level::Debug,
                        format_args!("unsubscribing from sync committee subnet {subnet_id}"),
                    );

                    // TODO(Grandine Team): Does it make sense to use the Phase 0 digest here?
                    if let Some(topic) = self.subnet_gossip_topic(subnet) {
                        ServiceInboundMessage::Unsubscribe(topic).send(&self.network_to_service_tx);
                    }

                    ServiceInboundMessage::UpdateEnrSubnet(subnet, false)
                        .send(&self.network_to_service_tx);
                }
            }
        }
    }

    fn handle_network_event(&mut self, network_event: NetworkEvent<RequestId, P>) {
        match network_event {
            NetworkEvent::PeerConnectedIncoming(peer_id) => {
                self.log_with_feature(format_args!("peer {peer_id} connected incoming"));
            }
            NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                self.log_with_feature(format_args!("peer {peer_id} connected outgoing"));
                self.init_status_peer_request(peer_id);
            }
            NetworkEvent::PeerDisconnected(peer_id) => {
                self.log_with_feature(format_args!("peer {peer_id} disconnected"));
                P2pToSync::RemovePeer(peer_id).send(&self.channels.p2p_to_sync_tx);
            }
            NetworkEvent::RPCFailed { peer_id, id, error } => {
                self.log(
                    Level::Debug,
                    format_args!("request {id:?} to peer {peer_id} failed: {error}"),
                );
                P2pToSync::RequestFailed(peer_id).send(&self.channels.p2p_to_sync_tx);
            }
            NetworkEvent::RequestReceived {
                peer_id,
                id,
                request,
            } => {
                if let Err(error) = self.handle_request(peer_id, id, request) {
                    error!("error while handling request: {error}");
                }
            }
            NetworkEvent::ResponseReceived {
                peer_id,
                id,
                response,
            } => self.handle_response(peer_id, id, response),
            NetworkEvent::PubsubMessage {
                id,
                source,
                message,
                ..
            } => self.handle_pubsub_message(id, source, message),
            NetworkEvent::StatusPeer(peer_id) => self.init_status_peer_request(peer_id),
            NetworkEvent::NewListenAddr(multiaddr) => {
                // These come from `libp2p`. We don't use them anywhere. `eth2_libp2p` outputs them
                // even though Lighthouse only uses them in its REST API and could do without that.
                self.log_with_feature(format_args!("libp2p listening on {multiaddr}"));
            }
            NetworkEvent::ZeroListeners => self.log_with_feature("libp2p has zero listeners"),
        }
    }

    fn handle_request(
        &mut self,
        peer_id: PeerId,
        peer_request_id: PeerRequestId,
        request: Request,
    ) -> Result<()> {
        match request {
            Request::Status(remote) => {
                self.handle_status_request(peer_id, peer_request_id, remote);
                Ok(())
            }
            Request::BlocksByRange(request) => {
                self.handle_blocks_by_range_request(peer_id, peer_request_id, request)
            }
            Request::BlocksByRoot(request) => {
                self.handle_blocks_by_root_request(peer_id, peer_request_id, request);
                Ok(())
            }
            Request::LightClientBootstrap(_) => {
                // TODO(Altair Light Client Sync Protocol)
                self.log_with_feature(format_args!(
                    "received LightClientBootstrap request (peer_id: {peer_id})",
                ));

                Ok(())
            }
            Request::LightClientOptimisticUpdate => {
                self.log_with_feature(format_args!(
                    "received LightClientOptimisticUpdate request (peer_id: {peer_id})",
                ));

                Ok(())
            }
            Request::LightClientFinalityUpdate => {
                self.log_with_feature(format_args!(
                    "received LightClientFinalityUpdate request (peer_id: {peer_id})",
                ));

                Ok(())
            }
            Request::BlobsByRange(request) => {
                self.handle_blobs_by_range_request(peer_id, peer_request_id, request)
            }
            Request::BlobsByRoot(request) => {
                self.handle_blobs_by_root_request(peer_id, peer_request_id, request);
                Ok(())
            }
            Request::DataColumnsByRoot(request) => {
                self.handle_data_columns_by_root_request(peer_id, peer_request_id, request);
                Ok(())
            }
            Request::DataColumnsByRange(request) => {
                self.handle_data_columns_by_range_request(peer_id, peer_request_id, request)
            }
        }
    }

    fn handle_status_request(
        &mut self,
        peer_id: PeerId,
        peer_request_id: PeerRequestId,
        remote: StatusMessage,
    ) {
        self.log_with_feature(format_args!(
            "received Status request (peer_id: {peer_id}, remote: {remote:?})",
        ));

        let local = self.local_status();

        self.log_with_feature(format_args!(
            "sending Status response (peer_request_id: {peer_request_id:?}, peer_id: {peer_id}, local: {local:?})",
        ));

        self.respond(peer_id, peer_request_id, Response::<P>::Status(local));

        self.check_status(&local, remote, peer_id);
    }

    fn handle_blocks_by_range_request(
        &self,
        peer_id: PeerId,
        peer_request_id: PeerRequestId,
        request: BlocksByRangeRequest,
    ) -> Result<()> {
        self.log(
            Level::Debug,
            format_args!(
                "received BeaconBlocksByRange request (peer_id: {peer_id}, request: {request:?})",
            ),
        );

        let start_slot = request.start_slot();
        let difference = request.count().min(MAX_FOR_DOS_PREVENTION);

        // `end_slot` is exclusive.
        let end_slot = start_slot
            .checked_add(difference)
            .ok_or(Error::EndSlotOverflow {
                start_slot,
                difference,
            })?;

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();

        let connected_peers = self.network_globals.connected_peers();
        let target_peers = self.target_peers;

        self.dedicated_executor
            .spawn(async move {
                let blocks = controller.blocks_by_range(start_slot..end_slot)?;

                for block_with_root in blocks {
                    let block = block_with_root.block;

                    log(
                        Level::Debug,
                        connected_peers,
                        target_peers,
                        format_args!(
                            "sending BeaconBlocksByRange response chunk \
                         (peer_request_id: {peer_request_id:?}, peer_id: {peer_id}, block: {block:?})",
                        ),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        peer_request_id,
                        Box::new(Response::BlocksByRange(Some(block))),
                    )
                    .send(&network_to_service_tx);
                }

                log(
                    Level::Debug,
                    connected_peers,
                    target_peers,
                    "terminating BeaconBlocksByRange response stream",
                );

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    peer_request_id,
                    Box::new(Response::BlocksByRange(None)),
                )
                .send(&network_to_service_tx);

                Ok::<_, anyhow::Error>(())
            })
            .detach();

        Ok(())
    }

    fn handle_blobs_by_range_request(
        &self,
        peer_id: PeerId,
        peer_request_id: PeerRequestId,
        request: BlobsByRangeRequest,
    ) -> Result<()> {
        self.log(
            Level::Debug,
            format_args!(
                "received BlobSidecarsByRange request (peer_id: {peer_id}, request: {request:?})",
            ),
        );

        let BlobsByRangeRequest { start_slot, count } = request;

        // > Clients MAY limit the number of blocks and sidecars in the response.
        let difference = count
            .min(self.controller.chain_config().max_request_blob_sidecars)
            .min(MAX_FOR_DOS_PREVENTION);

        let end_slot = start_slot
            .checked_add(difference)
            .ok_or(Error::EndSlotOverflow {
                start_slot,
                difference,
            })?;

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();

        let connected_peers = self.network_globals.connected_peers();
        let target_peers = self.target_peers;

        self.dedicated_executor
            .spawn(async move {
                let blob_sidecars = controller.blob_sidecars_by_range(start_slot..end_slot)?;

                for blob_sidecar in blob_sidecars {
                    log(
                        Level::Debug,
                        connected_peers,
                        target_peers,
                        format_args!(
                            "sending BlobSidecarsByRange response chunk \
                         (peer_request_id: {peer_request_id:?}, peer_id: {peer_id}, blob_sidecar: {blob_sidecar:?})",
                        ),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        peer_request_id,
                        Box::new(Response::BlobsByRange(Some(blob_sidecar))),
                    )
                    .send(&network_to_service_tx);
                }

                log(
                    Level::Debug,
                    connected_peers,
                    target_peers,
                    "terminating BlobSidecarsByRange response stream",
                );

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    peer_request_id,
                    Box::new(Response::BlobsByRange(None)),
                )
                .send(&network_to_service_tx);

                Ok::<_, anyhow::Error>(())
            })
            .detach();

        Ok(())
    }

    fn handle_data_columns_by_root_request(
        &self,
        peer_id: PeerId,
        peer_request_id: PeerRequestId,
        request: DataColumnsByRootRequest,
    ) {
        self.log(
            Level::Debug,
            format_args!(
                "received DataColumnsByRoot request (peer_id: {peer_id}, request: {request:?})"
            ),
        );

        let DataColumnsByRootRequest { data_column_ids } = request;

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();

        // TODO(feature/eip7549): MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS
        let connected_peers = self.network_globals.connected_peers();
        let target_peers = self.target_peers;

        self.dedicated_executor
            .spawn(async move {
                // > Clients MAY limit the number of blocks and sidecars in the response.
                let data_column_ids = data_column_ids.into_iter().take(
                        MaxRequestDataColumnSidecars::USIZE
                );

                let data_column_sidecars = controller.data_column_sidecars_by_ids(data_column_ids)?;

                for data_column_sidecar in data_column_sidecars {
                    log(
                        Level::Debug,
                        connected_peers,
                        target_peers,
                        format_args!(
                            "sending DataColumnsSidecarsByRoot response chunk \
                         (peer_request_id: {peer_request_id:?}, peer_id: {peer_id}, data_column_sidecar: {data_column_sidecar:?})",
                        ),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        peer_request_id,
                        Box::new(Response::DataColumnsByRoot(Some(data_column_sidecar))),
                    )
                    .send(&network_to_service_tx);
                }

                log(
                    Level::Debug,
                    connected_peers,
                    target_peers,
                    "terminating DataColumnsByRoot response stream",
                );

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    peer_request_id,
                    Box::new(Response::DataColumnsByRoot(None)),
                )
                .send(&network_to_service_tx);

                Ok::<_, anyhow::Error>(())
            })
            .detach();
    }

    fn handle_data_columns_by_range_request(
        &self,
        peer_id: PeerId,
        peer_request_id: PeerRequestId,
        request: DataColumnsByRangeRequest,
    ) -> Result<()> {
        self.log(
            Level::Debug,
            format_args!(
                "received DataColumnsByRange request (peer_id: {peer_id}, request: {request:?})"
            ),
        );

        let DataColumnsByRangeRequest {
            start_slot,
            count,
            columns,
        } = request;

        let controller = self.controller.clone_arc();

        // TODO(feature/eip-7594): MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS
        // Let data_column_serve_range be
        //  [max(current_epoch - MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS, EIP7594_FORK_EPOCH), current_epoch].
        let start_slot = start_slot.max(misc::compute_start_slot_at_epoch::<P>(
            self.controller.chain_config().eip7594_fork_epoch,
        ));

        // > Clients MAY limit the number of data column sidecars in the response.
        let difference = count.min(MaxRequestDataColumnSidecars::U64);

        let current_slot = self.controller.head_slot();
        let end_slot = start_slot
            .checked_add(difference)
            .ok_or(Error::EndSlotOverflow {
                start_slot,
                difference,
            })?
            .min(current_slot);

        let network_to_service_tx = self.network_to_service_tx.clone();
        let connected_peers = self.network_globals.connected_peers();
        let target_peers = self.target_peers;

        self.dedicated_executor
            .spawn(async move {
                let mut data_column_sidecars = controller.data_column_sidecars_by_range(start_slot..end_slot, &columns)?;

                // The following data column sidecars, where they exist, MUST be sent in (slot, column_index) order.
                data_column_sidecars.sort_by_key(|sidecar| (sidecar.slot(), sidecar.index));

                for data_column_sidecar in data_column_sidecars {
                    log(
                        Level::Debug,
                        connected_peers,
                        target_peers,
                        format_args!(
                            "sending DataColumnsSidecarsByRange response chunk \
                         (peer_request_id: {peer_request_id:?}, peer_id: {peer_id}, data_column_sidecar: {data_column_sidecar:?})",
                        ),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        peer_request_id,
                        Box::new(Response::DataColumnsByRange(Some(data_column_sidecar))),
                    )
                    .send(&network_to_service_tx);
                }

                log(
                    Level::Debug,
                    connected_peers,
                    target_peers,
                    "terminating DataColumnsByRange response stream",
                );

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    peer_request_id,
                    Box::new(Response::DataColumnsByRange(None)),
                )
                .send(&network_to_service_tx);

                Ok::<_, anyhow::Error>(())
            })
            .detach();

        Ok(())
    }

    fn handle_blobs_by_root_request(
        &self,
        peer_id: PeerId,
        peer_request_id: PeerRequestId,
        request: BlobsByRootRequest,
    ) {
        self.log(
            Level::Debug,
            format_args!(
                "received BlobsByRootRequest request (peer_id: {peer_id}, request: {request:?})"
            ),
        );

        // TODO(feature/deneb): MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS
        let BlobsByRootRequest { blob_ids } = request;

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();

        let connected_peers = self.network_globals.connected_peers();
        let target_peers = self.target_peers;
        let max_request_blob_sidecars = self.controller.chain_config().max_request_blob_sidecars;

        self.dedicated_executor
            .spawn(async move {
                // > Clients MAY limit the number of blocks and sidecars in the response.
                let blob_ids = blob_ids.into_iter().take(
                    MAX_FOR_DOS_PREVENTION
                        .min(max_request_blob_sidecars)
                        .try_into()?,
                );

                let blob_sidecars = controller.blob_sidecars_by_ids(blob_ids)?;

                for blob_sidecar in blob_sidecars {
                    log(
                        Level::Debug,
                        connected_peers,
                        target_peers,
                        format_args!(
                            "sending BlobSidecarsByRoot response chunk \
                         (peer_request_id: {peer_request_id:?}, peer_id: {peer_id}, blob_sidecar: {blob_sidecar:?})",
                        ),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        peer_request_id,
                        Box::new(Response::BlobsByRoot(Some(blob_sidecar))),
                    )
                    .send(&network_to_service_tx);
                }

                log(
                    Level::Debug,
                    connected_peers,
                    target_peers,
                    "terminating BlobSidecarsByRoot response stream",
                );

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    peer_request_id,
                    Box::new(Response::BlobsByRoot(None)),
                )
                .send(&network_to_service_tx);

                Ok::<_, anyhow::Error>(())
            })
            .detach();
    }

    fn handle_blocks_by_root_request(
        &self,
        peer_id: PeerId,
        peer_request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) {
        let block_roots = request.block_roots();

        self.log(
            Level::Debug,
            format_args!(
                "received BeaconBlocksByRoot request \
                 (peer_id: {peer_id}, block_roots: {block_roots:?})",
            ),
        );

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();

        let connected_peers = self.network_globals.connected_peers();
        let target_peers = self.target_peers;

        self.dedicated_executor
            .spawn(async move {
                let block_roots = block_roots
                    .into_iter()
                    .take(MAX_FOR_DOS_PREVENTION.try_into()?);

                let blocks = controller.blocks_by_root(block_roots)?;

                for block in blocks.into_iter().map(WithStatus::value) {
                    log(
                        Level::Debug,
                        connected_peers,
                        target_peers,
                        format_args!(
                            "sending BeaconBlocksByRoot response chunk \
                         (peer_request_id: {peer_request_id:?}, peer_id: {peer_id}, block: {block:?})",
                        ),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        peer_request_id,
                        Box::new(Response::BlocksByRoot(Some(block))),
                    )
                    .send(&network_to_service_tx);
                }

                log(
                    Level::Debug,
                    connected_peers,
                    target_peers,
                    "terminating BeaconBlocksByRoot response stream",
                );

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    peer_request_id,
                    Box::new(Response::BlocksByRoot(None)),
                )
                .send(&network_to_service_tx);

                Ok::<_, anyhow::Error>(())
            })
            .detach();
    }

    #[allow(clippy::too_many_lines)]
    fn handle_response(&mut self, peer_id: PeerId, request_id: RequestId, response: Response<P>) {
        match response {
            Response::Status(remote) => {
                self.log_with_feature(format_args!(
                    "received Status response (peer_id: {peer_id}, remote: {remote:?})",
                ));

                self.check_status(&self.local_status(), remote, peer_id);
            }
            // TODO(feature/deneb): This appears to be unfinished.
            // > Before consuming the next response chunk, the response reader SHOULD verify the
            // > blob sidecar is well-formatted, has valid inclusion proof, and is correct w.r.t. the expected KZG commitments
            // > through `verify_blob_kzg_proof``.
            Response::BlobsByRange(Some(blob_sidecar)) => {
                let blob_sidecar_slot = blob_sidecar.signed_block_header.message.slot;
                let blob_identifier = blob_sidecar.as_ref().into();

                self.log(
                    Level::Debug,
                    format_args!(
                        "received BlobsByRange response chunk \
                         (request_id: {request_id}, peer_id: {peer_id}, slot: {blob_sidecar_slot}, blob: {blob_sidecar:?})",
                    ),
                );

                if self.register_new_received_blob_sidecar(blob_identifier, blob_sidecar_slot) {
                    let block_seen = self
                        .received_block_roots
                        .contains_key(&blob_identifier.block_root);

                    P2pToSync::RequestedBlobSidecar(blob_sidecar, block_seen, peer_id)
                        .send(&self.channels.p2p_to_sync_tx);
                }
            }
            Response::BlobsByRange(None) => {
                self.log_with_feature(format_args!(
                    "peer {peer_id} terminated BlobsByRange response stream for request_id: {request_id}",
                ));

                P2pToSync::BlobsByRangeRequestFinished(request_id)
                    .send(&self.channels.p2p_to_sync_tx);
            }
            Response::BlobsByRoot(Some(blob_sidecar)) => {
                let blob_sidecar_slot = blob_sidecar.signed_block_header.message.slot;
                let blob_identifier = blob_sidecar.as_ref().into();

                self.log(
                    Level::Debug,
                    format_args!(
                        "received BlobsByRoot response chunk \
                         (request_id: {request_id}, peer_id: {peer_id}, slot: {blob_sidecar_slot}, blob: {blob_sidecar:?})",
                    ),
                );

                if self.register_new_received_blob_sidecar(blob_identifier, blob_sidecar_slot) {
                    let block_seen = self
                        .received_block_roots
                        .contains_key(&blob_identifier.block_root);

                    P2pToSync::RequestedBlobSidecar(blob_sidecar, block_seen, peer_id)
                        .send(&self.channels.p2p_to_sync_tx);
                }

                P2pToSync::BlobsByRootChunkReceived(blob_identifier, peer_id, request_id)
                    .send(&self.channels.p2p_to_sync_tx);
            }
            Response::BlobsByRoot(None) => {
                self.log_with_feature(format_args!(
                    "peer {peer_id} terminated BlobsByRoot response stream for request_id: {request_id}",
                ));
            }
            Response::BlocksByRange(Some(block)) => {
                let block_slot = block.message().slot();
                let block_root = block.message().hash_tree_root();

                self.log(
                    Level::Debug,
                    format_args!(
                        "received BeaconBlocksByRange response chunk \
                         (request_id: {request_id}, peer_id: {peer_id}, slot: {block_slot}, block: {block:?})",
                    ),
                );

                if self.register_new_received_block(block_root, block_slot) {
                    P2pToSync::RequestedBlock((block, peer_id, request_id))
                        .send(&self.channels.p2p_to_sync_tx);
                }
            }
            Response::BlocksByRange(None) => {
                self.log_with_feature(format_args!(
                    "peer {peer_id} terminated BeaconBlocksByRange response stream for request_id: {request_id}",
                ));

                P2pToSync::BlocksByRangeRequestFinished(request_id)
                    .send(&self.channels.p2p_to_sync_tx);

                P2pToSync::HeadState(self.controller.head_state().value)
                    .send(&self.channels.p2p_to_sync_tx);
            }
            Response::BlocksByRoot(Some(block)) => {
                let block_slot = block.message().slot();
                let block_root = block.message().hash_tree_root();

                self.log(
                    Level::Debug,
                    format_args!(
                        "received BeaconBlocksByRoot response chunk \
                         (request_id: {request_id}, peer_id: {peer_id}, slot: {block_slot}, block: {block:?})",
                    ),
                );

                self.log_with_feature(format_args!(
                    "received beacon block from RPC (request_id: {request_id}, peer_id: {peer_id}, slot: {block_slot}, root: {block_root})",
                ));

                P2pToSync::BlockByRootRequestFinished(block_root)
                    .send(&self.channels.p2p_to_sync_tx);

                if self.register_new_received_block(block_root, block_slot) {
                    self.controller
                        .on_requested_block(block.clone_arc(), Some(peer_id));

                    if let Some(network_to_slasher_tx) = &self.channels.network_to_slasher_tx {
                        P2pToSlasher::Block(block).send(network_to_slasher_tx);
                    }
                }
            }
            Response::BlocksByRoot(None) => {
                self.log_with_feature(format_args!(
                    "peer {peer_id} terminated BeaconBlocksByRoot response stream for request_id: {request_id}",
                ));
            }
            Response::LightClientBootstrap(_)
            | Response::LightClientOptimisticUpdate(_)
            | Response::LightClientFinalityUpdate(_) => {
                self.log(
                    Level::Debug,
                    format_args!(
                        "received {response:?} response chunk (request_id: {request_id}, peer_id: {peer_id})",
                    ),
                );
            }
            Response::DataColumnsByRange(Some(data_column_sidecar)) => {
                let data_column_sidecar_slot = data_column_sidecar.signed_block_header.message.slot;
                let data_column_identifier = data_column_sidecar.as_ref().into();

                self.log(
                    Level::Debug,
                    format_args!(
                        "received DataColumnsByRange response chunk \
                        (request_id: {request_id}, peer_id: {peer_id}, slot: {data_column_sidecar_slot}, data_column: {data_column_sidecar:?})",
                    ),
                );

                if self.register_new_received_data_column_sidecar(
                    data_column_identifier,
                    data_column_sidecar_slot,
                ) {
                    P2pToSync::RequestedDataColumnSidecar(data_column_sidecar, peer_id)
                        .send(&self.channels.p2p_to_sync_tx);
                }
            }
            Response::DataColumnsByRange(None) => {
                self.log_with_feature(format_args!(
                    "peer {peer_id} terminated DataColumnsByRange response stream for request_id: {request_id}",
                ));

                P2pToSync::DataColumnsByRangeRequestFinished(request_id)
                    .send(&self.channels.p2p_to_sync_tx);
            }
            Response::DataColumnsByRoot(Some(data_column_sidecar)) => {
                let data_column_sidecar_slot = data_column_sidecar.signed_block_header.message.slot;
                let data_column_identifier = data_column_sidecar.as_ref().into();

                self.log(
                    Level::Debug,
                    format_args!(
                        "received DataColumnsByRoot response chunk \
                        (request_id: {request_id}, peer_id: {peer_id}, slot: {data_column_sidecar_slot}, data_column: {data_column_sidecar:?})",
                    ),
                );

                if self.register_new_received_data_column_sidecar(
                    data_column_identifier,
                    data_column_sidecar_slot,
                ) {
                    // let block_seen = self
                    //     .received_block_roots
                    //     .contains_key(&data_column_identifier.block_root);

                    P2pToSync::RequestedDataColumnSidecar(data_column_sidecar, peer_id)
                        .send(&self.channels.p2p_to_sync_tx);
                }

                P2pToSync::DataColumnsByRootChunkReceived(
                    data_column_identifier,
                    peer_id,
                    request_id,
                )
                .send(&self.channels.p2p_to_sync_tx);
            }
            Response::DataColumnsByRoot(None) => {
                self.log_with_feature(format_args!(
                    "peer {peer_id} terminated DataColumnsByRoot response stream for request_id: {request_id}",
                ));
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_pubsub_message(
        &mut self,
        message_id: MessageId,
        source: PeerId,
        message: PubsubMessage<P>,
    ) {
        match message {
            PubsubMessage::BeaconBlock(beacon_block) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["beacon_block"]);
                }

                let block_root = beacon_block.message().hash_tree_root();
                let block_slot = beacon_block.message().slot();

                if !self.register_new_received_block(block_root, block_slot) {
                    return;
                }

                let block_slot_timestamp = misc::compute_timestamp_at_slot(
                    self.controller.chain_config(),
                    &self.controller.head_state().value(),
                    block_slot,
                );

                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.observe_block_duration_to_slot(block_slot_timestamp);
                }

                self.log(
                    Level::Info,
                    format_args!(
                        "received beacon block as gossip (slot: {block_slot}, root: {block_root:?}, peer_id: {source})",
                    ),
                );

                if let Some(network_to_slasher_tx) = &self.channels.network_to_slasher_tx {
                    P2pToSlasher::Block(beacon_block.clone_arc()).send(network_to_slasher_tx);
                }

                self.controller
                    .on_gossip_block(beacon_block, GossipId { source, message_id });
            }
            PubsubMessage::BlobSidecar(data) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["blob_sidecar"]);
                }

                let (subnet_id, blob_sidecar) = *data;
                let blob_identifier: BlobIdentifier = blob_sidecar.as_ref().into();

                self.log_with_feature(format_args!(
                    "received blob sidecar as gossip in subnet {subnet_id}: {blob_identifier:?} from {source}",
                ));

                let block_seen = self
                    .received_block_roots
                    .contains_key(&blob_identifier.block_root);

                self.controller.on_gossip_blob_sidecar(
                    blob_sidecar,
                    subnet_id,
                    GossipId { source, message_id },
                    block_seen,
                );
            }
            PubsubMessage::DataColumnSidecar(data) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["data_column_sidecar"]);
                }

                let (subnet_id, data_column_sidecar) = *data;

                self.log_with_feature(format_args!(
                    "received data column sidecar as gossip in subnet {subnet_id}: {data_column_sidecar:?} from {source}",
                ));

                let chain_config = self.controller.chain_config().as_ref();
                let epoch = misc::compute_epoch_at_slot::<P>(data_column_sidecar.slot());

                if chain_config.is_eip7594_fork(epoch) {
                    self.controller.on_gossip_data_column_sidecar(
                        data_column_sidecar,
                        subnet_id,
                        GossipId { source, message_id },
                    );
                } else {
                    self.log_with_feature(format_args!(
                        "ignoring pre-eip7594 data column sidecar in slot {} / {epoch}",
                        data_column_sidecar.slot(),
                    ));
                }
            }
            PubsubMessage::AggregateAndProofAttestation(aggregate_and_proof) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["aggregate_and_proof_attestation"]);
                }

                self.log(
                    Level::Debug,
                    format_args!(
                        "received aggregate and proof as gossip: {aggregate_and_proof:?} from {source}",
                    ),
                );

                if let Some(network_to_slasher_tx) = &self.channels.network_to_slasher_tx {
                    let attestation = Arc::new(aggregate_and_proof.message.aggregate.clone());
                    P2pToSlasher::Attestation(attestation).send(network_to_slasher_tx);
                }

                let gossip_id = GossipId { source, message_id };

                P2pToAttestationVerifier::GossipAggregateAndProof(aggregate_and_proof, gossip_id)
                    .send(&self.channels.p2p_to_attestation_verifier_tx);
            }
            PubsubMessage::Attestation(subnet_id, attestation) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["attestation"]);
                }

                self.log(
                    Level::Debug,
                    format_args!(
                        "received singular attestation as gossip in subnet {subnet_id}: \
                         {attestation:?} from {source}",
                    ),
                );

                if let Some(network_to_slasher_tx) = &self.channels.network_to_slasher_tx {
                    P2pToSlasher::Attestation(attestation.clone_arc()).send(network_to_slasher_tx);
                }

                let gossip_id = GossipId { source, message_id };

                P2pToAttestationVerifier::GossipAttestation(attestation, subnet_id, gossip_id)
                    .send(&self.channels.p2p_to_attestation_verifier_tx);
            }
            PubsubMessage::VoluntaryExit(signed_voluntary_exit) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["voluntary_exit"]);
                }

                self.log(
                    Level::Debug,
                    format_args!(
                        "received signed voluntary exit as gossip: {signed_voluntary_exit:?} from {source}",
                    ),
                );

                P2pToValidator::VoluntaryExit(
                    signed_voluntary_exit,
                    GossipId { source, message_id },
                )
                .send(&self.channels.p2p_to_validator_tx);
            }
            PubsubMessage::ProposerSlashing(proposer_slashing) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["proposer_slashing"]);
                }

                self.log(
                    Level::Debug,
                    format_args!(
                        "received proposer slashing as gossip: {proposer_slashing:?} from {source}"
                    ),
                );

                let gossip_id = GossipId { source, message_id };

                P2pToValidator::ProposerSlashing(proposer_slashing, gossip_id)
                    .send(&self.channels.p2p_to_validator_tx);
            }
            PubsubMessage::AttesterSlashing(attester_slashing) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["attester_slashing"]);
                }

                self.log(
                    Level::Debug,
                    format_args!(
                        "received attester slashing as gossip: {attester_slashing:?} from {source}"
                    ),
                );

                let gossip_id = GossipId { source, message_id };

                self.controller
                    .on_gossip_attester_slashing(attester_slashing.clone());

                P2pToValidator::AttesterSlashing(attester_slashing, gossip_id)
                    .send(&self.channels.p2p_to_validator_tx);
            }
            PubsubMessage::SignedContributionAndProof(proof) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["signed_contribution_and_proof"]);
                }

                let gossip_id = GossipId { source, message_id };

                self.log(
                    Level::Debug,
                    format_args!(
                        "received signed contribution and proof as gossip: {proof:?} from {source}"
                    ),
                );

                // Handle it asynchronously to not block the event loop.
                self.sync_committee_agg_pool
                    .handle_external_contribution_and_proof_detached(
                        *proof,
                        Origin::Gossip(gossip_id),
                    )
            }
            PubsubMessage::SyncCommitteeMessage(message) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["sync_committee_message"]);
                }

                let (subnet_id, sync_committee_message) = *message;
                let gossip_id = GossipId { source, message_id };

                self.log(
                    Level::Debug,
                    format_args!(
                        "received sync committee message as gossip in subnet {subnet_id}: \
                         {sync_committee_message:?} from {source}",
                    ),
                );

                // Handle it asynchronously to not block the event loop.
                self.sync_committee_agg_pool
                    .handle_external_message_detached(
                        sync_committee_message,
                        subnet_id,
                        Origin::Gossip(gossip_id),
                    )
            }
            PubsubMessage::BlsToExecutionChange(signed_bls_to_execution_change) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["bls_to_execution_change"]);
                }

                self.log(
                    Level::Debug,
                    format_args!(
                        "received signed bls execution change as gossip: {signed_bls_to_execution_change:?} from {source}"
                    ),
                );

                self.bls_to_execution_change_pool
                    .notify_external_signed_bls_to_execution_change(
                        signed_bls_to_execution_change,
                        Origin::Gossip(GossipId { source, message_id }),
                    );
            }
            PubsubMessage::LightClientFinalityUpdate(_) => {
                self.log(
                    Level::Debug,
                    "received light client finality update as gossip",
                );
            }
            PubsubMessage::LightClientOptimisticUpdate(_) => {
                self.log(
                    Level::Debug,
                    "received light client optimistic update as gossip",
                );
            }
        }
    }

    fn init_status_peer_request(&self, peer_id: PeerId) {
        P2pToSync::StatusPeer(peer_id).send(&self.channels.p2p_to_sync_tx);
    }

    fn request_peer_status(&mut self, request_id: RequestId, peer_id: PeerId) {
        let status = self.local_status();

        self.log(
            Level::Debug,
            format_args!("sending Status request (request_id: {request_id}, peer_id: {peer_id}, status: {status:?})"),
        );

        self.request(peer_id, request_id, Request::Status(status));
    }

    fn local_status(&self) -> StatusMessage {
        let head = self.controller.head().value;
        let finalized_epoch = self.controller.finalized_epoch();
        let finalized_root = if finalized_epoch == GENESIS_EPOCH {
            H256::zero()
        } else {
            self.controller.finalized_root()
        };

        StatusMessage {
            fork_digest: fork_digest(&self.fork_context),
            finalized_root,
            finalized_epoch,
            head_root: head.block_root,
            head_slot: head.slot(),
        }
    }

    fn check_status(&mut self, local: &StatusMessage, remote: StatusMessage, peer_id: PeerId) {
        if local.fork_digest != remote.fork_digest {
            self.log(
                Level::Warn,
                format_args!(
                    "local fork digest doesn't match remote fork digest \
                     (local: {local:?}, remote: {remote:?}, peer_id: {peer_id}); \
                     disconnecting from peer",
                ),
            );
            P2pToSync::RemovePeer(peer_id).send(&self.channels.p2p_to_sync_tx);
            ServiceInboundMessage::GoodbyePeer(
                peer_id,
                GoodbyeReason::IrrelevantNetwork,
                ReportSource::SyncService,
            )
            .send(&self.network_to_service_tx);
            return;
        }

        let info = SyncInfo {
            head_slot: remote.head_slot,
            head_root: remote.head_root,
            finalized_epoch: remote.finalized_epoch,
            finalized_root: remote.finalized_root,
        };

        let (local_finalized_root_at_remote_finalized_epoch, sync_status) =
            match local.finalized_epoch.cmp(&remote.finalized_epoch) {
                Ordering::Less => (None, SyncStatus::Advanced { info }),
                Ordering::Equal => (Some(local.finalized_root), SyncStatus::Synced { info }),
                Ordering::Greater => {
                    let remote_finalized_slot = Self::start_of_epoch(remote.finalized_epoch);

                    (
                        self.controller
                            .finalized_block_root_before_or_at(remote_finalized_slot),
                        SyncStatus::Behind { info },
                    )
                }
            };

        if let Some(root) = local_finalized_root_at_remote_finalized_epoch {
            if root != remote.finalized_root {
                self.log(
                    Level::Warn,
                    format_args!(
                        "peer {} has different block finalized at epoch {} ({:?} != {:?})",
                        peer_id, remote.finalized_epoch, root, remote.finalized_root,
                    ),
                );

                P2pToSync::RemovePeer(peer_id).send(&self.channels.p2p_to_sync_tx);
                ServiceInboundMessage::GoodbyePeer(
                    peer_id,
                    GoodbyeReason::IrrelevantNetwork,
                    ReportSource::SyncService,
                )
                .send(&self.network_to_service_tx);

                return;
            }
        }

        // Update status
        self.network_globals()
            .peers
            .write()
            .update_sync_status(&peer_id, sync_status);

        // BlockSyncService will initiate requesting blocks by range when it has info about peers
        P2pToSync::AddPeer(peer_id, remote).send(&self.channels.p2p_to_sync_tx);
    }

    fn request_blobs_by_range(
        &mut self,
        request_id: RequestId,
        peer_id: PeerId,
        start_slot: Slot,
        count: u64,
    ) {
        // TODO: is count capped in eth2_libp2p?
        let request = BlobsByRangeRequest { start_slot, count };

        self.log(
            Level::Debug,
            format_args!(
                "sending BlobSidecarsByRange request (request_id: {request_id} peer_id: {peer_id}, request: {request:?})",
            ),
        );

        self.request(peer_id, request_id, Request::BlobsByRange(request));
    }

    fn request_blobs_by_root(
        &self,
        request_id: RequestId,
        peer_id: PeerId,
        // TODO(feature/deneb): move duplicated constants out of eth2_libp2p
        blob_identifiers: Vec<BlobIdentifier>,
    ) {
        let blob_identifiers = blob_identifiers
            .into_iter()
            .filter(|blob_identifier| !self.received_blob_sidecars.contains_key(blob_identifier))
            .collect::<Vec<_>>();

        if blob_identifiers.is_empty() {
            self.log(
                Level::Debug,
                format_args!(
                    "cannot request BlobSidecarsByRoot: all requested blob sidecars have been received",
                ),
            );

            return;
        }

        let request = BlobsByRootRequest::new(
            blob_identifiers
                .try_into()
                .expect("length is under maximum"),
        );

        self.log(
            Level::Debug,
            format_args!(
                "sending BlobSidecarsByRoot request (request_id: {request_id}, peer_id: {peer_id}, request: {request:?})",
            ),
        );

        self.request(peer_id, request_id, Request::BlobsByRoot(request));
    }

    fn request_blocks_by_range(
        &mut self,
        request_id: RequestId,
        peer_id: PeerId,
        start_slot: Slot,
        count: u64,
    ) {
        let request = BlocksByRangeRequest::new(start_slot, count);

        self.log(
            Level::Debug,
            format_args!(
                "sending BeaconBlocksByRange request (reqeuest_id: {request_id}, peer_id: {peer_id}, request: {request:?})",
            ),
        );

        self.request(peer_id, request_id, Request::BlocksByRange(request));
    }

    fn request_block_by_root(&self, request_id: RequestId, peer_id: PeerId, block_root: H256) {
        if self.received_block_roots.contains_key(&block_root) {
            return;
        }

        let request = BlocksByRootRequest::new(
            vec![block_root]
                .try_into()
                .expect("length is under maximum"),
        );

        self.log(
            Level::Debug,
            format_args!(
                "sending BeaconBlocksByRoot request (request_id: {request_id}, peer_id: {peer_id}, request: {request:?})",
            ),
        );

        self.request(peer_id, request_id, Request::BlocksByRoot(request));
    }

    fn request_data_columns_by_range(
        &mut self,
        request_id: RequestId,
        peer_id: PeerId,
        start_slot: Slot,
        count: u64,
    ) {
        let epoch = misc::compute_epoch_at_slot::<P>(start_slot);
        let custody_columns = self.network_globals.custody_columns();

        // prevent node from sending excessive requests, since custody peers is not available.
        if self.check_good_peers_on_column_subnets(epoch) {
            // TODO: is count capped in eth2_libp2p?
            let request = DataColumnsByRangeRequest {
                start_slot,
                count,
                columns: Arc::new(
                    ContiguousList::try_from(custody_columns)
                        .expect("fail to parse custody_columns"),
                ),
            };

            self.log(
                Level::Debug,
                format_args!(
                    "sending DataColumnsByRange request (request_id: {request_id} peer_id: {peer_id}, request: {request:?})",
                ),
            );

            self.request(peer_id, request_id, Request::DataColumnsByRange(request));
        } else {
            self.log(
                Level::Debug,
                format_args!(
                    "Waiting for peers to be available on custody_columns: {custody_columns:?}"
                ),
            );
        }
    }

    #[must_use]
    fn map_peer_custody_columns(
        &self,
        custody_columns: &Vec<ColumnIndex>,
    ) -> HashMap<PeerId, Vec<ColumnIndex>> {
        let mut peer_columns_mapping = HashMap::new();

        for column_index in custody_columns {
            let Some(custodial_peer) = self.get_random_custodial_peer(*column_index) else {
                // this should return no custody column error, rather than warning
                warn!("No custodial peer for column_index: {column_index}");
                continue;
            };

            let peer_custody_columns = peer_columns_mapping
                .entry(custodial_peer)
                .or_insert_with(|| vec![]);

            peer_custody_columns.push(*column_index);
        }

        peer_columns_mapping
    }

    fn request_data_columns_by_root(
        &self,
        request_id: RequestId,
        peer_id: PeerId,
        data_column_identifiers: Vec<DataColumnIdentifier>,
    ) {
        let data_column_identifiers = data_column_identifiers
            .into_iter()
            .filter(|identifier| !self.received_data_column_sidecars.contains_key(identifier))
            .collect::<Vec<_>>();

        if data_column_identifiers.is_empty() {
            self.log(
                Level::Debug,
                format_args!(
                    "cannot request DataColumnSidecarsByRoot: all requested data column sidecars have been received",
                ),
            );

            return;
        }

        let request = DataColumnsByRootRequest::new(
            data_column_identifiers
                .try_into()
                .expect("length is under maximum"),
        );

        self.log(
            Level::Debug,
            format_args!(
                "sending DataColumnSidecarsByRoot request (request_id: {request_id}, peer_id: {peer_id}, request: {request:?})",
            ),
        );

        self.request(peer_id, request_id, Request::DataColumnsByRoot(request));
    }

    fn subscribe_to_core_topics(&mut self) {
        // `subscribe_kind` locks `gossipsub_subscriptions` for writing.
        // Read current subscriptions before subscribing to avoid a deadlock.
        let subscribed_topics = self
            .network_globals
            .gossipsub_subscriptions
            .read()
            .iter()
            .map(GossipTopic::kind)
            .cloned()
            .collect::<HashSet<_>>();

        let current_phase = self.fork_context.current_fork();

        for kind in core_topics_to_subscribe(current_phase)
            .iter()
            .filter(|kind| !subscribed_topics.contains(kind))
            .cloned()
        {
            ServiceInboundMessage::SubscribeKind(kind).send(&self.network_to_service_tx);
        }
    }

    fn subscribe_to_data_column_topics(&mut self) {
        for subnet_id in self.network_globals.custody_subnets() {
            let subnet = Subnet::DataColumn(subnet_id);

            if let Some(topic) = self.subnet_gossip_topic(subnet) {
                ServiceInboundMessage::Subscribe(topic).send(&self.network_to_service_tx);
            } else {
                warn!("Could not subscribe to gossipsub topic on subnet_id: {subnet_id}");
            }
        }
    }

    fn report_outcome(&self, gossip_id: GossipId, message_acceptance: MessageAcceptance) {
        ServiceInboundMessage::ReportMessageValidationResult(gossip_id, message_acceptance)
            .send(&self.network_to_service_tx);
    }

    fn report_peer(
        &self,
        peer_id: PeerId,
        peer_action: PeerAction,
        source: ReportSource,
        reason: impl Into<&'static str>,
    ) {
        ServiceInboundMessage::ReportPeer(peer_id, peer_action, source, reason.into())
            .send(&self.network_to_service_tx);
    }

    fn publish(&self, message: PubsubMessage<P>) {
        ServiceInboundMessage::Publish(message).send(&self.network_to_service_tx);
    }

    fn publish_batch(&self, messages: Vec<PubsubMessage<P>>) {
        ServiceInboundMessage::PublishBatch(messages).send(&self.network_to_service_tx);
    }

    fn request(&self, peer_id: PeerId, request_id: RequestId, request: Request) {
        ServiceInboundMessage::SendRequest(peer_id, request_id, request)
            .send(&self.network_to_service_tx);
    }

    fn respond(&self, peer_id: PeerId, peer_request_id: PeerRequestId, response: Response<P>) {
        ServiceInboundMessage::SendResponse(peer_id, peer_request_id, Box::new(response))
            .send(&self.network_to_service_tx);
    }

    fn subnet_gossip_topic(&self, subnet: Subnet) -> Option<GossipTopic> {
        let current_phase = self.fork_context.current_fork();

        self.fork_context
            .to_context_bytes(current_phase)
            .map(|digest| GossipTopic::new(subnet.into(), GossipEncoding::default(), digest))
    }

    fn prune_received_data_column_sidecars(&mut self, epoch: Epoch) {
        let start_of_epoch = Self::start_of_epoch(epoch);

        self.received_data_column_sidecars
            .retain(|_, slot| *slot >= start_of_epoch);
    }

    fn prune_received_blob_sidecars(&mut self, epoch: Epoch) {
        let start_of_epoch = Self::start_of_epoch(epoch);

        self.received_blob_sidecars
            .retain(|_, slot| *slot >= start_of_epoch);
    }

    fn prune_received_block_roots(&mut self, epoch: Epoch) {
        let start_of_epoch = Self::start_of_epoch(epoch);

        self.received_block_roots
            .retain(|_, slot| *slot >= start_of_epoch);
    }

    fn register_new_received_block(&mut self, block_root: H256, slot: Slot) -> bool {
        self.received_block_roots.insert(block_root, slot).is_none()
    }

    fn register_new_received_blob_sidecar(
        &mut self,
        blob_identifier: BlobIdentifier,
        slot: Slot,
    ) -> bool {
        self.received_blob_sidecars
            .insert(blob_identifier, slot)
            .is_none()
    }

    fn register_new_received_data_column_sidecar(
        &mut self,
        data_column_identifier: DataColumnIdentifier,
        slot: Slot,
    ) -> bool {
        self.received_data_column_sidecars
            .insert(data_column_identifier, slot)
            .is_none()
    }

    /// Log a message with peer count information.
    fn log(&self, level: Level, message: impl Display) {
        log(
            level,
            self.network_globals.connected_peers(),
            self.target_peers,
            message,
        );
    }

    fn log_with_feature(&self, message: impl Display) {
        features::log!(
            DebugP2p,
            "[Peers: {}/{}] {}",
            self.network_globals.connected_peers(),
            self.target_peers,
            message,
        );
    }

    fn ensure_peer_connected(&self, peer_id: Option<PeerId>) -> Option<PeerId> {
        peer_id
            .filter(|peer_id| self.network_globals.is_peer_connected(peer_id))
            .or_else(|| {
                self.log(
                    Level::Debug,
                    format_args!("Peer {peer_id:?} is no longer connected, will find a new peer"),
                );

                None
            })
    }

    fn track_collection_metrics(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            let type_name = tynm::type_name::<Self>();

            metrics.set_collection_length(
                &type_name,
                "received_blob_sidecars",
                self.received_blob_sidecars.len(),
            );

            metrics.set_collection_length(
                &type_name,
                "received_block_roots",
                self.received_block_roots.len(),
            );

            metrics.set_collection_length(
                &type_name,
                "received_data_column_sidecars",
                self.received_data_column_sidecars.len(),
            );
        }
    }

    /// Checks all custody column subnets for peers. Returns `true` if there is at least one peer in
    /// every custody column subnet.
    fn check_good_peers_on_column_subnets(&self, epoch: Epoch) -> bool {
        let chain_config = self.controller.chain_config();

        if chain_config.is_eip7594_fork(epoch) {
            self.network_globals.custody_subnets().all(|subnet_id| {
                let peer_count = self
                    .network_globals
                    .peers
                    .read()
                    .good_custody_subnet_peer(subnet_id)
                    .count();

                self.metrics.as_ref().map(|metrics| {
                    metrics.set_column_subnet_peers(&subnet_id.to_string(), peer_count)
                });
                peer_count > 0
            })
        } else {
            true
        }
    }

    const fn start_of_epoch(epoch: Epoch) -> Slot {
        misc::compute_start_slot_at_epoch::<P>(epoch)
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("end slot overflowed ({start_slot} + {difference})")]
    EndSlotOverflow { start_slot: u64, difference: u64 },
}

fn fork_digest(fork_context: &ForkContext) -> ForkDigest {
    fork_context
        .to_context_bytes(fork_context.current_fork())
        .expect("fork digest for current fork are added when fork context is created")
}

fn run_network_service<P: Preset>(
    mut service: Service<RequestId, P>,
    mut network_to_service_rx: UnboundedReceiver<ServiceInboundMessage<P>>,
    service_to_network_tx: UnboundedSender<ServiceOutboundMessage<P>>,
) {
    tokio::spawn(async move {
        loop {
            select! {
                network_event = service.next_event().fuse() => {
                    ServiceOutboundMessage::NetworkEvent(network_event).send(&service_to_network_tx);
                }

                message = network_to_service_rx.select_next_some() => {
                    match message {
                        ServiceInboundMessage::DiscoverSubnetPeers(subnet_discoveries) => {
                            service.discover_subnet_peers(subnet_discoveries);
                        }
                        ServiceInboundMessage::GoodbyePeer(peer_id, goodbye_reason, report_source) => {
                            service.goodbye_peer(&peer_id, goodbye_reason, report_source);
                        }
                        ServiceInboundMessage::Publish(message) => {
                            service.publish(vec![message]);
                        }
                        ServiceInboundMessage::PublishBatch(messages) => {
                            service.publish(messages);
                        }
                        ServiceInboundMessage::ReportPeer(peer_id, action, source, msg) => {
                            service.report_peer(&peer_id, action, source, msg);
                        }
                        ServiceInboundMessage::ReportMessageValidationResult(gossip_id, message_acceptance) => {
                            service.report_message_validation_result(
                                &gossip_id.source,
                                gossip_id.message_id,
                                message_acceptance,
                            );
                        }
                        ServiceInboundMessage::SendRequest(peer_id, request_id, request) => {
                            if let Err((request_id, error)) = service.send_request(peer_id, request_id, request) {
                                warn!("error while sending request_id: {request_id} with error: {error:?}");
                            }
                        }
                        ServiceInboundMessage::SendResponse(peer_id, peer_request_id, response) => {
                            service.send_response(peer_id, peer_request_id, *response);
                        }
                        ServiceInboundMessage::Subscribe(gossip_topic) => {
                            service.subscribe(gossip_topic);
                        }
                        ServiceInboundMessage::SubscribeKind(gossip_kind) => {
                            service.subscribe_kind(gossip_kind);
                        }
                        ServiceInboundMessage::SubscribeNewForkTopics(phase, fork_digest) => {
                            service.subscribe_new_fork_topics(phase, fork_digest);
                        }
                        ServiceInboundMessage::Unsubscribe(gossip_topic) => {
                            service.unsubscribe(gossip_topic);
                        }
                        ServiceInboundMessage::UnsubscribeFromForkTopicsExcept(fork_digest) => {
                            service.unsubscribe_from_fork_topics_except(fork_digest);
                        }
                        ServiceInboundMessage::UpdateEnrSubnet(subnet, advertise) => {
                            service.update_enr_subnet(subnet, advertise);
                        }
                        ServiceInboundMessage::UpdateForkVersion(enr_fork_id) => {
                            service.update_fork_version(enr_fork_id);
                        }
                    }
                }
            }
        }
    });
}

fn log(level: Level, connected_peers: usize, target_peers: usize, message: impl Display) {
    log!(
        level,
        "[Peers: {}/{}] {}",
        connected_peers,
        target_peers,
        message,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_REQUEST_BLOCKS: u64 = 1024;

    #[test]
    fn ensure_constant_sanity() {
        assert!(MAX_FOR_DOS_PREVENTION < MAX_REQUEST_BLOCKS);
    }
}
