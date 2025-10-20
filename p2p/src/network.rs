use core::{cmp::Ordering, time::Duration};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::Instant,
};

use anyhow::{bail, Result};
use data_dumper::DataDumper;
use dedicated_executor::DedicatedExecutor;
use eip_7594::{compute_columns_for_custody_group, get_custody_groups};
use enum_iterator::Sequence as _;
use eth1_api::{BlobFetcherToP2p, RealController};
use eth2_libp2p::{
    rpc::{
        methods::{
            BlobsByRangeRequest, BlobsByRootRequest, BlocksByRootRequest,
            DataColumnsByRangeRequest, DataColumnsByRootRequest, OldBlocksByRangeRequest,
            RpcErrorResponse, RpcResponse,
        },
        GoodbyeReason, InboundRequestId, RequestType, StatusMessage, StatusMessageV2,
    },
    service::{api_types::AppRequestId, Network as Service},
    types::{core_topics_to_subscribe, EnrForkId, ForkContext, GossipEncoding},
    Context, GossipId, GossipTopic, MessageAcceptance, MessageId, NetworkConfig, NetworkEvent,
    NetworkGlobals, PeerAction, PeerId, PubsubMessage, ReportSource, Response, ShutdownReason,
    Subnet, SubnetDiscovery, SyncInfo, SyncStatus, TaskExecutor,
};
use features::Feature;
use fork_choice_control::{BlockWithRoot, MutatorRejectionReason, P2pMessage};
use futures::{
    channel::mpsc::{Receiver, UnboundedReceiver, UnboundedSender},
    future::FutureExt as _,
    select,
    stream::StreamExt as _,
};
use helper_functions::{accessors, misc};
use logging::{
    debug_with_peers, error_with_peers, info_with_peers, trace_with_peers, warn_with_peers,
    PEER_LOG_METRICS,
};
use operation_pools::{BlsToExecutionChangePool, Origin, PoolToP2pMessage, SyncCommitteeAggPool};
use prometheus_client::registry::Registry;
use prometheus_metrics::Metrics;
use ssz::ContiguousList;
use std_ext::ArcExt as _;
use thiserror::Error;
use tokio_stream::wrappers::IntervalStream;
use types::{
    altair::containers::{SignedContributionAndProof, SyncCommitteeMessage},
    capella::containers::SignedBlsToExecutionChange,
    combined::{Attestation, AttesterSlashing, SignedAggregateAndProof, SignedBeaconBlock},
    config::Config,
    deneb::containers::{BlobIdentifier, BlobSidecar},
    fulu::{
        containers::{DataColumnIdentifier, DataColumnSidecar, DataColumnsByRootIdentifier},
        primitives::ColumnIndex,
    },
    nonstandard::{Phase, RelativeEpoch, WithStatus},
    phase0::{
        consts::{FAR_FUTURE_EPOCH, GENESIS_EPOCH},
        containers::{ProposerSlashing, SignedVoluntaryExit},
        primitives::{Epoch, NodeId, Slot, SubnetId, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::{
    messages::{
        ApiToP2p, P2pToSlasher, P2pToSync, P2pToValidator, ServiceInboundMessage,
        ServiceOutboundMessage, SubnetServiceToP2p, SyncToP2p, ValidatorToP2p,
    },
    misc::{
        AttestationSubnetActions, RPCRequestType, SubnetPeerDiscovery, SyncCommitteeSubnetAction,
    },
    upnp::PortMappings,
};

const GOSSIPSUB_PARAMETER_UPDATE_INTERVAL: Duration = Duration::from_secs(60);
const NETWORK_METRICS_UPDATE_INTERVAL: Duration = Duration::from_secs(1);

// > Clients MAY limit the number of blocks and sidecars in the response.
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
    pub blob_fetcher_to_p2p_rx: UnboundedReceiver<BlobFetcherToP2p<P>>,
    pub fork_choice_to_p2p_rx: UnboundedReceiver<P2pMessage<P>>,
    pub pool_to_p2p_rx: UnboundedReceiver<PoolToP2pMessage>,
    pub p2p_to_sync_tx: UnboundedSender<P2pToSync<P>>,
    pub p2p_to_validator_tx: UnboundedSender<P2pToValidator<P>>,
    pub sync_to_p2p_rx: UnboundedReceiver<SyncToP2p<P>>,
    pub validator_to_p2p_rx: UnboundedReceiver<ValidatorToP2p<P>>,
    pub network_to_slasher_tx: Option<UnboundedSender<P2pToSlasher<P>>>,
    pub subnet_service_to_p2p_rx: UnboundedReceiver<SubnetServiceToP2p>,
}

#[expect(clippy::struct_field_names)]
pub struct Network<P: Preset> {
    network_globals: Arc<NetworkGlobals>,
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
    #[expect(dead_code)]
    port_mappings: Option<PortMappings>,
    data_dumper: Arc<DataDumper>,
    earliest_available_slot: Slot,
    last_nfd_update_epoch: Option<Epoch>,
    backfill_custody_groups: bool,
}

impl<P: Preset> Network<P> {
    #[must_use]
    pub const fn network_globals(&self) -> &Arc<NetworkGlobals> {
        &self.network_globals
    }

    #[expect(clippy::too_many_arguments)]
    pub async fn new(
        network_config: Arc<NetworkConfig>,
        controller: RealController<P>,
        slot: Slot,
        channels: Channels<P>,
        dedicated_executor: Arc<DedicatedExecutor>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P>>,
        bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
        metrics: Option<Arc<Metrics>>,
        libp2p_registry: Option<&mut Registry>,
        data_dumper: Arc<DataDumper>,
        backfill_custody_groups: bool,
    ) -> Result<Self> {
        let chain_config = controller.chain_config();
        let head_state = controller.head_state().value;

        let fork_context = Arc::new(ForkContext::new::<P>(
            chain_config,
            slot,
            head_state.genesis_validators_root(),
        ));

        let enr_fork_id = Self::enr_fork_id(&controller, &fork_context, slot);
        let (shutdown_tx, shutdown_rx) = futures::channel::mpsc::channel(1);
        let executor = TaskExecutor::new(shutdown_tx);

        let mut custody_group_count =
            chain_config.custody_group_count(network_config.subscribe_all_data_column_subnets);

        let context = Context {
            chain_config: chain_config.clone_arc(),
            config: network_config.clone_arc(),
            enr_fork_id,
            fork_context: fork_context.clone_arc(),
            libp2p_registry,
        };

        // Box the future to pass `clippy::large_futures`.
        let (mut service, network_globals) = Box::pin(Service::new(
            chain_config.clone_arc(),
            executor,
            context,
            custody_group_count,
        ))
        .await?;

        let mut port_mappings = None;

        if network_config.upnp_enabled && !network_config.disable_discovery {
            match PortMappings::new(&network_config) {
                Ok(mappings) => port_mappings = Some(mappings),
                Err(error) => warn_with_peers!("error while initializing UPnP: {error}"),
            }
        }

        let earliest_available_slot = controller.anchor_block().message().slot();

        if chain_config.is_peerdas_scheduled() {
            // dereference is required to avoid deadlock
            let metadata = *network_globals.local_metadata.read();
            let node_id = network_globals.local_enr().node_id().raw();

            if let Some(prev_custody_group_count) = metadata.custody_group_count() {
                // If the node's custody requirements are increased,
                // it SHOULD immediately advertise the updated custody_group_count.
                // It MAY backfill custody groups as a result of this change.
                if prev_custody_group_count < custody_group_count {
                    service.update_enr_cgc(custody_group_count);

                    if backfill_custody_groups {
                        let prev_sampling_size =
                            chain_config.sampling_size_custody_groups(prev_custody_group_count);

                        let prev_sampling_columns =
                            Self::sampling_columns(chain_config, node_id, prev_sampling_size)?;

                        let current_sampling_size =
                            chain_config.sampling_size_custody_groups(custody_group_count);

                        let current_sampling_columns =
                            Self::sampling_columns(chain_config, node_id, current_sampling_size)?;

                        let backfill_column_indices =
                            &prev_sampling_columns - &current_sampling_columns;

                        if !backfill_column_indices.is_empty() {
                            P2pToSync::RequestCustodyGroupBackfill(
                                backfill_column_indices,
                                earliest_available_slot,
                            )
                            .send(&channels.p2p_to_sync_tx);
                        }
                    }
                }

                custody_group_count = custody_group_count.max(prev_custody_group_count);
            }

            let sampling_size = chain_config.sampling_size_custody_groups(custody_group_count);
            let sampling_columns = Self::sampling_columns(chain_config, node_id, sampling_size)?;

            controller.on_store_sampling_columns(sampling_columns);
        }

        if let Some(metrics) = metrics.as_ref() {
            metrics.set_beacon_custody_groups(custody_group_count);
        }

        let (network_to_service_tx, network_to_service_rx) = futures::channel::mpsc::unbounded();
        let (service_to_network_tx, service_to_network_rx) = futures::channel::mpsc::unbounded();

        run_network_service(service, network_to_service_rx, service_to_network_tx);

        let network = Self {
            network_globals,
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
            port_mappings,
            data_dumper,
            earliest_available_slot,
            last_nfd_update_epoch: None,
            backfill_custody_groups,
        };

        Ok(network)
    }

    #[expect(clippy::too_many_lines)]
    pub async fn run(mut self) -> Result<()> {
        let mut gossipsub_parameter_update_interval =
            IntervalStream::new(tokio::time::interval(GOSSIPSUB_PARAMETER_UPDATE_INTERVAL)).fuse();

        loop {
            select! {
                _ = gossipsub_parameter_update_interval.select_next_some() => {
                    let debug_info = message_debug_info("update_gossipsub_parameters");

                    self.update_gossipsub_parameters();

                    debug_info.handle();
                },

                message = self.service_to_network_rx.select_next_some() => {
                    let debug_info = message_debug_info(&message);

                    match message {
                        ServiceOutboundMessage::NetworkEvent(network_event) => {
                            self.handle_network_event(network_event)
                        }
                    }

                    debug_info.handle();
                },

                message = self.channels.blob_fetcher_to_p2p_rx.select_next_some() => {
                    let debug_info = message_debug_info(&message);

                    match message {
                        BlobFetcherToP2p::BlobsNeeded(identifiers, slot, peer_id) => {
                            debug_with_peers!("blobs needed: {identifiers:?} from {peer_id:?}");

                            P2pToSync::BlobsNeeded(identifiers, slot, peer_id)
                                .send(&self.channels.p2p_to_sync_tx);
                        }
                        BlobFetcherToP2p::DataColumnsNeeded(data_columns_by_root, slot) => {
                            debug_with_peers!("data columns needed: {data_columns_by_root:?}");

                            P2pToSync::DataColumnsNeeded(data_columns_by_root, slot)
                                .send(&self.channels.p2p_to_sync_tx);
                        }
                    }

                    debug_info.handle();
                },

                message = self.channels.api_to_p2p_rx.select_next_some() => {
                    let debug_info = message_debug_info(&message);

                    let success = match message {
                        ApiToP2p::PublishBeaconBlock(beacon_block) => {
                            self.publish_beacon_block(beacon_block);
                            true
                        },
                        ApiToP2p::PublishBlobSidecar(blob_sidecar) => {
                            self.publish_blob_sidecar(blob_sidecar);
                            true
                        },
                        ApiToP2p::PublishDataColumnSidecar(data_column_sidecar) => {
                            self.publish_data_column_sidecar(data_column_sidecar);
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
                        ApiToP2p::PublishProposerSlashing(proposer_slashing) => {
                            self.publish_proposer_slashing(proposer_slashing);
                            true
                        }
                        ApiToP2p::PublishAttesterSlashing(attester_slashing) => {
                            self.publish_attester_slashing(attester_slashing);
                            true
                        }
                        ApiToP2p::PublishVoluntaryExit(voluntary_exit) => {
                            self.publish_voluntary_exit(voluntary_exit);
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
                        debug_with_peers!("send to HTTP API failed because the receiver was dropped");
                    }

                    debug_info.handle();
                },

                message = self.channels.pool_to_p2p_rx.select_next_some() => {
                    let debug_info = message_debug_info(&message);

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

                    debug_info.handle();
                },

                message = self.channels.fork_choice_to_p2p_rx.select_next_some() => {
                    let debug_info = message_debug_info(&message);

                    match message {
                        P2pMessage::Slot(slot) => {
                            self.on_slot(slot);
                        }
                        P2pMessage::Accept(gossip_id) => {
                            self.report_outcome(gossip_id, MessageAcceptance::Accept);
                        }
                        P2pMessage::Ignore(gossip_id) => {
                            self.report_outcome(gossip_id, MessageAcceptance::Ignore);
                        }
                        P2pMessage::PublishBlobSidecar(blob_sidecar) => {
                            self.publish_blob_sidecar(blob_sidecar);
                        },
                        P2pMessage::PublishDataColumnSidecar(data_column_sidecar) => {
                            self.publish_data_column_sidecar(data_column_sidecar);
                        }
                        P2pMessage::PenalizePeer(peer_id, mutator_rejection_reason) => {
                            self.report_peer(
                                peer_id,
                                PeerAction::LowToleranceError,
                                ReportSource::Processor,
                                mutator_rejection_reason,
                            );
                        }
                        P2pMessage::Reject(gossip_id, mutator_rejection_reason) => {
                            match mutator_rejection_reason {
                                MutatorRejectionReason::InvalidBlobSidecar { blob_identifier } => {
                                    P2pToSync::BlobSidecarRejected(blob_identifier)
                                        .send(&self.channels.p2p_to_sync_tx)
                                }
                                MutatorRejectionReason::InvalidDataColumnSidecar { data_column_identifier } => {
                                    P2pToSync::DataColumnSidecarRejected(data_column_identifier)
                                        .send(&self.channels.p2p_to_sync_tx)
                                }
                                _ => {}
                            }

                            if let Some(gossip_id) = gossip_id {
                                self.report_outcome(gossip_id.clone(), MessageAcceptance::Reject);
                                self.report_peer(
                                    gossip_id.source,
                                    PeerAction::LowToleranceError,
                                    ReportSource::Processor,
                                    mutator_rejection_reason,
                                );
                            }
                        }
                        P2pMessage::BlockNeeded(root, peer_id) => {
                            P2pToSync::BlockNeeded(root, peer_id)
                                .send(&self.channels.p2p_to_sync_tx);
                        }
                        P2pMessage::FinalizedCheckpoint(finalized_checkpoint) => {
                            P2pToSync::FinalizedCheckpoint(finalized_checkpoint)
                                .send(&self.channels.p2p_to_sync_tx);
                        }
                        P2pMessage::HeadChanged(_root) => {
                            // This message is only used in tests
                        }
                        P2pMessage::Stop => {
                            ServiceInboundMessage::Stop.send(&self.network_to_service_tx);
                            P2pToSync::Stop.send(&self.channels.p2p_to_sync_tx);
                            break;
                        }
                    }

                    debug_info.handle();
                },

                message = self.channels.validator_to_p2p_rx.select_next_some() => {
                    let debug_info = message_debug_info(&message);

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
                        ValidatorToP2p::PublishDataColumnSidecar(data_column_sidecar) => {
                            self.publish_data_column_sidecar(data_column_sidecar);
                        }
                        ValidatorToP2p::PublishSingularAttestation(attestation, subnet_id) => {
                            self.publish_singular_attestation(attestation, subnet_id);
                        }
                        ValidatorToP2p::PublishAggregateAndProof(aggregate_and_proof) => {
                            self.publish_aggregate_and_proof(aggregate_and_proof);
                        }
                        ValidatorToP2p::PublishSyncCommitteeMessage(message) => {
                            self.publish_sync_committee_message(message);
                        }
                        ValidatorToP2p::PublishContributionAndProof(contribution_and_proof) => {
                            self.publish_contribution_and_proof(contribution_and_proof);
                        }
                        ValidatorToP2p::UpdateDataColumnSubnets(custody_group_count) => {
                            self.update_data_column_subnets(custody_group_count);
                        }
                    }

                    debug_info.handle();
                },

                message = self.channels.sync_to_p2p_rx.select_next_some() => {
                    let debug_info = message_debug_info(&message);

                    match message {
                        SyncToP2p::ReportPeer(peer_id, peer_action, report_source, reason) => {
                            self.report_peer(
                                peer_id,
                                peer_action,
                                report_source,
                                reason
                            );
                        }
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
                        SyncToP2p::RequestDataColumnsByRange(request_id, peer_id, start_slot, count, columns) => {
                            self.request_data_columns_by_range(request_id, peer_id, start_slot, count, columns);
                        }
                        SyncToP2p::RequestPeerStatus(request_id, peer_id) => {
                            self.request_peer_status(request_id, peer_id);
                        }
                        SyncToP2p::SubscribeToCoreTopics => {
                            self.subscribe_to_core_topics();
                        }
                        SyncToP2p::UpdateEarliestAvailableSlot(slot) => {
                            self.update_earliest_available_slot(slot);
                        }
                    }

                    debug_info.handle();
                },

                message = self.channels.subnet_service_to_p2p_rx.select_next_some() => {
                    let debug_info = message_debug_info(&message);

                    match message {
                        SubnetServiceToP2p::UpdateAttestationSubnets(actions) => {
                            self.update_attestation_subnets(actions);
                        }
                        SubnetServiceToP2p::UpdateSyncCommitteeSubnets(actions) => {
                            self.update_sync_committee_subnets(actions);
                        }
                    }

                    debug_info.handle();
                },

                shutdown_reason = self.shutdown_rx.select_next_some() => match shutdown_reason {
                    ShutdownReason::Failure(message) => {
                        bail!("eth2_libp2p initiated shutdown: {message}");
                    }
                }
            }
        }

        Ok(())
    }

    fn on_slot(&mut self, slot: Slot) {
        P2pToSync::Slot(slot).send(&self.channels.p2p_to_sync_tx);

        let chain_config = self.controller.chain_config();
        let phase_by_slot = chain_config.phase_at_slot::<P>(slot);
        let phase_by_state = self.fork_context.current_fork_name();
        let epoch = misc::compute_epoch_at_slot::<P>(slot);

        let fork_digest_by_epoch = self.fork_context.context_bytes(epoch);
        let fork_digest_by_state = self.fork_context.current_fork_digest();

        if fork_digest_by_state != fork_digest_by_epoch {
            if phase_by_slot == phase_by_state {
                info_with_peers!(
                    "updating fork digest from {fork_digest_by_state} to {fork_digest_by_epoch}"
                );
            } else {
                info_with_peers!("switching from {phase_by_state} to {phase_by_slot}");
            }
            self.fork_context.update_current_fork();

            let new_enr_fork_id = Self::enr_fork_id(&self.controller, &self.fork_context, slot);

            ServiceInboundMessage::UpdateFork(new_enr_fork_id).send(&self.network_to_service_tx);
        }

        // Update `nfd` field in `eth2` in ENR.
        if chain_config.is_peerdas_scheduled() && self.last_nfd_update_epoch != Some(epoch) {
            let next_fork_digest = self.fork_context.next_fork_digest().unwrap_or_default();

            if fork_digest_by_state != fork_digest_by_epoch || self.last_nfd_update_epoch.is_none()
            {
                ServiceInboundMessage::UpdateNextForkDigest(next_fork_digest)
                    .send(&self.network_to_service_tx);
            }

            self.last_nfd_update_epoch = Some(epoch);
        }

        // Subscribe to the topics of the next phase.
        if let Some((next_phase, next_fork_digest, next_fork_epoch)) = self.fork_context.next_fork()
        {
            let next_phase_slot = misc::compute_start_slot_at_epoch::<P>(next_fork_epoch);

            if slot + NEW_PHASE_TOPICS_ADVANCE_SLOTS == next_phase_slot {
                info_with_peers!(
                    "subscribing to new topics for {next_phase} with digest {next_fork_digest}"
                );

                ServiceInboundMessage::SubscribeNewForkTopics(next_phase, next_fork_digest)
                    .send(&self.network_to_service_tx);
            }
        }

        if Some(phase_by_slot) > Phase::first() && misc::is_epoch_start::<P>(slot) {
            // Unsubscribe from the topics of previous phases.
            if self.fork_context.current_fork_epoch() + OLD_PHASE_TOPICS_REMAIN_EPOCHS == epoch {
                info_with_peers!("unsubscribing from old topics");

                let fork_digest = self.fork_context.current_fork_digest();
                ServiceInboundMessage::UnsubscribeFromForkTopicsExcept(fork_digest)
                    .send(&self.network_to_service_tx);
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
            // > Furthermore, the existing `next_fork_epoch` field under the `eth2` entry MUST be
            // > set to the epoch of the next fork, whether a regular fork, _or a BPO fork_.
            //
            // > If no future fork is planned,
            // > set `next_fork_epoch = FAR_FUTURE_EPOCH` to signal this fact
            next_fork_epoch = fork_context
                .next_fork()
                .map(|(_, _, fork_epoch)| fork_epoch)
                .unwrap_or(FAR_FUTURE_EPOCH);
        }

        EnrForkId {
            fork_digest: fork_context.current_fork_digest(),
            next_fork_version,
            next_fork_epoch,
        }
    }

    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId::from_be_bytes(self.network_globals.local_enr().node_id().raw())
    }

    fn publish_beacon_block(&self, beacon_block: Arc<SignedBeaconBlock<P>>) {
        debug_with_peers!(
            "publishing beacon block slot: {}, root: {:?}",
            beacon_block.message().slot(),
            beacon_block.message().hash_tree_root()
        );

        self.publish(PubsubMessage::BeaconBlock(beacon_block));
    }

    fn publish_blob_sidecar(&self, blob_sidecar: Arc<BlobSidecar<P>>) {
        let subnet_id =
            misc::compute_subnet_for_blob_sidecar(self.controller.chain_config(), &blob_sidecar);

        let blob_identifier: BlobIdentifier = blob_sidecar.as_ref().into();

        debug_with_peers!("publishing blob sidecar: {blob_identifier:?}, subnet_id: {subnet_id}");

        self.publish(PubsubMessage::BlobSidecar(Box::new((
            subnet_id,
            blob_sidecar,
        ))));
    }

    fn publish_data_column_sidecar(&self, data_column_sidecar: Arc<DataColumnSidecar<P>>) {
        let subnet_id = misc::compute_subnet_for_data_column_sidecar(
            self.controller.chain_config(),
            data_column_sidecar.index,
        );

        let data_column_identifier: DataColumnIdentifier = data_column_sidecar.as_ref().into();

        debug_with_peers!(
            "publishing data column sidecar: {data_column_identifier:?}, subnet_id: {subnet_id}",
        );

        self.publish(PubsubMessage::DataColumnSidecar(Box::new((
            subnet_id,
            data_column_sidecar,
        ))));
    }

    fn publish_singular_attestation(&self, attestation: Arc<Attestation<P>>, subnet_id: SubnetId) {
        if attestation.count_aggregation_bits() != 1 {
            error_with_peers!(
                "attempted to publish singular attestation \
                 with invalid number of participants: {attestation:?}",
            );

            return;
        }

        trace_with_peers!(
            "publishing singular attestation (attestation: {attestation:?}, subnet_id: {subnet_id})",
        );

        match Arc::unwrap_or_clone(attestation) {
            Attestation::Phase0(phase0_attestation) => {
                self.publish(PubsubMessage::Attestation(
                    subnet_id,
                    Attestation::Phase0(phase0_attestation).into(),
                ));
            }
            Attestation::Electra(electra_attestation) => {
                let network_to_service_tx = self.network_to_service_tx.clone();
                let controller = self.controller.clone_arc();

                // Attestation conversion may be CPU intensive, so it is done in a separate task.
                self.dedicated_executor
                    .spawn(async move {
                        let single_attestation = match operation_pools::try_convert_to_single_attestation(
                            &controller,
                            electra_attestation,
                        ) {
                            Ok(single_attestation) => single_attestation,
                            Err(error) => {
                                warn_with_peers!(
                                    "cannot convert electra attestation to single attestation: {error:?}",
                                );
                                return;
                            }
                        };

                        let message = PubsubMessage::SingleAttestation(
                            subnet_id,
                            single_attestation,
                        );

                        ServiceInboundMessage::Publish(message).send(&network_to_service_tx);
                    })
                    .detach();
            }
            Attestation::Single(single_attestation) => {
                self.publish(PubsubMessage::SingleAttestation(
                    subnet_id,
                    single_attestation,
                ));
            }
        }
    }

    fn publish_aggregate_and_proof(&self, aggregate_and_proof: Arc<SignedAggregateAndProof<P>>) {
        if aggregate_and_proof
            .message()
            .aggregate()
            .count_aggregation_bits()
            == 0
        {
            error_with_peers!(
                "attempted to publish aggregate and proof with no participants: \
                 {aggregate_and_proof:?}",
            );

            return;
        }

        trace_with_peers!("publishing aggregate and proof: {aggregate_and_proof:?}");

        self.publish(PubsubMessage::AggregateAndProofAttestation(
            aggregate_and_proof,
        ));
    }

    fn publish_proposer_slashing(&self, slashing: Box<ProposerSlashing>) {
        debug_with_peers!("publishing proposer slashing: {slashing:?}");

        self.publish(PubsubMessage::ProposerSlashing(slashing));
    }

    fn publish_attester_slashing(&self, slashing: Box<AttesterSlashing<P>>) {
        debug_with_peers!("publishing attester slashing: {slashing:?}");

        self.publish(PubsubMessage::AttesterSlashing(slashing));
    }

    fn publish_voluntary_exit(&self, voluntary_exit: Box<SignedVoluntaryExit>) {
        debug_with_peers!("publishing voluntary exit: {voluntary_exit:?}");

        self.publish(PubsubMessage::VoluntaryExit(voluntary_exit));
    }

    fn publish_sync_committee_message(&self, message: Box<(SubnetId, SyncCommitteeMessage)>) {
        trace_with_peers!("publishing sync committee message: {message:?}");

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
            warn_with_peers!(
                "attempted to publish sync committee contribution \
                and proof with no participants: {contribution_and_proof:?}",
            );

            return;
        }

        trace_with_peers!(
            "publishing sync committee contribution and proof: {contribution_and_proof:?}"
        );

        self.publish(PubsubMessage::SignedContributionAndProof(
            contribution_and_proof,
        ));
    }

    fn publish_signed_bls_to_execution_change(
        &self,
        signed_bls_to_execution_change: Box<SignedBlsToExecutionChange>,
    ) {
        trace_with_peers!(
            "publishing signed bls to execution change: {signed_bls_to_execution_change:?}"
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
                            * chain_config.slot_duration_ms.as_secs();
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
                debug_with_peers!("subscribing to attestation subnet (subnet_id: {subnet_id})");

                // TODO(Grandine Team): The Honest Validator specification says:
                //                      > *Note*: When preparing for a hard fork, a validator must
                //                      > select and subscribe to random subnets of the future
                //                      > fork versioning at least
                //                      > `EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION` epochs in
                //                      > advance of the fork.
                let topic = self.subnet_gossip_topic(subnet);
                ServiceInboundMessage::Subscribe(topic).send(&self.network_to_service_tx);
            } else {
                debug_with_peers!("unsubscribing from attestation subnet {subnet_id}");

                let topic = self.subnet_gossip_topic(subnet);
                ServiceInboundMessage::Unsubscribe(topic).send(&self.network_to_service_tx);
            }
        }

        for (subnet_id, add_to_enr) in enr {
            let subnet = Subnet::Attestation(subnet_id);

            if add_to_enr {
                debug_with_peers!("adding attestation subnet to ENR (subnet_id: {subnet_id})");
            } else {
                debug_with_peers!("removing attestation subnet from ENR (subnet_id: {subnet_id})");
            }

            ServiceInboundMessage::UpdateEnrSubnet(subnet, add_to_enr)
                .send(&self.network_to_service_tx);
        }
    }

    fn update_gossipsub_parameters(&self) {
        let head_state = self.controller.head_state().value();
        let active_validator_count =
            accessors::active_validator_count_u64(&head_state, RelativeEpoch::Current);

        ServiceInboundMessage::UpdateGossipsubParameters(active_validator_count, head_state.slot())
            .send(&self.network_to_service_tx);
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
                    debug_with_peers!("subscribing to sync committee subnet {subnet_id}");

                    // TODO(Grandine Team): Does it make sense to use the Phase 0 digest here?
                    let topic = self.subnet_gossip_topic(subnet);

                    ServiceInboundMessage::Subscribe(topic).send(&self.network_to_service_tx);
                    ServiceInboundMessage::UpdateEnrSubnet(subnet, true)
                        .send(&self.network_to_service_tx);
                }
                SyncCommitteeSubnetAction::DiscoverPeers => {
                    debug_with_peers!("discovering peers in sync committee subnet {subnet_id}");
                }
                SyncCommitteeSubnetAction::Unsubscribe => {
                    debug_with_peers!("unsubscribing from sync committee subnet {subnet_id}");

                    // TODO(Grandine Team): Does it make sense to use the Phase 0 digest here?
                    let topic = self.subnet_gossip_topic(subnet);

                    ServiceInboundMessage::Unsubscribe(topic).send(&self.network_to_service_tx);
                    ServiceInboundMessage::UpdateEnrSubnet(subnet, false)
                        .send(&self.network_to_service_tx);
                }
            }
        }
    }

    fn update_data_column_subnets(&mut self, custody_group_count: u64) {
        ServiceInboundMessage::UpdateEnrCgc(custody_group_count).send(&self.network_to_service_tx);

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.set_beacon_custody_groups(custody_group_count);
        }

        let node_id = self.network_globals.local_enr().node_id().raw();
        let config = self.controller.chain_config();
        let sampling_size = config.sampling_size_custody_groups(custody_group_count);

        ServiceInboundMessage::UpdateDataColumnSubnets(sampling_size)
            .send(&self.network_to_service_tx);

        let sampling_columns = Self::sampling_columns(config, node_id, sampling_size)
            .expect("should compute node custody groups and columns");

        if self.backfill_custody_groups {
            let current_sampling_columns = self.controller.sampling_columns();
            let backfill_column_indices = &sampling_columns - &current_sampling_columns;

            if !backfill_column_indices.is_empty() {
                P2pToSync::RequestCustodyGroupBackfill(
                    backfill_column_indices,
                    self.earliest_available_slot,
                )
                .send(&self.channels.p2p_to_sync_tx);

                self.update_earliest_available_slot(self.controller.slot());
            }
        }

        self.controller.on_store_sampling_columns(sampling_columns);
    }

    fn sampling_columns(
        chain_config: &Config,
        raw_node_id: [u8; 32],
        sampling_size: u64,
    ) -> Result<HashSet<ColumnIndex>> {
        let custody_groups = get_custody_groups(chain_config, raw_node_id, sampling_size)?;

        let mut sampling_columns = HashSet::new();
        for custody_index in custody_groups {
            let columns = compute_columns_for_custody_group::<P>(chain_config, custody_index)?;
            sampling_columns.extend(columns);
        }

        Ok(sampling_columns)
    }

    const fn update_earliest_available_slot(&mut self, slot: Slot) {
        self.earliest_available_slot = slot;
    }

    fn handle_network_event(&self, network_event: NetworkEvent<P>) {
        match network_event {
            NetworkEvent::PeerConnectedIncoming(peer_id) => {
                debug_with_peers!("peer {peer_id} connected incoming");
                self.update_peer_count();
            }
            NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                debug_with_peers!("peer {peer_id} connected outgoing");
                self.update_peer_count();
                self.init_status_peer_request(peer_id);
            }
            NetworkEvent::PeerDisconnected(peer_id) => {
                debug_with_peers!("peer {peer_id} disconnected");
                P2pToSync::RemovePeer(peer_id).send(&self.channels.p2p_to_sync_tx);
                self.update_peer_count();
            }
            NetworkEvent::RPCFailed {
                app_request_id,
                peer_id,
                error,
            } => {
                debug_with_peers!(
                    "app_request_id: {app_request_id:?} to peer {peer_id} failed: {error}"
                );
                P2pToSync::RequestFailed(peer_id).send(&self.channels.p2p_to_sync_tx);
            }
            NetworkEvent::RequestReceived {
                peer_id,
                inbound_request_id,
                request_type,
            } => {
                if let Err(error) = self.handle_request(peer_id, inbound_request_id, request_type) {
                    error_with_peers!("error while handling request: {error}");
                }
            }
            NetworkEvent::ResponseReceived {
                peer_id,
                app_request_id,
                response,
            } => self.handle_response(peer_id, app_request_id, response),
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
                debug_with_peers!("libp2p listening on {multiaddr}");
            }
            NetworkEvent::ZeroListeners => debug_with_peers!("libp2p has zero listeners"),
            NetworkEvent::PeerUpdatedCustodyGroupCount(peer_id) => {
                debug_with_peers!(
                    "peer {peer_id} has updated their advertised custody group count"
                );
                P2pToSync::PeerCgcUpdated(peer_id).send(&self.channels.p2p_to_sync_tx);
            }
        }
    }

    fn handle_request(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request_type: RequestType<P>,
    ) -> Result<()> {
        match request_type {
            RequestType::Status(remote) => {
                self.handle_status_request(peer_id, inbound_request_id, remote);
                Ok(())
            }
            RequestType::BlocksByRange(request) => {
                self.handle_blocks_by_range_request(peer_id, inbound_request_id, request)
            }
            RequestType::BlocksByRoot(request) => {
                self.handle_blocks_by_root_request(peer_id, inbound_request_id, request);
                Ok(())
            }
            RequestType::DataColumnsByRoot(request) => {
                self.handle_data_columns_by_root_request(peer_id, inbound_request_id, request);
                Ok(())
            }
            RequestType::DataColumnsByRange(request) => {
                self.handle_data_columns_by_range_request(peer_id, inbound_request_id, request)
            }
            RequestType::LightClientBootstrap(_) => {
                // TODO(Altair Light Client Sync Protocol)
                debug_with_peers!(
                    "received LightClientBootstrap request (peer_id: {peer_id}, \
                    inbound_request_id: {inbound_request_id:?})",
                );

                Ok(())
            }
            RequestType::LightClientFinalityUpdate => {
                // TODO(Altair Light Client Sync Protocol)
                debug_with_peers!(
                    "received LightClientFinalityUpdate request (peer_id: {peer_id}, \
                    inbound_request_id: {inbound_request_id:?})",
                );

                Ok(())
            }
            RequestType::LightClientOptimisticUpdate => {
                // TODO(Altair Light Client Sync Protocol)
                debug_with_peers!(
                    "received LightClientOptimisticUpdate request (peer_id: {peer_id}, \
                    inbound_request_id: {inbound_request_id:?})",
                );

                Ok(())
            }
            RequestType::LightClientUpdatesByRange(_) => {
                // TODO(Altair Light Client Sync Protocol)
                debug_with_peers!(
                    "received LightClientUpdatesByRange request (peer_id: {peer_id}, \
                    inbound_request_id: {inbound_request_id:?})",
                );

                Ok(())
            }
            RequestType::BlobsByRange(request) => {
                self.handle_blobs_by_range_request(peer_id, inbound_request_id, request)
            }
            RequestType::BlobsByRoot(request) => {
                self.handle_blobs_by_root_request(peer_id, inbound_request_id, request);
                Ok(())
            }
            RequestType::Goodbye(goodbye_reason) => {
                debug_with_peers!(
                    "received GoodBye request (peer_id: {peer_id}, \
                    inbound_request_id: {inbound_request_id:?}, reason: {goodbye_reason:?})",
                );

                Ok(())
            }
            RequestType::Ping(ping) => {
                debug_with_peers!(
                    "received Ping request (peer_id: {peer_id}, \
                    inbound_request_id: {inbound_request_id:?}, ping: {ping:?})",
                );

                Ok(())
            }
            RequestType::MetaData(request) => {
                debug_with_peers!(
                    "received MetaData request (peer_id: {peer_id}, \
                    inbound_request_id: {inbound_request_id:?}, request: {request:?})",
                );

                Ok(())
            }
        }
    }

    fn handle_status_request(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        remote: StatusMessage,
    ) {
        debug_with_peers!(
            "received Status request (peer_id: {peer_id}, \
            inbound_request_id: {inbound_request_id:?}, remote: {remote:?})",
        );

        let local = self.local_status();

        debug_with_peers!(
            "sending Status response (inbound_request_id: {inbound_request_id:?}, \
            peer_id: {peer_id}, local: {local:?})",
        );

        self.respond(peer_id, inbound_request_id, Response::<P>::Status(local));

        self.check_status(&local, remote, peer_id);
    }

    fn handle_blocks_by_range_request(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: OldBlocksByRangeRequest,
    ) -> Result<()> {
        debug_with_peers!(
            "received BeaconBlocksByRange request (peer_id: {peer_id}, \
            inbound_request_id: {inbound_request_id:?}, request: {request:?})",
        );

        let start_slot = request.start_slot();
        let max_request_blocks = request.max_request_blocks(self.controller.chain_config());
        let difference = request
            .count()
            .min(max_request_blocks)
            .min(MAX_FOR_DOS_PREVENTION);

        // `end_slot` is exclusive.
        let end_slot = start_slot
            .checked_add(difference)
            .ok_or(Error::EndSlotOverflow {
                start_slot,
                difference,
            })?;

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();

        self.dedicated_executor
            .spawn(async move {
                let blocks = controller.blocks_by_range(start_slot..end_slot)?;

                for block_with_root in blocks {
                    let BlockWithRoot { block, root } = block_with_root;

                    debug_with_peers!(
                        "sending BeaconBlocksByRange response chunk \
                        (inbound_request_id: {inbound_request_id:?}, peer_id: {peer_id}, \
                        slot: {}, root: {root:?})",
                        block.message().slot(),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        inbound_request_id,
                        Box::new(Response::BlocksByRange(Some(block))),
                    )
                    .send(&network_to_service_tx);
                }

                debug_with_peers!("terminating BeaconBlocksByRange response stream");

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    inbound_request_id,
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
        inbound_request_id: InboundRequestId,
        request: BlobsByRangeRequest,
    ) -> Result<()> {
        debug_with_peers!(
            "received BlobSidecarsByRange request (peer_id: {peer_id}, \
            inbound_request_id: {inbound_request_id:?}, request: {request:?})",
        );

        let start_epoch = misc::compute_epoch_at_slot::<P>(request.start_slot);

        if start_epoch < self.controller.min_checked_blob_availability_epoch() {
            debug_with_peers!(
                "received invalid request requesting blobs before availability period: \
                (peer_id: {peer_id}, inbound_request_id: {inbound_request_id:?}, \
                request: {request:?})",
            );

            ServiceInboundMessage::SendErrorResponse(
                peer_id,
                inbound_request_id,
                RpcErrorResponse::InvalidRequest,
                "requested blobs before data availability period",
            )
            .send(&self.network_to_service_tx);

            return Ok(());
        }

        let BlobsByRangeRequest { start_slot, count } = request;

        let difference = count.min(MAX_FOR_DOS_PREVENTION);

        let end_slot = start_slot
            .checked_add(difference)
            .ok_or(Error::EndSlotOverflow {
                start_slot,
                difference,
            })?;

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();

        self.dedicated_executor
            .spawn(async move {
                let blob_sidecars = controller.blob_sidecars_by_range(start_slot..end_slot)?;

                for blob_sidecar in blob_sidecars {
                    let blob_identifier: BlobIdentifier = blob_sidecar.as_ref().into();

                    debug_with_peers!(
                        "sending BlobSidecarsByRange response chunk \
                        (inbound_request_id: {inbound_request_id:?}, peer_id: {peer_id}, \
                        slot: {}, id: {blob_identifier:?})",
                        blob_sidecar.slot(),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        inbound_request_id,
                        Box::new(Response::BlobsByRange(Some(blob_sidecar))),
                    )
                    .send(&network_to_service_tx);
                }

                debug_with_peers!("terminating BlobSidecarsByRange response stream");

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    inbound_request_id,
                    Box::new(Response::BlobsByRange(None)),
                )
                .send(&network_to_service_tx);

                Ok::<_, anyhow::Error>(())
            })
            .detach();

        Ok(())
    }

    fn handle_data_columns_by_range_request(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: DataColumnsByRangeRequest<P>,
    ) -> Result<()> {
        debug_with_peers!(
            "received DataColumnsByRange request (peer_id: {peer_id}, \
            inbound_request_id: {inbound_request_id:?}, request: {request:?})",
        );

        let start_epoch = misc::compute_epoch_at_slot::<P>(request.start_slot);

        if start_epoch < self.controller.min_checked_data_column_availability_epoch() {
            debug_with_peers!(
                "received invalid request requesting data columns before availability period: \
                (peer_id: {peer_id}, inbound_request_id: {inbound_request_id:?}, \
                request: {request:?})",
            );

            ServiceInboundMessage::SendErrorResponse(
                peer_id,
                inbound_request_id,
                RpcErrorResponse::InvalidRequest,
                "requested data columns before data availability period",
            )
            .send(&self.network_to_service_tx);

            return Ok(());
        }

        let DataColumnsByRangeRequest {
            start_slot,
            count,
            columns,
        } = request;

        let difference = count.min(MAX_FOR_DOS_PREVENTION);

        let end_slot = start_slot
            .checked_add(difference)
            .ok_or(Error::EndSlotOverflow {
                start_slot,
                difference,
            })?;

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();
        let max_request_data_column_sidecars: usize = self
            .controller
            .chain_config()
            .max_request_data_column_sidecars
            .try_into()?;

        self.dedicated_executor
            .spawn(async move {
                // > Clients MAY limit the number of data column sidecars in the response.
                let mut data_column_sidecars = controller.data_column_sidecars_by_range(
                    start_slot..end_slot,
                    &columns,
                    max_request_data_column_sidecars,
                )?;

                // > The following data column sidecars, where they exist, MUST be sent in (slot, column_index) order.
                data_column_sidecars.sort_by_key(|sidecar| (sidecar.slot(), sidecar.index));

                for data_column_sidecar in data_column_sidecars {
                    let data_column_identifier: DataColumnIdentifier =
                        data_column_sidecar.as_ref().into();

                    debug_with_peers!(
                        "sending DataColumnsSidecarsByRange response chunk \
                        (inbound_request_id: {inbound_request_id:?}, peer_id: {peer_id}, \
                        slot: {}, id: {data_column_identifier:?})",
                        data_column_sidecar.slot(),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        inbound_request_id,
                        Box::new(Response::DataColumnsByRange(Some(data_column_sidecar))),
                    )
                    .send(&network_to_service_tx);
                }

                debug_with_peers!("terminating DataColumnsByRange response stream");

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    inbound_request_id,
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
        inbound_request_id: InboundRequestId,
        request: BlobsByRootRequest,
    ) {
        debug_with_peers!(
            "received BlobsByRootRequest request (peer_id: {peer_id}, \
            inbound_request_id: {inbound_request_id:?}, request: {request:?})",
        );

        let BlobsByRootRequest { blob_ids } = request;

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();

        self.dedicated_executor
            .spawn(async move {
                // > Clients MAY limit the number of blocks and sidecars in the response.
                let blob_ids = blob_ids
                    .into_iter()
                    .take(MAX_FOR_DOS_PREVENTION.try_into()?);

                let blob_sidecars = controller.blob_sidecars_by_ids(blob_ids)?;

                for blob_sidecar in blob_sidecars {
                    let blob_identifier: BlobIdentifier = blob_sidecar.as_ref().into();

                    debug_with_peers!(
                        "sending BlobSidecarsByRoot response chunk \
                        (inbound_request_id: {inbound_request_id:?}, peer_id: {peer_id}, \
                        slot: {}, id: {blob_identifier:?})",
                        blob_sidecar.slot(),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        inbound_request_id,
                        Box::new(Response::BlobsByRoot(Some(blob_sidecar))),
                    )
                    .send(&network_to_service_tx);
                }

                debug_with_peers!("terminating BlobSidecarsByRoot response stream");

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    inbound_request_id,
                    Box::new(Response::BlobsByRoot(None)),
                )
                .send(&network_to_service_tx);

                Ok::<_, anyhow::Error>(())
            })
            .detach()
    }

    fn handle_blocks_by_root_request(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: BlocksByRootRequest,
    ) {
        let max_request_blocks = request.max_request_blocks(self.controller.chain_config());
        let block_roots = request.block_roots();

        debug_with_peers!(
            "received BeaconBlocksByRoot request (peer_id: {peer_id}, \
            inbound_request_id: {inbound_request_id:?}, block_roots: {block_roots:?})",
        );

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();

        self.dedicated_executor
            .spawn(async move {
                let block_roots = block_roots
                    .into_iter()
                    .take(MAX_FOR_DOS_PREVENTION.min(max_request_blocks).try_into()?);

                let blocks = controller.blocks_by_root(block_roots)?;

                for block in blocks.into_iter().map(WithStatus::value) {
                    debug_with_peers!(
                        "sending BeaconBlocksByRoot response chunk \
                        (inbound_request_id: {inbound_request_id:?}, peer_id: {peer_id}, \
                        slot: {}, root: {:?})",
                        block.message().slot(),
                        block.message().hash_tree_root(),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        inbound_request_id,
                        Box::new(Response::BlocksByRoot(Some(block))),
                    )
                    .send(&network_to_service_tx);
                }

                debug_with_peers!("terminating BeaconBlocksByRoot response stream");

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    inbound_request_id,
                    Box::new(Response::BlocksByRoot(None)),
                )
                .send(&network_to_service_tx);

                Ok::<_, anyhow::Error>(())
            })
            .detach();
    }

    fn handle_data_columns_by_root_request(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: DataColumnsByRootRequest<P>,
    ) {
        debug_with_peers!(
            "received DataColumnsByRoot request (peer_id: {peer_id}, \
            inbound_request_id: {inbound_request_id:?}, request: {request:?})",
        );

        let DataColumnsByRootRequest { data_column_ids } = request;

        let controller = self.controller.clone_arc();
        let network_to_service_tx = self.network_to_service_tx.clone();

        // TODO(feature/eip7549): MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS
        let max_request_data_column_sidecars = self
            .controller
            .chain_config()
            .max_request_data_column_sidecars;

        self.dedicated_executor
            .spawn(async move {
                // > Clients MAY limit the number of blocks and sidecars in the response.
                let data_column_ids = data_column_ids
                    .into_iter()
                    .flat_map(Into::<Vec<DataColumnIdentifier>>::into)
                    .take(max_request_data_column_sidecars.try_into()?);

                let data_column_sidecars =
                    controller.data_column_sidecars_by_ids(data_column_ids)?;

                for data_column_sidecar in data_column_sidecars {
                    let data_column_identifier: DataColumnIdentifier =
                        data_column_sidecar.as_ref().into();

                    debug_with_peers!(
                        "sending DataColumnsSidecarsByRoot response chunk \
                        (inbound_request_id: {inbound_request_id:?}, peer_id: {peer_id}, \
                        slot: {}, id: {data_column_identifier:?})",
                        data_column_sidecar.slot(),
                    );

                    ServiceInboundMessage::SendResponse(
                        peer_id,
                        inbound_request_id,
                        Box::new(Response::DataColumnsByRoot(Some(data_column_sidecar))),
                    )
                    .send(&network_to_service_tx);
                }

                debug_with_peers!("terminating DataColumnsByRoot response stream");

                ServiceInboundMessage::SendResponse(
                    peer_id,
                    inbound_request_id,
                    Box::new(Response::DataColumnsByRoot(None)),
                )
                .send(&network_to_service_tx);

                Ok::<_, anyhow::Error>(())
            })
            .detach();
    }

    #[expect(clippy::cognitive_complexity)]
    #[expect(clippy::too_many_lines)]
    fn handle_response(
        &self,
        peer_id: PeerId,
        app_request_id: AppRequestId,
        response: Response<P>,
    ) {
        match response {
            Response::Status(remote) => {
                debug_with_peers!(
                    "received Status response (peer_id: {peer_id}, remote: {remote:?})"
                );

                self.check_status(&self.local_status(), remote, peer_id);
            }
            // TODO(feature/deneb): This appears to be unfinished.
            // > Before consuming the next response chunk, the response reader SHOULD verify the
            // > blob sidecar is well-formatted, has valid inclusion proof, and is correct w.r.t. the expected KZG commitments
            // > through `verify_blob_kzg_proof``.
            Response::BlobsByRange(Some(blob_sidecar)) => {
                let blob_identifier: BlobIdentifier = blob_sidecar.as_ref().into();

                debug_with_peers!(
                    "received BlobsByRange response chunk \
                    (app_request_id: {app_request_id:?}, peer_id: {peer_id}, \
                    slot: {}, id: {blob_identifier:?})",
                    blob_sidecar.slot(),
                );

                P2pToSync::RequestedBlobSidecar(
                    blob_sidecar,
                    peer_id,
                    app_request_id,
                    RPCRequestType::Range,
                )
                .send(&self.channels.p2p_to_sync_tx);
            }
            Response::BlobsByRange(None) => {
                debug_with_peers!(
                    "peer {peer_id} terminated BlobsByRange response stream for \
                    app_request_id: {app_request_id:?}",
                );

                P2pToSync::BlobsByRangeRequestFinished(app_request_id)
                    .send(&self.channels.p2p_to_sync_tx);
            }
            Response::BlobsByRoot(Some(blob_sidecar)) => {
                let blob_identifier: BlobIdentifier = blob_sidecar.as_ref().into();

                debug_with_peers!(
                    "received BlobsByRoot response chunk \
                    (app_request_id: {app_request_id:?}, peer_id: {peer_id}, \
                    slot: {}, id: {blob_identifier:?})",
                    blob_sidecar.slot(),
                );

                P2pToSync::RequestedBlobSidecar(
                    blob_sidecar,
                    peer_id,
                    app_request_id,
                    RPCRequestType::Root,
                )
                .send(&self.channels.p2p_to_sync_tx);
            }
            Response::BlobsByRoot(None) => {
                debug_with_peers!(
                    "peer {peer_id} terminated BlobsByRoot response stream for \
                    app_request_id: {app_request_id:?}",
                );
            }
            Response::BlocksByRange(Some(block)) => {
                let block_root = block.message().hash_tree_root();
                let block_slot = block.message().slot();

                debug_with_peers!(
                    "received BeaconBlocksByRange response chunk \
                    (app_request_id: {app_request_id:?}, peer_id: {peer_id}, \
                    slot: {block_slot}, root: {block_root:?})",
                );

                P2pToSync::RequestedBlock(block, peer_id, app_request_id, RPCRequestType::Range)
                    .send(&self.channels.p2p_to_sync_tx);
            }
            Response::BlocksByRange(None) => {
                debug_with_peers!(
                    "peer {peer_id} terminated BeaconBlocksByRange response stream for \
                    app_request_id: {app_request_id:?}",
                );

                P2pToSync::BlocksByRangeRequestFinished(peer_id, app_request_id)
                    .send(&self.channels.p2p_to_sync_tx);
            }
            Response::BlocksByRoot(Some(block)) => {
                let block_root = block.message().hash_tree_root();
                let block_slot = block.message().slot();

                debug_with_peers!(
                    "received BeaconBlocksByRoot response chunk \
                    (app_request_id: {app_request_id:?}, peer_id: {peer_id}, \
                    slot: {block_slot}, root: {block_root:?})",
                );

                P2pToSync::RequestedBlock(
                    block.clone_arc(),
                    peer_id,
                    app_request_id,
                    RPCRequestType::Root,
                )
                .send(&self.channels.p2p_to_sync_tx);

                if let Some(network_to_slasher_tx) = &self.channels.network_to_slasher_tx {
                    P2pToSlasher::Block(block).send(network_to_slasher_tx);
                }
            }
            Response::BlocksByRoot(None) => {
                debug_with_peers!(
                    "peer {peer_id} terminated BeaconBlocksByRoot response stream for \
                    app_request_id: {app_request_id:?}",
                );
            }
            Response::DataColumnsByRange(Some(data_column_sidecar)) => {
                let data_column_identifier: DataColumnIdentifier =
                    data_column_sidecar.as_ref().into();

                debug_with_peers!(
                    "received DataColumnsByRange response chunk \
                    (app_request_id: {app_request_id:?}, peer_id: {peer_id}, \
                    slot: {}, id: {data_column_identifier:?})",
                    data_column_sidecar.slot(),
                );

                P2pToSync::RequestedDataColumnSidecar(
                    data_column_sidecar,
                    peer_id,
                    app_request_id,
                    RPCRequestType::Range,
                )
                .send(&self.channels.p2p_to_sync_tx);
            }
            Response::DataColumnsByRange(None) => {
                debug_with_peers!(
                    "peer {peer_id} terminated DataColumnsByRange response stream for \
                    app_request_id: {app_request_id:?}"
                );

                P2pToSync::DataColumnsByRangeRequestFinished(app_request_id)
                    .send(&self.channels.p2p_to_sync_tx);
            }
            Response::DataColumnsByRoot(Some(data_column_sidecar)) => {
                let data_column_identifier: DataColumnIdentifier =
                    data_column_sidecar.as_ref().into();

                debug_with_peers!(
                    "received DataColumnsByRoot response chunk \
                    (app_request_id: {app_request_id:?}, peer_id: {peer_id}, \
                    slot: {}, id: {data_column_identifier:?})",
                    data_column_sidecar.slot(),
                );

                P2pToSync::RequestedDataColumnSidecar(
                    data_column_sidecar,
                    peer_id,
                    app_request_id,
                    RPCRequestType::Root,
                )
                .send(&self.channels.p2p_to_sync_tx);
            }
            Response::DataColumnsByRoot(None) => {
                debug_with_peers!(
                    "peer {peer_id} terminated DataColumnsByRoot response stream for \
                    app_request_id: {app_request_id:?}"
                );
            }
            Response::LightClientBootstrap(_) => {
                // TODO(Altair Light Client Sync Protocol)
                debug_with_peers!(
                    "received LightClientBootstrap response chunk (peer_id: {peer_id})"
                );
            }
            Response::LightClientFinalityUpdate(_) => {
                // TODO(Altair Light Client Sync Protocol)
                debug_with_peers!(
                    "received LightClientFinalityUpdate response (peer_id: {peer_id})"
                );
            }
            Response::LightClientOptimisticUpdate(_) => {
                // TODO(Altair Light Client Sync Protocol)
                debug_with_peers!(
                    "received LightClientOptimisticUpdate response (peer_id: {peer_id})"
                );
            }
            Response::LightClientUpdatesByRange(_) => {
                // TODO(Altair Light Client Sync Protocol)
                debug_with_peers!(
                    "received LightClientUpdatesByRange response (peer_id: {peer_id})"
                );
            }
        }
    }

    #[expect(clippy::cognitive_complexity)]
    #[expect(clippy::too_many_lines)]
    fn handle_pubsub_message(
        &self,
        message_id: MessageId,
        source: PeerId,
        message: PubsubMessage<P>,
    ) {
        match message {
            PubsubMessage::BeaconBlock(beacon_block) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["beacon_block"]);
                }

                if let Some(network_to_slasher_tx) = &self.channels.network_to_slasher_tx {
                    P2pToSlasher::Block(beacon_block.clone_arc()).send(network_to_slasher_tx);
                }

                P2pToSync::GossipBlock(beacon_block, source, GossipId { source, message_id })
                    .send(&self.channels.p2p_to_sync_tx);
            }
            PubsubMessage::BlobSidecar(data) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["blob_sidecar"]);
                }

                let (subnet_id, blob_sidecar) = *data;
                let blob_identifier: BlobIdentifier = blob_sidecar.as_ref().into();

                debug_with_peers!(
                    "received blob sidecar as gossip in subnet {subnet_id}: {blob_identifier:?} \
                    from {source}",
                );

                P2pToSync::GossipBlobSidecar(
                    blob_sidecar,
                    subnet_id,
                    GossipId { source, message_id },
                )
                .send(&self.channels.p2p_to_sync_tx);
            }
            PubsubMessage::DataColumnSidecar(data) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["data_column_sidecar"]);
                }

                let (subnet_id, data_column_sidecar) = *data;
                let data_column_identifier: DataColumnIdentifier =
                    data_column_sidecar.as_ref().into();

                debug_with_peers!(
                    "received data column sidecar as gossip in subnet {subnet_id}: {data_column_identifier:?} \
                    from {source}",
                );

                P2pToSync::GossipDataColumnSidecar(
                    data_column_sidecar,
                    subnet_id,
                    GossipId { source, message_id },
                )
                .send(&self.channels.p2p_to_sync_tx);
            }
            PubsubMessage::AggregateAndProofAttestation(aggregate_and_proof) => {
                self.data_dumper
                    .dump_signed_aggregate_and_proof(aggregate_and_proof.clone_arc());

                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["aggregate_and_proof_attestation"]);
                }

                trace_with_peers!(
                    "received aggregate and proof as gossip: {aggregate_and_proof:?} from {source}",
                );

                if let Some(network_to_slasher_tx) = &self.channels.network_to_slasher_tx {
                    let attestation = Arc::new(aggregate_and_proof.message().aggregate());
                    P2pToSlasher::Attestation(attestation).send(network_to_slasher_tx);
                }

                let gossip_id = GossipId { source, message_id };

                self.controller
                    .on_gossip_aggregate_and_proof(aggregate_and_proof, gossip_id);
            }
            PubsubMessage::Attestation(subnet_id, attestation) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["attestation"]);
                }

                trace_with_peers!(
                    "received singular attestation as gossip in subnet {subnet_id}: \
                    {attestation:?} from {source}",
                );

                if let Some(network_to_slasher_tx) = &self.channels.network_to_slasher_tx {
                    P2pToSlasher::Attestation(attestation.clone_arc()).send(network_to_slasher_tx);
                }

                let gossip_id = GossipId { source, message_id };

                self.controller
                    .on_gossip_singular_attestation(attestation, subnet_id, gossip_id);
            }
            PubsubMessage::SingleAttestation(subnet_id, single_attestation) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["attestation"]);
                }

                trace_with_peers!(
                    "received single attestation as gossip in subnet {subnet_id}: \
                    {single_attestation:?} from {source}",
                );

                let attestation = Arc::new(Attestation::Single(single_attestation));

                if let Some(network_to_slasher_tx) = &self.channels.network_to_slasher_tx {
                    P2pToSlasher::Attestation(attestation.clone_arc()).send(network_to_slasher_tx);
                }

                let gossip_id = GossipId { source, message_id };

                self.controller
                    .on_gossip_singular_attestation(attestation, subnet_id, gossip_id);
            }
            PubsubMessage::VoluntaryExit(signed_voluntary_exit) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["voluntary_exit"]);
                }

                debug_with_peers!(
                    "received signed voluntary exit as gossip: {signed_voluntary_exit:?} \
                    from {source}",
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

                debug_with_peers!(
                    "received proposer slashing as gossip: {proposer_slashing:?} from {source}"
                );

                let gossip_id = GossipId { source, message_id };

                P2pToValidator::ProposerSlashing(proposer_slashing, gossip_id)
                    .send(&self.channels.p2p_to_validator_tx);
            }
            PubsubMessage::AttesterSlashing(attester_slashing) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_gossip_object(&["attester_slashing"]);
                }

                debug_with_peers!(
                    "received attester slashing as gossip: {attester_slashing:?} from {source}"
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

                trace_with_peers!(
                    "received signed contribution and proof as gossip: {proof:?} from {source}"
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

                trace_with_peers!(
                    "received sync committee message as gossip in subnet {subnet_id}: \
                    {sync_committee_message:?} from {source}",
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

                trace_with_peers!(
                    "received signed bls execution change as gossip: \
                    {signed_bls_to_execution_change:?} from {source}"
                );

                self.bls_to_execution_change_pool
                    .notify_external_signed_bls_to_execution_change(
                        signed_bls_to_execution_change,
                        Origin::Gossip(GossipId { source, message_id }),
                    );
            }
            PubsubMessage::LightClientFinalityUpdate(_) => {
                debug_with_peers!("received light client finality update as gossip");
            }
            PubsubMessage::LightClientOptimisticUpdate(_) => {
                debug_with_peers!("received light client optimistic update as gossip");
            }
        }
    }

    fn init_status_peer_request(&self, peer_id: PeerId) {
        P2pToSync::StatusPeer(peer_id).send(&self.channels.p2p_to_sync_tx);
    }

    fn request_peer_status(&self, app_request_id: AppRequestId, peer_id: PeerId) {
        let status = self.local_status();

        debug_with_peers!(
            "sending Status request (app_request_id: {app_request_id:?}, peer_id: {peer_id}, \
            status: {status:?})"
        );

        self.request(peer_id, app_request_id, RequestType::Status(status));
    }

    fn local_status(&self) -> StatusMessage {
        let head = self.controller.head().value;
        let finalized_epoch = self.controller.finalized_epoch();
        let finalized_root = if finalized_epoch == GENESIS_EPOCH {
            H256::zero()
        } else {
            self.controller.finalized_root()
        };

        StatusMessage::V2(StatusMessageV2 {
            fork_digest: self.fork_context.current_fork_digest(),
            finalized_root,
            finalized_epoch,
            head_root: head.block_root,
            head_slot: head.slot(),
            earliest_available_slot: self.earliest_available_slot,
        })
    }

    fn check_status(&self, local: &StatusMessage, remote: StatusMessage, peer_id: PeerId) {
        if local.fork_digest() != remote.fork_digest() {
            debug_with_peers!(
                "local fork digest doesn't match remote fork digest \
                (local: {local:?}, remote: {remote:?}, peer_id: {peer_id}); \
                disconnecting from peer",
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
            head_slot: remote.head_slot(),
            head_root: remote.head_root(),
            finalized_epoch: remote.finalized_epoch(),
            finalized_root: remote.finalized_root(),
            earliest_available_slot: remote.earliest_available_slot(),
        };

        let (local_finalized_root_at_remote_finalized_epoch, sync_status) =
            match local.finalized_epoch().cmp(&remote.finalized_epoch()) {
                Ordering::Less => (None, SyncStatus::Advanced { info }),
                Ordering::Equal => {
                    let max_empty_slots = self.controller.store_config().max_empty_slots;

                    let status = if remote.head_slot() + max_empty_slots < local.head_slot() {
                        SyncStatus::Behind { info }
                    } else {
                        SyncStatus::Synced { info }
                    };

                    (Some(local.finalized_root()), status)
                }
                Ordering::Greater => {
                    let remote_finalized_slot = Self::start_of_epoch(remote.finalized_epoch());

                    let finalized_root_at_slot = match self
                        .controller
                        .finalized_block_root_before_or_at(remote_finalized_slot)
                    {
                        Ok(root) => root,
                        Err(error) => {
                            warn_with_peers!("failed to query for finalized block root: {error:?}");
                            None
                        }
                    };

                    (finalized_root_at_slot, SyncStatus::Behind { info })
                }
            };

        if let Some(root) = local_finalized_root_at_remote_finalized_epoch {
            if root != remote.finalized_root() {
                debug_with_peers!(
                    "peer {peer_id} has different block finalized at epoch {} ({root:?} != {:?})",
                    remote.finalized_epoch(),
                    remote.finalized_root(),
                );

                if !Feature::DisableFinalizedRootCheck.is_enabled() {
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
        } else if matches!(sync_status, SyncStatus::Behind { .. })
            && local.finalized_root() != H256::zero()
            && remote.finalized_root() != H256::zero()
        {
            debug_with_peers!(
                "disconnecting peer {peer_id} due to missing historical data \
                 required to validate finalized root {:?} at epoch {}",
                remote.finalized_root(),
                remote.finalized_epoch(),
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

        // Update status
        self.network_globals()
            .peers
            .write()
            .update_sync_status(&peer_id, sync_status);

        // BlockSyncService will initiate requesting blocks by range when it has info about peers
        P2pToSync::AddPeer(peer_id, remote).send(&self.channels.p2p_to_sync_tx);
    }

    fn request_blobs_by_range(
        &self,
        app_request_id: AppRequestId,
        peer_id: PeerId,
        start_slot: Slot,
        count: u64,
    ) {
        // TODO: is count capped in eth2_libp2p?
        let request = BlobsByRangeRequest { start_slot, count };

        debug_with_peers!(
            "sending BlobSidecarsByRange request (app_request_id: {app_request_id:?}, \
            peer_id: {peer_id}, request: {request:?})",
        );

        self.request(peer_id, app_request_id, RequestType::BlobsByRange(request));
    }

    fn request_blobs_by_root(
        &self,
        app_request_id: AppRequestId,
        peer_id: PeerId,
        blob_identifiers: Vec<BlobIdentifier>,
    ) {
        let request = BlobsByRootRequest::new(
            self.controller.chain_config(),
            self.controller.phase(),
            blob_identifiers.into_iter(),
        );

        debug_with_peers!(
            "sending BlobSidecarsByRoot request (app_request_id: {app_request_id:?}, \
            peer_id: {peer_id}, request: {request:?})",
        );

        self.request(peer_id, app_request_id, RequestType::BlobsByRoot(request));
    }

    fn request_blocks_by_range(
        &self,
        app_request_id: AppRequestId,
        peer_id: PeerId,
        start_slot: Slot,
        count: u64,
    ) {
        let request = OldBlocksByRangeRequest::new(start_slot, count, 1);

        debug_with_peers!(
            "sending BeaconBlocksByRange request (app_request_id: {app_request_id:?}, \
            peer_id: {peer_id}, request: {request:?})",
        );

        self.request(peer_id, app_request_id, RequestType::BlocksByRange(request));
    }

    fn request_block_by_root(
        &self,
        app_request_id: AppRequestId,
        peer_id: PeerId,
        block_root: H256,
    ) {
        let request = BlocksByRootRequest::new(
            self.controller.chain_config(),
            self.controller.phase(),
            core::iter::once(block_root),
        );

        debug_with_peers!(
            "sending BeaconBlocksByRoot request (app_request_id: {app_request_id:?}, \
            peer_id: {peer_id}, request: {request:?})",
        );

        self.request(peer_id, app_request_id, RequestType::BlocksByRoot(request));
    }

    fn request_data_columns_by_range(
        &self,
        app_request_id: AppRequestId,
        peer_id: PeerId,
        start_slot: Slot,
        count: u64,
        columns: Arc<ContiguousList<ColumnIndex, P::NumberOfColumns>>,
    ) {
        // TODO: is count capped in eth2_libp2p?
        let request = DataColumnsByRangeRequest {
            start_slot,
            count,
            columns,
        };

        debug_with_peers!(
            "sending DataColumnsByRange request (app_request_id: {app_request_id:?}, \
            peer_id: {peer_id}, request: {request:?})",
        );

        self.request(
            peer_id,
            app_request_id,
            RequestType::DataColumnsByRange(request),
        );
    }

    fn request_data_columns_by_root(
        &self,
        app_request_id: AppRequestId,
        peer_id: PeerId,
        data_columns_by_root_identifiers: Vec<DataColumnsByRootIdentifier<P>>,
    ) {
        let request = DataColumnsByRootRequest::new(
            self.controller.chain_config(),
            data_columns_by_root_identifiers.into_iter(),
        );

        debug_with_peers!(
            "sending DataColumnSidecarsByRoot request (app_request_id: {app_request_id:?}, \
            peer_id: {peer_id}, request: {request:?})",
        );

        self.request(
            peer_id,
            app_request_id,
            RequestType::DataColumnsByRoot(request),
        );
    }

    fn subscribe_to_core_topics(&self) {
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

        let current_phase = self.fork_context.current_fork_name();
        let core_topics = core_topics_to_subscribe(
            self.controller.chain_config(),
            current_phase,
            &self.network_globals.as_topic_config(),
        );

        for kind in core_topics
            .iter()
            .filter(|kind| !subscribed_topics.contains(kind))
            .cloned()
        {
            ServiceInboundMessage::SubscribeKind(kind).send(&self.network_to_service_tx);
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
        let reason = reason.into();

        debug_with_peers!("reporting peer: {peer_id} {peer_action} {source:?} {reason}");

        ServiceInboundMessage::ReportPeer(peer_id, peer_action, source, reason)
            .send(&self.network_to_service_tx);
    }

    fn publish(&self, message: PubsubMessage<P>) {
        ServiceInboundMessage::Publish(message).send(&self.network_to_service_tx);
    }

    fn request(&self, peer_id: PeerId, app_request_id: AppRequestId, request: RequestType<P>) {
        ServiceInboundMessage::SendRequest(peer_id, app_request_id, request)
            .send(&self.network_to_service_tx);
    }

    fn respond(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        response: Response<P>,
    ) {
        ServiceInboundMessage::SendResponse(peer_id, inbound_request_id, Box::new(response))
            .send(&self.network_to_service_tx);
    }

    fn subnet_gossip_topic(&self, subnet: Subnet) -> GossipTopic {
        let digest = self.fork_context.current_fork_digest();

        GossipTopic::new(subnet.into(), GossipEncoding::default(), digest)
    }

    fn update_peer_count(&self) {
        PEER_LOG_METRICS.set_connected_peer_count(self.network_globals.connected_peers())
    }

    const fn start_of_epoch(epoch: Epoch) -> Slot {
        misc::compute_start_slot_at_epoch::<P>(epoch)
    }
}

pub struct MessageDebugInfo {
    pub info: String,
    pub processing_started_at: Instant,
}

pub trait MessageDebugInfoHandler {
    fn handle(&self);
}

impl MessageDebugInfoHandler for Option<MessageDebugInfo> {
    fn handle(&self) {
        let Some(info) = self else {
            return;
        };

        let duration_ms = info.processing_started_at.elapsed().as_millis();

        if duration_ms > 10 {
            warn_with_peers!("processed P2p message in {duration_ms} ms: {}", info.info);
        }
    }
}

fn message_debug_info(message: &(impl core::fmt::Debug + ?Sized)) -> Option<MessageDebugInfo> {
    if !Feature::DebugP2pMessages.is_enabled() {
        return None;
    }

    Some(MessageDebugInfo {
        info: format!("{:.1000}", format!("{message:?}")),
        processing_started_at: Instant::now(),
    })
}

#[derive(Debug, Error)]
enum Error {
    #[error("end slot overflowed ({start_slot} + {difference})")]
    EndSlotOverflow { start_slot: u64, difference: u64 },
}

#[expect(clippy::too_many_lines)]
fn run_network_service<P: Preset>(
    mut service: Service<P>,
    mut network_to_service_rx: UnboundedReceiver<ServiceInboundMessage<P>>,
    service_to_network_tx: UnboundedSender<ServiceOutboundMessage<P>>,
) {
    tokio::spawn(async move {
        let mut network_metrics_update_interval =
            IntervalStream::new(tokio::time::interval(NETWORK_METRICS_UPDATE_INTERVAL)).fuse();

        let metrics_enabled = service.network_globals().network_config.metrics_enabled;

        loop {
            tokio::select! {
                _ = network_metrics_update_interval.select_next_some(), if metrics_enabled => {
                    let debug_info = message_debug_info("network_metrics_update_interval");

                    eth2_libp2p::metrics::update_discovery_metrics();
                    eth2_libp2p::metrics::update_sync_metrics(service.network_globals());
                    eth2_libp2p::metrics::update_gossipsub_extended_metrics(
                        service.gossipsub(),
                        service.network_globals(),
                    );

                    debug_info.handle();
                },

                network_event = service.next_event().fuse() => {
                    ServiceOutboundMessage::NetworkEvent(network_event).send(&service_to_network_tx);
                }

                message = network_to_service_rx.select_next_some() => {
                    let debug_info = message_debug_info(&message);

                    match message {
                        ServiceInboundMessage::DiscoverSubnetPeers(subnet_discoveries) => {
                            service.discover_subnet_peers(subnet_discoveries);
                        }
                        ServiceInboundMessage::GoodbyePeer(peer_id, goodbye_reason, report_source) => {
                            service.goodbye_peer(&peer_id, goodbye_reason, report_source);
                        }
                        ServiceInboundMessage::Publish(message) => {
                            service.publish(message);
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
                        ServiceInboundMessage::SendErrorResponse(peer_id, inbound_request_id, rpc_error_response, reason) => {
                            service.send_response(
                                peer_id,
                                inbound_request_id,
                                RpcResponse::Error(rpc_error_response, reason.into()),
                            );
                        }
                        ServiceInboundMessage::SendRequest(peer_id, request_id, request) => {
                            if let Err(error) = service.send_request(peer_id, request_id, request) {
                                debug_with_peers!("Unable to send request to peer: {peer_id}: {error:?}");
                            }
                        }
                        ServiceInboundMessage::SendResponse(peer_id, inbound_request_id, response) => {
                            service.send_response(peer_id, inbound_request_id, *response);
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
                        ServiceInboundMessage::UpdateDataColumnSubnets(sampling_size) => {
                            service.subscribe_new_data_column_subnets(sampling_size);
                        }
                        ServiceInboundMessage::UpdateEnrCgc(custody_group_count) => {
                            service.update_enr_cgc(custody_group_count);
                        }
                        ServiceInboundMessage::UpdateEnrSubnet(subnet, advertise) => {
                            service.update_enr_subnet(subnet, advertise);
                        }
                        ServiceInboundMessage::UpdateFork(enr_fork_id) => {
                            service.update_fork_version(enr_fork_id);
                            service.remove_topic_weight_except(enr_fork_id.fork_digest);
                        }
                        ServiceInboundMessage::UpdateGossipsubParameters(active_validator_count, slot) => {
                            if let Err(error) = service.update_gossipsub_parameters(
                                active_validator_count,
                                slot
                            ) {
                                warn_with_peers!("unable to update gossipsub scoring parameters: {error:?}");
                            }
                        }
                        ServiceInboundMessage::UpdateNextForkDigest(next_fork_digest) => {
                            service.update_nfd(next_fork_digest);
                        }
                        ServiceInboundMessage::Stop => break,
                    }

                    debug_info.handle();
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use crate::network::MAX_FOR_DOS_PREVENTION;

    use types::{config::Config, nonstandard::Phase};

    #[test]
    fn ensure_constant_sanity() {
        assert!(MAX_FOR_DOS_PREVENTION < Config::mainnet().max_request_blocks(Phase::Phase0));
        assert!(MAX_FOR_DOS_PREVENTION < Config::mainnet().max_request_blocks(Phase::Deneb));
    }
}
