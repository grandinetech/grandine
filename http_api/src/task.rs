use core::{future::IntoFuture as _, net::SocketAddr};
use std::{collections::HashSet, sync::Arc};

use anyhow::{Error as AnyhowError, Result};
use axum::Router;
use block_producer::BlockProducer;
use bls::PublicKeyBytes;
use eth1_api::{ApiController, Eth1Api};
use fork_choice_control::{ApiMessage, Wait};
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    future::{FutureExt as _, TryFutureExt as _},
    select,
    stream::StreamExt as _,
};
use genesis::AnchorCheckpointProvider;
use http_api_utils::ApiMetrics;
use liveness_tracker::ApiToLiveness;
use log::{debug, info};
use metrics::ApiToMetrics;
use operation_pools::{
    AttestationAggPool, BlsToExecutionChangePool, PoolToApiMessage, SyncCommitteeAggPool,
};
use p2p::{ApiToP2p, NetworkConfig, SyncToApi, ToSubnetService};
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use tokio::net::TcpListener;
use types::preset::Preset;
use validator::{ApiToValidator, ValidatorConfig, ValidatorToApi};

use crate::{
    error::Error,
    events::{EventChannels, Topic},
    http_api_config::HttpApiConfig,
    misc::{BackSyncedStatus, SyncedStatus},
    routing::{self, NormalState},
};

pub struct Channels<P: Preset> {
    pub api_to_liveness_tx: Option<UnboundedSender<ApiToLiveness>>,
    pub api_to_metrics_tx: Option<UnboundedSender<ApiToMetrics>>,
    pub api_to_p2p_tx: UnboundedSender<ApiToP2p<P>>,
    pub api_to_validator_tx: UnboundedSender<ApiToValidator<P>>,
    pub fc_to_api_rx: UnboundedReceiver<ApiMessage<P>>,
    pub pool_to_api_rx: UnboundedReceiver<PoolToApiMessage>,
    pub subnet_service_tx: UnboundedSender<ToSubnetService>,
    pub sync_to_api_rx: UnboundedReceiver<SyncToApi>,
    pub validator_to_api_rx: UnboundedReceiver<ValidatorToApi<P>>,
}

#[allow(clippy::struct_field_names)]
pub struct HttpApi<P: Preset, W: Wait> {
    pub block_producer: Arc<BlockProducer<P, W>>,
    pub controller: ApiController<P, W>,
    pub anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    pub eth1_api: Arc<Eth1Api>,
    pub validator_keys: Arc<HashSet<PublicKeyBytes>>,
    pub validator_config: Arc<ValidatorConfig>,
    pub network_config: Arc<NetworkConfig>,
    pub http_api_config: HttpApiConfig,
    pub attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    pub sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    pub bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
    pub channels: Channels<P>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> HttpApi<P, W> {
    pub async fn run(self) -> Result<()> {
        let listener = self.http_api_config.listener().await?;
        self.run_internal(|_, router| router, listener).await
    }

    // This is needed for snapshot testing.
    // Passing in `AddrIncoming` achieves 2 things:
    // - It ensures that the socket is bound and listening by the time we submit requests.
    // - It allows us to extract the port assigned by binding to port 0.
    pub(crate) async fn run_internal(
        self,
        extend_router: impl FnOnce(NormalState<P, W>, Router) -> Router + Send,
        listener: TcpListener,
    ) -> Result<()> {
        let Self {
            block_producer,
            controller,
            anchor_checkpoint_provider,
            eth1_api,
            validator_keys,
            validator_config,
            network_config,
            http_api_config,
            attestation_agg_pool,
            sync_committee_agg_pool,
            bls_to_execution_change_pool,
            channels,
            metrics,
        } = self;

        let HttpApiConfig {
            address,
            allow_origin,
            max_events,
            timeout,
        } = http_api_config;

        let Channels {
            api_to_liveness_tx,
            api_to_metrics_tx,
            api_to_p2p_tx,
            api_to_validator_tx,
            fc_to_api_rx,
            pool_to_api_rx,
            subnet_service_tx,
            sync_to_api_rx,
            validator_to_api_rx,
        } = channels;

        let is_synced = Arc::new(SyncedStatus::new(controller.is_forward_synced()));
        let is_back_synced = Arc::new(BackSyncedStatus::default());
        let event_channels = Arc::new(EventChannels::new(max_events));

        let state = NormalState {
            chain_config: controller.chain_config().clone_arc(),
            block_producer,
            controller,
            anchor_checkpoint_provider,
            eth1_api,
            validator_keys,
            validator_config,
            metrics: metrics.clone(),
            network_config,
            attestation_agg_pool,
            sync_committee_agg_pool,
            bls_to_execution_change_pool,
            is_synced: is_synced.clone_arc(),
            is_back_synced: is_back_synced.clone_arc(),
            event_channels: event_channels.clone_arc(),
            api_to_liveness_tx,
            api_to_metrics_tx,
            api_to_p2p_tx,
            api_to_validator_tx,
            subnet_service_tx,
        };

        let router = extend_router(state.clone(), routing::normal_routes(state));
        let router = http_api_utils::extend_router_with_middleware::<Error>(
            router,
            timeout,
            allow_origin,
            metrics.map(ApiMetrics::http),
        );

        let service = router.into_make_service_with_connect_info::<SocketAddr>();

        let serve_requests = axum::serve(listener, service)
            .into_future()
            .map_err(AnyhowError::new);

        let handle_events = handle_events(
            is_synced,
            is_back_synced,
            event_channels,
            fc_to_api_rx,
            pool_to_api_rx,
            sync_to_api_rx,
            validator_to_api_rx,
        );

        info!("HTTP server listening on {address}");

        select! {
            result = serve_requests.fuse() => result,
            result = handle_events.fuse() => result,
        }
    }
}

async fn handle_events<P: Preset>(
    is_synced: Arc<SyncedStatus>,
    is_back_synced: Arc<BackSyncedStatus>,
    event_channels: Arc<EventChannels>,
    mut fc_to_api_rx: UnboundedReceiver<ApiMessage<P>>,
    mut pool_to_api_rx: UnboundedReceiver<PoolToApiMessage>,
    mut sync_to_api_rx: UnboundedReceiver<SyncToApi>,
    mut validator_to_api_rx: UnboundedReceiver<ValidatorToApi<P>>,
) -> Result<()> {
    let EventChannels {
        attestations,
        attester_slashings,
        blob_sidecars,
        blocks,
        bls_to_execution_changes,
        chain_reorgs,
        contribution_and_proofs,
        finalized_checkpoints,
        heads,
        proposer_slashings,
        voluntary_exits,
    } = event_channels.as_ref();

    loop {
        select! {
            message = sync_to_api_rx.select_next_some() => {
                match message {
                    SyncToApi::SyncStatus(status) => is_synced.set(status),
                    SyncToApi::BackSyncStatus(status) => is_back_synced.set(status),
                }
            }

            message = validator_to_api_rx.select_next_some() => {
                let receivers = match message {
                    ValidatorToApi::AttesterSlashing(attester_slashing) => {
                        let event = Topic::AttesterSlashing.build(attester_slashing)?;
                        attester_slashings.send(event).unwrap_or_default()
                    }
                    ValidatorToApi::ContributionAndProof(signed_contribution_and_proof) => {
                        let event =
                            Topic::ContributionAndProof.build(signed_contribution_and_proof)?;
                        contribution_and_proofs.send(event).unwrap_or_default()
                    }
                    ValidatorToApi::ProposerSlashing(proposer_slashing) => {
                        let event = Topic::ProposerSlashing.build(proposer_slashing)?;
                        proposer_slashings.send(event).unwrap_or_default()
                    }
                    ValidatorToApi::VoluntaryExit(signed_voluntary_exit) => {
                        let event = Topic::VoluntaryExit.build(signed_voluntary_exit)?;
                        voluntary_exits.send(event).unwrap_or_default()
                    }
                };

                debug!("event from validator sent to {receivers} receivers");
            }

            message = fc_to_api_rx.select_next_some() => {
                let receivers = match message {
                    ApiMessage::AttestationEvent(attestation) => {
                        let event = Topic::Attestation.build(attestation)?;
                        attestations.send(event).unwrap_or_default()
                    }
                    ApiMessage::BlobSidecarEvent(blob_sidecar) => {
                        let event = Topic::BlobSidecar.build(blob_sidecar)?;
                        blob_sidecars.send(event).unwrap_or_default()
                    }
                    ApiMessage::BlockEvent(block_event) => {
                        let event = Topic::Block.build(block_event)?;
                        blocks.send(event).unwrap_or_default()
                    }
                    ApiMessage::ChainReorgEvent(chain_reorg_event) => {
                        let event = Topic::ChainReorg.build(chain_reorg_event)?;
                        chain_reorgs.send(event).unwrap_or_default()
                    }
                    ApiMessage::FinalizedCheckpoint(finalized_checkpoint_event) => {
                        let event = Topic::FinalizedCheckpoint.build(finalized_checkpoint_event)?;
                        finalized_checkpoints.send(event).unwrap_or_default()
                    }
                    ApiMessage::Head(head_event) => {
                        let event = Topic::Head.build(head_event)?;
                        heads.send(event).unwrap_or_default()
                    }
                };

                debug!("event from fork choice store sent to {receivers} receivers");
            }

            message = pool_to_api_rx.select_next_some() => {
                let receivers = match message {
                    PoolToApiMessage::SignedBlsToExecutionChange(signed_bls_to_execution_change) => {
                        let event = Topic::BlsToExecutionChange.build(signed_bls_to_execution_change)?;
                        bls_to_execution_changes.send(event).unwrap_or_default()
                    }
                };

                debug!("event from operation pool sent to {receivers} receivers");
            }

            complete => break Ok(()),
        }
    }
}
