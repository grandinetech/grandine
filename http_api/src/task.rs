use core::{future::IntoFuture as _, net::SocketAddr};
use std::{collections::HashSet, sync::Arc};

use anyhow::{Error as AnyhowError, Result};
use axum::Router;
use binary_utils::TracingHandle;
use block_producer::BlockProducer;
use bls::PublicKeyBytes;
use eth1_api::{ApiController, Eth1Api};
use fork_choice_control::{EventChannels, Wait};
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    future::{FutureExt as _, TryFutureExt as _},
    select,
    stream::StreamExt as _,
};
use genesis::AnchorCheckpointProvider;
use http_api_utils::ApiMetrics;
use liveness_tracker::ApiToLiveness;
use logging::info_with_peers;
use operation_pools::{AttestationAggPool, BlsToExecutionChangePool, SyncCommitteeAggPool};
use p2p::{ApiToP2p, NetworkConfig, SyncToApi, ToSubnetService};
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use tokio::net::TcpListener;
use tracing::instrument;
use types::preset::Preset;
use validator::{ApiToValidator, ValidatorConfig};

use crate::{
    error::Error,
    http_api_config::HttpApiConfig,
    misc::SyncedStatus,
    routing::{self, NormalState},
};

pub struct Channels<P: Preset> {
    pub api_to_liveness_tx: Option<UnboundedSender<ApiToLiveness>>,
    pub api_to_p2p_tx: UnboundedSender<ApiToP2p<P>>,
    pub api_to_validator_tx: UnboundedSender<ApiToValidator<P>>,
    pub subnet_service_tx: UnboundedSender<ToSubnetService>,
    pub sync_to_api_rx: UnboundedReceiver<SyncToApi>,
}

#[expect(clippy::struct_field_names)]
pub struct HttpApi<P: Preset, W: Wait> {
    pub block_producer: Arc<BlockProducer<P, W>>,
    pub controller: ApiController<P, W>,
    pub anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    pub eth1_api: Arc<Eth1Api>,
    pub event_channels: Arc<EventChannels<P>>,
    pub validator_keys: Arc<HashSet<PublicKeyBytes>>,
    pub validator_config: Arc<ValidatorConfig>,
    pub network_config: Arc<NetworkConfig>,
    pub http_api_config: HttpApiConfig,
    pub attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    pub sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    pub bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
    pub channels: Channels<P>,
    pub metrics: Option<Arc<Metrics>>,
    pub tracing_handle: Option<TracingHandle>,
}

impl<P: Preset, W: Wait> HttpApi<P, W> {
    #[instrument(parent = None, skip(self), fields(address = %self.http_api_config.address))]
    pub async fn run(self) -> Result<()> {
        let listener = self.http_api_config.listener().await?;
        self.run_internal(|_, router| router, listener).await
    }

    // This is needed for snapshot testing.
    // Passing in `AddrIncoming` achieves 2 things:
    // - It ensures that the socket is bound and listening by the time we submit requests.
    // - It allows us to extract the port assigned by binding to port 0.
    #[instrument(parent = None, skip_all)]
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
            event_channels,
            validator_keys,
            validator_config,
            network_config,
            http_api_config,
            attestation_agg_pool,
            sync_committee_agg_pool,
            bls_to_execution_change_pool,
            channels,
            metrics,
            tracing_handle,
        } = self;

        let HttpApiConfig {
            address,
            allow_origin,
            timeout,
        } = http_api_config;

        let Channels {
            api_to_liveness_tx,
            api_to_p2p_tx,
            api_to_validator_tx,
            subnet_service_tx,
            sync_to_api_rx,
        } = channels;

        let is_synced = Arc::new(SyncedStatus::new(controller.is_forward_synced()));

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
            event_channels,
            api_to_liveness_tx,
            api_to_p2p_tx,
            api_to_validator_tx,
            subnet_service_tx,
            tracing_handle,
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

        let handle_sync_statuses = handle_sync_statuses(is_synced, sync_to_api_rx);

        info_with_peers!("HTTP server listening on {}", address);

        select! {
            result = serve_requests.fuse() => result,
            result = handle_sync_statuses.fuse() => result,
        }
    }
}

async fn handle_sync_statuses(
    is_synced: Arc<SyncedStatus>,
    mut sync_to_api_rx: UnboundedReceiver<SyncToApi>,
) -> Result<()> {
    loop {
        select! {
            message = sync_to_api_rx.select_next_some() => {
                match message {
                    SyncToApi::SyncStatus(status) => is_synced.set(status),
                    SyncToApi::Stop => break Ok(()),
                }
            }

            complete => break Ok(()),
        }
    }
}
