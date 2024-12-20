use core::{
    error::Error as StdError,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result};
use axum::{
    extract::{FromRef, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use http_api_utils::{ApiError, ApiMetrics};
use log::info;
use prometheus::TextEncoder;
use prometheus_client::registry::Registry;
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use thiserror::Error;
use tower_http::cors::AllowOrigin;

#[derive(Clone, Debug)]
pub struct MetricsServerConfig {
    pub metrics_address: IpAddr,
    pub metrics_port: u16,
    pub timeout: u64,
}

impl From<&MetricsServerConfig> for SocketAddr {
    fn from(config: &MetricsServerConfig) -> Self {
        Self::from((config.metrics_address, config.metrics_port))
    }
}

#[derive(Clone)]
pub struct MetricsState {
    pub libp2p_registry: Option<Arc<Registry>>,
    pub metrics: Arc<Metrics>,
}

impl FromRef<MetricsState> for Option<Arc<Registry>> {
    fn from_ref(state: &MetricsState) -> Self {
        state.libp2p_registry.clone()
    }
}

impl FromRef<MetricsState> for Arc<Metrics> {
    fn from_ref(state: &MetricsState) -> Self {
        state.metrics.clone_arc()
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("internal error")]
    Internal(#[from] AnyhowError),
}

impl ApiError for Error {
    fn sources(&self) -> impl Iterator<Item = &dyn StdError> {
        let mut error: Option<&dyn StdError> = Some(self);

        core::iter::from_fn(move || {
            let source = error?.source();
            core::mem::replace(&mut error, source)
        })
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

#[expect(clippy::module_name_repetitions)]
pub async fn run_metrics_server(
    config: MetricsServerConfig,
    libp2p_registry: Option<Registry>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let addr = SocketAddr::from(&config);

    info!("metrics server is listening on {addr}");

    let state = MetricsState {
        libp2p_registry: libp2p_registry.map(Arc::new),
        metrics: metrics.clone_arc(),
    };

    let router = Router::new()
        .route("/metrics", get(prometheus_metrics))
        .with_state(state);

    let router = http_api_utils::extend_router_with_middleware::<Error>(
        router,
        Some(Duration::from_millis(config.timeout)),
        AllowOrigin::any(),
        Some(ApiMetrics::metrics(metrics)),
    );

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(AnyhowError::new)
}

/// `GET /metrics`
pub async fn prometheus_metrics(
    State(libp2p_registry): State<Option<Arc<Registry>>>,
    State(metrics): State<Arc<Metrics>>,
) -> Result<String, Error> {
    let mut buffer = String::new();

    metrics.set_live();
    metrics.metrics_requests_since_last_update.inc();

    // gossipsub metrics
    if let Some(registry) = libp2p_registry {
        prometheus_client::encoding::text::encode(&mut buffer, &registry)
            .map_err(AnyhowError::new)?;
    }

    TextEncoder::new()
        .encode_utf8(prometheus::gather().as_slice(), &mut buffer)
        .map_err(AnyhowError::new)?;

    Ok(buffer)
}
