#![allow(clippy::unused_async)]

use core::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use std::{error::Error as StdError, sync::Arc};

use anyhow::{anyhow, Error as AnyhowError, Result};
use axum::{
    extract::{FromRef, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use directories::Directories;
use eth1_api::ApiController;
use eth2_libp2p::NetworkGlobals;
use fork_choice_control::Wait;
use futures::channel::mpsc::UnboundedSender;
use helper_functions::misc;
use http_api_utils::ApiError;
use log::{info, warn};
use prometheus::TextEncoder;
use prometheus_client::registry::Registry;
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use thiserror::Error;
use tower_http::cors::AllowOrigin;
use transition_functions::combined::Statistics;
use types::{
    combined::BeaconState,
    nonstandard::{RelativeEpoch, SystemStats},
    preset::Preset,
    traits::BeaconState as _,
};

use crate::{beaconchain::ProcessMetrics, messages::MetricsToMetrics};

#[derive(Clone, Debug)]
pub struct MetricsServerConfig {
    pub metrics_address: IpAddr,
    pub metrics_port: u16,
    pub timeout: u64,
    pub directories: Arc<Directories>,
}

impl From<&MetricsServerConfig> for SocketAddr {
    fn from(config: &MetricsServerConfig) -> Self {
        Self::from((config.metrics_address, config.metrics_port))
    }
}

#[derive(Clone)]
pub struct MetricsState<P: Preset, W: Wait> {
    pub controller: ApiController<P, W>,
    pub directories: Arc<Directories>,
    pub libp2p_registry: Option<Arc<Registry>>,
    pub metrics: Arc<Metrics>,
    pub metrics_to_metrics_tx: Option<UnboundedSender<MetricsToMetrics>>, // TODO: is still relevant, update naming if so
    pub network_globals: Arc<NetworkGlobals>,
}

impl<P: Preset, W: Wait> FromRef<MetricsState<P, W>> for ApiController<P, W> {
    fn from_ref(state: &MetricsState<P, W>) -> Self {
        state.controller.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<MetricsState<P, W>> for Arc<Directories> {
    fn from_ref(state: &MetricsState<P, W>) -> Self {
        state.directories.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<MetricsState<P, W>> for Option<Arc<Registry>> {
    fn from_ref(state: &MetricsState<P, W>) -> Self {
        state.libp2p_registry.clone()
    }
}

impl<P: Preset, W: Wait> FromRef<MetricsState<P, W>> for Arc<Metrics> {
    fn from_ref(state: &MetricsState<P, W>) -> Self {
        state.metrics.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<MetricsState<P, W>> for Option<UnboundedSender<MetricsToMetrics>> {
    fn from_ref(state: &MetricsState<P, W>) -> Self {
        state.metrics_to_metrics_tx.clone()
    }
}

impl<P: Preset, W: Wait> FromRef<MetricsState<P, W>> for Arc<NetworkGlobals> {
    fn from_ref(state: &MetricsState<P, W>) -> Self {
        state.network_globals.clone_arc()
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

#[allow(clippy::module_name_repetitions)]
pub async fn run_metrics_server<P: Preset, W: Wait>(
    config: MetricsServerConfig,
    controller: ApiController<P, W>,
    libp2p_registry: Option<Registry>,
    metrics: Arc<Metrics>,
    metrics_to_metrics_tx: Option<UnboundedSender<MetricsToMetrics>>,
    network_globals: Arc<NetworkGlobals>,
) -> Result<()> {
    let addr = SocketAddr::from(&config);

    info!("Metrics server is listening on {addr}");

    let directories = config.directories.clone_arc();
    let state = MetricsState {
        controller,
        directories,
        libp2p_registry: libp2p_registry.map(Arc::new),
        metrics,
        metrics_to_metrics_tx,
        network_globals,
    };

    let router = Router::new()
        .route("/metrics", get(prometheus_metrics))
        .with_state(state);

    let router = http_api_utils::extend_router_with_middleware::<Error>(
        router,
        Some(Duration::from_millis(config.timeout)),
        AllowOrigin::any(),
        None,
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
pub async fn prometheus_metrics<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(directories): State<Arc<Directories>>,
    State(libp2p_registry): State<Option<Arc<Registry>>>,
    State(metrics): State<Arc<Metrics>>,
    State(metrics_to_metrics_tx): State<Option<UnboundedSender<MetricsToMetrics>>>,
    State(network_globals): State<Arc<NetworkGlobals>>,
) -> Result<String, Error> {
    let mut buffer = String::new();

    metrics.set_live();

    eth2_libp2p::metrics::scrape_discovery_metrics();
    eth2_libp2p::metrics::scrape_sync_metrics(&network_globals);

    // gossipsub metrics
    if let Some(registry) = libp2p_registry {
        prometheus_client::encoding::text::encode(&mut buffer, &registry)
            .map_err(AnyhowError::new)?;
    }

    if let Err(error) = scrape_system_stats(metrics.clone_arc(), metrics_to_metrics_tx).await {
        warn!("Unable to scrape system stats: {error:?}");
    }
    #[cfg(not(target_os = "windows"))]
    if let Err(error) = scrape_jemalloc_stats(&metrics) {
        warn!("Unable to scrape jemalloc stats: {error:?}");
    }

    // Scrape disk usage
    metrics.set_disk_usage(
        directories
            .disk_usage()
            .map_err(|error| {
                warn!("Unable to fetch Grandine disk usage: {error:?}");
                error
            })
            .unwrap_or_default(),
    );

    let head_slot = controller.head().value.slot();
    let store_slot = controller.slot();
    let max_empty_slots = controller.store_config().max_empty_slots;

    if head_slot + max_empty_slots >= store_slot {
        let epoch = misc::compute_epoch_at_slot::<P>(head_slot);
        // Take state at last slot in epoch
        let slot = misc::compute_start_slot_at_epoch::<P>(epoch).saturating_sub(1);
        if let Some(state) = controller.state_at_slot(slot)? {
            scrape_epoch_statistics(&state.value, &metrics)?;
        }
    }

    TextEncoder::new()
        .encode_utf8(prometheus::gather().as_slice(), &mut buffer)
        .map_err(AnyhowError::new)?;

    Ok(buffer)
}

pub fn scrape_epoch_statistics<P: Preset>(
    state: &Arc<BeaconState<P>>,
    metrics: &Arc<Metrics>,
) -> Result<()> {
    let statistics = transition_functions::combined::statistics(state)?;

    if let Some(value) = state.cache().total_active_balance[RelativeEpoch::Previous].get() {
        metrics.set_beacon_participation_prev_epoch_active_gwei_total(value.get());
    }

    match statistics {
        Statistics::Phase0(statistics) => {
            metrics.set_beacon_participation_prev_epoch_target_attesting_gwei_total(
                statistics.previous_epoch_target_attesting_balance,
            );
        }
        Statistics::Altair(statistics) => {
            metrics.set_beacon_participation_prev_epoch_target_attesting_gwei_total(
                statistics.previous_epoch_target_participating_balance,
            );
        }
    }

    Ok(())
}

async fn scrape_system_stats(
    metrics: Arc<Metrics>,
    metrics_to_metrics_tx: Option<UnboundedSender<MetricsToMetrics>>,
) -> Result<()> {
    let metrics_tx =
        metrics_to_metrics_tx.ok_or_else(|| anyhow!("metrics service is not configured"))?;

    let (sender, receiver) = futures::channel::oneshot::channel();
    MetricsToMetrics::SystemStats(sender).send(&metrics_tx);

    let SystemStats {
        core_count,
        grandine_used_memory,
        grandine_total_cpu_percentage,
        rx_bytes,
        tx_bytes,
        system_cpu_percentage,
        system_total_memory,
        system_used_memory,
    } = receiver.await??;

    // can we just set them at with no sending
    metrics.set_cores(core_count);
    metrics.set_used_memory(grandine_used_memory);
    metrics.set_rx_bytes(rx_bytes);
    metrics.set_tx_bytes(tx_bytes);
    metrics.set_system_cpu_percentage(system_cpu_percentage);
    metrics.set_total_cpu_percentage(grandine_total_cpu_percentage);
    metrics.set_system_total_memory(system_total_memory);
    metrics.set_system_used_memory(system_used_memory);

    let process_metrics = ProcessMetrics::get();

    metrics.set_grandine_thread_count(process_metrics.thread_count);
    metrics.set_total_cpu_seconds(process_metrics.cpu_process_seconds_total);

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn scrape_jemalloc_stats(metrics: &Arc<Metrics>) -> Result<()> {
    jemalloc_ctl::epoch::advance().map_err(AnyhowError::msg)?;

    metrics.set_jemalloc_bytes_allocated(
        jemalloc_ctl::stats::allocated::read().map_err(AnyhowError::msg)?,
    );

    metrics
        .set_jemalloc_bytes_active(jemalloc_ctl::stats::active::read().map_err(AnyhowError::msg)?);

    metrics.set_jemalloc_bytes_metadata(
        jemalloc_ctl::stats::metadata::read().map_err(AnyhowError::msg)?,
    );

    metrics.set_jemalloc_bytes_resident(
        jemalloc_ctl::stats::resident::read().map_err(AnyhowError::msg)?,
    );

    metrics
        .set_jemalloc_bytes_mapped(jemalloc_ctl::stats::mapped::read().map_err(AnyhowError::msg)?);

    metrics.set_jemalloc_bytes_retained(
        jemalloc_ctl::stats::retained::read().map_err(AnyhowError::msg)?,
    );

    Ok(())
}
