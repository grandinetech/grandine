use core::time::Duration;
use std::{collections::HashSet, sync::Arc, time::Instant};

use anyhow::{Error, Result};
use bls::PublicKeyBytes;
use derive_more::Debug;
use directories::Directories;
use eth1_api::{Eth1ApiToMetrics, Eth1Metrics, RealController};
use futures::{channel::mpsc::UnboundedReceiver, future::Either, select, StreamExt as _};
use helper_functions::misc;
use log::{debug, info, warn};
use p2p::SyncToMetrics;
use prometheus_metrics::Metrics;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use sysinfo::System;
use tokio_stream::wrappers::IntervalStream;
use transition_functions::combined::Statistics;
use types::{
    combined::BeaconState, nonstandard::RelativeEpoch, preset::Preset, redacting_url::RedactingUrl,
    traits::BeaconState as _,
};

use crate::{
    beaconchain::{
        BeaconNodeMetrics, Meta, Metrics as BeaconChainMetrics, MetricsContent, ProcessMetrics,
        SystemMetrics, ValidatorMetrics,
    },
    helpers,
};

const MIN_TIME_BETWEEN_SYSTEM_STATS_REFRESH: Duration = Duration::from_secs(1);
const REMOTE_METRICS_UPDATE_INTERVAL: Duration = Duration::from_secs(60);
const REMOTE_METRICS_UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct MetricsChannels {
    pub eth1_api_to_metrics_rx: Option<UnboundedReceiver<Eth1ApiToMetrics>>,
    pub sync_to_metrics_rx: UnboundedReceiver<SyncToMetrics>,
}

#[derive(Clone, Debug)]
pub struct MetricsServiceConfig {
    pub directories: Arc<Directories>,
    pub metrics_update_interval: Duration,
    pub remote_metrics_url: Option<RedactingUrl>,
}

#[expect(clippy::module_name_repetitions)]
pub struct MetricsService<P: Preset> {
    pub(crate) config: MetricsServiceConfig,
    pub(crate) controller: RealController<P>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) eth1_metrics: Eth1Metrics,
    pub(crate) is_synced: bool,
    pub(crate) slasher_active: bool,
    // For simplicity's sake assume that validator keys won't change at runtime.
    pub(crate) validator_keys: Arc<HashSet<PublicKeyBytes>>,
    channels: MetricsChannels,
}

impl<P: Preset> MetricsService<P> {
    #[must_use]
    pub const fn new(
        config: MetricsServiceConfig,
        controller: RealController<P>,
        eth1_metrics: Eth1Metrics,
        metrics: Arc<Metrics>,
        slasher_active: bool,
        validator_keys: Arc<HashSet<PublicKeyBytes>>,
        channels: MetricsChannels,
    ) -> Self {
        Self {
            config,
            controller,
            eth1_metrics,
            metrics,
            is_synced: false,
            slasher_active,
            validator_keys,
            channels,
        }
    }

    #[expect(clippy::too_many_lines)]
    pub async fn run(mut self) -> Result<()> {
        let MetricsServiceConfig {
            ref directories,
            metrics_update_interval,
            ref remote_metrics_url,
        } = self.config;

        let mut system = System::new_all();
        let mut system_refresh_time = Instant::now();
        let mut epoch_with_metrics = None;

        let grandine_pid = sysinfo::get_current_pid().map_err(Error::msg)?;

        // Refresh is required for CPU usage stats.
        // See <https://github.com/GuillaumeGomez/sysinfo/blob/4b863fe1daf4d7482ea4b19078890ce84f875d97/src/traits.rs#L292>.
        system.refresh_all();

        let mut interval = if remote_metrics_url.is_some() {
            Either::Left(
                IntervalStream::new(tokio::time::interval(REMOTE_METRICS_UPDATE_INTERVAL)).fuse(),
            )
        } else {
            Either::Right(futures::stream::pending())
        };

        let mut system_stats_refresh_interval =
            IntervalStream::new(tokio::time::interval(metrics_update_interval)).fuse();

        let mut eth1_api_to_metrics_rx = match self.channels.eth1_api_to_metrics_rx.take() {
            Some(rx) => Either::Left(rx),
            None => Either::Right(futures::stream::pending()),
        };

        let client = Client::builder()
            .timeout(REMOTE_METRICS_UPDATE_REQUEST_TIMEOUT)
            .connection_verbose(true)
            .build()?;

        loop {
            select! {
                _ = system_stats_refresh_interval.select_next_some() => {
                    // skip system metrics update if no one is hitting /metrics
                    if self.metrics.metrics_requests_since_last_update.get() == 0 {
                        continue;
                    }

                    self.metrics.metrics_requests_since_last_update.reset();

                    refresh_system_stats(&mut system, &mut system_refresh_time);

                    let grandine = system
                        .process(grandine_pid)
                        .expect("the current process should always be available");

                    let (rx_bytes, tx_bytes) = helpers::get_network_bytes();

                    self.metrics.set_cores(system.cpus().len());
                    self.metrics.set_used_memory(grandine.memory());
                    self.metrics.set_rx_bytes(rx_bytes);
                    self.metrics.set_tx_bytes(tx_bytes);
                    self.metrics.set_total_cpu_percentage(grandine.cpu_usage());
                    self.metrics.set_system_cpu_percentage(system.global_cpu_usage());
                    self.metrics.set_system_total_memory(system.total_memory());
                    self.metrics.set_system_used_memory(system.used_memory());

                    let process_metrics = ProcessMetrics::get();

                    self.metrics.set_grandine_thread_count(process_metrics.thread_count);
                    self.metrics.set_total_cpu_seconds(process_metrics.cpu_process_seconds_total);

                    // Update disk usage
                    self.metrics.set_disk_usage(
                        directories
                            .disk_usage()
                            .map_err(|error| {
                                warn!("unable to fetch Grandine disk usage: {error:?}");
                                error
                            })
                            .unwrap_or_default(),
                    );

                    #[cfg(not(target_os = "windows"))]
                    if let Err(error) = update_jemalloc_metrics(&self.metrics) {
                        warn!("unable to update jemalloc metrics: {error:?}");
                    }

                    let head_slot = self.controller.head().value.slot();
                    let store_slot = self.controller.slot();
                    let max_empty_slots = self.controller.store_config().max_empty_slots;

                    if head_slot + max_empty_slots >= store_slot {
                        let epoch = misc::compute_epoch_at_slot::<P>(head_slot);

                        let should_update_metrics = epoch_with_metrics
                            .map(|metrics_present_for_epoch| metrics_present_for_epoch != epoch)
                            .unwrap_or(true);

                        if should_update_metrics {
                            // Take state at last slot in epoch
                            let slot = misc::compute_start_slot_at_epoch::<P>(epoch).saturating_sub(1);

                            let state_opt = match self.controller.state_at_slot(slot) {
                                Ok(state_opt) => state_opt,
                                Err(error) => {
                                    warn!("unable to update epoch metrics: {error:?}");
                                    continue;
                                }
                            };

                            if let Some(state) = state_opt {
                                match self.update_epoch_metrics(&state.value) {
                                    Ok(()) => epoch_with_metrics = Some(epoch),
                                    Err(error) => warn!("unable to update epoch metrics: {error:?}"),
                                }
                            }
                        }
                    }
                },

                _ = interval.select_next_some() => {
                    debug!("sending metrics to external service");

                    if let Some(url) = remote_metrics_url.clone() {
                        refresh_system_stats(&mut system, &mut system_refresh_time);

                        let process_metrics = ProcessMetrics::get();

                        let response = client
                            .post(url.into_url())
                            .json(&[
                                self.beacon_node_metrics(process_metrics),
                                self.validator_metrics(process_metrics),
                                Self::system_metrics(&system),
                            ])
                            .send()
                            .await;

                        match response {
                            Ok(response) => {
                                debug!("received response: {response:#?}");

                                match response.status() {
                                    StatusCode::OK => info!("metrics sent to external service"),
                                    status => match response.json::<RemoteError>().await {
                                        Ok(body) => debug!("received JSON: {status} {body:#?}"),
                                        Err(error) => debug!(
                                            "unable to receive JSON body: {status} {error:?}"
                                        ),
                                    },
                                }
                            }
                            Err(error) => {
                                warn!("received error while sending external metrics: {error:?}");
                            }
                        }
                    }
                },

                eth1_api_message = eth1_api_to_metrics_rx.select_next_some() => {
                    match eth1_api_message {
                        Eth1ApiToMetrics::Eth1Connection(eth1_connection_data) => self.eth1_metrics.eth1_connection_data = eth1_connection_data,
                    }
                },

                sync_message = self.channels.sync_to_metrics_rx.select_next_some() => {
                    match sync_message {
                        SyncToMetrics::SyncStatus(is_synced) => self.is_synced = is_synced,
                        SyncToMetrics::Stop => break Ok(()),
                    }
                },

                complete => break Ok(()),
            }
        }
    }

    fn update_epoch_metrics(&self, state: &Arc<BeaconState<P>>) -> Result<()> {
        let statistics = transition_functions::combined::statistics(state)?;

        if let Some(value) = state.cache().total_active_balance[RelativeEpoch::Previous].get() {
            self.metrics
                .set_beacon_participation_prev_epoch_active_gwei_total(value.get());
        }

        match statistics {
            Statistics::Phase0(statistics) => {
                self.metrics
                    .set_beacon_participation_prev_epoch_target_attesting_gwei_total(
                        statistics.previous_epoch_target_attesting_balance,
                    );
            }
            Statistics::Altair(statistics) => {
                self.metrics
                    .set_beacon_participation_prev_epoch_target_attesting_gwei_total(
                        statistics.previous_epoch_target_participating_balance,
                    );
            }
        }

        Ok(())
    }

    fn beacon_node_metrics(&self, general: ProcessMetrics) -> BeaconChainMetrics {
        BeaconChainMetrics {
            meta: Meta::new(),
            metrics: MetricsContent::BeaconNode {
                general,
                additional: BeaconNodeMetrics::get(self),
            },
        }
    }

    fn validator_metrics(&self, general: ProcessMetrics) -> BeaconChainMetrics {
        BeaconChainMetrics {
            meta: Meta::new(),
            metrics: MetricsContent::Validator {
                general,
                additional: ValidatorMetrics::get(self),
            },
        }
    }

    fn system_metrics(system: &System) -> BeaconChainMetrics {
        BeaconChainMetrics {
            meta: Meta::new(),
            metrics: MetricsContent::System(SystemMetrics::get(system)),
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn update_jemalloc_metrics(metrics: &Arc<Metrics>) -> Result<()> {
    jemalloc_ctl::epoch::advance().map_err(Error::msg)?;

    metrics
        .set_jemalloc_bytes_allocated(jemalloc_ctl::stats::allocated::read().map_err(Error::msg)?);

    metrics.set_jemalloc_bytes_active(jemalloc_ctl::stats::active::read().map_err(Error::msg)?);
    metrics.set_jemalloc_bytes_metadata(jemalloc_ctl::stats::metadata::read().map_err(Error::msg)?);
    metrics.set_jemalloc_bytes_resident(jemalloc_ctl::stats::resident::read().map_err(Error::msg)?);
    metrics.set_jemalloc_bytes_mapped(jemalloc_ctl::stats::mapped::read().map_err(Error::msg)?);
    metrics.set_jemalloc_bytes_retained(jemalloc_ctl::stats::retained::read().map_err(Error::msg)?);

    Ok(())
}

fn refresh_system_stats(system: &mut System, time: &mut Instant) {
    if time.elapsed() >= MIN_TIME_BETWEEN_SYSTEM_STATS_REFRESH {
        *time = Instant::now();
        system.refresh_all();
    }
}

#[expect(dead_code)]
#[derive(Debug, Deserialize)]
struct RemoteError {
    data: String,
    status: String,
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::sync::Arc;

    use anyhow::Result;
    use types::redacting_url::RedactingUrl;

    use super::MetricsServiceConfig;

    #[test]
    fn test_config_debug_with_sensitive_url() -> Result<()> {
        let config = MetricsServiceConfig {
            directories: Arc::default(),
            metrics_update_interval: Duration::from_secs(5),
            remote_metrics_url: "http://username:password@metrics.service.url"
                .parse::<RedactingUrl>()?
                .into(),
        };

        assert_eq!(
            format!("{config:?}"),
            "MetricsServiceConfig { \
                directories: Directories { data_dir: None, store_directory: None, network_dir: None, validator_dir: None }, \
                metrics_update_interval: 5s, \
                remote_metrics_url: Some(\"http://*:*@metrics.service.url/\") \
            }",
        );

        Ok(())
    }
}
