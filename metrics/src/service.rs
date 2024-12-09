use core::time::Duration;
use std::{collections::HashSet, sync::Arc, time::Instant};

use anyhow::Result;
use bls::PublicKeyBytes;
use derive_more::Debug;
use directories::Directories;
use eth1_api::{Eth1ApiToMetrics, Eth1Metrics, RealController};
use futures::{channel::mpsc::UnboundedReceiver, future::Either, select, StreamExt as _};
use log::{debug, info, warn};
use p2p::SyncToMetrics;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use sysinfo::System;
use tokio_stream::wrappers::IntervalStream;
use types::{preset::Preset, redacting_url::RedactingUrl};

use crate::{
    beaconchain::{
        BeaconNodeMetrics, Meta, Metrics, MetricsContent, ProcessMetrics, SystemMetrics,
        ValidatorMetrics,
    },
    gui,
    messages::MetricsToMetrics,
    ApiToMetrics,
};

const MIN_TIME_BETWEEN_SYSTEM_STATS_REFRESH: Duration = Duration::from_secs(1);
const METRICS_UPDATE_INTERVAL: Duration = Duration::from_secs(60);
const METRICS_UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct MetricsChannels {
    pub api_to_metrics_rx: UnboundedReceiver<ApiToMetrics>,
    pub eth1_api_to_metrics_rx: Option<UnboundedReceiver<Eth1ApiToMetrics>>,
    pub metrics_to_metrics_rx: UnboundedReceiver<MetricsToMetrics>,
    pub sync_to_metrics_rx: UnboundedReceiver<SyncToMetrics>,
}

#[derive(Clone, Debug)]
pub struct MetricsServiceConfig {
    pub remote_metrics_url: Option<RedactingUrl>,
    pub directories: Arc<Directories>,
}

#[allow(clippy::module_name_repetitions)]
pub struct MetricsService<P: Preset> {
    pub(crate) config: MetricsServiceConfig,
    pub(crate) controller: RealController<P>,
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
        slasher_active: bool,
        validator_keys: Arc<HashSet<PublicKeyBytes>>,
        channels: MetricsChannels,
    ) -> Self {
        Self {
            config,
            controller,
            eth1_metrics,
            is_synced: false,
            slasher_active,
            validator_keys,
            channels,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let mut system = System::new_all();
        let mut system_refresh_time = Instant::now();

        // Refresh is required for CPU usage stats.
        // See <https://github.com/GuillaumeGomez/sysinfo/blob/4b863fe1daf4d7482ea4b19078890ce84f875d97/src/traits.rs#L292>.
        system.refresh_all();

        let mut interval = if self.config.remote_metrics_url.is_some() {
            Either::Left(IntervalStream::new(tokio::time::interval(METRICS_UPDATE_INTERVAL)).fuse())
        } else {
            Either::Right(futures::stream::pending())
        };

        let mut eth1_api_to_metrics_rx = match self.channels.eth1_api_to_metrics_rx.take() {
            Some(rx) => Either::Left(rx),
            None => Either::Right(futures::stream::pending()),
        };

        let client = Client::builder()
            .timeout(METRICS_UPDATE_REQUEST_TIMEOUT)
            .connection_verbose(true)
            .build()?;

        loop {
            select! {
                _ = interval.select_next_some() => {
                    debug!("sending metrics to external service");

                    refresh_system_stats(&mut system, &mut system_refresh_time);

                    if let Some(url) = self.config.remote_metrics_url.clone() {
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
                                        Err(error) => debug!("unable to receive JSON body: {status} {error:#?}"),
                                    },
                                }
                            }
                            Err(error) => {
                                warn!("received error while sending external metrics: {error:#?}");
                            }
                        }
                    }
                },

                metrics_message = self.channels.metrics_to_metrics_rx.select_next_some() => {
                    match metrics_message {
                        MetricsToMetrics::SystemStats(sender) => {
                            refresh_system_stats(&mut system, &mut system_refresh_time);
                            let system_stats = gui::get_stats(&system);

                            if let Err(error) = sender.send(system_stats) {
                                info!("unable to send system stats: {error:#?}");
                            }
                        }
                    }
                },

                api_message = self.channels.api_to_metrics_rx.select_next_some() => {
                    match api_message {
                        ApiToMetrics::SystemStats(sender) => {
                            refresh_system_stats(&mut system, &mut system_refresh_time);
                            let system_stats = gui::get_stats(&system);

                            if let Err(error) = sender.send(system_stats) {
                                info!("unable to send system stats: {error:#?}");
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
                    }
                },

                complete => break Ok(()),
            }
        }
    }

    fn beacon_node_metrics(&self, general: ProcessMetrics) -> Metrics {
        Metrics {
            meta: Meta::new(),
            metrics: MetricsContent::BeaconNode {
                general,
                additional: BeaconNodeMetrics::get(self),
            },
        }
    }

    fn validator_metrics(&self, general: ProcessMetrics) -> Metrics {
        Metrics {
            meta: Meta::new(),
            metrics: MetricsContent::Validator {
                general,
                additional: ValidatorMetrics::get(self),
            },
        }
    }

    fn system_metrics(system: &System) -> Metrics {
        Metrics {
            meta: Meta::new(),
            metrics: MetricsContent::System(SystemMetrics::get(system)),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct RemoteError {
    data: String,
    status: String,
}

fn refresh_system_stats(system: &mut System, time: &mut Instant) {
    if time.elapsed() >= MIN_TIME_BETWEEN_SYSTEM_STATS_REFRESH {
        *time = Instant::now();
        system.refresh_all();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::Result;
    use types::redacting_url::RedactingUrl;

    use super::MetricsServiceConfig;

    #[test]
    fn test_config_debug_with_sensitive_url() -> Result<()> {
        let config = MetricsServiceConfig {
            remote_metrics_url: "http://username:password@metrics.service.url"
                .parse::<RedactingUrl>()?
                .into(),
            directories: Arc::default(),
        };

        assert_eq!(
            format!("{config:?}"),
            "MetricsServiceConfig { \
                remote_metrics_url: Some(\"http://*:*@metrics.service.url/\"), \
                directories: Directories { data_dir: None, store_directory: None, network_dir: None, validator_dir: None } \
            }",
        );

        Ok(())
    }
}
