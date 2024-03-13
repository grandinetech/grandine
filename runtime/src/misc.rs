use core::num::NonZeroU64;
use std::sync::Arc;

use bytesize::ByteSize;
use directories::Directories;
use metrics::{MetricsServerConfig, MetricsServiceConfig};
use prometheus_metrics::Metrics;

#[derive(Clone, Debug)]
pub struct MetricsConfig {
    pub metrics: Option<Arc<Metrics>>,
    pub metrics_server_config: Option<MetricsServerConfig>,
    pub metrics_service_config: Option<MetricsServiceConfig>,
}

#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub in_memory: bool,
    pub db_size: ByteSize,
    pub directories: Arc<Directories>,
    pub eth1_db_size: ByteSize,
    pub archival_epoch_interval: NonZeroU64,
    pub prune_storage: bool,
}
