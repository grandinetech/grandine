pub use crate::{
    messages::ApiToMetrics,
    server::{run_metrics_server, MetricsServerConfig},
    service::{MetricsChannels, MetricsService, MetricsServiceConfig},
};
pub fn initialize_metrics_module() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO) // log level 
        .init();
}

mod beaconchain;
mod gui;
mod helpers;
mod messages;
mod server;
mod service;
