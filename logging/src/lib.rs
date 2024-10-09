
use core::sync::atomic::{AtomicUsize, Ordering};

use derive_more::Display;
use std::sync::Arc;

use tracing::{info, trace};
use tracing_appender::non_blocking::NonBlocking;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter};

pub static PEER_LOG_METRICS: PeerLogMetrics = PeerLogMetrics::new(0);


#[derive(Display, Debug)]
#[display(fmt = "peers: {connected_peer_count:?}/{target_peer_count:?}")]
pub struct PeerLogMetrics {
    connected_peer_count: AtomicUsize,
    target_peer_count: AtomicUsize,
}

impl PeerLogMetrics {
    #[must_use]
    pub const fn new(target_peer_count: usize) -> Self {
        Self {
            connected_peer_count: AtomicUsize::new(0),
            target_peer_count: AtomicUsize::new(target_peer_count),
        }
    }

    pub fn set_connected_peer_count(&self, connected_peer_count: usize) {
        self.connected_peer_count
            .store(connected_peer_count, Ordering::Relaxed)
    }

    pub fn set_target_peer_count(&self, target_peer_count: usize) {
        self.target_peer_count
            .store(target_peer_count, Ordering::Relaxed)
    }
}

pub fn setup_tracing() -> impl Drop {
    let log_path = "logs/testing.log";
    let log_appender = RollingFileAppender::new(Rotation::DAILY, "", log_path);
    let (file_non_blocking, file_guard) = NonBlocking::new(log_appender);

    let stdout_layer = fmt::layer().with_writer(std::io::stdout).with_ansi(true);

    let file_layer = fmt::layer().with_writer(file_non_blocking).with_ansi(false);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            EnvFilter::new("info,fork_choice_control::block_processor=trace")
        })
        .add_directive("fork_choice_control::block_processor=trace".parse().unwrap());
    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer);

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to initialize tracing subscriber");

    info!("Tracing initialized successfully.");
    trace!("Trace-level logging is enabled for block_processor.");
    file_guard

    
}
