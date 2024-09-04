use core::sync::atomic::{AtomicUsize, Ordering};

use derive_more::Display;
use tracing::info;
use tracing_appender::non_blocking::NonBlocking;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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
    let (log_non_blocking, guard) = NonBlocking::new(log_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .expect("Failed to create EnvFilter");

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(log_non_blocking).with_ansi(false))
        .try_init()
        .expect("Failed to initialize tracing subscriber");
    info!("This is a message from lib.rs.");
    println!("Tracing initialized successfully.");
    guard
}
