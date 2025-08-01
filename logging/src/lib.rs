use core::sync::atomic::{AtomicUsize, Ordering};

use derive_more::Display;

pub static PEER_LOG_METRICS: PeerLogMetrics = PeerLogMetrics::new(0);

#[derive(Display, Debug)]
#[display("peers: {connected_peer_count:?}/{target_peer_count:?}")]
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

#[macro_export]
macro_rules! info_with_peers {
    ($($arg:tt)*) => {
        ::log::info!("[{}] {}", $crate::PEER_LOG_METRICS, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! debug_with_peers {
    ($($arg:tt)*) => {
        ::log::debug!("[{}] {}", $crate::PEER_LOG_METRICS, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! warn_with_peers {
    ($($arg:tt)*) => {
        ::log::warn!("[{}] {}", $crate::PEER_LOG_METRICS, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! error_with_peers {
    ($($arg:tt)*) => {
        ::log::error!("[{}] {}", $crate::PEER_LOG_METRICS, format_args!($($arg)*));
    };
}

// macro for tracing
// #[macro_export]
// macro_rules! info_with_peers {
//     ($($arg:tt)*) => {
//         ::tracing::info!(peers = %$crate::PEER_LOG_METRICS, $($arg)*);
//     };
// }