use core::sync::atomic::{AtomicUsize, Ordering};
use tracing as _;

use derive_more::Display;

pub static PEER_LOG_METRICS: PeerLogMetrics = PeerLogMetrics::new(0);

#[derive(Display, Debug)]
#[display("[{connected_peer_count:?}/{target_peer_count:?}]")]
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
    ( $( $rest:tt )* ) => {
        ::tracing::info!(
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[macro_export]
macro_rules! warn_with_peers {
    ( $( $rest:tt )* ) => {
        ::tracing::warn!(
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[macro_export]
macro_rules! error_with_peers {
    ( $( $rest:tt )* ) => {
        ::tracing::error!(
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[macro_export]
macro_rules! exception {
    ( $( $rest:tt )* ) => {
        ::tracing::error!(
            target: "exception",
            type_error = "suspicious behavior",
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[macro_export]
macro_rules! debug_with_peers {
    ( $( $rest:tt )* ) => {
        ::tracing::debug!(
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[macro_export]
macro_rules! trace_with_peers {
    ( $( $rest:tt )* ) => {
        ::tracing::trace!(
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}
