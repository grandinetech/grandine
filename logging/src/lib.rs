use core::sync::atomic::{AtomicUsize, Ordering};

use derive_more::Display;

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
