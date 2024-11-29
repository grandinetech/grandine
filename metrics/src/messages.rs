use anyhow::Result;
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use log::debug;
use types::nonstandard::SystemStats;

pub enum ApiToMetrics {
    SystemStats(Sender<Result<SystemStats>>),
}

impl ApiToMetrics {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send from HTTP API to metrics failed because the receiver was dropped");
        }
    }
}

// Metrics Server to Metrics Service
// TODO: refactor to system stats service?
pub enum MetricsToMetrics {
    SystemStats(Sender<Result<SystemStats>>),
}

impl MetricsToMetrics {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!("send from metrics server to metrics service failed because the receiver was dropped");
        }
    }
}
