use core::cmp::Reverse;
use std::sync::Arc;

use anyhow::{Result, bail};
use futures::{
    StreamExt as _,
    future::{Either, join_all},
    stream::{self, FusedStream},
};
use logging::{info_with_peers, warn_with_peers};
use tokio::time::{Instant, interval_at};
use tokio_stream::wrappers::IntervalStream;
use types::config::Config as ChainConfig;

use crate::{health::Health, remote_beacon_node::RemoteBeaconNode};

pub struct RemoteBeaconNodes {
    chain_config: Arc<ChainConfig>,
    nodes: Vec<Arc<RemoteBeaconNode>>,
}

impl RemoteBeaconNodes {
    #[must_use]
    pub const fn new(chain_config: Arc<ChainConfig>, nodes: Vec<Arc<RemoteBeaconNode>>) -> Self {
        Self {
            chain_config,
            nodes,
        }
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn serving(&self) -> impl Iterator<Item = &Arc<RemoteBeaconNode>> {
        let mut nodes = self
            .nodes
            .iter()
            .filter(|node| node.health().can_serve())
            .collect::<Vec<_>>();

        nodes.sort_by_key(|node| Reverse(node.health()));
        nodes.into_iter()
    }

    async fn refresh(&self) -> (usize, usize) {
        join_all(self.nodes.iter().map(|node| node.refresh_health())).await;

        let ready = self.count(Health::is_ready);
        let serving = self.count(Health::can_serve);

        (ready, serving)
    }

    fn count(&self, predicate: fn(Health) -> bool) -> usize {
        self.nodes
            .iter()
            .filter(|node| predicate(node.health()))
            .count()
    }

    #[must_use]
    pub fn incompatible(&self) -> Option<&Arc<RemoteBeaconNode>> {
        self.nodes
            .iter()
            .find(|node| node.health() == Health::Incompatible)
    }

    pub async fn check_status(&self) {
        if self.is_empty() {
            return;
        }

        let (ready, serving) = self.refresh().await;

        if ready > 0 {
            return;
        }

        if serving > 0 {
            warn_with_peers!("no remote beacon node is fully synced");
        } else {
            warn_with_peers!("no remote beacon node can serve duties");
        }
    }

    /// Only a wrong network is fatal; anything else may be fine by the next poll.
    pub async fn check_on_startup(&self) -> Result<()> {
        info_with_peers!("checking remote beacon nodes");

        self.check_status().await;

        if let Some(node) = self.incompatible() {
            bail!("beacon node at {node} is on a different network");
        }

        Ok(())
    }

    pub fn poll_interval(&self) -> impl FusedStream<Item = Instant> + use<> {
        if self.is_empty() {
            return Either::Right(stream::pending().fuse());
        }

        let slot_duration = self.chain_config.slot_duration_ms;

        let start = Instant::now()
            .checked_add(slot_duration)
            .expect("poll interval is far shorter than the maximum instant");

        Either::Left(IntervalStream::new(interval_at(start, slot_duration)).fuse())
    }
}
