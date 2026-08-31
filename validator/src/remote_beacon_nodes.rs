use core::cmp::Reverse;
use std::sync::Arc;

use anyhow::{Result, bail};
use futures::future::join_all;
use logging::{info_with_peers, warn_with_peers};
use std_ext::ArcExt;
use types::{phase0::primitives::Slot, preset::Preset};

use crate::{chain_head::stream_head_events, health::Health, remote_beacon_node::RemoteBeaconNode};

pub struct RemoteBeaconNodes {
    nodes: Vec<Arc<RemoteBeaconNode>>,
}

impl RemoteBeaconNodes {
    #[must_use]
    pub const fn new(nodes: Vec<Arc<RemoteBeaconNode>>) -> Self {
        Self { nodes }
    }

    pub fn spawn_head_streams<P: Preset>(&self) {
        tokio::spawn(stream_head_events::<P>(
            self.nodes.iter().map(ArcExt::clone_arc).collect(),
        ));
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

    async fn refresh(&self, slot: Slot) -> (usize, usize) {
        join_all(self.nodes.iter().map(|node| node.refresh_health(slot))).await;
        join_all(self.nodes.iter().map(|node| node.refresh_head(slot))).await;

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

    pub async fn check_status(&self, slot: Slot) {
        if self.is_empty() {
            return;
        }

        let (ready, serving) = self.refresh(slot).await;

        if ready > 0 {
            return;
        }

        if serving > 0 {
            warn_with_peers!("no remote beacon node is fully synced");
        } else {
            warn_with_peers!("no remote beacon node can serve duties");
        }
    }

    pub async fn check_on_startup(&self, slot: Slot) -> Result<()> {
        info_with_peers!("checking remote beacon nodes");

        self.check_status(slot).await;

        // Only a wrong network is fatal; anything else may be fine by the next poll.
        if let Some(node) = self.incompatible() {
            bail!("beacon node at {node} is on a different network");
        }

        Ok(())
    }
}
