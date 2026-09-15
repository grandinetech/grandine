use core::cmp::Reverse;
use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, bail, ensure};
use bls::PublicKeyBytes;
use futures::{channel::mpsc::UnboundedSender, future::join_all};
use logging::{info_with_peers, warn_with_peers};
use std_ext::ArcExt;
use thiserror::Error;
use types::{
    nonstandard::PublishedDuty,
    phase0::primitives::{H256, Slot, ValidatorIndex},
    preset::Preset,
};

use crate::{
    beacon_nodes::first_success,
    chain_events::stream_events,
    health::Health,
    messages::InternalMessage,
    remote_beacon_node::{Genesis, RemoteBeaconNode},
};

/// Only possible on startup and not fixed by restarting, so the restart loop exits on these.
#[derive(Debug, Error)]
pub enum StartupError {
    #[error("beacon node at {node} is on a different network")]
    DifferentNetwork { node: String },
    #[error(
        "beacon nodes at {first} and {second} are on different chains: \
         genesis validators roots {first_root:?} and {second_root:?}"
    )]
    DifferentChains {
        first: String,
        second: String,
        first_root: H256,
        second_root: H256,
    },
    #[error(
        "beacon nodes given with --beacon-node-urls are on a chain with genesis validators root \
         {actual:?} where {expected:?} was expected"
    )]
    UnexpectedChain { expected: H256, actual: H256 },
}

pub struct RemoteBeaconNodes {
    nodes: Vec<Arc<RemoteBeaconNode>>,
    publish_to_every_node: Vec<PublishedDuty>,
    use_builder: bool,
}

impl RemoteBeaconNodes {
    #[must_use]
    pub const fn new(
        nodes: Vec<Arc<RemoteBeaconNode>>,
        publish_to_every_node: Vec<PublishedDuty>,
        use_builder: bool,
    ) -> Self {
        Self {
            nodes,
            publish_to_every_node,
            use_builder,
        }
    }

    #[must_use]
    pub fn publish_to_every_node(&self) -> &[PublishedDuty] {
        &self.publish_to_every_node
    }

    #[must_use]
    pub const fn use_builder(&self) -> bool {
        self.use_builder
    }

    pub fn spawn_event_streams<P: Preset>(&self, internal_tx: UnboundedSender<InternalMessage>) {
        tokio::spawn(stream_events::<P>(
            self.nodes.iter().map(ArcExt::clone_arc).collect(),
            internal_tx,
        ));
    }

    pub async fn agreed_genesis(&self) -> Result<Option<Genesis>> {
        let responses = join_all(
            self.nodes
                .iter()
                .map(|node| async move { (node, node.genesis().await) }),
        )
        .await;

        let mut agreed: Option<(&Arc<RemoteBeaconNode>, Genesis)> = None;

        for (node, result) in responses {
            match result {
                Ok(genesis) => match &agreed {
                    Some((first, first_genesis)) => ensure!(
                        first_genesis.genesis_validators_root == genesis.genesis_validators_root,
                        StartupError::DifferentChains {
                            first: first.to_string(),
                            second: node.to_string(),
                            first_root: first_genesis.genesis_validators_root,
                            second_root: genesis.genesis_validators_root,
                        },
                    ),
                    None => agreed = Some((node, genesis)),
                },
                Err(error) => {
                    warn_with_peers!("{node} beacon node failed to report genesis: {error:?}");
                }
            }
        }

        Ok(agreed.map(|(_, genesis)| genesis))
    }

    pub fn seed_genesis_validators_root(&self, genesis_validators_root: H256) {
        for node in &self.nodes {
            node.seed_genesis_validators_root(genesis_validators_root);
        }
    }

    pub async fn validator_indices(
        &self,
        public_keys: &[PublicKeyBytes],
    ) -> Result<HashMap<PublicKeyBytes, ValidatorIndex>> {
        let mut attempts = vec![];

        for node in self.serving() {
            let attempt = node.validator_indices(public_keys);
            attempts.push((node, attempt));
        }

        first_success("resolve validator indices", attempts)
            .await
            .map(|(_, indices)| indices)
    }

    pub fn serving(&self) -> impl Iterator<Item = &Arc<RemoteBeaconNode>> {
        let mut nodes = self
            .nodes
            .iter()
            .filter(|node| node.health().can_serve())
            .collect::<Vec<_>>();

        // Among equally healthy nodes the newest head goes first, then the configured order.
        nodes.sort_by_cached_key(|node| {
            let head_slot = node.chain_head().cached().map_or(0, |(slot, _)| slot);

            Reverse((node.health(), head_slot))
        });

        nodes.into_iter()
    }

    pub async fn refresh(&self, slot: Slot) {
        join_all(self.nodes.iter().map(|node| node.refresh_health(slot))).await;
        join_all(self.nodes.iter().map(|node| node.refresh_head(slot))).await;

        if self.nodes.iter().any(|node| node.health().is_ready()) {
            return;
        }

        if self
            .nodes
            .iter()
            .any(|node| node.health() > Health::Unreachable)
        {
            warn_with_peers!("no remote beacon node is fully synced");
        } else {
            warn_with_peers!("no remote beacon node can serve duties");
        }
    }

    pub async fn check_on_startup(&self, slot: Slot) -> Result<()> {
        info_with_peers!("checking remote beacon nodes");

        self.refresh(slot).await;

        // Only a wrong network is fatal; anything else may be fine by the next poll.
        if let Some(node) = self
            .nodes
            .iter()
            .find(|node| node.health() == Health::Incompatible)
        {
            bail!(StartupError::DifferentNetwork {
                node: node.to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use reqwest::Client;
    use types::config::Config as ChainConfig;

    use super::*;

    fn node(url: &str) -> Result<Arc<RemoteBeaconNode>> {
        Ok(Arc::new(RemoteBeaconNode::new(
            Arc::new(ChainConfig::mainnet()),
            Client::new(),
            url.parse()?,
            32,
        )))
    }

    fn order(nodes: &RemoteBeaconNodes) -> Vec<Arc<RemoteBeaconNode>> {
        nodes.serving().map(ArcExt::clone_arc).collect()
    }

    // Nodes stuck on the same block must not outvote the one that follows the chain.
    #[test]
    fn the_newest_head_outranks_a_head_more_nodes_hold() -> Result<()> {
        let first = node("http://first")?;
        let second = node("http://second")?;
        let ahead = node("http://ahead")?;

        first.chain_head().update(10, H256::repeat_byte(2));
        second.chain_head().update(10, H256::repeat_byte(2));
        ahead.chain_head().update(11, H256::repeat_byte(1));

        let nodes = RemoteBeaconNodes::new(
            vec![first.clone_arc(), second.clone_arc(), ahead.clone_arc()],
            vec![],
            false,
        );

        let order = order(&nodes);

        assert!(Arc::ptr_eq(&order[0], &ahead));
        assert!(Arc::ptr_eq(&order[1], &first));
        assert!(Arc::ptr_eq(&order[2], &second));

        Ok(())
    }

    // The newer head wins over the configured order.
    #[test]
    fn a_newer_head_outranks_the_configured_order() -> Result<()> {
        let behind = node("http://behind")?;
        let ahead = node("http://ahead")?;

        behind.chain_head().update(10, H256::repeat_byte(1));
        ahead.chain_head().update(11, H256::repeat_byte(2));

        let nodes =
            RemoteBeaconNodes::new(vec![behind.clone_arc(), ahead.clone_arc()], vec![], false);
        let order = order(&nodes);

        assert!(Arc::ptr_eq(&order[0], &ahead));
        assert!(Arc::ptr_eq(&order[1], &behind));

        Ok(())
    }

    // Health decides first; the head only orders nodes of equal health.
    #[test]
    fn a_ready_node_outranks_a_fresher_head_on_a_degraded_one() -> Result<()> {
        let ready = node("http://ready")?;
        let unusable = node("http://unusable")?;

        ready.set_health(Health::Ready);
        unusable.set_health(Health::Unusable);
        ready.chain_head().update(10, H256::repeat_byte(1));
        unusable.chain_head().update(11, H256::repeat_byte(2));

        let nodes =
            RemoteBeaconNodes::new(vec![unusable.clone_arc(), ready.clone_arc()], vec![], false);
        let order = order(&nodes);

        assert!(Arc::ptr_eq(&order[0], &ready));
        assert!(Arc::ptr_eq(&order[1], &unusable));

        Ok(())
    }

    // An unreachable node is kept as the last choice; one on another network is never asked.
    #[test]
    fn an_unreachable_node_serves_last_and_an_incompatible_one_not_at_all() -> Result<()> {
        let ready = node("http://ready")?;
        let unreachable = node("http://unreachable")?;
        let incompatible = node("http://incompatible")?;

        ready.set_health(Health::Ready);
        unreachable.set_health(Health::Unreachable);
        incompatible.set_health(Health::Incompatible);

        let nodes = RemoteBeaconNodes::new(
            vec![
                incompatible.clone_arc(),
                unreachable.clone_arc(),
                ready.clone_arc(),
            ],
            vec![],
            false,
        );
        let order = order(&nodes);

        assert_eq!(order.len(), 2);
        assert!(Arc::ptr_eq(&order[0], &ready));
        assert!(Arc::ptr_eq(&order[1], &unreachable));

        Ok(())
    }
}
