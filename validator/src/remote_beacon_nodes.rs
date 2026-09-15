use core::cmp::Reverse;
use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, anyhow, bail, ensure};
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
    beacon_node_api::BeaconNodeApi,
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

    pub async fn validator_indices<P: Preset>(
        &self,
        public_keys: &[PublicKeyBytes],
    ) -> Result<HashMap<PublicKeyBytes, ValidatorIndex>> {
        let mut last_error = None;

        for node in self.serving() {
            match BeaconNodeApi::<P>::validator_indices(node.as_ref(), public_keys).await {
                Ok(indices) => return Ok(indices),
                Err(error) => {
                    warn_with_peers!(
                        "{node} beacon node failed to resolve validator indices: {error:?}"
                    );
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("no remote beacon node can serve requests")))
    }

    pub fn serving(&self) -> impl Iterator<Item = &Arc<RemoteBeaconNode>> {
        let mut nodes = self
            .nodes
            .iter()
            .filter(|node| node.health().can_serve())
            .collect::<Vec<_>>();

        // A head most nodes hold outranks one node that is ahead, as a lone node may have accepted
        // a block the others rejected; a newer head breaks ties, then the configured order.
        let mut holders = HashMap::<H256, usize>::new();

        for (_, block_root) in nodes.iter().filter_map(|node| node.chain_head().cached()) {
            let held_by = holders.entry(block_root).or_default();
            *held_by = held_by.saturating_add(1);
        }

        nodes.sort_by_cached_key(|node| {
            let head = node.chain_head().cached();
            let held_by = head.map_or(0, |(_, block_root)| {
                holders.get(&block_root).copied().unwrap_or_default()
            });
            let head_slot = head.map_or(0, |(slot, _)| slot);

            Reverse((node.health(), held_by, head_slot))
        });

        nodes.into_iter()
    }

    pub async fn refresh(&self, slot: Slot) {
        join_all(self.nodes.iter().map(|node| node.refresh_health(slot))).await;
        join_all(self.nodes.iter().map(|node| node.refresh_head(slot))).await;

        if self.nodes.iter().any(|node| node.health().is_ready()) {
            return;
        }

        if self.nodes.iter().any(|node| node.health().can_serve()) {
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

    // A lone node that is ahead may have accepted a block the others rejected.
    #[test]
    fn the_head_most_nodes_hold_outranks_a_lone_newer_one() -> Result<()> {
        let ahead = node("http://ahead")?;
        let first = node("http://first")?;
        let second = node("http://second")?;

        ahead.chain_head().update(11, H256::repeat_byte(1));
        first.chain_head().update(10, H256::repeat_byte(2));
        second.chain_head().update(10, H256::repeat_byte(2));

        let nodes = RemoteBeaconNodes::new(
            vec![ahead.clone_arc(), first.clone_arc(), second.clone_arc()],
            vec![],
            false,
        );

        let order = order(&nodes);

        assert!(Arc::ptr_eq(&order[0], &first));
        assert!(Arc::ptr_eq(&order[1], &second));
        assert!(Arc::ptr_eq(&order[2], &ahead));

        Ok(())
    }

    // Without a majority the newer head wins over the configured order.
    #[test]
    fn a_newer_head_breaks_a_tie() -> Result<()> {
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
}
