use core::cmp::Reverse;
use std::sync::Arc;

use anyhow::{Result, bail, ensure};
use bls::PublicKeyBytes;
use futures::future::join_all;
use logging::{info_with_peers, warn_with_peers};
use std_ext::ArcExt;
use thiserror::Error;
use types::{
    phase0::primitives::{H256, Slot, ValidatorIndex},
    preset::Preset,
};

use crate::{
    beacon_node_api::BeaconNodeApi,
    chain_head::stream_head_events,
    health::Health,
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

    /// The genesis every reachable node reports; [`None`] when none can be reached.
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

    /// The genesis validators root any serving node has reported.
    #[must_use]
    pub fn genesis_validators_root(&self) -> Option<H256> {
        self.serving()
            .find_map(|node| node.genesis_validators_root())
    }

    /// Resolves `pubkey` on the first serving node that answers; [`None`] when no node knows it.
    pub async fn validator_index<P: Preset>(
        &self,
        pubkey: PublicKeyBytes,
    ) -> Result<Option<ValidatorIndex>> {
        let mut last_error = None;

        for node in self.serving() {
            match BeaconNodeApi::<P>::validator_indices(node.as_ref(), &[pubkey]).await {
                Ok(indices) => return Ok(indices.get(&pubkey).copied()),
                Err(error) => {
                    warn_with_peers!(
                        "{node} beacon node failed to resolve a validator index: {error:?}"
                    );
                    last_error = Some(error);
                }
            }
        }

        match last_error {
            Some(error) => Err(error),
            None => Ok(None),
        }
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
            bail!(StartupError::DifferentNetwork {
                node: node.to_string(),
            });
        }

        Ok(())
    }
}
