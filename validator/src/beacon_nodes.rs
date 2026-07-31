use core::{convert::identity, fmt::Display, future::Future};
use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result};
use fork_choice_control::Wait;
use futures::future::join_all;
use logging::{debug_with_peers, warn_with_peers};
use std_ext::ArcExt;
use tap::Pipe as _;
use types::{
    nonstandard::{OwnAttestation, PublishedDuty},
    phase0::{
        containers::AttestationData,
        primitives::{CommitteeIndex, Slot},
    },
    preset::Preset,
};

use crate::{
    beacon_node_api::BeaconNodeApi, local_beacon_node::LocalBeaconNode,
    remote_beacon_node::RemoteBeaconNode, remote_beacon_nodes::RemoteBeaconNodes,
};

pub struct BeaconNodes<P: Preset, W: Wait> {
    local_node: Option<LocalBeaconNode<P, W>>,
    remote_nodes: Vec<Arc<RemoteBeaconNode>>,
    publish_to_every_node: Vec<PublishedDuty>,
}

impl<P: Preset, W: Wait + Sync> BeaconNodes<P, W> {
    pub fn new(
        local_node: Option<LocalBeaconNode<P, W>>,
        remotes: &RemoteBeaconNodes,
        publish_to_every_node: Vec<PublishedDuty>,
    ) -> Self {
        Self {
            local_node,
            remote_nodes: remotes.serving().map(ArcExt::clone_arc).collect(),
            publish_to_every_node,
        }
    }
}

impl<P: Preset, W: Wait + Sync> BeaconNodeApi<P> for BeaconNodes<P, W> {
    async fn attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData> {
        let operation = format!("produce attestation data for slot {slot}");

        if let Some(node) = &self.local_node {
            match node.attestation_data(slot, committee_index).await {
                Ok(data) => {
                    debug_with_peers!(
                        "{node} beacon node produced attestation data for slot {slot}: {data:?}",
                    );

                    return Ok(data);
                }
                Err(error) => {
                    warn_with_peers!("{node} beacon node failed to {operation}: {error:?}");
                }
            }
        }

        let mut attempts = Vec::with_capacity(self.remote_nodes.len());

        for node in &self.remote_nodes {
            attempts.push((
                node.as_ref(),
                BeaconNodeApi::<P>::attestation_data(node.as_ref(), slot, committee_index),
            ));
        }

        let (node, data) = first_success(&operation, attempts).await?;

        if !node.health().is_ready() {
            debug_with_peers!(
                "attestation data for slot {slot} came from {node}, which is not fully synced",
            );
        }

        debug_with_peers!("{node} beacon node produced attestation data for slot {slot}: {data:?}",);

        Ok(data)
    }

    async fn publish_singular_attestations(
        &self,
        attestations: &[OwnAttestation<P>],
    ) -> Result<()> {
        let publish_to = self
            .remote_nodes
            .iter()
            .filter(|node| node.health().can_serve())
            .map(ArcExt::clone_arc)
            .collect::<Vec<_>>();

        if !publish_to.is_empty() {
            if self
                .publish_to_every_node
                .contains(&PublishedDuty::Attestations)
            {
                spawn_publish_to_every_node(publish_to, attestations.to_vec());
            } else {
                spawn_publish(publish_to, attestations.to_vec());
            }
        }

        match &self.local_node {
            Some(node) => node.publish_singular_attestations(attestations).await,
            None => Ok(()),
        }
    }
}

/// Publishes to the first remote node that accepts, without holding up the caller.
///
/// The walk is detached rather than each node separately, so that the nodes are still tried in
/// order: deciding whether to fall through to the next one needs the previous one's result.
/// Attestations are published from the validator's main loop, so awaiting the walk there would let
/// a single unresponsive node delay every later duty in the slot.
fn spawn_publish<P: Preset>(
    remotes: Vec<Arc<RemoteBeaconNode>>,
    attestations: Vec<OwnAttestation<P>>,
) {
    tokio::spawn(async move {
        let mut attempts = Vec::with_capacity(remotes.len());

        for node in &remotes {
            attempts.push((
                node.as_ref(),
                node.publish_singular_attestations(&attestations),
            ));
        }

        if first_success("publish attestations", attempts)
            .await
            .is_err()
        {
            warn_with_peers!("no remote beacon node accepted the attestations");
        }
    });
}

fn spawn_publish_to_every_node<P: Preset>(
    remotes: Vec<Arc<RemoteBeaconNode>>,
    attestations: Vec<OwnAttestation<P>>,
) {
    tokio::spawn(async move {
        let attestations = attestations.as_slice();

        let accepted = remotes
            .iter()
            .map(|node| async move {
                node.publish_singular_attestations(attestations)
                    .await
                    .inspect_err(|error| {
                        warn_with_peers!(
                            "{node} beacon node failed to publish attestations: {error:?}"
                        );
                    })
                    .is_ok()
            })
            .pipe(join_all)
            .await;

        if !accepted.into_iter().any(identity) {
            warn_with_peers!("no remote beacon node accepted the attestations");
        }
    });
}

async fn first_success<N: Display, T, F: Future<Output = Result<T>>>(
    operation: &str,
    attempts: impl IntoIterator<Item = (N, F)>,
) -> Result<(N, T)> {
    let mut last_error = None;

    for (name, attempt) in attempts {
        match attempt.await {
            Ok(value) => return Ok((name, value)),
            Err(error) => {
                warn_with_peers!("{name} beacon node failed to {operation}: {error:?}");
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        AnyhowError::msg(format!("no beacon node is configured to {operation}"))
    }))
}

#[cfg(test)]
mod tests {
    use core::{iter::once, time::Duration};

    use anyhow::ensure;
    use tokio::time::sleep;

    use super::*;

    const SLOW: Duration = Duration::from_millis(50);
    const FAST: Duration = Duration::ZERO;

    // Attempts are ordered, not raced, so the earlier node wins even when a later one is faster.
    #[tokio::test]
    async fn first_success_prefers_the_earlier_node() -> Result<()> {
        let (name, value) = first_success(
            "answer",
            [
                ("slow", answer(1, SLOW, false)),
                ("fast", answer(2, FAST, false)),
            ],
        )
        .await?;

        assert_eq!(name, "slow");
        assert_eq!(value, 1);

        Ok(())
    }

    #[tokio::test]
    async fn first_success_ignores_a_failing_node() -> Result<()> {
        let (name, value) = first_success(
            "answer",
            [
                ("broken", answer(2, FAST, true)),
                ("slow", answer(3, SLOW, false)),
            ],
        )
        .await?;

        assert_eq!(name, "slow");
        assert_eq!(value, 3);

        Ok(())
    }

    #[tokio::test]
    async fn first_success_fails_without_any_node() {
        // `take(0)` only to give the empty iterator a concrete future type.
        let attempts = once(("unused", answer(1, FAST, false))).take(0);

        first_success("answer", attempts)
            .await
            .expect_err("there is no node that could produce an answer");
    }

    #[tokio::test]
    async fn first_success_fails_when_every_node_fails() {
        first_success(
            "answer",
            [
                ("broken", answer(1, FAST, true)),
                ("also broken", answer(2, SLOW, true)),
            ],
        )
        .await
        .expect_err("every attempt fails, so no answer can be produced");
    }

    async fn answer(value: u64, delay: Duration, fails: bool) -> Result<u64> {
        sleep(delay).await;
        ensure!(!fails, AnyhowError::msg("no"));
        Ok(value)
    }
}
