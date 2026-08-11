use core::{convert::identity, fmt::Display, future::Future, ops::Range};
use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result};
use fork_choice_control::Wait;
use futures::future::join_all;
use logging::{debug_with_peers, warn_with_peers};
use p2p::BeaconCommitteeSubscription;
use std_ext::ArcExt;
use tap::Pipe as _;
use types::{
    nonstandard::{OwnAttestation, PublishedDuty},
    phase0::{
        containers::AttestationData,
        primitives::{CommitteeIndex, Epoch, H256, Slot, ValidatorIndex},
    },
    preset::Preset,
};

use crate::{
    beacon_node_api::{AttesterDuties, BeaconNodeApi},
    local_beacon_node::LocalBeaconNode,
    misc,
    remote_beacon_node::RemoteBeaconNode,
    remote_beacon_nodes::RemoteBeaconNodes,
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

    fn serving_nodes(&self) -> Vec<Arc<RemoteBeaconNode>> {
        self.remote_nodes
            .iter()
            .filter(|node| node.health().can_serve())
            .map(ArcExt::clone_arc)
            .collect()
    }

    #[must_use]
    pub const fn has_local_node(&self) -> bool {
        self.local_node.is_some()
    }

    // The built-in beacon node computes only what is about to be needed; a remote one answers a
    // whole epoch per request, so nothing is gained by asking for less than the epochs in flight.
    #[must_use]
    pub fn prefetch_slots(&self, current_slot: Slot) -> Range<Slot> {
        if self.has_local_node() {
            return misc::slots_to_compute_in_advance(current_slot);
        }

        let current_epoch = helper_functions::misc::compute_epoch_at_slot::<P>(current_slot);

        helper_functions::misc::compute_start_slot_at_epoch::<P>(current_epoch)
            ..helper_functions::misc::compute_start_slot_at_epoch::<P>(
                current_epoch.saturating_add(2),
            )
    }

    // `slots` must lie within one epoch, as the duties carry a single dependent root.
    pub async fn attester_duties_at_slots(
        &self,
        slots: Range<Slot>,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        let epoch = helper_functions::misc::compute_epoch_at_slot::<P>(slots.start);

        if let Some(node) = &self.local_node {
            match node
                .attester_duties_at_slots(slots, validator_indices)
                .await
            {
                Ok(duties) => return Ok(duties),
                Err(error) if self.remote_nodes.is_empty() => return Err(error),
                Err(error) => {
                    warn_with_peers!(
                        "{node} beacon node failed to produce attester duties for epoch \
                         {epoch}: {error:?}",
                    );
                }
            }
        }

        self.remote_attester_duties(epoch, validator_indices).await
    }

    async fn remote_attester_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        let operation = format!("produce attester duties for epoch {epoch}");
        let mut attempts = Vec::with_capacity(self.remote_nodes.len());

        for node in &self.remote_nodes {
            attempts.push((
                node.as_ref(),
                BeaconNodeApi::<P>::attester_duties(node.as_ref(), epoch, validator_indices),
            ));
        }

        let (node, duties) = first_success(&operation, attempts).await?;

        debug_with_peers!(
            "{node} beacon node produced {} attester duties for epoch {epoch} \
             under dependent root {:?}",
            duties.duties.len(),
            duties.dependent_root,
        );

        Ok(duties)
    }
}

impl<P: Preset, W: Wait + Sync> BeaconNodeApi<P> for BeaconNodes<P, W> {
    async fn dependent_root(
        &self,
        epoch: Epoch,
        validator_index: Option<ValidatorIndex>,
    ) -> Result<H256> {
        let operation = format!("produce the dependent root of epoch {epoch}");

        if let Some(node) = &self.local_node {
            match node.dependent_root(epoch, validator_index).await {
                Ok(dependent_root) => return Ok(dependent_root),
                Err(error) if self.remote_nodes.is_empty() => return Err(error),
                Err(error) => {
                    warn_with_peers!("{node} beacon node failed to {operation}: {error:?}");
                }
            }
        }

        let mut attempts = Vec::with_capacity(self.remote_nodes.len());

        for node in &self.remote_nodes {
            attempts.push((
                node.as_ref(),
                BeaconNodeApi::<P>::dependent_root(node.as_ref(), epoch, validator_index),
            ));
        }

        first_success(&operation, attempts)
            .await
            .map(|(_, dependent_root)| dependent_root)
    }

    async fn attester_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        if let Some(node) = &self.local_node {
            match node.attester_duties(epoch, validator_indices).await {
                Ok(duties) => return Ok(duties),
                Err(error) if self.remote_nodes.is_empty() => return Err(error),
                Err(error) => {
                    warn_with_peers!(
                        "{node} beacon node failed to produce attester duties for epoch \
                         {epoch}: {error:?}",
                    );
                }
            }
        }

        self.remote_attester_duties(epoch, validator_indices).await
    }

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
                Err(error) if self.remote_nodes.is_empty() => return Err(error),
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
        let publish_to = self.serving_nodes();

        if !publish_to.is_empty() {
            if self
                .publish_to_every_node
                .contains(&PublishedDuty::Attestations)
            {
                let attestations = Arc::new(attestations.to_vec());

                spawn_broadcast("publish attestations", publish_to, move |node| {
                    let attestations = attestations.clone_arc();

                    async move {
                        BeaconNodeApi::<P>::publish_singular_attestations(
                            node.as_ref(),
                            &attestations,
                        )
                        .await
                    }
                });
            } else {
                spawn_publish(publish_to, attestations.to_vec());
            }
        }

        match &self.local_node {
            Some(node) => node.publish_singular_attestations(attestations).await,
            None => Ok(()),
        }
    }

    async fn subscribe_to_beacon_committees(
        &self,
        current_slot: Slot,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<()> {
        if subscriptions.is_empty() {
            return Ok(());
        }

        let subscribe_on = self.serving_nodes();

        if !subscribe_on.is_empty() {
            let subscriptions = Arc::new(subscriptions.to_vec());

            // Every node is told, as any of them may be asked to produce or aggregate later.
            spawn_broadcast(
                "update beacon committee subscriptions",
                subscribe_on,
                move |node| {
                    let subscriptions = subscriptions.clone_arc();

                    async move {
                        BeaconNodeApi::<P>::subscribe_to_beacon_committees(
                            node.as_ref(),
                            current_slot,
                            &subscriptions,
                        )
                        .await
                    }
                },
            );
        }

        match &self.local_node {
            Some(node) => {
                node.subscribe_to_beacon_committees(current_slot, subscriptions)
                    .await
            }
            None => Ok(()),
        }
    }
}

// Detached as a whole rather than per node, so that the nodes are still tried in order.
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
            warn_with_peers!("no remote beacon node was able to publish attestations");
        }
    });
}

// Detached for the same reason as `spawn_publish`.
fn spawn_broadcast<F, Fut>(operation: &'static str, remotes: Vec<Arc<RemoteBeaconNode>>, attempt: F)
where
    F: Fn(Arc<RemoteBeaconNode>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send,
{
    tokio::spawn(async move {
        let accepted = remotes
            .iter()
            .map(|node| {
                let attempt = attempt(node.clone_arc());

                async move {
                    attempt
                        .await
                        .inspect_err(|error| {
                            warn_with_peers!("{node} beacon node failed to {operation}: {error:?}");
                        })
                        .is_ok()
                }
            })
            .pipe(join_all)
            .await;

        if !accepted.into_iter().any(identity) {
            warn_with_peers!("no remote beacon node was able to {operation}");
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
