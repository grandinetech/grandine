use core::{convert::identity, fmt::Display, future::Future, ops::Range, ptr};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, OnceLock},
};

use anyhow::{Result, anyhow, bail, ensure};
use block_producer::ProposerData;
use bls::{PublicKeyBytes, SignatureBytes};
use builder_api::unphased::containers::SignedValidatorRegistrationV1;
use fork_choice_control::Wait;
use futures::future::join_all;
use http_api_utils::{ValidatorLivenessResponse, ValidatorSyncDutyResponse};
use logging::{debug_with_peers, warn_with_peers};
use p2p::{BeaconCommitteeSubscription, SyncCommitteeSubscription};
use ssz::ContiguousList;
use std_ext::ArcExt;
use tap::Pipe as _;
use types::{
    altair::{
        containers::{SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::{
        Attestation, BeaconState, SignedAggregateAndProof, SignedBeaconBlock,
        SignedBlindedBeaconBlock,
    },
    deneb::primitives::{Blob, KzgProof},
    gloas::containers::{
        PayloadAttestationData, PayloadAttestationMessage, SignedExecutionPayloadEnvelope,
        SignedProposerPreferences,
    },
    nonstandard::{KzgProofs, OwnAttestation, PublishedDuty},
    phase0::{
        containers::AttestationData,
        primitives::{CommitteeIndex, Epoch, H256, Slot, Uint256, ValidatorIndex},
    },
    preset::Preset,
};

use crate::{
    beacon_node_api::{AttesterDuties, BeaconNodeApi, ProducedBlock, ProposerDuties, PtcDuties},
    local_beacon_node::LocalBeaconNode,
    misc,
    remote_beacon_node::RemoteBeaconNode,
    remote_beacon_nodes::RemoteBeaconNodes,
    slot_head::SlotHead,
};

/// The beacon nodes a slot's duties are performed against, at the head the slot's duties are
/// performed on: the built-in node with its state, or the serving remote ones when there is none.
#[derive(Clone)]
pub enum BeaconNodes<P: Preset, W: Wait> {
    Local(LocalBeaconNode<P, W>),
    Remote {
        nodes: RemoteNodes,
        slot_head: SlotHead<P>,
    },
}

/// The remote beacon nodes serving at a slot, in health order.
#[derive(Clone)]
pub struct RemoteNodes {
    nodes: Vec<Arc<RemoteBeaconNode>>,
    current_slot: Slot,
    max_empty_slots: u64,
    publish_to_every_node: Vec<PublishedDuty>,
    /// The node that produced the block of the slot, which alone holds its payload.
    producer: OnceLock<Arc<RemoteBeaconNode>>,
}

impl<P: Preset, W: Wait + Sync> BeaconNodes<P, W> {
    #[must_use]
    pub const fn has_local_node(&self) -> bool {
        matches!(self, Self::Local(_))
    }

    #[must_use]
    pub const fn head(&self) -> &SlotHead<P> {
        match self {
            Self::Local(node) => node.head(),
            Self::Remote { slot_head, .. } => slot_head,
        }
    }

    /// The state of the built-in beacon node's head; a remote head comes without one.
    #[must_use]
    pub const fn state(&self) -> Option<&Arc<BeaconState<P>>> {
        match self {
            Self::Local(node) => Some(node.state()),
            Self::Remote { .. } => None,
        }
    }

    #[must_use]
    pub fn prefetch_slots(&self, current_slot: Slot) -> Range<Slot> {
        match self {
            Self::Local(_) => misc::slots_to_compute_in_advance(current_slot),
            // A remote node answers a whole epoch per request, so nothing is gained by asking
            // for less than the epochs in flight.
            Self::Remote { .. } => {
                let current_epoch =
                    helper_functions::misc::compute_epoch_at_slot::<P>(current_slot);

                helper_functions::misc::compute_start_slot_at_epoch::<P>(current_epoch)
                    ..helper_functions::misc::compute_start_slot_at_epoch::<P>(
                        current_epoch.saturating_add(2),
                    )
            }
        }
    }

    pub async fn attester_duties_at_slots(
        &self,
        slots: Range<Slot>,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        match self {
            Self::Local(node) => node.attester_duties_at_slots(slots, validator_indices),
            Self::Remote { nodes: remotes, .. } => {
                remotes
                    .attester_duties_at_slots::<P>(slots, validator_indices)
                    .await
            }
        }
    }

    /// <https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockRoot>
    pub async fn head_block_root(&self) -> Result<H256> {
        match self {
            Self::Local(node) => Ok(node.head_block_root()),
            Self::Remote { nodes: remotes, .. } => remotes.head_block_root().await,
        }
    }
}

impl RemoteNodes {
    pub fn new(remotes: &RemoteBeaconNodes, current_slot: Slot, max_empty_slots: u64) -> Self {
        Self {
            nodes: remotes.serving().map(ArcExt::clone_arc).collect(),
            current_slot,
            max_empty_slots,
            publish_to_every_node: remotes.publish_to_every_node().to_vec(),
            producer: OnceLock::new(),
        }
    }

    fn serving_nodes(&self) -> Vec<Arc<RemoteBeaconNode>> {
        self.nodes
            .iter()
            .filter(|node| node.health().can_serve())
            .map(ArcExt::clone_arc)
            .collect()
    }

    async fn attester_duties_at_slots<P: Preset>(
        &self,
        slots: Range<Slot>,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        // `slots` must lie within one epoch, as the duties carry a single dependent root.
        let epoch = helper_functions::misc::compute_epoch_at_slot::<P>(slots.start);
        let operation = format!("produce attester duties for epoch {epoch}");

        let (node, duties) = self
            .first_success(&operation, |node| {
                node.attester_duties(epoch, validator_indices)
            })
            .await?;

        debug_with_peers!(
            "{node} beacon node produced {} attester duties for epoch {epoch} \
             under dependent root {:?}",
            duties.duties.len(),
            duties.dependent_root,
        );

        Ok(duties)
    }

    /// Performs a duty against the nodes in order, returning the one that answered.
    async fn first_success<'this, T, Fut>(
        &'this self,
        operation: &str,
        attempt: impl Fn(&'this RemoteBeaconNode) -> Fut,
    ) -> Result<(&'this Arc<RemoteBeaconNode>, T)>
    where
        Fut: Future<Output = Result<T>>,
    {
        let mut attempts = Vec::with_capacity(self.nodes.len());

        for node in &self.nodes {
            attempts.push((node, attempt(node.as_ref())));
        }

        first_success(operation, attempts).await
    }

    async fn head_block_root(&self) -> Result<H256> {
        let operation = "produce the head block root";

        // The head of the earliest node holding one, so that the root signed for is one it knows.
        for node in &self.nodes {
            if let Ok(Some(block_root)) = node
                .chain_head()
                .get(self.current_slot, self.max_empty_slots)
            {
                return Ok(block_root);
            }
        }

        let (node, root) = self
            .first_success(operation, |node| {
                node.fresh_head_block_root(self.current_slot)
            })
            .await?;

        debug_with_peers!("{node} beacon node reported head block root {root:?}");

        Ok(root)
    }

    /// Publishes to the serving nodes, to all of them or the first that accepts as
    /// `--publish-to-every-node` directs, trying the producing node first as it is known to be
    /// able to import what it produced.
    async fn publish_from_producer<F, Fut>(&self, operation: &'static str, attempt: F) -> Result<()>
    where
        F: Fn(Arc<RemoteBeaconNode>) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let producer = self.producer.get();

        let publish_to = producer
            .map(ArcExt::clone_arc)
            .into_iter()
            .chain(
                self.serving_nodes()
                    .into_iter()
                    .filter(|node| producer.is_none_or(|producer| !Arc::ptr_eq(node, producer))),
            )
            .collect();

        if should_publish_to_every_node(&self.publish_to_every_node, PublishedDuty::Blocks) {
            broadcast(operation, publish_to, attempt).await
        } else {
            publish(operation, publish_to, attempt).await
        }
    }

    /// Publishes `items` to the serving nodes in the background, to all of them or the first that
    /// accepts as `--publish-to-every-node` directs.
    fn spawn_publish<T, F, Fut>(
        &self,
        operation: &'static str,
        duty: PublishedDuty,
        items: &T,
        attempt: F,
    ) where
        T: ToOwned + ?Sized,
        T::Owned: Send + Sync + 'static,
        F: Fn(Arc<RemoteBeaconNode>, Arc<T::Owned>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send,
    {
        let publish_to = self.serving_nodes();
        let items = Arc::new(items.to_owned());
        let attempt = move |node| attempt(node, items.clone_arc());

        if should_publish_to_every_node(&self.publish_to_every_node, duty) {
            spawn_broadcast(operation, publish_to, attempt);
        } else {
            spawn_publish(operation, publish_to, attempt);
        }
    }

    /// [`Self::spawn_publish`] awaited, so that the caller learns whether any node accepted.
    async fn publish<T, F, Fut>(
        &self,
        operation: &'static str,
        duty: PublishedDuty,
        items: &T,
        attempt: F,
    ) -> Result<()>
    where
        T: ToOwned + Sync + ?Sized,
        T::Owned: Send + Sync,
        F: Fn(Arc<RemoteBeaconNode>, Arc<T::Owned>) -> Fut + Send,
        Fut: Future<Output = Result<()>> + Send,
    {
        let publish_to = self.serving_nodes();
        let items = Arc::new(items.to_owned());
        let attempt = move |node| attempt(node, items.clone_arc());

        if should_publish_to_every_node(&self.publish_to_every_node, duty) {
            broadcast(operation, publish_to, attempt).await
        } else {
            publish(operation, publish_to, attempt).await
        }
    }

    /// Publishes `items` to every serving node in the background.
    fn spawn_broadcast<T, F, Fut>(&self, operation: &'static str, items: &T, attempt: F)
    where
        T: ToOwned + ?Sized,
        T::Owned: Send + Sync + 'static,
        F: Fn(Arc<RemoteBeaconNode>, Arc<T::Owned>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send,
    {
        let items = Arc::new(items.to_owned());

        spawn_broadcast(operation, self.serving_nodes(), move |node| {
            attempt(node, items.clone_arc())
        });
    }

    /// [`Self::spawn_broadcast`] awaited; fails when no node serves or none accepts.
    async fn broadcast<T, F, Fut>(
        &self,
        operation: &'static str,
        items: &T,
        attempt: F,
    ) -> Result<()>
    where
        T: ToOwned + Sync + ?Sized,
        T::Owned: Send + Sync,
        F: Fn(Arc<RemoteBeaconNode>, Arc<T::Owned>) -> Fut + Send,
        Fut: Future<Output = Result<()>> + Send,
    {
        let items = Arc::new(items.to_owned());

        broadcast(operation, self.serving_nodes(), move |node| {
            attempt(node, items.clone_arc())
        })
        .await
    }
}

impl<P: Preset> BeaconNodeApi<P> for RemoteNodes {
    async fn validator_indices(
        &self,
        public_keys: &[PublicKeyBytes],
    ) -> Result<HashMap<PublicKeyBytes, ValidatorIndex>> {
        let operation = "resolve validator indices";
        let mut indices = HashMap::new();
        let mut answered = false;
        let mut last_error = None;

        // A validator missing from one node's head may be present in another's.
        for node in &self.nodes {
            let unresolved = public_keys
                .iter()
                .copied()
                .filter(|public_key| !indices.contains_key(public_key))
                .collect::<Vec<_>>();

            if unresolved.is_empty() {
                break;
            }

            match BeaconNodeApi::<P>::validator_indices(node.as_ref(), &unresolved).await {
                Ok(resolved) => {
                    answered = true;
                    indices.extend(resolved);
                }
                Err(error) => {
                    warn_with_peers!("{node} beacon node failed to {operation}: {error:?}");
                    last_error = Some(error);
                }
            }
        }

        // Keys nobody knows are simply missing from the answer. An error is reported only when no
        // node managed to answer at all, so that one unreachable node does not make a validator
        // look undeposited.
        match last_error {
            Some(error) if !answered => Err(error),
            _ => Ok(indices),
        }
    }

    async fn liveness(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorLivenessResponse>> {
        // A validator seen live by any node is live.
        let mut liveness = validator_indices
            .iter()
            .map(|validator_index| (*validator_index, false))
            .collect::<BTreeMap<_, _>>();

        let mut any_success = false;

        let responses = join_all(self.nodes.iter().map(|node| async move {
            let result = BeaconNodeApi::<P>::liveness(node.as_ref(), epoch, validator_indices);
            (result.await, node)
        }))
        .await;

        for (result, node) in responses {
            match result {
                Ok(response) => {
                    any_success = true;

                    for entry in response {
                        if entry.is_live
                            && let Some(live) = liveness.get_mut(&entry.index)
                        {
                            *live = true;
                        }
                    }
                }
                Err(error) => warn_with_peers!(
                    "{node} beacon node failed to report liveness for epoch {epoch}: {error:?}",
                ),
            }
        }

        ensure!(
            any_success,
            "no beacon node could report validator liveness for epoch {epoch}",
        );

        Ok(liveness
            .into_iter()
            .map(|(index, is_live)| ValidatorLivenessResponse { index, is_live })
            .collect())
    }

    async fn dependent_root(&self, epoch: Epoch, validator_index: ValidatorIndex) -> Result<H256> {
        // A head event already reported the root, sparing the request it would take to ask.
        for node in &self.nodes {
            if let Some(dependent_root) = node.chain_head().dependent_root_for(epoch) {
                return Ok(dependent_root);
            }
        }

        let operation = format!("produce the dependent root of epoch {epoch}");

        self.first_success(&operation, |node| {
            BeaconNodeApi::<P>::dependent_root(node, epoch, validator_index)
        })
        .await
        .map(|(_, dependent_root)| dependent_root)
    }

    async fn attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData> {
        let operation = format!("produce attestation data for slot {slot}");

        let (node, data) = self
            .first_success(&operation, |node| {
                BeaconNodeApi::<P>::attestation_data(node, slot, committee_index)
            })
            .await?;

        if !node.health().is_ready() {
            debug_with_peers!(
                "attestation data for slot {slot} came from {node}, which is not fully synced",
            );
        }

        debug_with_peers!("{node} beacon node produced attestation data for slot {slot}: {data:?}");

        Ok(data)
    }

    async fn aggregate_attestation(
        &self,
        data: AttestationData,
        committee_index: CommitteeIndex,
    ) -> Result<Attestation<P>> {
        let operation = format!(
            "produce an aggregate attestation for committee {committee_index} in slot {}",
            data.slot,
        );

        self.first_success(&operation, |node| {
            BeaconNodeApi::<P>::aggregate_attestation(node, data, committee_index)
        })
        .await
        .map(|(_, aggregate)| aggregate)
    }

    async fn publish_singular_attestations(
        &self,
        attestations: &[OwnAttestation<P>],
    ) -> Result<()> {
        self.spawn_publish(
            "publish attestations",
            PublishedDuty::Attestations,
            attestations,
            move |node, attestations| async move {
                BeaconNodeApi::<P>::publish_singular_attestations(node.as_ref(), &attestations)
                    .await
            },
        );

        Ok(())
    }

    async fn publish_aggregates_and_proofs(
        &self,
        aggregates_and_proofs: &[Arc<SignedAggregateAndProof<P>>],
    ) -> Result<()> {
        self.spawn_publish(
            "publish aggregates and proofs",
            PublishedDuty::Aggregates,
            aggregates_and_proofs,
            move |node, aggregates_and_proofs| async move {
                BeaconNodeApi::<P>::publish_aggregates_and_proofs(
                    node.as_ref(),
                    &aggregates_and_proofs,
                )
                .await
            },
        );

        Ok(())
    }

    async fn subscribe_to_beacon_committees(
        &self,
        current_slot: Slot,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<()> {
        self.spawn_broadcast(
            "update beacon committee subscriptions",
            subscriptions,
            move |node, subscriptions| async move {
                BeaconNodeApi::<P>::subscribe_to_beacon_committees(
                    node.as_ref(),
                    current_slot,
                    &subscriptions,
                )
                .await
            },
        );

        Ok(())
    }

    async fn slot_head(&self, slot: Slot) -> Result<Option<SlotHead<P>>> {
        for node in &self.nodes {
            match BeaconNodeApi::<P>::slot_head(node.as_ref(), slot).await {
                Ok(Some(slot_head)) => return Ok(Some(slot_head)),
                Ok(None) => {}
                Err(error) => {
                    warn_with_peers!("{node} beacon node reported an unusable head: {error:?}");
                }
            }
        }

        Ok(None)
    }

    async fn sync_committee_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorSyncDutyResponse>> {
        let operation = format!("produce sync committee duties for epoch {epoch}");

        let (node, duties) = self
            .first_success(&operation, |node| {
                BeaconNodeApi::<P>::sync_committee_duties(node, epoch, validator_indices)
            })
            .await?;

        debug_with_peers!(
            "{node} beacon node produced {} sync committee duties for epoch {epoch}",
            duties.len(),
        );

        Ok(duties)
    }

    async fn publish_sync_committee_messages(
        &self,
        messages: &BTreeMap<SubcommitteeIndex, Vec<SyncCommitteeMessage>>,
    ) -> Result<()> {
        self.spawn_publish(
            "publish sync committee messages",
            PublishedDuty::SyncCommitteeMessages,
            messages,
            move |node, messages| async move {
                BeaconNodeApi::<P>::publish_sync_committee_messages(node.as_ref(), &messages).await
            },
        );

        Ok(())
    }

    async fn subscribe_to_sync_committees(
        &self,
        current_epoch: Epoch,
        subscriptions: &[SyncCommitteeSubscription],
    ) -> Result<()> {
        // Every node is told, as any of them may be asked to contribute later.
        self.broadcast(
            "update sync committee subscriptions",
            subscriptions,
            move |node, subscriptions| async move {
                BeaconNodeApi::<P>::subscribe_to_sync_committees(
                    node.as_ref(),
                    current_epoch,
                    &subscriptions,
                )
                .await
            },
        )
        .await
    }

    async fn sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: SubcommitteeIndex,
        beacon_block_root: H256,
    ) -> Result<SyncCommitteeContribution<P>> {
        let operation = format!(
            "produce a sync committee contribution for subcommittee {subcommittee_index} \
             in slot {slot}",
        );

        self.first_success(&operation, |node| {
            BeaconNodeApi::<P>::sync_committee_contribution(
                node,
                slot,
                subcommittee_index,
                beacon_block_root,
            )
        })
        .await
        .map(|(_, contribution)| contribution)
    }

    async fn publish_contributions_and_proofs(
        &self,
        contributions_and_proofs: &[SignedContributionAndProof<P>],
    ) -> Result<()> {
        self.spawn_publish(
            "publish contributions and proofs",
            PublishedDuty::SyncCommitteeContributions,
            contributions_and_proofs,
            move |node, contributions_and_proofs| async move {
                BeaconNodeApi::<P>::publish_contributions_and_proofs(
                    node.as_ref(),
                    &contributions_and_proofs,
                )
                .await
            },
        );

        Ok(())
    }

    async fn ptc_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<PtcDuties> {
        let operation = format!("produce PTC duties for epoch {epoch}");

        let (node, duties) = self
            .first_success(&operation, |node| {
                BeaconNodeApi::<P>::ptc_duties(node, epoch, validator_indices)
            })
            .await?;

        debug_with_peers!(
            "{node} beacon node produced {} PTC duties for epoch {epoch} \
             under dependent root {:?}",
            duties.duties.len(),
            duties.dependent_root,
        );

        Ok(duties)
    }

    async fn proposer_duties(&self, epoch: Epoch) -> Result<ProposerDuties> {
        let operation = format!("produce proposer duties for epoch {epoch}");

        let (node, duties) = self
            .first_success(&operation, |node| {
                BeaconNodeApi::<P>::proposer_duties(node, epoch)
            })
            .await?;

        debug_with_peers!(
            "{node} beacon node produced {} proposer duties for epoch {epoch} \
             under dependent root {:?}",
            duties.duties.len(),
            duties.dependent_root,
        );

        Ok(duties)
    }

    async fn produce_block(
        &self,
        slot: Slot,
        randao_reveal: SignatureBytes,
        graffiti: Option<H256>,
        builder_boost_factor: Uint256,
    ) -> Result<ProducedBlock<P>> {
        // A node whose view differs from the fleet's would build on a parent the others reject.
        let parent_root = self.head_block_root().await?;

        // The cached head can lag a block every node already has; then no block matches it and
        // the first one built is still better than a missed slot.
        let fallback = OnceLock::new();
        let stash = &fallback;

        let attempt = self
            .first_success("produce a block", |node| async move {
                let produced_block = BeaconNodeApi::<P>::produce_block(
                    node,
                    slot,
                    randao_reveal,
                    graffiti,
                    builder_boost_factor,
                )
                .await?;

                let built_on = produced_block.block.parent_root();

                if built_on != parent_root {
                    drop(stash.set((node, produced_block)));
                    bail!("{node} built on {built_on:?} rather than the head {parent_root:?}");
                }

                Ok(produced_block)
            })
            .await;

        let (producer, block) = match attempt {
            Ok((producer, block)) => (Some(producer), block),
            Err(error) => {
                let Some((node, block)) = fallback.into_inner() else {
                    return Err(error);
                };

                warn_with_peers!(
                    "no beacon node built on the head {parent_root:?}; proposing the block \
                     {node} built on {:?}",
                    block.block.parent_root(),
                );

                let producer = self
                    .nodes
                    .iter()
                    .find(|candidate| ptr::eq(candidate.as_ref(), node));

                (producer, block)
            }
        };

        if let Some(producer) = producer {
            self.producer.get_or_init(|| producer.clone_arc());
        }

        Ok(block)
    }

    async fn publish_block(
        &self,
        signed_block: &Arc<SignedBeaconBlock<P>>,
        kzg_proofs: Option<&KzgProofs<P>>,
        blobs: Option<&ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>>,
    ) -> Result<()> {
        self.publish_from_producer("publish a block", |node| async move {
            BeaconNodeApi::<P>::publish_block(node.as_ref(), signed_block, kzg_proofs, blobs).await
        })
        .await
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock<P>,
    ) -> Result<()> {
        self.publish_from_producer("publish a blinded block", |node| async move {
            BeaconNodeApi::<P>::publish_blinded_block(node.as_ref(), signed_block).await
        })
        .await
    }

    async fn publish_execution_payload_envelope(
        &self,
        signed_envelope: &Arc<SignedExecutionPayloadEnvelope<P>>,
        kzg_proofs: &ContiguousList<KzgProof, P::MaxCellProofsPerBlock>,
        blobs: &ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
    ) -> Result<()> {
        self.publish_from_producer("publish an execution payload envelope", |node| async move {
            BeaconNodeApi::<P>::publish_execution_payload_envelope(
                node.as_ref(),
                signed_envelope,
                kzg_proofs,
                blobs,
            )
            .await
        })
        .await
    }

    async fn payload_attestation_data(&self, slot: Slot) -> Result<Option<PayloadAttestationData>> {
        let operation = format!("produce payload attestation data for slot {slot}");

        // A node that has seen no block only settles the slot once every node agrees; a node that
        // has fallen behind never answers with data.
        let mut none_seen = false;
        let mut last_error = None;

        for node in &self.nodes {
            match BeaconNodeApi::<P>::payload_attestation_data(node.as_ref(), slot).await {
                Ok(Some(data)) => {
                    debug_with_peers!(
                        "{node} beacon node produced payload attestation data \
                         for slot {slot}: {data:?}",
                    );
                    return Ok(Some(data));
                }
                Ok(None) => none_seen = true,
                Err(error) => {
                    warn_with_peers!("{node} beacon node failed to {operation}: {error:?}");
                    last_error = Some(error);
                }
            }
        }

        if none_seen {
            return Ok(None);
        }

        Err(last_error.unwrap_or_else(|| anyhow!("no beacon node is configured to {operation}")))
    }

    async fn publish_payload_attestations(
        &self,
        messages: &[Arc<PayloadAttestationMessage>],
    ) -> Result<()> {
        self.spawn_publish(
            "publish payload attestations",
            PublishedDuty::PayloadAttestations,
            messages,
            move |node, messages| async move {
                BeaconNodeApi::<P>::publish_payload_attestations(node.as_ref(), &messages).await
            },
        );

        Ok(())
    }

    async fn prepare_beacon_proposer(&self, proposers: &[ProposerData]) -> Result<()> {
        self.spawn_broadcast(
            "prepare beacon proposers",
            proposers,
            move |node, proposers| async move {
                BeaconNodeApi::<P>::prepare_beacon_proposer(node.as_ref(), &proposers).await
            },
        );

        Ok(())
    }

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<()> {
        self.spawn_broadcast(
            "register validators",
            registrations,
            move |node, registrations| async move {
                BeaconNodeApi::<P>::register_validators(node.as_ref(), &registrations).await
            },
        );

        Ok(())
    }

    async fn publish_proposer_preferences(
        &self,
        preferences: &[Arc<SignedProposerPreferences>],
    ) -> Result<()> {
        self.publish(
            "publish proposer preferences",
            PublishedDuty::ProposerPreferences,
            preferences,
            move |node, preferences| async move {
                BeaconNodeApi::<P>::publish_proposer_preferences(node.as_ref(), &preferences).await
            },
        )
        .await
    }
}

impl<P: Preset, W: Wait + Sync> BeaconNodeApi<P> for BeaconNodes<P, W> {
    async fn validator_indices(
        &self,
        public_keys: &[PublicKeyBytes],
    ) -> Result<HashMap<PublicKeyBytes, ValidatorIndex>> {
        match self {
            Self::Local(node) => node.validator_indices(public_keys).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::validator_indices(remotes, public_keys).await
            }
        }
    }

    async fn liveness(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorLivenessResponse>> {
        match self {
            Self::Local(node) => node.liveness(epoch, validator_indices).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::liveness(remotes, epoch, validator_indices).await
            }
        }
    }

    async fn dependent_root(&self, epoch: Epoch, validator_index: ValidatorIndex) -> Result<H256> {
        match self {
            Self::Local(node) => node.dependent_root(epoch, validator_index).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::dependent_root(remotes, epoch, validator_index).await
            }
        }
    }

    async fn attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData> {
        match self {
            Self::Local(node) => node.attestation_data(slot, committee_index).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::attestation_data(remotes, slot, committee_index).await
            }
        }
    }

    async fn aggregate_attestation(
        &self,
        data: AttestationData,
        committee_index: CommitteeIndex,
    ) -> Result<Attestation<P>> {
        match self {
            Self::Local(node) => node.aggregate_attestation(data, committee_index).await,
            Self::Remote { nodes: remotes, .. } => {
                remotes.aggregate_attestation(data, committee_index).await
            }
        }
    }

    async fn publish_singular_attestations(
        &self,
        attestations: &[OwnAttestation<P>],
    ) -> Result<()> {
        match self {
            Self::Local(node) => node.publish_singular_attestations(attestations).await,
            Self::Remote { nodes: remotes, .. } => {
                remotes.publish_singular_attestations(attestations).await
            }
        }
    }

    async fn publish_aggregates_and_proofs(
        &self,
        aggregates_and_proofs: &[Arc<SignedAggregateAndProof<P>>],
    ) -> Result<()> {
        match self {
            Self::Local(node) => {
                node.publish_aggregates_and_proofs(aggregates_and_proofs)
                    .await
            }
            Self::Remote { nodes: remotes, .. } => {
                remotes
                    .publish_aggregates_and_proofs(aggregates_and_proofs)
                    .await
            }
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

        match self {
            Self::Local(node) => {
                node.subscribe_to_beacon_committees(current_slot, subscriptions)
                    .await
            }
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::subscribe_to_beacon_committees(
                    remotes,
                    current_slot,
                    subscriptions,
                )
                .await
            }
        }
    }

    async fn slot_head(&self, slot: Slot) -> Result<Option<SlotHead<P>>> {
        match self {
            Self::Local(node) => node.slot_head(slot).await,
            Self::Remote { nodes: remotes, .. } => remotes.slot_head(slot).await,
        }
    }

    async fn sync_committee_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorSyncDutyResponse>> {
        match self {
            Self::Local(node) => node.sync_committee_duties(epoch, validator_indices).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::sync_committee_duties(remotes, epoch, validator_indices).await
            }
        }
    }

    async fn publish_sync_committee_messages(
        &self,
        messages: &BTreeMap<SubcommitteeIndex, Vec<SyncCommitteeMessage>>,
    ) -> Result<()> {
        match self {
            Self::Local(node) => node.publish_sync_committee_messages(messages).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::publish_sync_committee_messages(remotes, messages).await
            }
        }
    }

    async fn subscribe_to_sync_committees(
        &self,
        current_epoch: Epoch,
        subscriptions: &[SyncCommitteeSubscription],
    ) -> Result<()> {
        if subscriptions.is_empty() {
            return Ok(());
        }

        match self {
            Self::Local(node) => {
                node.subscribe_to_sync_committees(current_epoch, subscriptions)
                    .await
            }
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::subscribe_to_sync_committees(
                    remotes,
                    current_epoch,
                    subscriptions,
                )
                .await
            }
        }
    }

    async fn sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: SubcommitteeIndex,
        beacon_block_root: H256,
    ) -> Result<SyncCommitteeContribution<P>> {
        match self {
            Self::Local(node) => {
                node.sync_committee_contribution(slot, subcommittee_index, beacon_block_root)
                    .await
            }
            Self::Remote { nodes: remotes, .. } => {
                remotes
                    .sync_committee_contribution(slot, subcommittee_index, beacon_block_root)
                    .await
            }
        }
    }

    async fn publish_contributions_and_proofs(
        &self,
        contributions_and_proofs: &[SignedContributionAndProof<P>],
    ) -> Result<()> {
        match self {
            Self::Local(node) => {
                node.publish_contributions_and_proofs(contributions_and_proofs)
                    .await
            }
            Self::Remote { nodes: remotes, .. } => {
                remotes
                    .publish_contributions_and_proofs(contributions_and_proofs)
                    .await
            }
        }
    }

    async fn ptc_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<PtcDuties> {
        match self {
            Self::Local(node) => node.ptc_duties(epoch, validator_indices).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::ptc_duties(remotes, epoch, validator_indices).await
            }
        }
    }

    async fn proposer_duties(&self, epoch: Epoch) -> Result<ProposerDuties> {
        match self {
            Self::Local(node) => node.proposer_duties(epoch).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::proposer_duties(remotes, epoch).await
            }
        }
    }

    async fn produce_block(
        &self,
        slot: Slot,
        randao_reveal: SignatureBytes,
        graffiti: Option<H256>,
        builder_boost_factor: Uint256,
    ) -> Result<ProducedBlock<P>> {
        match self {
            Self::Local(node) => {
                node.produce_block(slot, randao_reveal, graffiti, builder_boost_factor)
                    .await
            }
            Self::Remote { nodes: remotes, .. } => {
                remotes
                    .produce_block(slot, randao_reveal, graffiti, builder_boost_factor)
                    .await
            }
        }
    }

    async fn publish_block(
        &self,
        signed_block: &Arc<SignedBeaconBlock<P>>,
        kzg_proofs: Option<&KzgProofs<P>>,
        blobs: Option<&ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>>,
    ) -> Result<()> {
        match self {
            Self::Local(node) => node.publish_block(signed_block, kzg_proofs, blobs).await,
            Self::Remote { nodes: remotes, .. } => {
                remotes.publish_block(signed_block, kzg_proofs, blobs).await
            }
        }
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock<P>,
    ) -> Result<()> {
        match self {
            Self::Local(node) => node.publish_blinded_block(signed_block).await,
            Self::Remote { nodes: remotes, .. } => {
                remotes.publish_blinded_block(signed_block).await
            }
        }
    }

    async fn publish_execution_payload_envelope(
        &self,
        signed_envelope: &Arc<SignedExecutionPayloadEnvelope<P>>,
        kzg_proofs: &ContiguousList<KzgProof, P::MaxCellProofsPerBlock>,
        blobs: &ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
    ) -> Result<()> {
        match self {
            Self::Local(node) => {
                node.publish_execution_payload_envelope(signed_envelope, kzg_proofs, blobs)
                    .await
            }
            Self::Remote { nodes: remotes, .. } => {
                remotes
                    .publish_execution_payload_envelope(signed_envelope, kzg_proofs, blobs)
                    .await
            }
        }
    }

    async fn payload_attestation_data(&self, slot: Slot) -> Result<Option<PayloadAttestationData>> {
        match self {
            Self::Local(node) => node.payload_attestation_data(slot).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::payload_attestation_data(remotes, slot).await
            }
        }
    }

    async fn publish_payload_attestations(
        &self,
        messages: &[Arc<PayloadAttestationMessage>],
    ) -> Result<()> {
        match self {
            Self::Local(node) => node.publish_payload_attestations(messages).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::publish_payload_attestations(remotes, messages).await
            }
        }
    }

    async fn prepare_beacon_proposer(&self, proposers: &[ProposerData]) -> Result<()> {
        if proposers.is_empty() {
            return Ok(());
        }

        match self {
            Self::Local(node) => node.prepare_beacon_proposer(proposers).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::prepare_beacon_proposer(remotes, proposers).await
            }
        }
    }

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<()> {
        if registrations.is_empty() {
            return Ok(());
        }

        match self {
            Self::Local(node) => node.register_validators(registrations).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::register_validators(remotes, registrations).await
            }
        }
    }

    async fn publish_proposer_preferences(
        &self,
        preferences: &[Arc<SignedProposerPreferences>],
    ) -> Result<()> {
        match self {
            Self::Local(node) => node.publish_proposer_preferences(preferences).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::publish_proposer_preferences(remotes, preferences).await
            }
        }
    }
}

fn spawn_publish<F, Fut>(operation: &'static str, remotes: Vec<Arc<RemoteBeaconNode>>, attempt: F)
where
    F: Fn(Arc<RemoteBeaconNode>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send,
{
    tokio::spawn(async move {
        if let Err(error) = publish(operation, remotes, attempt).await {
            warn_with_peers!("{error:?}");
        }
    });
}

async fn publish<F, Fut>(
    operation: &'static str,
    remotes: Vec<Arc<RemoteBeaconNode>>,
    attempt: F,
) -> Result<()>
where
    F: Fn(Arc<RemoteBeaconNode>) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let attempts = remotes
        .iter()
        .map(|node| (node.clone_arc(), attempt(node.clone_arc())))
        .collect::<Vec<_>>();

    ensure!(
        first_success(operation, attempts).await.is_ok(),
        "no remote beacon node was able to {operation}",
    );

    Ok(())
}

fn spawn_broadcast<F, Fut>(operation: &'static str, remotes: Vec<Arc<RemoteBeaconNode>>, attempt: F)
where
    F: Fn(Arc<RemoteBeaconNode>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send,
{
    tokio::spawn(async move {
        if let Err(error) = broadcast(operation, remotes, attempt).await {
            warn_with_peers!("{error:?}");
        }
    });
}

/// Succeeds when any node accepts, having warned about each one that did not.
async fn broadcast<F, Fut>(
    operation: &'static str,
    remotes: Vec<Arc<RemoteBeaconNode>>,
    attempt: F,
) -> Result<()>
where
    F: Fn(Arc<RemoteBeaconNode>) -> Fut,
    Fut: Future<Output = Result<()>>,
{
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

    ensure!(
        accepted.into_iter().any(identity),
        "no remote beacon node was able to {operation}",
    );

    Ok(())
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

    Err(last_error.unwrap_or_else(|| anyhow!("no beacon node is configured to {operation}")))
}

fn should_publish_to_every_node(configured: &[PublishedDuty], duty: PublishedDuty) -> bool {
    configured
        .iter()
        .any(|configured| matches!(configured, PublishedDuty::All) || *configured == duty)
}

#[cfg(test)]
mod tests {
    use core::{iter::once, time::Duration};

    use anyhow::ensure;
    use tokio::time::sleep;

    use super::*;

    const SLOW: Duration = Duration::from_millis(50);
    const FAST: Duration = Duration::ZERO;

    #[test]
    fn all_covers_every_published_duty() {
        for duty in [
            PublishedDuty::Aggregates,
            PublishedDuty::Attestations,
            PublishedDuty::Blocks,
            PublishedDuty::PayloadAttestations,
            PublishedDuty::ProposerPreferences,
            PublishedDuty::SyncCommitteeContributions,
            PublishedDuty::SyncCommitteeMessages,
        ] {
            assert!(should_publish_to_every_node(&[PublishedDuty::All], duty));
        }

        assert!(should_publish_to_every_node(
            &[PublishedDuty::Attestations],
            PublishedDuty::Attestations,
        ));

        assert!(!should_publish_to_every_node(
            &[PublishedDuty::Attestations],
            PublishedDuty::Aggregates,
        ));

        assert!(!should_publish_to_every_node(
            &[],
            PublishedDuty::Aggregates
        ));
    }

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
        ensure!(!fails, anyhow!("no"));
        Ok(value)
    }
}
