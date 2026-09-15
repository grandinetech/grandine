use core::{fmt::Display, future::Future, ops::Range, ptr};
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};

use anyhow::{Error, Result, anyhow, bail, ensure};
use block_producer::ProposerData;
use bls::SignatureBytes;
use builder_api::unphased::containers::SignedValidatorRegistrationV1;
use fork_choice_control::Wait;
use futures::{StreamExt as _, future::join_all, stream::FuturesUnordered};
use http_api_utils::{ValidatorLivenessResponse, ValidatorSyncDutyResponse};
use logging::{debug_with_peers, warn_with_peers};
use p2p::{BeaconCommitteeSubscription, SyncCommitteeSubscription};
use ssz::ContiguousList;
use std_ext::ArcExt;
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
    health::Health,
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

    pub fn slot_head<P: Preset>(&self, slot: Slot) -> Option<SlotHead<P>> {
        for node in &self.nodes {
            match node.slot_head::<P>(slot) {
                Ok(Some(slot_head)) => return Some(slot_head),
                Ok(None) => {}
                Err(error) => {
                    warn_with_peers!("{node} beacon node reported an unusable head: {error:?}");
                }
            }
        }

        None
    }

    fn producer_first(&self) -> Vec<Arc<RemoteBeaconNode>> {
        let producer = self.producer.get();

        // The producer goes first, as it is known to be able to import what it produced.
        producer
            .map(ArcExt::clone_arc)
            .into_iter()
            .chain(
                self.serving_nodes()
                    .into_iter()
                    .filter(|node| producer.is_none_or(|producer| !Arc::ptr_eq(node, producer))),
            )
            .collect()
    }

    fn should_publish_to_every_node(&self, duty: Option<PublishedDuty>) -> bool {
        duty.is_none_or(|duty| should_publish_to_every_node(&self.publish_to_every_node, duty))
    }

    async fn publish_from_producer<F, Fut>(&self, operation: &'static str, attempt: F) -> Result<()>
    where
        F: Fn(Arc<RemoteBeaconNode>) -> Fut,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let to_every_node = self.should_publish_to_every_node(Some(PublishedDuty::Blocks));

        publish(operation, self.producer_first(), to_every_node, attempt).await
    }

    fn spawn_publish<T, F, Fut>(
        &self,
        operation: &'static str,
        duty: Option<PublishedDuty>,
        items: &T,
        attempt: F,
    ) where
        T: ToOwned + ?Sized + 'static,
        T::Owned: Send + Sync + 'static,
        F: Fn(Arc<RemoteBeaconNode>, Arc<T::Owned>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let publishing = self.publish(operation, duty, items, attempt);

        tokio::spawn(async move {
            if let Err(error) = publishing.await {
                warn_with_peers!("{error:?}");
            }
        });
    }

    fn publish<T, F, Fut>(
        &self,
        operation: &'static str,
        duty: Option<PublishedDuty>,
        items: &T,
        attempt: F,
    ) -> impl Future<Output = Result<()>> + Send + use<T, F, Fut>
    where
        T: ToOwned + ?Sized + 'static,
        T::Owned: Send + Sync + 'static,
        F: Fn(Arc<RemoteBeaconNode>, Arc<T::Owned>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let publish_to = self.serving_nodes();
        let to_every_node = self.should_publish_to_every_node(duty);
        let items = Arc::new(items.to_owned());
        let attempt = move |node| attempt(node, items.clone_arc());

        publish(operation, publish_to, to_every_node, attempt)
    }
}

impl<P: Preset> BeaconNodeApi<P> for RemoteNodes {
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

        // A node that is behind has not seen the attestations and reports nobody live.
        let ready_nodes = self.nodes.iter().filter(|node| node.health().is_ready());

        let responses = join_all(ready_nodes.map(|node| async move {
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
            "no synced beacon node could report validator liveness for epoch {epoch}",
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
            Some(PublishedDuty::Attestations),
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
            Some(PublishedDuty::Aggregates),
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
        self.spawn_publish(
            "update beacon committee subscriptions",
            None,
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
            Some(PublishedDuty::SyncCommitteeMessages),
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
        self.publish(
            "update sync committee subscriptions",
            None,
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
            Some(PublishedDuty::SyncCommitteeContributions),
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
        // A node whose view differs from the fleet's would build on a parent the others reject;
        // without a known head there is nothing to judge by, and any block beats a missed slot.
        let parent_root = match self.head_block_root().await {
            Ok(parent_root) => Some(parent_root),
            Err(error) => {
                warn_with_peers!("producing a block without a known head: {error:?}");
                None
            }
        };

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

                // A node sharing the fleet's head still builds on the grandparent when it reorgs
                // a late parent; only a node whose head differs is passed over.
                let shares_head = |parent_root| {
                    node.chain_head()
                        .cached()
                        .is_some_and(|(_, head)| head == parent_root)
                };

                if let Some(parent_root) = parent_root
                    && built_on != parent_root
                    && !shares_head(parent_root)
                {
                    if stash.set((node, produced_block)).is_err() {
                        debug_with_peers!(
                            "the block {node} built on {built_on:?} is not kept as the fallback; \
                             an earlier node's block already is",
                        );
                    }

                    bail!("{node} built on {built_on:?} rather than the head {parent_root:?}");
                }

                Ok(produced_block)
            })
            .await;

        let (producer, block) = match attempt {
            Ok((producer, block)) => (Some(producer), block),
            Err(error) => {
                let (Some(parent_root), Some((node, block))) = (parent_root, fallback.into_inner())
                else {
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
        let signed_block = signed_block.clone_arc();
        let kzg_proofs = Arc::new(kzg_proofs.cloned());
        let blobs = Arc::new(blobs.cloned());

        self.publish_from_producer("publish a block", move |node| {
            let signed_block = signed_block.clone_arc();
            let kzg_proofs = kzg_proofs.clone_arc();
            let blobs = blobs.clone_arc();

            async move {
                BeaconNodeApi::<P>::publish_block(
                    node.as_ref(),
                    &signed_block,
                    kzg_proofs.as_ref().as_ref(),
                    blobs.as_ref().as_ref(),
                )
                .await
            }
        })
        .await
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock<P>,
    ) -> Result<()> {
        let signed_block = Arc::new(signed_block.clone());

        // Only the producer holds the header to unblind it, so no other node is asked.
        let producer = self
            .producer
            .get()
            .map(ArcExt::clone_arc)
            .into_iter()
            .collect();

        publish("publish a blinded block", producer, false, move |node| {
            let signed_block = signed_block.clone_arc();

            async move {
                BeaconNodeApi::<P>::publish_blinded_block(node.as_ref(), &signed_block).await
            }
        })
        .await
    }

    async fn publish_execution_payload_envelope(
        &self,
        signed_envelope: &Arc<SignedExecutionPayloadEnvelope<P>>,
        kzg_proofs: &ContiguousList<KzgProof, P::MaxCellProofsPerBlock>,
        blobs: &ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
    ) -> Result<()> {
        let signed_envelope = signed_envelope.clone_arc();
        let kzg_proofs = Arc::new(kzg_proofs.clone());
        let blobs = Arc::new(blobs.clone());

        let operation = "publish an execution payload envelope";

        // Only the producer is sure to hold the block by now; the others may still be importing
        // it and would refuse its envelope, so they are left to gossip unless the producer fails.
        publish(operation, self.producer_first(), false, move |node| {
            let signed_envelope = signed_envelope.clone_arc();
            let kzg_proofs = kzg_proofs.clone_arc();
            let blobs = blobs.clone_arc();

            async move {
                BeaconNodeApi::<P>::publish_execution_payload_envelope(
                    node.as_ref(),
                    &signed_envelope,
                    &kzg_proofs,
                    &blobs,
                )
                .await
            }
        })
        .await
    }

    async fn payload_attestation_data(&self, slot: Slot) -> Result<Option<PayloadAttestationData>> {
        let operation = format!("produce payload attestation data for slot {slot}");

        // A node that has seen no block only settles the slot once every node agrees; a node that
        // has fallen behind never answers with data.
        let mut none_seen = false;

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
                }
            }
        }

        if none_seen {
            return Ok(None);
        }

        bail!("no beacon node was able to {operation}")
    }

    async fn publish_payload_attestations(
        &self,
        messages: &[Arc<PayloadAttestationMessage>],
    ) -> Result<()> {
        self.spawn_publish(
            "publish payload attestations",
            Some(PublishedDuty::PayloadAttestations),
            messages,
            move |node, messages| async move {
                BeaconNodeApi::<P>::publish_payload_attestations(node.as_ref(), &messages).await
            },
        );

        Ok(())
    }

    async fn prepare_beacon_proposer(
        &self,
        current_slot: Slot,
        proposers: &[ProposerData],
    ) -> Result<()> {
        self.spawn_publish(
            "prepare beacon proposers",
            None,
            proposers,
            move |node, proposers| async move {
                BeaconNodeApi::<P>::prepare_beacon_proposer(node.as_ref(), current_slot, &proposers)
                    .await
            },
        );

        Ok(())
    }

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<()> {
        // Awaited so that the caller's chunks reach the relay one at a time.
        self.publish(
            "register validators",
            None,
            registrations,
            move |node, registrations| async move {
                BeaconNodeApi::<P>::register_validators(node.as_ref(), &registrations).await
            },
        )
        .await
    }

    async fn publish_proposer_preferences(
        &self,
        preferences: &[Arc<SignedProposerPreferences>],
    ) -> Result<()> {
        self.publish(
            "publish proposer preferences",
            Some(PublishedDuty::ProposerPreferences),
            preferences,
            move |node, preferences| async move {
                BeaconNodeApi::<P>::publish_proposer_preferences(node.as_ref(), &preferences).await
            },
        )
        .await
    }
}

impl<P: Preset, W: Wait + Sync> BeaconNodeApi<P> for BeaconNodes<P, W> {
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

    async fn prepare_beacon_proposer(
        &self,
        current_slot: Slot,
        proposers: &[ProposerData],
    ) -> Result<()> {
        if proposers.is_empty() {
            return Ok(());
        }

        match self {
            Self::Local(node) => node.prepare_beacon_proposer(current_slot, proposers).await,
            Self::Remote { nodes: remotes, .. } => {
                BeaconNodeApi::<P>::prepare_beacon_proposer(remotes, current_slot, proposers).await
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

async fn publish<F, Fut>(
    operation: &'static str,
    remotes: Vec<Arc<RemoteBeaconNode>>,
    to_every_node: bool,
    attempt: F,
) -> Result<()>
where
    F: Fn(Arc<RemoteBeaconNode>) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    if to_every_node {
        return broadcast(operation, remotes, attempt).await;
    }

    let mut timed_out = false;

    for node in &remotes {
        match attempt(node.clone_arc()).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                log_publish_failure(node, operation, &error);
                timed_out |= is_timeout(&error);
            }
        }
    }

    Err(publish_error(operation, timed_out))
}

async fn broadcast<F, Fut>(
    operation: &'static str,
    remotes: Vec<Arc<RemoteBeaconNode>>,
    attempt: F,
) -> Result<()>
where
    F: Fn(Arc<RemoteBeaconNode>) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    // Spawned so that a node slow to answer is still published to after another has accepted.
    let mut attempts = remotes
        .into_iter()
        .map(|node| {
            let attempt = attempt(node.clone_arc());

            tokio::spawn(async move {
                attempt
                    .await
                    .inspect_err(|error| log_publish_failure(&node, operation, error))
            })
        })
        .collect::<FuturesUnordered<_>>();

    let mut timed_out = false;

    while let Some(result) = attempts.next().await {
        match result {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => timed_out |= is_timeout(&error),
            Err(error) => warn_with_peers!("task to {operation} failed: {error:?}"),
        }
    }

    Err(publish_error(operation, timed_out))
}

fn log_publish_failure(node: &RemoteBeaconNode, operation: &str, error: &Error) {
    // The health poll has already reported the node as unreachable.
    if node.health() == Health::Unreachable {
        debug_with_peers!("{node} beacon node failed to {operation}: {error:?}");
    } else if is_timeout(error) {
        warn_with_peers!("timed out waiting for {node} beacon node to {operation}: {error:?}");
    } else {
        warn_with_peers!("{node} beacon node failed to {operation}: {error:?}");
    }
}

fn publish_error(operation: &str, timed_out: bool) -> Error {
    if timed_out {
        anyhow!("timed out waiting to {operation}")
    } else {
        anyhow!("no remote beacon node was able to {operation}")
    }
}

fn is_timeout(error: &Error) -> bool {
    error
        .downcast_ref::<reqwest::Error>()
        .is_some_and(reqwest::Error::is_timeout)
}

pub async fn first_success<N: Display, T, F: Future<Output = Result<T>>>(
    operation: &str,
    attempts: impl IntoIterator<Item = (N, F)>,
) -> Result<(N, T)> {
    for (name, attempt) in attempts {
        match attempt.await {
            Ok(value) => return Ok((name, value)),
            Err(error) => {
                warn_with_peers!("{name} beacon node failed to {operation}: {error:?}");
            }
        }
    }

    bail!("no beacon node was able to {operation}")
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
    use reqwest::Client;
    use tokio::time::sleep;
    use types::{config::Config as ChainConfig, preset::Mainnet};

    use super::*;

    // Only a synced node has seen the epoch's attestations, so a lagging one is never asked.
    #[tokio::test]
    async fn liveness_is_not_asked_of_a_node_that_is_not_ready() -> Result<()> {
        let node = Arc::new(RemoteBeaconNode::new(
            Arc::new(ChainConfig::mainnet()),
            Client::new(),
            "http://unusable".parse()?,
            32,
        ));

        node.set_health(Health::Unusable);

        let remotes = RemoteBeaconNodes::new(vec![node], vec![], false);
        let nodes = RemoteNodes::new(&remotes, 0, 32);

        BeaconNodeApi::<Mainnet>::liveness(&nodes, 0, &[0])
            .await
            .expect_err("a node that is not ready cannot report liveness");

        Ok(())
    }

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

    // Each node's failure is logged as it happens; the error names no node, so that the last
    // one tried is not taken for the cause.
    #[tokio::test]
    async fn first_success_reports_the_operation_rather_than_a_node() {
        let error = first_success(
            "answer",
            [
                ("best", answer(1, FAST, true)),
                ("worst", answer(2, FAST, true)),
            ],
        )
        .await
        .expect_err("every attempt fails, so no answer can be produced");

        assert_eq!(error.to_string(), "no beacon node was able to answer");
    }

    async fn answer(value: u64, delay: Duration, fails: bool) -> Result<u64> {
        sleep(delay).await;
        ensure!(!fails, anyhow!("no"));
        Ok(value)
    }
}
