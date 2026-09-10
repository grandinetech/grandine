use core::{convert::identity, fmt::Display, future::Future, ops::Range};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, OnceLock},
};

use anyhow::{Error as AnyhowError, Result, ensure};
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
    combined::{Attestation, SignedAggregateAndProof, SignedBeaconBlock, SignedBlindedBeaconBlock},
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

pub struct BeaconNodes<P: Preset, W: Wait> {
    local_node: Option<LocalBeaconNode<P, W>>,
    remote_nodes: Vec<Arc<RemoteBeaconNode>>,
    current_slot: Slot,
    max_empty_slots: u64,
    publish_to_every_node: Vec<PublishedDuty>,
    /// The remote node that produced the block of the slot, which alone holds its payload.
    producer: OnceLock<Arc<RemoteBeaconNode>>,
}

impl<P: Preset, W: Wait + Sync> BeaconNodes<P, W> {
    pub fn new(
        local_node: Option<LocalBeaconNode<P, W>>,
        current_slot: Slot,
        max_empty_slots: u64,
        remotes: Option<&RemoteBeaconNodes>,
        publish_to_every_node: Vec<PublishedDuty>,
    ) -> Self {
        Self {
            local_node,
            remote_nodes: remotes
                .into_iter()
                .flat_map(RemoteBeaconNodes::serving)
                .map(ArcExt::clone_arc)
                .collect(),
            current_slot,
            max_empty_slots,
            publish_to_every_node,
            producer: OnceLock::new(),
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

    #[must_use]
    pub fn prefetch_slots(&self, current_slot: Slot) -> Range<Slot> {
        if self.has_local_node() {
            return misc::slots_to_compute_in_advance(current_slot);
        }

        // A remote node answers a whole epoch per request, so nothing is gained by asking for
        // less than the epochs in flight.

        let current_epoch = helper_functions::misc::compute_epoch_at_slot::<P>(current_slot);

        helper_functions::misc::compute_start_slot_at_epoch::<P>(current_epoch)
            ..helper_functions::misc::compute_start_slot_at_epoch::<P>(
                current_epoch.saturating_add(2),
            )
    }

    pub async fn attester_duties_at_slots(
        &self,
        slots: Range<Slot>,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        // `slots` must lie within one epoch, as the duties carry a single dependent root.
        let epoch = helper_functions::misc::compute_epoch_at_slot::<P>(slots.start);
        let operation = format!("produce attester duties for epoch {epoch}");

        let (node, duties) = self
            .local_then_remotes(
                &operation,
                |node| node.attester_duties_at_slots(slots, validator_indices),
                |node| node.attester_duties(epoch, validator_indices),
            )
            .await?;

        if let Some(node) = node {
            debug_with_peers!(
                "{node} beacon node produced {} attester duties for epoch {epoch} \
                 under dependent root {:?}",
                duties.duties.len(),
                duties.dependent_root,
            );
        }

        Ok(duties)
    }

    /// Performs a duty against the built-in beacon node, falling back to the remote ones in
    /// order. Returns the remote node that answered, or [`None`] for the built-in one.
    async fn local_then_remotes<'this, T, LFut, RFut>(
        &'this self,
        operation: &str,
        local: impl FnOnce(&'this LocalBeaconNode<P, W>) -> LFut,
        remote: impl Fn(&'this RemoteBeaconNode) -> RFut,
    ) -> Result<(Option<&'this Arc<RemoteBeaconNode>>, T)>
    where
        LFut: Future<Output = Result<T>>,
        RFut: Future<Output = Result<T>>,
    {
        if let Some(node) = &self.local_node {
            match local(node).await {
                Ok(value) => return Ok((None, value)),
                Err(error) if self.remote_nodes.is_empty() => return Err(error),
                Err(error) => {
                    warn_with_peers!("{node} beacon node failed to {operation}: {error:?}");
                }
            }
        }

        let mut attempts = Vec::with_capacity(self.remote_nodes.len());

        for node in &self.remote_nodes {
            attempts.push((node, remote(node.as_ref())));
        }

        first_success(operation, attempts)
            .await
            .map(|(node, value)| (Some(node), value))
    }

    /// <https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockRoot>
    pub async fn head_block_root(&self) -> Result<H256> {
        let operation = "produce the head block root";

        if let Some(node) = &self.local_node {
            return Ok(node.head_block_root());
        }

        // The head of the earliest node holding one, so that the root signed for is one it knows.
        for node in &self.remote_nodes {
            if let Ok(Some(block_root)) = node
                .chain_head()
                .get(self.current_slot, self.max_empty_slots)
            {
                return Ok(block_root);
            }
        }

        let mut attempts = Vec::with_capacity(self.remote_nodes.len());

        for node in &self.remote_nodes {
            attempts.push((node.as_ref(), node.fresh_head_block_root(self.current_slot)));
        }

        let (node, root) = first_success(operation, attempts).await?;

        debug_with_peers!("{node} beacon node reported head block root {root:?}");

        Ok(root)
    }

    /// Publishes to the serving remote nodes, to all of them or the first that accepts as
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

    /// Publishes to the serving remote nodes, to all of them or the first that accepts as
    /// `--publish-to-every-node` directs. `make_attempt` is only called when there are any.
    fn spawn_publish_to_remotes<F, Fut>(
        &self,
        operation: &'static str,
        duty: PublishedDuty,
        make_attempt: impl FnOnce() -> F,
    ) where
        F: Fn(Arc<RemoteBeaconNode>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send,
    {
        let publish_to = self.serving_nodes();

        if publish_to.is_empty() {
            return;
        }

        if should_publish_to_every_node(&self.publish_to_every_node, duty) {
            spawn_broadcast(operation, publish_to, make_attempt());
        } else {
            spawn_publish(operation, publish_to, make_attempt());
        }
    }

    async fn publish_to_remotes<F, Fut>(
        &self,
        operation: &'static str,
        duty: PublishedDuty,
        attempt: F,
    ) -> Result<()>
    where
        F: Fn(Arc<RemoteBeaconNode>) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let publish_to = self.serving_nodes();

        if publish_to.is_empty() {
            return Ok(());
        }

        if should_publish_to_every_node(&self.publish_to_every_node, duty) {
            broadcast(operation, publish_to, attempt).await
        } else {
            publish(operation, publish_to, attempt).await
        }
    }
}

impl<P: Preset, W: Wait + Sync> BeaconNodeApi<P> for BeaconNodes<P, W> {
    /// Combines liveness from every node: a validator seen live by any node is live.
    async fn liveness(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorLivenessResponse>> {
        let mut liveness = validator_indices
            .iter()
            .map(|validator_index| (*validator_index, false))
            .collect::<BTreeMap<_, _>>();

        let mut any_success = false;

        let mut merge = |response: Vec<ValidatorLivenessResponse>| {
            any_success = true;

            for entry in response {
                if entry.is_live
                    && let Some(live) = liveness.get_mut(&entry.index)
                {
                    *live = true;
                }
            }
        };

        if let Some(node) = &self.local_node {
            match node.liveness(epoch, validator_indices).await {
                Ok(response) => merge(response),
                Err(error) => warn_with_peers!(
                    "{node} beacon node failed to report liveness for epoch {epoch}: {error:?}",
                ),
            }
        }

        let responses = join_all(self.remote_nodes.iter().map(|node| async move {
            let result = BeaconNodeApi::<P>::liveness(node.as_ref(), epoch, validator_indices);

            (result.await, node)
        }))
        .await;

        for (result, node) in responses {
            match result {
                Ok(response) => merge(response),
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

    async fn dependent_root(
        &self,
        epoch: Epoch,
        validator_index: Option<ValidatorIndex>,
    ) -> Result<H256> {
        let operation = format!("produce the dependent root of epoch {epoch}");

        // A head event already reported the root, sparing the request it would take to ask.
        if self.local_node.is_none() {
            for node in &self.remote_nodes {
                if let Some(dependent_root) = node.chain_head().dependent_root_for(epoch) {
                    return Ok(dependent_root);
                }
            }
        }

        self.local_then_remotes(
            &operation,
            |node| node.dependent_root(epoch, validator_index),
            |node| BeaconNodeApi::<P>::dependent_root(node, epoch, validator_index),
        )
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
            .local_then_remotes(
                &operation,
                |node| node.attestation_data(slot, committee_index),
                |node| BeaconNodeApi::<P>::attestation_data(node, slot, committee_index),
            )
            .await?;

        match node {
            Some(node) => {
                if !node.health().is_ready() {
                    debug_with_peers!(
                        "attestation data for slot {slot} came from {node}, \
                         which is not fully synced",
                    );
                }

                debug_with_peers!(
                    "{node} beacon node produced attestation data for slot {slot}: {data:?}",
                );
            }
            None => debug_with_peers!(
                "local beacon node produced attestation data for slot {slot}: {data:?}",
            ),
        }

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

        self.local_then_remotes(
            &operation,
            |node| node.aggregate_attestation(data, committee_index),
            |node| BeaconNodeApi::<P>::aggregate_attestation(node, data, committee_index),
        )
        .await
        .map(|(_, aggregate)| aggregate)
    }

    async fn publish_singular_attestations(
        &self,
        attestations: &[OwnAttestation<P>],
    ) -> Result<()> {
        self.spawn_publish_to_remotes("publish attestations", PublishedDuty::Attestations, || {
            let owned = Arc::new(attestations.to_vec());

            move |node: Arc<RemoteBeaconNode>| {
                let attestations = owned.clone_arc();

                async move {
                    BeaconNodeApi::<P>::publish_singular_attestations(node.as_ref(), &attestations)
                        .await
                }
            }
        });

        match &self.local_node {
            Some(node) => node.publish_singular_attestations(attestations).await,
            None => Ok(()),
        }
    }

    async fn publish_aggregates_and_proofs(
        &self,
        aggregates_and_proofs: &[Arc<SignedAggregateAndProof<P>>],
    ) -> Result<()> {
        self.spawn_publish_to_remotes(
            "publish aggregates and proofs",
            PublishedDuty::Aggregates,
            || {
                let owned = Arc::new(aggregates_and_proofs.to_vec());

                move |node: Arc<RemoteBeaconNode>| {
                    let aggregates_and_proofs = owned.clone_arc();

                    async move {
                        BeaconNodeApi::<P>::publish_aggregates_and_proofs(
                            node.as_ref(),
                            &aggregates_and_proofs,
                        )
                        .await
                    }
                }
            },
        );

        match &self.local_node {
            Some(node) => {
                node.publish_aggregates_and_proofs(aggregates_and_proofs)
                    .await
            }
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

    async fn validator_indices(
        &self,
        public_keys: &[PublicKeyBytes],
    ) -> Result<HashMap<PublicKeyBytes, ValidatorIndex>> {
        let operation = "resolve validator indices";
        let mut indices = HashMap::new();
        let mut answered = false;
        let mut last_error = None;

        if let Some(node) = &self.local_node {
            match node.validator_indices(public_keys).await {
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

        // A validator missing from one node's head may be present in another's.
        for node in &self.remote_nodes {
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

    async fn slot_head(&self, slot: Slot) -> Result<Option<SlotHead<P>>> {
        if let Some(node) = &self.local_node {
            return node.slot_head(slot).await;
        }

        for node in &self.remote_nodes {
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
            .local_then_remotes(
                &operation,
                |node| node.sync_committee_duties(epoch, validator_indices),
                |node| BeaconNodeApi::<P>::sync_committee_duties(node, epoch, validator_indices),
            )
            .await?;

        if let Some(node) = node {
            debug_with_peers!(
                "{node} beacon node produced {} sync committee duties for epoch {epoch}",
                duties.len(),
            );
        }

        Ok(duties)
    }

    async fn publish_sync_committee_messages(
        &self,
        messages: &BTreeMap<SubcommitteeIndex, Vec<SyncCommitteeMessage>>,
    ) -> Result<()> {
        self.spawn_publish_to_remotes(
            "publish sync committee messages",
            PublishedDuty::SyncCommitteeMessages,
            || {
                let owned = Arc::new(messages.clone());

                move |node: Arc<RemoteBeaconNode>| {
                    let messages = owned.clone_arc();

                    async move {
                        BeaconNodeApi::<P>::publish_sync_committee_messages(
                            node.as_ref(),
                            &messages,
                        )
                        .await
                    }
                }
            },
        );

        match &self.local_node {
            Some(node) => node.publish_sync_committee_messages(messages).await,
            None => Ok(()),
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

        let operation = "update sync committee subscriptions";
        let subscribe_on = self.serving_nodes();
        let remote_subscriptions = Arc::new(subscriptions.to_vec());

        // Every node is told, as any of them may be asked to contribute later.
        let attempt = move |node: Arc<RemoteBeaconNode>| {
            let subscriptions = remote_subscriptions.clone_arc();

            async move {
                BeaconNodeApi::<P>::subscribe_to_sync_committees(
                    node.as_ref(),
                    current_epoch,
                    &subscriptions,
                )
                .await
            }
        };

        // With a local node this runs on the tick, which must not wait for remote nodes.
        match &self.local_node {
            Some(node) => {
                if !subscribe_on.is_empty() {
                    spawn_broadcast(operation, subscribe_on, attempt);
                }

                node.subscribe_to_sync_committees(current_epoch, subscriptions)
                    .await
            }
            None => broadcast(operation, subscribe_on, attempt).await,
        }
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

        self.local_then_remotes(
            &operation,
            |node| node.sync_committee_contribution(slot, subcommittee_index, beacon_block_root),
            |node| {
                BeaconNodeApi::<P>::sync_committee_contribution(
                    node,
                    slot,
                    subcommittee_index,
                    beacon_block_root,
                )
            },
        )
        .await
        .map(|(_, contribution)| contribution)
    }

    async fn publish_contributions_and_proofs(
        &self,
        contributions_and_proofs: &[SignedContributionAndProof<P>],
    ) -> Result<()> {
        self.spawn_publish_to_remotes(
            "publish contributions and proofs",
            PublishedDuty::SyncCommitteeContributions,
            || {
                let owned = Arc::new(contributions_and_proofs.to_vec());

                move |node: Arc<RemoteBeaconNode>| {
                    let contributions_and_proofs = owned.clone_arc();

                    async move {
                        BeaconNodeApi::<P>::publish_contributions_and_proofs(
                            node.as_ref(),
                            &contributions_and_proofs,
                        )
                        .await
                    }
                }
            },
        );

        match &self.local_node {
            Some(node) => {
                node.publish_contributions_and_proofs(contributions_and_proofs)
                    .await
            }
            None => Ok(()),
        }
    }

    async fn ptc_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<PtcDuties> {
        let operation = format!("produce PTC duties for epoch {epoch}");

        let (node, duties) = self
            .local_then_remotes(
                &operation,
                |node| node.ptc_duties(epoch, validator_indices),
                |node| BeaconNodeApi::<P>::ptc_duties(node, epoch, validator_indices),
            )
            .await?;

        if let Some(node) = node {
            debug_with_peers!(
                "{node} beacon node produced {} PTC duties for epoch {epoch} \
                 under dependent root {:?}",
                duties.duties.len(),
                duties.dependent_root,
            );
        }

        Ok(duties)
    }

    async fn proposer_duties(&self, epoch: Epoch) -> Result<ProposerDuties> {
        let operation = format!("produce proposer duties for epoch {epoch}");

        let (node, duties) = self
            .local_then_remotes(
                &operation,
                |node| node.proposer_duties(epoch),
                |node| BeaconNodeApi::<P>::proposer_duties(node, epoch),
            )
            .await?;

        if let Some(node) = node {
            debug_with_peers!(
                "{node} beacon node produced {} proposer duties for epoch {epoch} \
                 under dependent root {:?}",
                duties.duties.len(),
                duties.dependent_root,
            );
        }

        Ok(duties)
    }

    async fn produce_block(
        &self,
        slot: Slot,
        randao_reveal: SignatureBytes,
        graffiti: Option<H256>,
        builder_boost_factor: Uint256,
    ) -> Result<ProducedBlock<P>> {
        let (producer, block) = self
            .local_then_remotes(
                "produce a block",
                |node| node.produce_block(slot, randao_reveal, graffiti, builder_boost_factor),
                |node| {
                    BeaconNodeApi::<P>::produce_block(
                        node,
                        slot,
                        randao_reveal,
                        graffiti,
                        builder_boost_factor,
                    )
                },
            )
            .await?;

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
        // The built-in node puts the block on gossip itself, which reaches the remote ones too.
        if let Some(node) = &self.local_node
            && self.producer.get().is_none()
        {
            return node.publish_block(signed_block, kzg_proofs, blobs).await;
        }

        self.publish_from_producer("publish a block", |node| async move {
            BeaconNodeApi::<P>::publish_block(node.as_ref(), signed_block, kzg_proofs, blobs).await
        })
        .await
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock<P>,
    ) -> Result<()> {
        if let Some(node) = &self.local_node
            && self.producer.get().is_none()
        {
            return node.publish_blinded_block(signed_block).await;
        }

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
        if let Some(node) = &self.local_node
            && self.producer.get().is_none()
        {
            return node
                .publish_execution_payload_envelope(signed_envelope, kzg_proofs, blobs)
                .await;
        }

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

        // The built-in node settles the slot by itself. A remote node that has seen no block only
        // settles it once every node agrees; a node that has fallen behind never answers with data.
        let mut none_seen = false;
        let mut last_error = None;

        if let Some(node) = &self.local_node {
            match node.payload_attestation_data(slot).await {
                Ok(data) => return Ok(data),
                Err(error) => {
                    warn_with_peers!("{node} beacon node failed to {operation}: {error:?}");
                    last_error = Some(error);
                }
            }
        }

        for node in &self.remote_nodes {
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

        Err(last_error.unwrap_or_else(|| {
            AnyhowError::msg(format!("no beacon node is configured to {operation}"))
        }))
    }

    async fn publish_payload_attestations(
        &self,
        messages: &[Arc<PayloadAttestationMessage>],
    ) -> Result<()> {
        self.spawn_publish_to_remotes(
            "publish payload attestations",
            PublishedDuty::PayloadAttestations,
            || {
                let owned = Arc::new(messages.to_vec());

                move |node: Arc<RemoteBeaconNode>| {
                    let messages = owned.clone_arc();

                    async move {
                        BeaconNodeApi::<P>::publish_payload_attestations(node.as_ref(), &messages)
                            .await
                    }
                }
            },
        );

        match &self.local_node {
            Some(node) => node.publish_payload_attestations(messages).await,
            None => Ok(()),
        }
    }

    async fn prepare_beacon_proposer(&self, proposers: &[ProposerData]) -> Result<()> {
        if proposers.is_empty() {
            return Ok(());
        }

        let prepare_on = self.serving_nodes();

        if !prepare_on.is_empty() {
            let proposers = Arc::new(proposers.to_vec());

            spawn_broadcast("prepare beacon proposers", prepare_on, move |node| {
                let proposers = proposers.clone_arc();

                async move {
                    BeaconNodeApi::<P>::prepare_beacon_proposer(node.as_ref(), &proposers).await
                }
            });
        }

        match &self.local_node {
            Some(node) => node.prepare_beacon_proposer(proposers).await,
            None => Ok(()),
        }
    }

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<()> {
        if registrations.is_empty() {
            return Ok(());
        }

        let register_on = self.serving_nodes();

        if !register_on.is_empty() {
            let registrations = Arc::new(registrations.to_vec());

            spawn_broadcast("register validators", register_on, move |node| {
                let registrations = registrations.clone_arc();

                async move {
                    BeaconNodeApi::<P>::register_validators(node.as_ref(), &registrations).await
                }
            });
        }

        match &self.local_node {
            Some(node) => node.register_validators(registrations).await,
            None => Ok(()),
        }
    }

    async fn publish_proposer_preferences(
        &self,
        preferences: &[Arc<SignedProposerPreferences>],
    ) -> Result<()> {
        let operation = "publish proposer preferences";
        let duty = PublishedDuty::ProposerPreferences;
        let owned = Arc::new(preferences.to_vec());

        let attempt = move |node: Arc<RemoteBeaconNode>| {
            let preferences = owned.clone_arc();

            async move {
                BeaconNodeApi::<P>::publish_proposer_preferences(node.as_ref(), &preferences).await
            }
        };

        // A local node gossips them itself, so the remote outcome only matters without one.
        match &self.local_node {
            Some(node) => {
                self.spawn_publish_to_remotes(operation, duty, || attempt);
                node.publish_proposer_preferences(preferences).await
            }
            None => self.publish_to_remotes(operation, duty, attempt).await,
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
            warn_with_peers!("{error}");
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
            warn_with_peers!("{error}");
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

    Err(last_error.unwrap_or_else(|| {
        AnyhowError::msg(format!("no beacon node is configured to {operation}"))
    }))
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
        ensure!(!fails, AnyhowError::msg("no"));
        Ok(value)
    }
}
