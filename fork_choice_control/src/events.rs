use std::sync::Arc;

use anyhow::Result;
use execution_engine::PayloadAttributes;
use fork_choice_store::{ChainLink, Storage, Store};
use helper_functions::misc;
use logging::warn_with_peers;
use prometheus_metrics::Metrics;
use scc::HashMap as SccHashMap;
use sse::{
    BlobSidecarEvent, BlockEvent, BlockGossipEvent, ChainReorgEvent, DataColumnSidecarEvent, Event,
    ExecutionPayloadAvailableEvent, ExecutionPayloadBidEvent, ExecutionPayloadEvent,
    ExecutionPayloadGossipEvent, FinalizedCheckpointEvent, HeadEvent, HeadV2Event, HeadV2EventData,
    PayloadAttestationEvent, PayloadAttributesEvent, ProposerPreferencesEvent, Topic,
};
use tap::Pipe as _;
use tokio::sync::broadcast::{self, Receiver, Sender};
use types::{
    altair::containers::SignedContributionAndProof,
    capella::containers::SignedBlsToExecutionChange,
    combined::{Attestation, AttesterSlashing, DataColumnSidecar},
    deneb::containers::BlobSidecar,
    electra::containers::SingleAttestation,
    gloas::{
        containers::{
            PayloadAttestationMessage, SignedExecutionPayloadBid, SignedProposerPreferences,
        },
        primitives::{BuilderIndex, PayloadStatus},
    },
    nonstandard::Phase,
    phase0::{
        containers::{Checkpoint, ProposerSlashing, SignedVoluntaryExit},
        primitives::{ExecutionBlockHash, ExecutionBlockNumber, H256, Slot, ValidatorIndex},
    },
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

pub const DEFAULT_MAX_EVENTS: usize = 100;

#[expect(clippy::partial_pub_fields)]
#[derive(Clone, Debug)]
pub struct EventChannels<P: Preset> {
    pub attestations: Sender<Event<P>>,
    pub attester_slashings: Sender<Event<P>>,
    pub blob_sidecars: Sender<Event<P>>,
    pub blocks: Sender<Event<P>>,
    pub blocks_gossip: Sender<Event<P>>,
    pub bls_to_execution_changes: Sender<Event<P>>,
    pub chain_reorgs: Sender<Event<P>>,
    pub contribution_and_proofs: Sender<Event<P>>,
    pub data_column_sidecars: Sender<Event<P>>,
    pub execution_payloads: Sender<Event<P>>,
    pub execution_payload_available: Sender<Event<P>>,
    pub execution_payload_bids: Sender<Event<P>>,
    pub execution_payloads_gossip: Sender<Event<P>>,
    pub finalized_checkpoints: Sender<Event<P>>,
    pub heads: Sender<Event<P>>,
    pub heads_v2: Sender<Event<P>>,
    pub payload_attestations: Sender<Event<P>>,
    pub payload_attributes: Sender<Event<P>>,
    pub proposer_preferences: Sender<Event<P>>,
    pub proposer_slashings: Sender<Event<P>>,
    pub single_attestations: Sender<Event<P>>,
    pub voluntary_exits: Sender<Event<P>>,
    // See <https://github.com/grandinetech/grandine/issues/254> for rationale
    optimistic_reorgs: SccHashMap<(H256, Slot), ChainReorgEvent>,
}

impl<P: Preset> Default for EventChannels<P> {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_EVENTS)
    }
}

impl<P: Preset> EventChannels<P> {
    #[must_use]
    pub fn new(max_events: usize) -> Self {
        Self {
            attestations: broadcast::channel(max_events).0,
            attester_slashings: broadcast::channel(max_events).0,
            blob_sidecars: broadcast::channel(max_events).0,
            blocks: broadcast::channel(max_events).0,
            blocks_gossip: broadcast::channel(max_events).0,
            bls_to_execution_changes: broadcast::channel(max_events).0,
            chain_reorgs: broadcast::channel(max_events).0,
            contribution_and_proofs: broadcast::channel(max_events).0,
            data_column_sidecars: broadcast::channel(max_events).0,
            execution_payloads: broadcast::channel(max_events).0,
            execution_payload_available: broadcast::channel(max_events).0,
            execution_payload_bids: broadcast::channel(max_events).0,
            execution_payloads_gossip: broadcast::channel(max_events).0,
            finalized_checkpoints: broadcast::channel(max_events).0,
            heads: broadcast::channel(max_events).0,
            heads_v2: broadcast::channel(max_events).0,
            payload_attestations: broadcast::channel(max_events).0,
            payload_attributes: broadcast::channel(max_events).0,
            proposer_preferences: broadcast::channel(max_events).0,
            proposer_slashings: broadcast::channel(max_events).0,
            single_attestations: broadcast::channel(max_events).0,
            voluntary_exits: broadcast::channel(max_events).0,
            optimistic_reorgs: SccHashMap::default(),
        }
    }

    #[must_use]
    pub fn receiver_for(&self, topic: Topic) -> Receiver<Event<P>> {
        match topic {
            Topic::Attestation => &self.attestations,
            Topic::AttesterSlashing => &self.attester_slashings,
            Topic::BlobSidecar => &self.blob_sidecars,
            Topic::Block => &self.blocks,
            Topic::BlockGossip => &self.blocks_gossip,
            Topic::BlsToExecutionChange => &self.bls_to_execution_changes,
            Topic::ChainReorg => &self.chain_reorgs,
            Topic::ContributionAndProof => &self.contribution_and_proofs,
            Topic::DataColumnSidecar => &self.data_column_sidecars,
            Topic::ExecutionPayload => &self.execution_payloads,
            Topic::ExecutionPayloadAvailable => &self.execution_payload_available,
            Topic::ExecutionPayloadBid => &self.execution_payload_bids,
            Topic::ExecutionPayloadGossip => &self.execution_payloads_gossip,
            Topic::FinalizedCheckpoint => &self.finalized_checkpoints,
            Topic::Head => &self.heads,
            Topic::HeadV2 => &self.heads_v2,
            Topic::PayloadAttestationMessage => &self.payload_attestations,
            Topic::PayloadAttributes => &self.payload_attributes,
            Topic::ProposerPreferences => &self.proposer_preferences,
            Topic::ProposerSlashing => &self.proposer_slashings,
            Topic::SingleAttestation => &self.single_attestations,
            Topic::VoluntaryExit => &self.voluntary_exits,
        }
        .subscribe()
    }

    pub fn send_attestation_event(&self, attestation: Arc<Attestation<P>>) {
        if let Err(error) = self.send_attestation_event_internal(attestation) {
            warn_with_peers!("unable to send attestation event: {error}");
        }
    }

    pub fn send_attester_slashing_event(&self, attester_slashing: Box<AttesterSlashing<P>>) {
        if let Err(error) = self.send_attester_slashing_event_internal(attester_slashing) {
            warn_with_peers!("unable to send attester slashing event: {error}");
        }
    }

    pub fn send_blob_sidecar_event(&self, block_root: H256, blob_sidecar: &BlobSidecar<P>) {
        if let Err(error) = self.send_blob_sidecar_event_internal(block_root, blob_sidecar) {
            warn_with_peers!("unable to send blob sidecar event: {error}");
        }
    }

    pub fn send_block_event(&self, slot: Slot, block_root: H256, execution_optimistic: bool) {
        if let Err(error) = self.send_block_event_internal(slot, block_root, execution_optimistic) {
            warn_with_peers!("unable to send block event: {error}");
        }
    }

    pub fn send_block_gossip_event(&self, slot: Slot, block_root: H256) {
        if let Err(error) = self.send_block_gossip_event_internal(slot, block_root) {
            warn_with_peers!("unable to send block gossip event: {error}");
        }
    }

    pub fn send_bls_to_execution_change_event(
        &self,
        signed_bls_to_execution_change: SignedBlsToExecutionChange,
    ) {
        if let Err(error) =
            self.send_bls_to_execution_change_event_internal(signed_bls_to_execution_change)
        {
            warn_with_peers!("unable to send bls to execution change event: {error}");
        }
    }

    pub fn send_chain_reorg_event<S: Storage<P>>(
        &self,
        store: &Store<P, S>,
        new_head: &ChainLink<P>,
        old_head: &ChainLink<P>,
    ) {
        let chain_reorg_event = new_chain_reorg_event(store, old_head);

        if new_head.is_valid() {
            if let Err(error) = self.send_chain_reorg_event_internal(chain_reorg_event) {
                warn_with_peers!("unable to send chain reorg event: {error}");
            }

            return;
        }

        self.optimistic_reorgs
            .upsert_sync((new_head.block_root, new_head.slot()), chain_reorg_event);
    }

    pub fn send_contribution_and_proof_event(
        &self,
        signed_contribution_and_proof: SignedContributionAndProof<P>,
    ) {
        if let Err(error) =
            self.send_contribution_and_proof_event_internal(signed_contribution_and_proof)
        {
            warn_with_peers!("unable to send contribution and proof event: {error}");
        }
    }

    pub fn send_data_column_sidecar_event(
        &self,
        block_root: H256,
        data_column_sidecar: &DataColumnSidecar<P>,
    ) {
        if let Err(error) =
            self.send_data_column_sidecar_event_internal(block_root, data_column_sidecar)
        {
            warn_with_peers!("unable to send data column sidecar event: {error}");
        }
    }

    pub fn send_execution_payload_event(
        &self,
        slot: Slot,
        builder_index: BuilderIndex,
        block_hash: ExecutionBlockHash,
        block_root: H256,
        execution_optimistic: bool,
    ) {
        if let Err(error) = self.send_execution_payload_event_internal(
            slot,
            builder_index,
            block_hash,
            block_root,
            execution_optimistic,
        ) {
            warn_with_peers!("unable to send execution payload event: {error}");
        }
    }

    pub fn send_execution_payload_gossip_event(
        &self,
        slot: Slot,
        builder_index: BuilderIndex,
        block_hash: ExecutionBlockHash,
        block_root: H256,
    ) {
        if let Err(error) = self.send_execution_payload_gossip_event_internal(
            slot,
            builder_index,
            block_hash,
            block_root,
        ) {
            warn_with_peers!("unable to send execution payload gossip event: {error}");
        }
    }

    pub fn send_execution_payload_available_event(&self, slot: Slot, block_root: H256) {
        if let Err(error) = self.send_execution_payload_available_event_internal(slot, block_root) {
            warn_with_peers!("unable to send execution payload available event: {error}");
        }
    }

    pub fn send_execution_payload_bid_event(
        &self,
        phase: Phase,
        payload_bid: Arc<SignedExecutionPayloadBid<P>>,
    ) {
        if let Err(error) = self.send_execution_payload_bid_event_internal(phase, payload_bid) {
            warn_with_peers!("unable to send execution payload bid event: {error}");
        }
    }

    pub fn send_finalized_checkpoint_event(
        &self,
        block_root: H256,
        finalized_checkpoint: Checkpoint,
        execution_optimistic: bool,
    ) {
        if let Err(error) = self.send_finalized_checkpoint_event_internal(
            block_root,
            finalized_checkpoint,
            execution_optimistic,
        ) {
            warn_with_peers!("unable to send finalized checkpoint event: {error}");
        }
    }

    pub fn send_head_event(&self, head: &ChainLink<P>, dependent_roots: DependentRootsBundle) {
        if let Err(error) = self.send_head_event_internal(head, dependent_roots) {
            warn_with_peers!("unable to send head event: {error}");
        }

        if head.is_valid()
            && let Some((_, mut chain_reorg_event)) = self
                .optimistic_reorgs
                .remove_sync(&(head.block_root, head.slot()))
        {
            chain_reorg_event.execution_optimistic = head.is_optimistic();

            if let Err(error) = self.send_chain_reorg_event_internal(chain_reorg_event) {
                warn_with_peers!("unable to send chain reorg event: {error}");
            }
        }
    }

    pub fn send_head_v2_event(
        &self,
        head: &ChainLink<P>,
        payload_status: PayloadStatus,
        dependent_roots: DependentRootsBundle,
    ) {
        if let Err(error) = self.send_head_v2_event_internal(head, payload_status, dependent_roots)
        {
            warn_with_peers!("unable to send head_v2 event: {error}");
        }
    }

    pub fn send_payload_attestation_event(
        &self,
        phase: Phase,
        payload_attestation: &Arc<PayloadAttestationMessage>,
    ) {
        if let Err(error) = self.send_payload_attestation_event_internal(phase, payload_attestation)
        {
            warn_with_peers!("unable to send payload attestation event: {error}");
        }
    }

    #[expect(clippy::too_many_arguments)]
    pub fn send_payload_attributes_event(
        &self,
        phase: Phase,
        proposal_slot: Slot,
        proposer_index: ValidatorIndex,
        parent_block_root: H256,
        payload_attributes: &PayloadAttributes<P>,
        parent_block_number: Option<ExecutionBlockNumber>,
        parent_block_hash: ExecutionBlockHash,
    ) {
        if let Err(error) = self.send_payload_attributes_event_internal(
            phase,
            proposal_slot,
            proposer_index,
            parent_block_root,
            payload_attributes,
            parent_block_number,
            parent_block_hash,
        ) {
            warn_with_peers!("unable to send payload attributes event: {error}");
        }
    }

    pub fn send_proposer_preferences_event(
        &self,
        phase: Phase,
        signed_preferences: Arc<SignedProposerPreferences>,
    ) {
        if let Err(error) = self.send_proposer_preferences_event_internal(phase, signed_preferences)
        {
            warn_with_peers!("unable to send proposer preferences event: {error}");
        }
    }

    pub fn send_proposer_slashing_event(&self, proposer_slashing: ProposerSlashing) {
        if let Err(error) = self.send_proposer_slashing_event_internal(proposer_slashing) {
            warn_with_peers!("unable to send proposer slashing event: {error}");
        }
    }

    pub fn send_single_attestation_event(&self, single_attestation: SingleAttestation) {
        if let Err(error) = self.send_single_attestation_event_internal(single_attestation) {
            warn_with_peers!("unable to send single attestation event: {error}");
        }
    }

    pub fn send_voluntary_exit_event(&self, voluntary_exit: SignedVoluntaryExit) {
        if let Err(error) = self.send_voluntary_exit_event_internal(voluntary_exit) {
            warn_with_peers!("unable to send voluntary exit event: {error}");
        }
    }

    pub fn prune_after_finalization(&self, finalized_slot: Slot) {
        self.optimistic_reorgs
            .retain_sync(|(_, slot), _| *slot > finalized_slot);
    }

    pub fn track_collection_metrics(&self, metrics: &Arc<Metrics>) {
        let type_name = tynm::type_name::<Self>();

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "optimistic_reorgs",
            self.optimistic_reorgs.len(),
        );
    }

    fn send_attestation_event_internal(&self, attestation: Arc<Attestation<P>>) -> Result<()> {
        if self.attestations.receiver_count() > 0 {
            let event = Event::Attestation(attestation);
            self.attestations.send(event)?;
        }

        Ok(())
    }

    fn send_attester_slashing_event_internal(
        &self,
        attester_slashing: Box<AttesterSlashing<P>>,
    ) -> Result<()> {
        if self.attester_slashings.receiver_count() > 0 {
            let event = Event::AttesterSlashing(attester_slashing);
            self.attester_slashings.send(event)?;
        }

        Ok(())
    }

    fn send_blob_sidecar_event_internal(
        &self,
        block_root: H256,
        blob_sidecar: &BlobSidecar<P>,
    ) -> Result<()> {
        if self.blob_sidecars.receiver_count() > 0 {
            let blob_sidecar_event = BlobSidecarEvent::new(block_root, blob_sidecar);
            let event = Event::BlobSidecar(blob_sidecar_event);
            self.blob_sidecars.send(event)?;
        }

        Ok(())
    }

    fn send_block_event_internal(
        &self,
        slot: Slot,
        block_root: H256,
        execution_optimistic: bool,
    ) -> Result<()> {
        if self.blocks.receiver_count() > 0 {
            let block_event = BlockEvent {
                slot,
                block: block_root,
                execution_optimistic,
            };

            let event = Event::Block(block_event);
            self.blocks.send(event)?;
        }

        Ok(())
    }

    fn send_block_gossip_event_internal(&self, slot: Slot, block_root: H256) -> Result<()> {
        if self.blocks_gossip.receiver_count() > 0 {
            let block_gossip_event = BlockGossipEvent {
                slot,
                block: block_root,
            };

            let event = Event::BlockGossip(block_gossip_event);
            self.blocks_gossip.send(event)?;
        }

        Ok(())
    }

    fn send_bls_to_execution_change_event_internal(
        &self,
        signed_bls_to_execution_change: SignedBlsToExecutionChange,
    ) -> Result<()> {
        if self.bls_to_execution_changes.receiver_count() > 0 {
            let event = Event::BlsToExecutionChange(Box::new(signed_bls_to_execution_change));
            self.bls_to_execution_changes.send(event)?;
        }

        Ok(())
    }

    fn send_chain_reorg_event_internal(&self, chain_reorg_event: ChainReorgEvent) -> Result<()> {
        if self.chain_reorgs.receiver_count() > 0 {
            let event = Event::ChainReorg(chain_reorg_event);
            self.chain_reorgs.send(event)?;
        }

        Ok(())
    }

    fn send_contribution_and_proof_event_internal(
        &self,
        signed_contribution_and_proof: SignedContributionAndProof<P>,
    ) -> Result<()> {
        if self.contribution_and_proofs.receiver_count() > 0 {
            let event = Event::ContributionAndProof(Box::new(signed_contribution_and_proof));
            self.contribution_and_proofs.send(event)?;
        }

        Ok(())
    }

    fn send_data_column_sidecar_event_internal(
        &self,
        block_root: H256,
        data_column_sidecar: &DataColumnSidecar<P>,
    ) -> Result<()> {
        if self.data_column_sidecars.receiver_count() > 0 {
            let data_column_sidecar_event =
                DataColumnSidecarEvent::new(block_root, data_column_sidecar);

            let event = Event::DataColumnSidecar(data_column_sidecar_event);
            self.data_column_sidecars.send(event)?;
        }

        Ok(())
    }

    fn send_execution_payload_event_internal(
        &self,
        slot: Slot,
        builder_index: BuilderIndex,
        block_hash: ExecutionBlockHash,
        block_root: H256,
        execution_optimistic: bool,
    ) -> Result<()> {
        if self.execution_payloads.receiver_count() > 0 {
            let event = Event::ExecutionPayload(ExecutionPayloadEvent {
                slot,
                builder_index,
                block_hash,
                block_root,
                execution_optimistic,
            });
            self.execution_payloads.send(event)?;
        }

        Ok(())
    }

    fn send_execution_payload_gossip_event_internal(
        &self,
        slot: Slot,
        builder_index: BuilderIndex,
        block_hash: ExecutionBlockHash,
        block_root: H256,
    ) -> Result<()> {
        if self.execution_payloads_gossip.receiver_count() > 0 {
            let event = Event::ExecutionPayloadGossip(ExecutionPayloadGossipEvent {
                slot,
                builder_index,
                block_hash,
                block_root,
            });
            self.execution_payloads_gossip.send(event)?;
        }

        Ok(())
    }

    fn send_execution_payload_available_event_internal(
        &self,
        slot: Slot,
        block_root: H256,
    ) -> Result<()> {
        if self.execution_payload_available.receiver_count() > 0 {
            let event = Event::ExecutionPayloadAvailable(ExecutionPayloadAvailableEvent {
                slot,
                block_root,
            });
            self.execution_payload_available.send(event)?;
        }

        Ok(())
    }

    fn send_execution_payload_bid_event_internal(
        &self,
        phase: Phase,
        payload_bid: Arc<SignedExecutionPayloadBid<P>>,
    ) -> Result<()> {
        if self.execution_payload_bids.receiver_count() > 0 {
            let event = Event::ExecutionPayloadBid(ExecutionPayloadBidEvent {
                version: phase,
                data: payload_bid,
            });
            self.execution_payload_bids.send(event)?;
        }

        Ok(())
    }

    fn send_proposer_preferences_event_internal(
        &self,
        phase: Phase,
        signed_preferences: Arc<SignedProposerPreferences>,
    ) -> Result<()> {
        if self.proposer_preferences.receiver_count() > 0 {
            let event = Event::ProposerPreferences(ProposerPreferencesEvent {
                version: phase,
                data: signed_preferences,
            });
            self.proposer_preferences.send(event)?;
        }

        Ok(())
    }

    fn send_finalized_checkpoint_event_internal(
        &self,
        block_root: H256,
        finalized_checkpoint: Checkpoint,
        execution_optimistic: bool,
    ) -> Result<()> {
        if self.finalized_checkpoints.receiver_count() > 0 {
            let Checkpoint { epoch, root } = finalized_checkpoint;

            let finalized_checkpoint_event = FinalizedCheckpointEvent {
                block: block_root,
                state: root,
                epoch,
                execution_optimistic,
            };

            let event = Event::FinalizedCheckpoint(finalized_checkpoint_event);
            self.finalized_checkpoints.send(event)?;
        }

        Ok(())
    }

    fn send_head_event_internal(
        &self,
        head: &ChainLink<P>,
        dependent_roots: DependentRootsBundle,
    ) -> Result<()> {
        if self.heads.receiver_count() > 0 {
            let head_event = new_head_event(head, dependent_roots);
            let event = Event::Head(head_event);
            self.heads.send(event)?;
        }

        Ok(())
    }

    fn send_head_v2_event_internal(
        &self,
        head: &ChainLink<P>,
        payload_status: PayloadStatus,
        dependent_roots: DependentRootsBundle,
    ) -> Result<()> {
        if self.heads_v2.receiver_count() > 0 {
            let head_v2_event = new_head_v2_event(head, payload_status, dependent_roots);
            let event = Event::HeadV2(head_v2_event);
            self.heads_v2.send(event)?;
        }

        Ok(())
    }

    fn send_payload_attestation_event_internal(
        &self,
        phase: Phase,
        payload_attestation: &Arc<PayloadAttestationMessage>,
    ) -> Result<()> {
        if self.payload_attestations.receiver_count() > 0 {
            let payload_attestation_event =
                PayloadAttestationEvent::new(phase, payload_attestation);
            let event = Event::PayloadAttestation(payload_attestation_event);
            self.payload_attestations.send(event)?;
        }

        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    fn send_payload_attributes_event_internal(
        &self,
        phase: Phase,
        proposal_slot: Slot,
        proposer_index: ValidatorIndex,
        parent_block_root: H256,
        payload_attributes: &PayloadAttributes<P>,
        parent_block_number: Option<ExecutionBlockNumber>,
        parent_block_hash: ExecutionBlockHash,
    ) -> Result<()> {
        if self.payload_attributes.receiver_count() > 0 {
            let payload_attributes_event = PayloadAttributesEvent::new(
                proposal_slot,
                parent_block_root,
                parent_block_number,
                parent_block_hash,
                proposer_index,
                payload_attributes.clone(),
            );

            debug_assert_eq!(phase, payload_attributes_event.version());

            let event = Event::PayloadAttributes(payload_attributes_event);
            self.payload_attributes.send(event)?;
        }

        Ok(())
    }

    fn send_proposer_slashing_event_internal(
        &self,
        proposer_slashing: ProposerSlashing,
    ) -> Result<()> {
        if self.proposer_slashings.receiver_count() > 0 {
            let event = Event::ProposerSlashing(Box::new(proposer_slashing));
            self.proposer_slashings.send(event)?;
        }

        Ok(())
    }

    fn send_single_attestation_event_internal(
        &self,
        single_attestation: SingleAttestation,
    ) -> Result<()> {
        if self.single_attestations.receiver_count() > 0 {
            let event = Event::SingleAttestation(single_attestation);
            self.single_attestations.send(event)?;
        }

        Ok(())
    }

    fn send_voluntary_exit_event_internal(
        &self,
        voluntary_exit: SignedVoluntaryExit,
    ) -> Result<()> {
        if self.voluntary_exits.receiver_count() > 0 {
            let event = Event::VoluntaryExit(Box::new(voluntary_exit));
            self.voluntary_exits.send(event)?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct DependentRootsBundle {
    pub current_duty_dependent_root: H256,
    pub previous_duty_dependent_root: H256,
}

// Fork-choice-coupled constructors for SSE.
// They live here rather than in `sse` crate because they read fork-choice state
// (`ChainLink`, `Store`), which we want the `sse` crate to be used in `builder` client.

// The [Eth Beacon Node API specification] does not make it clear how `slot`, `depth`, and
// `epoch` should be computed. We try to match the behavior of Lighthouse.
//
// [Eth Beacon Node API specification]: https://ethereum.github.io/beacon-APIs/
fn new_chain_reorg_event<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
    old_head: &ChainLink<P>,
) -> ChainReorgEvent {
    let new_head = store.head();
    let old_slot = old_head.slot();
    let new_slot = new_head.slot();

    let depth = store
        .common_ancestor(old_head.block_root, new_head.block_root)
        .map(ChainLink::slot)
        .unwrap_or_else(|| {
            // A reorganization may be triggered by an alternate chain being finalized.
            // The old block will no longer be present in `store` if that happens.
            // Default to the old finalized slot like Lighthouse does.
            // A proper solution may require significant changes to `Mutator`.
            old_head
                .finalized_checkpoint
                .epoch
                .pipe(misc::compute_start_slot_at_epoch::<P>)
        })
        .abs_diff(old_slot);

    ChainReorgEvent {
        slot: new_slot,
        depth,
        old_head_block: old_head.block_root,
        new_head_block: new_head.block_root,
        old_head_state: old_head.block.message().state_root(),
        new_head_state: new_head.block.message().state_root(),
        epoch: misc::compute_epoch_at_slot::<P>(new_slot),
        execution_optimistic: new_head.is_optimistic(),
    }
}

fn new_head_event<P: Preset>(
    head: &ChainLink<P>,
    dependent_roots_bundle: DependentRootsBundle,
) -> HeadEvent {
    let DependentRootsBundle {
        current_duty_dependent_root,
        previous_duty_dependent_root,
    } = dependent_roots_bundle;

    let slot = head.slot();

    HeadEvent {
        slot,
        block: head.block_root,
        state: head.block.message().state_root(),
        epoch_transition: misc::is_epoch_start::<P>(slot),
        previous_duty_dependent_root,
        current_duty_dependent_root,
        execution_optimistic: head.is_optimistic(),
    }
}

fn new_head_v2_event<P: Preset>(
    head: &ChainLink<P>,
    payload_status: PayloadStatus,
    dependent_roots_bundle: DependentRootsBundle,
) -> HeadV2Event {
    let DependentRootsBundle {
        current_duty_dependent_root,
        previous_duty_dependent_root,
    } = dependent_roots_bundle;

    let slot = head.slot();

    HeadV2Event {
        version: head.block.phase(),
        data: HeadV2EventData {
            slot,
            block: head.block_root,
            state: head.block.message().state_root(),
            payload_status: payload_status.into(),
            epoch_transition: misc::is_epoch_start::<P>(slot),
            // #590 names dependent roots by the epoch whose duties the root
            // determines, inverting the old duty-period labels. The values are
            // unchanged, so this apparent swap is intentional, not a bug.
            current_epoch_dependent_root: previous_duty_dependent_root,
            next_epoch_dependent_root: current_duty_dependent_root,
            execution_optimistic: head.is_optimistic(),
        },
    }
}
