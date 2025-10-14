use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use execution_engine::{
    PayloadAttributes, PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3, WithdrawalV1,
};
use fork_choice_store::{ChainLink, Storage, Store};
use helper_functions::misc;
use logging::warn_with_peers;
use prometheus_metrics::Metrics;
use serde::Serialize;
use serde_with::DeserializeFromStr;
use ssz::ContiguousList;
use strum::{AsRefStr, EnumString};
use tap::Pipe as _;
use tokio::sync::broadcast::{self, Receiver, Sender};
use types::{
    altair::containers::SignedContributionAndProof,
    capella::{containers::SignedBlsToExecutionChange, primitives::WithdrawalIndex},
    combined::{Attestation, AttesterSlashing},
    deneb::{
        containers::BlobSidecar,
        primitives::{BlobIndex, KzgCommitment, VersionedHash},
    },
    fulu::{containers::DataColumnSidecar, primitives::ColumnIndex},
    nonstandard::Phase,
    phase0::{
        containers::{Checkpoint, ProposerSlashing, SignedVoluntaryExit},
        primitives::{
            Epoch, ExecutionAddress, ExecutionBlockHash, ExecutionBlockNumber, Gwei, Slot,
            UnixSeconds, ValidatorIndex, H256,
        },
    },
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

pub const DEFAULT_MAX_EVENTS: usize = 100;

#[derive(Clone, Copy, AsRefStr, EnumString, DeserializeFromStr)]
#[strum(serialize_all = "snake_case")]
pub enum Topic {
    Attestation,
    AttesterSlashing,
    BlobSidecar,
    Block,
    BlsToExecutionChange,
    ChainReorg,
    ContributionAndProof,
    DataColumnSidecar,
    FinalizedCheckpoint,
    Head,
    PayloadAttributes,
    ProposerSlashing,
    VoluntaryExit,
}

#[derive(Clone, Debug)]
pub enum Event<P: Preset> {
    Attestation(Arc<Attestation<P>>),
    AttesterSlashing(Box<AttesterSlashing<P>>),
    BlobSidecar(BlobSidecarEvent),
    Block(BlockEvent),
    BlsToExecutionChange(Box<SignedBlsToExecutionChange>),
    ChainReorg(ChainReorgEvent),
    ContributionAndProof(Box<SignedContributionAndProof<P>>),
    DataColumnSidecar(DataColumnSidecarEvent<P>),
    FinalizedCheckpoint(FinalizedCheckpointEvent),
    Head(HeadEvent),
    PayloadAttributes(PayloadAttributesEvent),
    ProposerSlashing(Box<ProposerSlashing>),
    VoluntaryExit(Box<SignedVoluntaryExit>),
}

impl<P: Preset> Event<P> {
    #[must_use]
    pub const fn topic(&self) -> Topic {
        match self {
            Self::Attestation(_) => Topic::Attestation,
            Self::AttesterSlashing(_) => Topic::AttesterSlashing,
            Self::BlobSidecar(_) => Topic::BlobSidecar,
            Self::Block(_) => Topic::Block,
            Self::BlsToExecutionChange(_) => Topic::BlsToExecutionChange,
            Self::ChainReorg(_) => Topic::ChainReorg,
            Self::ContributionAndProof(_) => Topic::ContributionAndProof,
            Self::DataColumnSidecar(_) => Topic::DataColumnSidecar,
            Self::FinalizedCheckpoint(_) => Topic::FinalizedCheckpoint,
            Self::Head(_) => Topic::Head,
            Self::PayloadAttributes(_) => Topic::PayloadAttributes,
            Self::ProposerSlashing(_) => Topic::ProposerSlashing,
            Self::VoluntaryExit(_) => Topic::VoluntaryExit,
        }
    }
}

#[expect(clippy::partial_pub_fields)]
#[derive(Clone, Debug)]
pub struct EventChannels<P: Preset> {
    pub attestations: Sender<Event<P>>,
    pub attester_slashings: Sender<Event<P>>,
    pub blob_sidecars: Sender<Event<P>>,
    pub blocks: Sender<Event<P>>,
    pub bls_to_execution_changes: Sender<Event<P>>,
    pub chain_reorgs: Sender<Event<P>>,
    pub contribution_and_proofs: Sender<Event<P>>,
    pub data_column_sidecars: Sender<Event<P>>,
    pub finalized_checkpoints: Sender<Event<P>>,
    pub heads: Sender<Event<P>>,
    pub payload_attributes: Sender<Event<P>>,
    pub proposer_slashings: Sender<Event<P>>,
    pub voluntary_exits: Sender<Event<P>>,
    // See <https://github.com/grandinetech/grandine/issues/254> for rationale
    optimistic_reorgs: DashMap<(H256, Slot), ChainReorgEvent>,
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
            bls_to_execution_changes: broadcast::channel(max_events).0,
            chain_reorgs: broadcast::channel(max_events).0,
            contribution_and_proofs: broadcast::channel(max_events).0,
            data_column_sidecars: broadcast::channel(max_events).0,
            finalized_checkpoints: broadcast::channel(max_events).0,
            heads: broadcast::channel(max_events).0,
            payload_attributes: broadcast::channel(max_events).0,
            proposer_slashings: broadcast::channel(max_events).0,
            voluntary_exits: broadcast::channel(max_events).0,
            optimistic_reorgs: DashMap::default(),
        }
    }

    #[must_use]
    pub fn receiver_for(&self, topic: Topic) -> Receiver<Event<P>> {
        match topic {
            Topic::Attestation => &self.attestations,
            Topic::AttesterSlashing => &self.attester_slashings,
            Topic::BlobSidecar => &self.blob_sidecars,
            Topic::Block => &self.blocks,
            Topic::BlsToExecutionChange => &self.bls_to_execution_changes,
            Topic::ChainReorg => &self.chain_reorgs,
            Topic::ContributionAndProof => &self.contribution_and_proofs,
            Topic::DataColumnSidecar => &self.data_column_sidecars,
            Topic::FinalizedCheckpoint => &self.finalized_checkpoints,
            Topic::Head => &self.heads,
            Topic::PayloadAttributes => &self.payload_attributes,
            Topic::ProposerSlashing => &self.proposer_slashings,
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
        let chain_reorg_event = ChainReorgEvent::new(store, old_head);

        if new_head.is_valid() {
            if let Err(error) = self.send_chain_reorg_event_internal(chain_reorg_event) {
                warn_with_peers!("unable to send chain reorg event: {error}");
            }

            return;
        }

        self.optimistic_reorgs
            .insert((new_head.block_root, new_head.slot()), chain_reorg_event);
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

    pub fn send_head_event(
        &self,
        head: &ChainLink<P>,
        calculate_dependent_roots: impl FnOnce(&ChainLink<P>) -> Result<DependentRootsBundle>,
    ) {
        if let Err(error) = self.send_head_event_internal(head, calculate_dependent_roots) {
            warn_with_peers!("unable to send head event: {error}");
        }

        if head.is_valid() {
            if let Some((_, mut chain_reorg_event)) = self
                .optimistic_reorgs
                .remove(&(head.block_root, head.slot()))
            {
                chain_reorg_event.execution_optimistic = head.is_optimistic();

                if let Err(error) = self.send_chain_reorg_event_internal(chain_reorg_event) {
                    warn_with_peers!("unable to send chain reorg event: {error}");
                }
            }
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
        parent_block_number: ExecutionBlockNumber,
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

    pub fn send_proposer_slashing_event(&self, proposer_slashing: ProposerSlashing) {
        if let Err(error) = self.send_proposer_slashing_event_internal(proposer_slashing) {
            warn_with_peers!("unable to send proposer slashing event: {error}");
        }
    }

    pub fn send_voluntary_exit_event(&self, voluntary_exit: SignedVoluntaryExit) {
        if let Err(error) = self.send_voluntary_exit_event_internal(voluntary_exit) {
            warn_with_peers!("unable to send voluntary exit event: {error}");
        }
    }

    pub fn prune_after_finalization(&self, finalized_slot: Slot) {
        self.optimistic_reorgs
            .retain(|(_, slot), _| *slot > finalized_slot);
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
        calculate_dependent_roots: impl FnOnce(&ChainLink<P>) -> Result<DependentRootsBundle>,
    ) -> Result<()> {
        if self.heads.receiver_count() > 0 {
            let head_event = HeadEvent::new(head, calculate_dependent_roots(head)?);
            let event = Event::Head(head_event);
            self.heads.send(event)?;
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
        parent_block_number: ExecutionBlockNumber,
        parent_block_hash: ExecutionBlockHash,
    ) -> Result<()> {
        if self.payload_attributes.receiver_count() > 0 {
            let payload_attributes_event = PayloadAttributesEvent {
                version: phase,
                data: PayloadAttributesEventData {
                    proposal_slot,
                    proposer_index,
                    parent_block_root,
                    payload_attributes: payload_attributes.clone().into(),
                    parent_block_number,
                    parent_block_hash,
                },
            };

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

#[derive(Clone, Copy, Debug, Serialize)]
pub struct BlobSidecarEvent {
    pub block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub index: BlobIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub kzg_commitment: KzgCommitment,
    pub versioned_hash: VersionedHash,
}

impl BlobSidecarEvent {
    fn new<P: Preset>(block_root: H256, blob_sidecar: &BlobSidecar<P>) -> Self {
        let kzg_commitment = blob_sidecar.kzg_commitment;

        Self {
            block_root,
            index: blob_sidecar.index,
            slot: blob_sidecar.slot(),
            kzg_commitment,
            versioned_hash: misc::kzg_commitment_to_versioned_hash(kzg_commitment),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct BlockEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub block: H256,
    pub execution_optimistic: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DataColumnSidecarEvent<P: Preset> {
    pub block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub index: ColumnIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub kzg_commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
}

impl<P: Preset> DataColumnSidecarEvent<P> {
    fn new(block_root: H256, data_column_sidecar: &DataColumnSidecar<P>) -> Self {
        Self {
            block_root,
            index: data_column_sidecar.index,
            slot: data_column_sidecar.slot(),
            kzg_commitments: data_column_sidecar.kzg_commitments.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ChainReorgEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub depth: u64,
    pub old_head_block: H256,
    pub new_head_block: H256,
    pub old_head_state: H256,
    pub new_head_state: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
    pub execution_optimistic: bool,
}

impl ChainReorgEvent {
    // The [Eth Beacon Node API specification] does not make it clear how `slot`, `depth`, and
    // `epoch` should be computed. We try to match the behavior of Lighthouse.
    //
    // [Eth Beacon Node API specification]: https://ethereum.github.io/beacon-APIs/
    #[must_use]
    fn new<P: Preset, S: Storage<P>>(store: &Store<P, S>, old_head: &ChainLink<P>) -> Self {
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

        Self {
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
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct FinalizedCheckpointEvent {
    pub block: H256,
    pub state: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
    pub execution_optimistic: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct HeadEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub block: H256,
    pub state: H256,
    pub epoch_transition: bool,
    pub previous_duty_dependent_root: H256,
    pub current_duty_dependent_root: H256,
    pub execution_optimistic: bool,
}

impl HeadEvent {
    fn new<P: Preset>(head: &ChainLink<P>, dependent_roots_bundle: DependentRootsBundle) -> Self {
        let DependentRootsBundle {
            current_duty_dependent_root,
            previous_duty_dependent_root,
        } = dependent_roots_bundle;

        let slot = head.slot();

        Self {
            slot,
            block: head.block_root,
            state: head.block.message().state_root(),
            epoch_transition: misc::is_epoch_start::<P>(slot),
            previous_duty_dependent_root,
            current_duty_dependent_root,
            execution_optimistic: head.is_optimistic(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PayloadAttributesEvent {
    pub version: Phase,
    pub data: PayloadAttributesEventData,
}

#[derive(Clone, Debug, Serialize)]
pub struct PayloadAttributesEventData {
    #[serde(with = "serde_utils::string_or_native")]
    pub proposal_slot: Slot,
    pub parent_block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub parent_block_number: ExecutionBlockNumber,
    pub parent_block_hash: ExecutionBlockHash,
    #[serde(with = "serde_utils::string_or_native")]
    pub proposer_index: ValidatorIndex,
    pub payload_attributes: CombinedPayloadAttributesEventData,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged, bound = "")]
pub enum CombinedPayloadAttributesEventData {
    Bellatrix(PayloadAttributesEventDataV1),
    Capella(PayloadAttributesEventDataV2),
    Deneb(PayloadAttributesEventDataV3),
    Electra(PayloadAttributesEventDataV3),
    Fulu(PayloadAttributesEventDataV3),
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct PayloadAttributesEventDataV1 {
    #[serde(with = "serde_utils::string_or_native")]
    pub timestamp: UnixSeconds,
    pub prev_randao: H256,
    pub suggested_fee_recipient: ExecutionAddress,
}

#[derive(Clone, Debug, Serialize)]
pub struct PayloadAttributesEventDataV2 {
    #[serde(with = "serde_utils::string_or_native")]
    pub timestamp: UnixSeconds,
    pub prev_randao: H256,
    pub suggested_fee_recipient: ExecutionAddress,
    pub withdrawals: Vec<WithdrawalEventDataV1>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PayloadAttributesEventDataV3 {
    #[serde(with = "serde_utils::string_or_native")]
    pub timestamp: UnixSeconds,
    pub prev_randao: H256,
    pub suggested_fee_recipient: ExecutionAddress,
    pub withdrawals: Vec<WithdrawalEventDataV1>,
    pub parent_beacon_block_root: H256,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct WithdrawalEventDataV1 {
    #[serde(with = "serde_utils::string_or_native")]
    pub index: WithdrawalIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub address: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
}

impl From<WithdrawalV1> for WithdrawalEventDataV1 {
    fn from(withdrawal: WithdrawalV1) -> Self {
        let WithdrawalV1 {
            index,
            validator_index,
            address,
            amount,
        } = withdrawal;

        Self {
            index,
            validator_index,
            address,
            amount,
        }
    }
}

impl From<PayloadAttributesV1> for PayloadAttributesEventDataV1 {
    fn from(payload_attributes: PayloadAttributesV1) -> Self {
        let PayloadAttributesV1 {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
        } = payload_attributes;

        Self {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
        }
    }
}

impl<P: Preset> From<PayloadAttributesV2<P>> for PayloadAttributesEventDataV2 {
    fn from(payload_attributes: PayloadAttributesV2<P>) -> Self {
        let PayloadAttributesV2 {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            withdrawals,
        } = payload_attributes;

        Self {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            withdrawals: withdrawals.into_iter().map(Into::into).collect::<Vec<_>>(),
        }
    }
}

impl<P: Preset> From<PayloadAttributesV3<P>> for PayloadAttributesEventDataV3 {
    fn from(payload_attributes: PayloadAttributesV3<P>) -> Self {
        let PayloadAttributesV3 {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            withdrawals,
            parent_beacon_block_root,
        } = payload_attributes;

        Self {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            withdrawals: withdrawals.into_iter().map(Into::into).collect::<Vec<_>>(),
            parent_beacon_block_root,
        }
    }
}

impl<P: Preset> From<PayloadAttributes<P>> for CombinedPayloadAttributesEventData {
    fn from(payload_attributes: PayloadAttributes<P>) -> Self {
        match payload_attributes {
            PayloadAttributes::Bellatrix(payload_attributes_v1) => {
                Self::Bellatrix(payload_attributes_v1.into())
            }
            PayloadAttributes::Capella(payload_attributes_v2) => {
                Self::Capella(payload_attributes_v2.into())
            }
            PayloadAttributes::Deneb(payload_attributes_v3) => {
                Self::Deneb(payload_attributes_v3.into())
            }
            PayloadAttributes::Electra(payload_attributes_v3) => {
                Self::Electra(payload_attributes_v3.into())
            }
            PayloadAttributes::Fulu(payload_attributes_v3) => {
                Self::Fulu(payload_attributes_v3.into())
            }
        }
    }
}
