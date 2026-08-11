use std::sync::Arc;

use anyhow::Error as AnyhowError;
use static_assertions::assert_eq_size;
use thiserror::Error;
use types::{
    PayloadExpectedWithdrawals,
    bellatrix::{containers::PowBlock, primitives::Gas},
    combined::{Attestation, DataColumnSidecar, SignedAggregateAndProof, SignedBeaconBlock},
    deneb::containers::BlobSidecar,
    gloas::containers::{
        SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope, SignedProposerPreferences,
    },
    phase0::primitives::{Epoch, H256, Slot, SubnetId, ValidatorIndex},
    preset::{Mainnet, Preset},
};

#[derive(Debug, Error)]
pub enum Error<P: Preset> {
    #[error("attestation data should have index as zero")]
    AttestationDataIndexNotZero { attestation: Arc<Attestation<P>> },
    #[error("attestation data with invalid payload status")]
    AttestationDataInvalidPayloadStatus { attestation: Arc<Attestation<P>> },
    #[error("attestation data for current slot with payload presence")]
    AttestationDataPayloadPresenceForCurrentSlot { attestation: Arc<Attestation<P>> },
    #[error("attestation with multiple committee bits")]
    AttestationFromMultipleCommittees { attestation: Arc<Attestation<P>> },
    #[error("aggregate attestation has no aggregation bits set: {aggregate_and_proof:?}")]
    AggregateAttestationHasNoAggregationBitsSet {
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
    },
    #[error(
        "aggregator is not in committee \
         (aggregate_and_proof: {aggregate_and_proof:?}, committee: {committee:?})"
    )]
    AggregatorNotInCommittee {
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
        committee: Box<[ValidatorIndex]>,
    },
    #[error(
        "attestation votes for a block from the future \
         (attestation: {attestation:?}, block: {block:?})"
    )]
    AttestationForFutureBlock {
        attestation: Arc<Attestation<P>>,
        block: Arc<SignedBeaconBlock<P>>,
    },
    #[error("block being voted for failed validation (attestation: {attestation:?})")]
    AttestationForRejectedBlock { attestation: Arc<Attestation<P>> },
    #[error("attestation votes for a checkpoint in the wrong epoch: {attestation:?}")]
    AttestationTargetsWrongEpoch { attestation: Arc<Attestation<P>> },
    #[error(
        "the current finalized_checkpoint is not an ancestor of the sidecar's block: {blob_sidecar:?}"
    )]
    BlobSidecarBlockNotADescendantOfFinalized { blob_sidecar: Arc<BlobSidecar<P>> },
    // TODO(feature/deneb): This is vague.
    //                      The validation that fails with this error actually checks commitments.
    #[error("blob sidecar is invalid: {blob_sidecar:?}")]
    BlobSidecarInvalid { blob_sidecar: Arc<BlobSidecar<P>> },
    #[error("blob sidecar's block's parent is invalid: {blob_sidecar:?}")]
    BlobSidecarInvalidParentOfBlock { blob_sidecar: Arc<BlobSidecar<P>> },
    #[error("blob sidecar contains invalid inclusion proof: {blob_sidecar:?}")]
    BlobSidecarInvalidInclusionProof { blob_sidecar: Arc<BlobSidecar<P>> },
    #[error("blob sidecar index is invalid: {blob_sidecar:?}")]
    BlobSidecarInvalidIndex { blob_sidecar: Arc<BlobSidecar<P>> },
    #[error("delayed until slot blob sidecar queue is full (slot: {slot})")]
    BlobSidecarSlotQueueFull { slot: Slot },
    #[error(
        "blob sidecar is not newer than block parent \
         (blob sidecar: {blob_sidecar:?}, parent_slot: {parent_slot})"
    )]
    BlobSidecarNotNewerThanBlockParent {
        blob_sidecar: Arc<BlobSidecar<P>>,
        parent_slot: Slot,
    },
    #[error(
        "blob sidecar published on incorrect subnet \
         (blob_sidecar: {blob_sidecar:?}, expected: {expected}, actual: {actual})"
    )]
    BlobSidecarOnIncorrectSubnet {
        blob_sidecar: Arc<BlobSidecar<P>>,
        expected: SubnetId,
        actual: SubnetId,
    },
    #[error(
        "blob sidecar has incorrect proposer index \
         (blob_sidecar: {blob_sidecar:?}, computed: {computed})"
    )]
    BlobSidecarProposerIndexMismatch {
        blob_sidecar: Arc<BlobSidecar<P>>,
        computed: ValidatorIndex,
    },
    #[error("builder index mismatch: expected {expected}, actual {actual}")]
    BuilderIndexMismatch {
        expected: ValidatorIndex,
        actual: ValidatorIndex,
    },
    #[error("block with root {block_root} not found in fork choice")]
    BlockNotFound { block_root: H256 },
    #[error("block parent rejected (block: {block:?}")]
    BlockParentRejectedBlock { block: Arc<SignedBeaconBlock<P>> },
    #[error("delayed until slot block queue is full (slot: {slot})")]
    BlockSlotQueueFull { slot: Slot },
    #[error(
        "the current finalized_checkpoint is not an ancestor of the sidecar's block: {data_column_sidecar:?}"
    )]
    DataColumnSidecarBlockNotADescendantOfFinalized {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    },
    #[error(
        "data column sidecar's block has no signed execution payload bid: {data_column_sidecar:?}"
    )]
    DataColumnSidecarBlockWithoutPayloadBid {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    },
    #[error("data column sidecar is invalid: {data_column_sidecar:?}")]
    DataColumnSidecarInvalid {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    },
    #[error("data column sidecar's kzg commitments is invalid: {data_column_sidecar:?}")]
    DataColumnSidecarInvalidKzgCommitments {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    },
    // TODO(feature/deneb): This is vague.
    //                      The validation that fails with this error actually checks commitments.
    #[error("data column sidecar's kzg proofs is invalid: {data_column_sidecar:?} error: {error}")]
    DataColumnSidecarInvalidKzgProofs {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        error: AnyhowError,
    },
    #[error("data column sidecar's block's parent is invalid: {data_column_sidecar:?}")]
    DataColumnSidecarInvalidParentOfBlock {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    },
    #[error("data column sidecar contains invalid inclusion proof: {data_column_sidecar:?}")]
    DataColumnSidecarInvalidInclusionProof {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    },
    #[error(
        "data column sidecar is not newer than block parent \
         (data_column_sidecar: {data_column_sidecar:?}, parent_slot: {parent_slot})"
    )]
    DataColumnSidecarNotNewerThanBlockParent {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        parent_slot: Slot,
    },
    #[error(
        "data column sidecar published on incorrect subnet \
         (data_column_sidecar: {data_column_sidecar:?}, expected: {expected}, actual: {actual})"
    )]
    DataColumnSidecarOnIncorrectSubnet {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        expected: SubnetId,
        actual: SubnetId,
    },
    #[error(
        "data column sidecar's slot mismatch the slot in beacon block: {data_column_sidecar:?}, block_slot: {block_slot}"
    )]
    DataColumnSidecarSlotMismatch {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        block_slot: Slot,
    },
    #[error("delayed until slot data column sidecar queue is full (slot: {slot})")]
    DataColumnSidecarSlotQueueFull { slot: Slot },
    #[error(
        "data column sidecar has incorrect proposer index \
         (data_column_sidecar: {data_column_sidecar:?}, computed: {computed})"
    )]
    DataColumnSidecarProposerIndexMismatch {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        computed: ValidatorIndex,
    },
    #[error("delayed objects until parent queue is full")]
    DelayedUntilParentQueueFull,
    #[error("execution payload bid's builder is not active at epoch {epoch}: {payload_bid:?}")]
    ExecutionPayloadBidBuilderInactive {
        payload_bid: Arc<SignedExecutionPayloadBid<P>>,
        epoch: Epoch,
    },
    #[error(
        "execution payload bid's slot {bid_slot} is not greater than parent slot {parent_slot}"
    )]
    ExecutionPayloadBidSlotNotGreaterThanParent { bid_slot: Slot, parent_slot: Slot },
    #[error("off-protocol payment is disallowed in gossip: {payload_bid:?}")]
    ExecutionPayloadBidOffProtocolPaymentDisallowed {
        payload_bid: Arc<SignedExecutionPayloadBid<P>>,
    },
    #[error(
        "execution payload bid's prev rando is incorrect (in_bid: {bid_prev_randao:?}, expected: {prev_randao:?})"
    )]
    ExecutionPayloadBidPrevRandaoIncorrect {
        bid_prev_randao: Box<H256>,
        prev_randao: Box<H256>,
    },
    #[error("self-build execution payload bids are never broadcast: {payload_bid:?}")]
    ExecutionPayloadBidSelfBuild {
        payload_bid: Arc<SignedExecutionPayloadBid<P>>,
    },
    #[error(
        "execution payload bid's builder version mismatch \
         (payload_bid: {payload_bid:?}, builder_version: {builder_version}, expected: {expected})"
    )]
    ExecutionPayloadBidBuilderVersionMismatch {
        payload_bid: Arc<SignedExecutionPayloadBid<P>>,
        builder_version: u8,
        expected: u8,
    },
    #[error(
        "execution payload block hash mismatch (envelope: {envelope:?}, expected: {expected:?})"
    )]
    ExecutionPayloadBlockHashMismatch {
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        expected: Box<H256>,
    },
    #[error(
        "execution payload beacon block root mismatch (envelope: {envelope:?}, expected: {expected:?})"
    )]
    ExecutionPayloadBeaconBlockRootMismatch {
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        expected: Box<H256>,
    },
    #[error(
        "execution payload parent beacon block root mismatch (envelope: {envelope:?}, expected: {expected:?})"
    )]
    ExecutionPayloadParentBeaconBlockRootMismatch {
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        expected: Box<H256>,
    },
    #[error("execution payload gas_limit mismatch (envelope: {envelope:?}, expected: {expected})")]
    ExecutionPayloadGasLimitMismatch {
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        expected: Gas,
    },
    #[error(
        "execution payload parent hash mismatch (envelope: {envelope:?}, expected: {expected:?})"
    )]
    ExecutionPayloadParentHashMismatch {
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        expected: Box<H256>,
    },
    #[error(
        "execution payload prev randao mismatch (envelope: {envelope:?}, expected: {expected:?})"
    )]
    ExecutionPayloadPrevRandaoMismatch {
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        expected: Box<H256>,
    },
    #[error(
        "execution payload requests hash mismatch (envelope: {envelope:?}, expected: {expected:?})"
    )]
    ExecutionPayloadRequestsHashMismatch {
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        expected: Box<H256>,
    },
    #[error("execution payload envelope slot mismatch: expected {expected}, actual {actual}")]
    ExecutionPayloadEnvelopeSlotMismatch { expected: Slot, actual: Slot },
    #[error(
        "execution payload timestamp mismatch (envelope: {envelope:?}, expected: {expected:?})"
    )]
    ExecutionPayloadTimestampMismatch {
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        expected: u64,
    },
    #[error(
        "execution payload withdrawals mismatch (envelope: {envelope:?}, expected: {expected:?})"
    )]
    ExecutionPayloadWithdrawalsHashMismatch {
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        expected: Box<PayloadExpectedWithdrawals>,
    },
    #[error("proposer preferences has invalid proposal slot: {signed_preferences:?}")]
    InvalidProposerPreferencesProposalSlot {
        signed_preferences: Arc<SignedProposerPreferences>,
    },
    #[error("proposer preferences has invalid dependent root: {signed_preferences:?}")]
    InvalidProposerPreferencesDependentRoot {
        signed_preferences: Arc<SignedProposerPreferences>,
    },
    #[error("proposer preferences has invalid signature: {signed_preferences:?}")]
    InvalidProposerPreferencesSignature {
        signed_preferences: Arc<SignedProposerPreferences>,
    },
    #[error("aggregate and proof has invalid signature: {aggregate_and_proof:?}")]
    InvalidAggregateAndProofSignature {
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
    },
    #[error("block has invalid execution payload")]
    InvalidExecutionPayload,
    #[error("execution payload bid has invalid signature: {payload_bid:?}")]
    InvalidExecutionPayloadBidSignature {
        payload_bid: Arc<SignedExecutionPayloadBid<P>>,
    },
    #[error("aggregate has invalid selection proof: {aggregate_and_proof:?}")]
    InvalidSelectionProof {
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
    },
    #[error("LMD GHOST vote is inconsistent with FFG vote target (attestation: {attestation:?})")]
    LmdGhostInconsistentWithFfgTarget { attestation: Arc<Attestation<P>> },
    #[error("merge block proposed before activation epoch: {block:?}")]
    MergeBlockBeforeActivationEpoch { block: Arc<SignedBeaconBlock<P>> },
    #[error("payload envelope's block is invalid: {payload_envelope:?}")]
    PayloadEnvelopeInvalidBlock {
        payload_envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
    },
    #[error(
        "payload envelope validation with pre-Gloas state: (envelope_slot: {envelope_slot}, state_slot: {state_slot})"
    )]
    PayloadEnvelopeWithPreGloasState {
        envelope_slot: Slot,
        state_slot: Slot,
    },
    #[error("validator {validator_index} is not a member of PTC at slot {slot}")]
    PayloadAttestationNotInCommittee {
        validator_index: ValidatorIndex,
        slot: Slot,
    },
    #[error("terminal PoW block has incorrect hash: {block:?}")]
    TerminalBlockHashMismatch { block: Arc<SignedBeaconBlock<P>> },
    #[error(
        "terminal PoW block did not reach terminal total difficulty \
         (block: {block:?}, pow_block: {pow_block:?})"
    )]
    TerminalTotalDifficultyNotReached {
        block: Arc<SignedBeaconBlock<P>>,
        pow_block: Box<PowBlock>,
    },
    #[error(
        "parent of terminal PoW block reached terminal total difficulty \
         (block: {block:?}, pow_block: {pow_block:?}, parent: {parent:?})"
    )]
    TerminalTotalDifficultyReachedByParent {
        block: Arc<SignedBeaconBlock<P>>,
        pow_block: Box<PowBlock>,
        parent: Box<PowBlock>,
    },
    #[error("too many blob KZG commitments (maximum: {maximum}, in_bid: {in_bid})")]
    TooManyBlobKzgCommitments { maximum: usize, in_bid: usize },
    #[error("validator is not an aggregator: {aggregate_and_proof:?}")]
    ValidatorNotAggregator {
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
    },
}

assert_eq_size!(Error<Mainnet>, [usize; 5]);
