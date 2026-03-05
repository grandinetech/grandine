use std::sync::Arc;

use anyhow::Error as AnyhowError;
use static_assertions::assert_eq_size;
use thiserror::Error;
use types::{
    bellatrix::{containers::PowBlock, primitives::Gas},
    combined::{Attestation, DataColumnSidecar, SignedAggregateAndProof, SignedBeaconBlock},
    deneb::containers::BlobSidecar,
    fulu::containers::{PartialDataColumn, PartialDataColumnHeader},
    gloas::containers::SignedExecutionPayloadBid,
    phase0::primitives::{Epoch, ExecutionAddress, Gwei, Slot, SubnetId, ValidatorIndex},
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
    #[error(
        "data column sidecar has incorrect proposer index \
         (data_column_sidecar: {data_column_sidecar:?}, computed: {computed})"
    )]
    DataColumnSidecarProposerIndexMismatch {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        computed: ValidatorIndex,
    },
    #[error("execution payload bid's builder is not active at epoch {epoch}: {payload_bid:?}")]
    ExecutionPayloadBidBuilderInactive {
        payload_bid: Arc<SignedExecutionPayloadBid<P>>,
        epoch: Epoch,
    },
    #[error(
        "execution payload bid's fee recipient mismatch (in_bid: {in_bid:?}, in_preference: {in_preference:?})"
    )]
    ExecutionPayloadBidFeeRecipientMismatch {
        in_preference: Box<ExecutionAddress>,
        in_bid: Box<ExecutionAddress>,
    },
    #[error(
        "execution payload bid's gas limit mismatch (in_bid: {in_bid}, in_preference: {in_preference})"
    )]
    ExecutionPayloadBidGasLimitMismatch { in_preference: Gas, in_bid: Gas },
    #[error("off-protocol payment is disallowed in gossip: {payload_bid:?}")]
    ExecutionPayloadBidOffProtocolPaymentDisallowed {
        payload_bid: Arc<SignedExecutionPayloadBid<P>>,
    },
    #[error("execution payload bid's signature for self-build is not empty")]
    ExecutionPayloadBidSignatureNotEmpty,
    #[error("execution payload bid's value for self-build is not zero, value: {value} gwei")]
    ExecutionPayloadBidValueNonZero { value: Gwei },
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
    #[error("partial message's group id is not hash of block header: {header:?}")]
    PartialGroupIdMismatch {
        header: Arc<PartialDataColumnHeader<P>>,
    },
    #[error("partial data column header with empty commitments: {header:?}")]
    PartialHeaderNoBlob {
        header: Arc<PartialDataColumnHeader<P>>,
    },
    #[error("partial data column header's block's parent is invalid: {header:?}")]
    PartialHeaderInvalidParentOfBlock {
        header: Arc<PartialDataColumnHeader<P>>,
    },
    #[error(
        "partial data column header is not newer than block parent \
         (header: {header:?}, parent_slot: {parent_slot})"
    )]
    PartialHeaderNotNewerThanBlockParent {
        header: Arc<PartialDataColumnHeader<P>>,
        parent_slot: Slot,
    },
    #[error(
        "the current finalized_checkpoint is not an ancestor of the header's block: {header:?}"
    )]
    PartialHeaderBlockNotADescendantOfFinalized {
        header: Arc<PartialDataColumnHeader<P>>,
    },
    #[error("partial data column header contains invalid inclusion proof: {header:?}")]
    PartialHeaderInvalidInclusionProof {
        header: Arc<PartialDataColumnHeader<P>>,
    },
    #[error(
        "partial data column header has incorrect proposer index \
         (header: {header:?}, computed: {computed})"
    )]
    PartialHeaderProposerIndexMismatch {
        header: Arc<PartialDataColumnHeader<P>>,
        computed: ValidatorIndex,
    },
    #[error(
        "The cells present bitmap length is not equal to the number of KZG commitments \
            (cells_bitmap_length: {cells_bitmap_length}, commitment_length: {commitment_length})"
    )]
    PartialColumnCellsBitmapLengthMismatch {
        cells_bitmap_length: usize,
        commitment_length: usize,
    },
    #[error(
        "The cells length is not equal to the kzg proofs length (cells_present_count: {cells_present_count}, \
            cells_length: {cells_length}, proofs_length: {proofs_length})"
    )]
    PartialColumnCellsProofsLengthMismatch {
        cells_present_count: usize,
        cells_length: usize,
        proofs_length: usize,
    },
    #[error("partial data column sidecar's kzg proofs is invalid: {column:?} error: {error}")]
    PartialColumnInvalidKzgProofs {
        column: Arc<PartialDataColumn<P>>,
        error: AnyhowError,
    },
    #[error("received no header partial data column sidecar with no header cached: {column:?}")]
    PartialColumnNoHeaderCached { column: Arc<PartialDataColumn<P>> },
    #[error(
        "received partial data column sidecar with header mismatch with the verified header: {header:?}"
    )]
    PartialHeaderMismatch {
        header: Arc<PartialDataColumnHeader<P>>,
    },
    #[error("received empty partial data column sidecar")]
    PartialColumnEmpty { column: Arc<PartialDataColumn<P>> },
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

assert_eq_size!(Error<Mainnet>, [usize; 4]);
