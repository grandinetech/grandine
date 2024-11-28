use std::sync::Arc;

use anyhow::Error as AnyhowError;
use static_assertions::assert_eq_size;
use thiserror::Error;
use types::{
    bellatrix::containers::PowBlock,
    combined::{Attestation, SignedAggregateAndProof, SignedBeaconBlock},
    deneb::containers::BlobSidecar,
    eip7594::DataColumnSidecar,
    phase0::{
        containers::{Attestation, SignedAggregateAndProof},
        primitives::{Slot, SubnetId, ValidatorIndex},
    },
    preset::{Mainnet, Preset},
};

#[derive(Debug, Error)]
pub enum Error<P: Preset> {
    #[error("attestation data should have index as zero")]
    AttestationDataIndexNotZero { attestation: Arc<Attestation<P>> },
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
    #[error("The current finalized_checkpoint is not an ancestor of the sidecar's block: {blob_sidecar:?}")]
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
    #[error("The current finalized_checkpoint is not an ancestor of the sidecar's block: {data_column_sidecar:?}")]
    DataColumnSidecarBlockNotADescendantOfFinalized {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    },
    // TODO(feature/deneb): This is vague.
    //                      The validation that fails with this error actually checks commitments.
    #[error("data_column sidecar is invalid: {data_column_sidecar:?} error: {error}")]
    DataColumnSidecarInvalid {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        error: AnyhowError,
    },
    #[error("data_column sidecar's block's parent is invalid: {data_column_sidecar:?}")]
    DataColumnSidecarInvalidParentOfBlock {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    },
    #[error("data_column sidecar contains invalid inclusion proof: {data_column_sidecar:?}")]
    DataColumnSidecarInvalidInclusionProof {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    },
    #[error("data_column sidecar index is invalid: {data_column_sidecar:?}")]
    DataColumnSidecarInvalidIndex {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
    },
    #[error(
        "data_column sidecar is not newer than block parent \
         (data_column sidecar: {data_column_sidecar:?}, parent_slot: {parent_slot})"
    )]
    DataColumnSidecarNotNewerThanBlockParent {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        parent_slot: Slot,
    },
    #[error(
        "data_column sidecar published on incorrect subnet \
         (data_column_sidecar: {data_column_sidecar:?}, expected: {expected}, actual: {actual})"
    )]
    DataColumnSidecarOnIncorrectSubnet {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        expected: SubnetId,
        actual: SubnetId,
    },
    #[error(
        "data_column sidecar has incorrect proposer index \
         (data_column_sidecar: {data_column_sidecar:?}, computed: {computed})"
    )]
    DataColumnSidecarProposerIndexMismatch {
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        computed: ValidatorIndex,
    },
    #[error("aggregate and proof has invalid signature: {aggregate_and_proof:?}")]
    InvalidAggregateAndProofSignature {
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
    },
    #[error("aggregate has invalid selection proof: {aggregate_and_proof:?}")]
    InvalidSelectionProof {
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
    },
    #[error("LMD GHOST vote is inconsistent with FFG vote target (attestation: {attestation:?})")]
    LmdGhostInconsistentWithFfgTarget { attestation: Arc<Attestation<P>> },
    #[error("merge block proposed before activation epoch: {block:?}")]
    MergeBlockBeforeActivationEpoch { block: Arc<SignedBeaconBlock<P>> },
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
    #[error("validator is not an aggregator: {aggregate_and_proof:?}")]
    ValidatorNotAggregator {
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
    },
}

assert_eq_size!(Error<Mainnet>, [usize; 4]);
