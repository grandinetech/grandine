use std::sync::Arc;

use static_assertions::assert_eq_size;
use thiserror::Error;
use types::{
    bellatrix::containers::PowBlock,
    combined::SignedBeaconBlock,
    deneb::containers::BlobSidecar,
    phase0::{
        containers::{Attestation, SignedAggregateAndProof},
        primitives::{Slot, SubnetId, ValidatorIndex},
    },
    preset::{Mainnet, Preset},
};

#[derive(Debug, Error)]
pub enum Error<P: Preset> {
    #[error("aggregate attestation has no aggregation bits set: {aggregate_and_proof:?}")]
    AggregateAttestationHasNoAggregationBitsSet {
        aggregate_and_proof: Box<SignedAggregateAndProof<P>>,
    },
    #[error(
        "aggregator is not in committee \
         (aggregate_and_proof: {aggregate_and_proof:?}, committee: {committee:?})"
    )]
    AggregatorNotInCommittee {
        aggregate_and_proof: Box<SignedAggregateAndProof<P>>,
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
    #[error("aggregate and proof has invalid signature: {aggregate_and_proof:?}")]
    InvalidAggregateAndProofSignature {
        aggregate_and_proof: Box<SignedAggregateAndProof<P>>,
    },
    #[error("aggregate has invalid selection proof: {aggregate_and_proof:?}")]
    InvalidSelectionProof {
        aggregate_and_proof: Box<SignedAggregateAndProof<P>>,
    },
    #[error("LMD GHOST vote is inconsistent with FFG vote target (attestation: {attestation:?})")]
    LmdGhostInconsistentWithFfgTarget { attestation: Arc<Attestation<P>> },
    #[error("merge block proposed before activation epoch: {block:?}")]
    MergeBlockBeforeActivationEpoch { block: Arc<SignedBeaconBlock<P>> },
    #[error(
        "singular attestation published on incorrect subnet \
         (attestation: {attestation:?}, expected: {expected}, actual: {actual})"
    )]
    SingularAttestationOnIncorrectSubnet {
        attestation: Arc<Attestation<P>>,
        expected: SubnetId,
        actual: SubnetId,
    },
    #[error("singular attestation has multiple aggregation bits set: {attestation:?}")]
    SingularAttestationHasMultipleAggregationBitsSet { attestation: Arc<Attestation<P>> },
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
        aggregate_and_proof: Box<SignedAggregateAndProof<P>>,
    },
}

assert_eq_size!(Error<Mainnet>, [usize; 4]);
