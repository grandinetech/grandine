use parse_display::Display;
use thiserror::Error;
use types::phase0::primitives::CommitteeIndex;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("attestation has no attesting indices")]
    AttestationHasNoAttestingIndices,
    #[error("attestation source does not match justified checkpoint")]
    AttestationSourceMismatch,
    #[error("attesting indices are not sorted and unique")]
    AttestingIndicesNotSortedAndUnique,
    #[error("cannot compute subnet for blob sidecar")]
    BlobSidecarSubnetNotAvailable,
    #[error("committee index is out of bounds")]
    CommitteeIndexOutOfBounds,
    #[error("aggregation bitlist length {aggregation_bitlist_length} does not match committee length {committee_length}")]
    CommitteeLengthMismatch {
        aggregation_bitlist_length: usize,
        committee_length: usize,
    },
    #[error("epoch is after next one relative to state")]
    EpochAfterNext,
    #[error("epoch is before previous one relative to state")]
    EpochBeforePrevious,
    #[error("epoch is in the future relative to state")]
    EpochInTheFuture,
    #[error("epoch number overflowed")]
    EpochOverflow,
    #[error("failed to select proposer")]
    FailedToSelectProposer,
    #[error("no validators are active")]
    NoActiveValidators,
    #[error("no committee attesters for {index} committee")]
    NoCommitteeAttesters { index: CommitteeIndex },
    #[error("aggregation bitlist length {aggregation_bitlist_length} does not match participants count {participants_count}")]
    ParticipantsCountMismatch {
        aggregation_bitlist_length: usize,
        participants_count: usize,
    },
    #[error("permutated prefix maximum overflowed")]
    PermutatedPrefixMaximumOverflow,
    #[error("{0} is invalid")]
    SignatureInvalid(SignatureKind),
    #[error("slot is out of range")]
    SlotOutOfRange,
    #[error("subnet ID overflowed")]
    SubnetIdOverflow,
    #[error("subnet prefix bit count overflowed")]
    SubnetPrefixBitCountOverflow,
}

#[derive(Debug, Display)]
pub enum SignatureKind {
    #[display("aggregate and proof signature")]
    AggregateAndProof,
    #[display("attestation signature")]
    Attestation,
    #[display("block signature in blob sidecar")]
    BlockInBlobSidecar,
    #[display("block signature")]
    Block,
    #[display("BLS to execution change signature")]
    BlsToExecutionChange,
    #[display("builder signature")]
    Builder,
    #[display("consolidation signature")]
    Consolidation,
    #[display("sync committee contribution and proof signature")]
    ContributionAndProof,
    #[display("deposit signature")]
    Deposit,
    #[display("collection of multiple signatures")]
    Multi,
    #[display("RANDAO reveal")]
    Randao,
    #[display("selection proof")]
    SelectionProof,
    #[display("sync aggregate signature")]
    SyncAggregate,
    #[display("sync committee contribution signature")]
    SyncCommitteeContribution,
    #[display("sync committee message signature")]
    SyncCommitteeMessage,
    #[display("sync committee selection proof")]
    SyncCommitteeSelectionProof,
    #[display("voluntary exit signature")]
    VoluntaryExit,
}
