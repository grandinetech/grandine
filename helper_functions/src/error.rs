use parse_display::Display;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("attestation has no attesting indices")]
    AttestationHasNoAttestingIndices,
    #[error("attestation source does not match justified checkpoint")]
    AttestationSourceMismatch,
    #[error("attesting indices are not sorted and unique")]
    AttestingIndicesNotSortedAndUnique,
    #[error("commitee index is out of bounds")]
    CommitteeIndexOutOfBounds,
    #[error("aggregation bitlist length does not match committee length")]
    CommitteeLengthMismatch,
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
    #[display("blob sidecar signature")]
    BlobSidecar,
    #[display("block signature")]
    Block,
    #[display("BLS to execution change signature")]
    BlsToExecutionChange,
    #[display("builder signature")]
    Builder,
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
