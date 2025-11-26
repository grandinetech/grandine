use ssz::ReadError;
use thiserror::Error;

use crate::phase0::{
    containers::AttestationData,
    primitives::{CommitteeIndex, ValidatorIndex},
};

#[derive(Debug, Error)]
pub enum AttestationConversionError {
    #[error("{attester_index} not in committee (committee index: {committee_index}, attestation data: {attestation_data:?}, committee: {committee:?})")]
    AttesterNotInCommittee {
        attester_index: ValidatorIndex,
        committee_index: CommitteeIndex,
        attestation_data: AttestationData,
        committee: Vec<ValidatorIndex>,
    },
    #[error("invalid aggregation bits for conversion")]
    InvalidAggregationBits(#[source] ReadError),
    #[error("invalid committee index for conversion")]
    InvalidCommitteeIndex,
    #[error("attestation is not relevant anymore")]
    Irrelevant,
}
