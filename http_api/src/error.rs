use core::fmt::Display;
use std::error::Error as StdError;

use anyhow::Error as AnyhowError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use bls::SignatureBytes;
use futures::channel::oneshot::Canceled;
use itertools::Itertools as _;
use serde::{Serialize, Serializer};
use thiserror::Error;
use tokio::task::JoinError;
use types::{deneb::primitives::BlobIndex, phase0::primitives::Slot};

#[derive(Debug, Error)]
pub enum Error {
    #[error("attestation cannot be found")]
    AttestationNotFound,
    #[error("block not found")]
    BlockNotFound,
    #[error(transparent)]
    Canceled(#[from] Canceled),
    #[error(
        "committees_at_slot ({requested}) does not match \
         the expected number of committees ({computed})"
    )]
    CommitteesAtSlotMismatch { requested: u64, computed: u64 },
    #[error("current slot has no sync committee")]
    CurrentSlotHasNoSyncCommittee,
    #[error("endpoint not implemented")]
    EndpointNotImplemented,
    #[error("epoch is before previous one relative to head")]
    EpochBeforePrevious,
    #[error("requested epoch is neither in current nor next sync committee period")]
    EpochNotInSyncCommitteePeriod,
    #[error("epoch is out of range for the randao_mixes of the state")]
    EpochOutOfRangeForStateRandao,
    #[error("execution payload not available")]
    ExecutionPayloadNotAvailable,
    #[error("no event topics specified")]
    EventTopicsEmpty,
    #[error("too many empty slots after head: {head_slot} + {max_empty_slots} < {slot}")]
    HeadFarBehind {
        head_slot: Slot,
        max_empty_slots: u64,
        slot: Slot,
    },
    #[error("head has not been fully verified by an execution engine")]
    HeadIsOptimistic,
    #[error("internal error")]
    Internal(#[from] AnyhowError),
    #[error("invalid aggregates and proofs")]
    InvalidAggregatesAndProofs(Vec<IndexedError>),
    #[error("invalid attestations")]
    InvalidAttestations(Vec<IndexedError>),
    #[error("invalid attester slashing, it will never pass validation so it's rejected")]
    InvalidAttesterSlashing(#[source] AnyhowError),
    #[error("invalid blob index {0}")]
    InvalidBlobIndex(BlobIndex),
    #[error("invalid block ID")]
    InvalidBlockId(#[source] AnyhowError),
    #[error("invalid block")]
    InvalidBlock(#[source] AnyhowError),
    #[error("invalid contribution and proofs")]
    InvalidContributionAndProofs(Vec<IndexedError>),
    #[error("invalid epoch")]
    InvalidEpoch(#[source] AnyhowError),
    #[error("invalid JSON body")]
    InvalidJsonBody(#[source] AnyhowError),
    #[error("invalid peer ID")]
    InvalidPeerId(#[source] AnyhowError),
    #[error(
        "randao_reveal must be {:?} when skip_randao_verification is set",
        SignatureBytes::empty()
    )]
    InvalidRandaoReveal,
    #[error("invalid state ID")]
    InvalidStateId(#[source] AnyhowError),
    #[error("invalid validator ID")]
    InvalidValidatorId(#[source] AnyhowError),
    #[error("invalid proposer slashing, it will never pass validation so it's rejected")]
    InvalidProposerSlashing(#[source] AnyhowError),
    #[error("invalid query string")]
    InvalidQuery(#[source] AnyhowError),
    #[error("invalid voluntary exit, it will never pass validation so it's rejected")]
    InvalidSignedVoluntaryExit(#[source] AnyhowError),
    #[error("invalid sync committee messages")]
    InvalidSyncCommitteeMessages(Vec<IndexedError>),
    #[error("invalid validator index")]
    InvalidValidatorIndex(#[source] AnyhowError),
    #[error("invalid validator signatures")]
    InvalidValidatorSignatures(Vec<IndexedError>),
    #[error("invalid BLS to execution changes")]
    InvalidSignedBlsToExecutionChanges(Vec<IndexedError>),
    #[error("liveness tracking not enabled")]
    LivenessTrackingNotEnabled,
    #[error("matching head block for attestation is not found")]
    MatchingAttestationHeadBlockNotFound,
    #[error("beacon node is currently syncing and not serving requests on this endpoint")]
    NodeIsSyncing,
    #[error("peer not found")]
    PeerNotFound,
    #[error("proposal slot is not later than parent state slot")]
    ProposalSlotNotLaterThanStateSlot,
    #[error("slot does not belong in epoch")]
    SlotNotInEpoch,
    #[error("state not found")]
    StateNotFound,
    #[error("head is not available")]
    SlotHeadNotAvailable,
    #[error("state is pre-Capella")]
    StatePreCapella,
    #[error("target state not found")]
    TargetStateNotFound,
    #[error(transparent)]
    TaskJoinFailed(#[from] JoinError),
    #[error("unable to produce attestation")]
    UnableToProduceAttestation(#[source] AnyhowError),
    #[error("unable to produce beacon block")]
    UnableToProduceBeaconBlock,
    #[error("unable to produce blinded block")]
    UnableToProduceBlindedBlock,
    #[error("unable to validate signed beacon block")]
    UnableToValidateSignedBlock,
    #[error("validator not found")]
    ValidatorNotFound,
    // TODO(Grandine Team): Some API clients do not set `validator_index`.
    //                      See <https://github.com/attestantio/vouch/issues/75>.
    // #[error("validator not in committee: {validator_index}")]
    // ValidatorNotInCommittee { validator_index: ValidatorIndex },
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.format_sources())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = self.status_code();
        let body = Json(self.body()).into_response();
        let extension = Extension(self);
        (status_code, extension, body).into_response()
    }
}

impl Error {
    // `anyhow::Error` prints the chain of sources if the alternate flag is specified.
    // Impls generated by `thiserror::Error` ignore the alternate flag. See:
    // - <https://github.com/dtolnay/thiserror/issues/78>
    // - <https://github.com/dtolnay/thiserror/issues/98>
    // - <https://github.com/dtolnay/thiserror/issues/214>
    pub fn format_sources(&self) -> impl Display + '_ {
        self.sources().format(": ")
    }

    // `StdError::sources` is not stable as of Rust 1.78.0.
    fn sources(&self) -> impl Iterator<Item = &dyn StdError> {
        let mut error: Option<&dyn StdError> = Some(self);

        core::iter::from_fn(move || {
            let source = error?.source();
            core::mem::replace(&mut error, source)
        })
    }

    const fn status_code(&self) -> StatusCode {
        match self {
            Self::AttestationNotFound
            | Self::BlockNotFound
            | Self::MatchingAttestationHeadBlockNotFound
            | Self::PeerNotFound
            | Self::StateNotFound
            | Self::TargetStateNotFound
            | Self::ValidatorNotFound => StatusCode::NOT_FOUND,
            Self::CommitteesAtSlotMismatch { .. }
            | Self::CurrentSlotHasNoSyncCommittee
            | Self::EpochBeforePrevious { .. }
            | Self::EpochNotInSyncCommitteePeriod
            | Self::EpochOutOfRangeForStateRandao
            | Self::EventTopicsEmpty
            | Self::InvalidAggregatesAndProofs(_)
            | Self::InvalidAttestations(_)
            | Self::InvalidAttesterSlashing(_)
            | Self::InvalidBlock(_)
            | Self::InvalidBlobIndex(_)
            | Self::InvalidBlockId(_)
            | Self::InvalidContributionAndProofs(_)
            | Self::InvalidEpoch(_)
            | Self::InvalidJsonBody(_)
            | Self::InvalidQuery(_)
            | Self::InvalidPeerId(_)
            | Self::InvalidProposerSlashing(_)
            | Self::InvalidSignedVoluntaryExit(_)
            | Self::InvalidStateId(_)
            | Self::InvalidSignedBlsToExecutionChanges(_)
            | Self::InvalidSyncCommitteeMessages(_)
            | Self::InvalidRandaoReveal
            | Self::InvalidValidatorId(_)
            | Self::InvalidValidatorIndex(_)
            | Self::InvalidValidatorSignatures(_)
            | Self::ProposalSlotNotLaterThanStateSlot
            | Self::SlotNotInEpoch
            | Self::StatePreCapella => StatusCode::BAD_REQUEST,
            // | Self::ValidatorNotInCommittee { .. }
            Self::Internal(_)
            | Self::Canceled(_)
            | Self::ExecutionPayloadNotAvailable
            | Self::LivenessTrackingNotEnabled
            | Self::SlotHeadNotAvailable
            | Self::TaskJoinFailed(_)
            | Self::UnableToProduceAttestation { .. }
            | Self::UnableToProduceBeaconBlock
            | Self::UnableToProduceBlindedBlock
            | Self::UnableToValidateSignedBlock => StatusCode::INTERNAL_SERVER_ERROR,
            Self::EndpointNotImplemented => StatusCode::NOT_IMPLEMENTED,
            Self::HeadFarBehind { .. } | Self::HeadIsOptimistic | Self::NodeIsSyncing => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }

    fn body(&self) -> EthErrorResponse {
        EthErrorResponse {
            code: self.status_code().as_u16(),
            message: self,
            failures: self.failures(),
        }
    }

    fn failures(&self) -> &[IndexedError] {
        match self {
            Self::InvalidAggregatesAndProofs(failures)
            | Self::InvalidAttestations(failures)
            | Self::InvalidContributionAndProofs(failures)
            | Self::InvalidSyncCommitteeMessages(failures)
            | Self::InvalidValidatorSignatures(failures)
            | Self::InvalidSignedBlsToExecutionChanges(failures) => failures,
            _ => &[],
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Serialize)]
pub struct IndexedError {
    pub index: usize,
    #[serde(rename = "message", with = "serde_utils::alternate_display")]
    pub error: AnyhowError,
}

#[derive(Serialize)]
struct EthErrorResponse<'error> {
    // The absence of `#[serde(with = "serde_utils::string_or_native")]` is intentional.
    // The `code` field is supposed to contain a number.
    code: u16,
    message: &'error Error,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    failures: &'error [IndexedError],
}

#[allow(clippy::needless_pass_by_value)]
#[cfg(test)]
mod tests {
    use serde_json::{json, Result, Value};
    use test_case::test_case;

    use super::*;

    #[test_case(
        Error::BlockNotFound,
        json!({
            "code": 404,
            "message": "block not found",
        })
    )]
    #[test_case(
        Error::InvalidAttestations(vec![IndexedError {
            index: 0,
            error: Error::TargetStateNotFound.into(),
        }]),
        json!({
            "code": 400,
            "message": "invalid attestations",
            "failures": [
                {
                    "index": 0,
                    "message": "target state not found",
                },
            ],
        })
    )]
    fn error_is_serialized_correctly(error: Error, expected_json: Value) -> Result<()> {
        let actual_json = serde_json::to_value(error.body())?;
        assert_eq!(actual_json, expected_json);
        Ok(())
    }
}
