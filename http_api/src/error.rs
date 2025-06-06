use core::error::Error as StdError;
use std::sync::Arc;

use anyhow::Error as AnyhowError;
use axum::{
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use axum_extra::extract::QueryRejection;
use bls::{traits::SignatureBytes as _, SignatureBytes};
use futures::channel::oneshot::Canceled;
use http_api_utils::{ApiError, PhaseHeaderError};
use serde::{Serialize, Serializer};
use ssz::H256;
use thiserror::Error;
use tokio::task::JoinError;
use types::{
    deneb::primitives::BlobIndex, fulu::primitives::ColumnIndex, phase0::primitives::Slot,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("attestation cannot be found")]
    AttestationNotFound,
    #[error("block {block_root} not validated")]
    BlockNotValidatedForAggregation { block_root: H256 },
    #[error("block not found")]
    BlockNotFound,
    #[error(transparent)]
    Canceled(#[from] Canceled),
    #[error(transparent)]
    InvalidRequestConsensusHeader(#[from] PhaseHeaderError),
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
    #[error("invalid column index {0}")]
    InvalidColumnIndex(ColumnIndex),
    #[error("invalid contribution and proofs")]
    InvalidContributionAndProofs(Vec<IndexedError>),
    #[error("invalid epoch")]
    InvalidEpoch(#[source] AnyhowError),
    #[error("invalid JSON body")]
    InvalidJsonBody(#[source] JsonRejection),
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
    InvalidQuery(#[source] QueryRejection),
    #[error("invalid voluntary exit, it will never pass validation so it's rejected")]
    InvalidSignedVoluntaryExit(#[source] AnyhowError),
    #[error("invalid sync committee messages")]
    InvalidSyncCommitteeMessages(Vec<IndexedError>),
    #[error("invalid validator indices")]
    InvalidValidatorIndices(#[source] JsonRejection),
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
    #[error("state is pre-Electra")]
    StatePreElectra,
    #[error("target state not found")]
    TargetStateNotFound,
    #[error(transparent)]
    TaskJoinFailed(#[from] JoinError),
    #[error("unable to publish block")]
    UnableToPublishBlock,
    #[error("unable to produce attestation")]
    UnableToProduceAttestation(#[source] AnyhowError),
    #[error("unable to produce beacon block")]
    UnableToProduceBeaconBlock,
    #[error("unable to produce blinded block")]
    UnableToProduceBlindedBlock,
    #[error("validator not found")]
    ValidatorNotFound,
    // TODO(Grandine Team): Some API clients do not set `validator_index`.
    //                      See <https://github.com/attestantio/vouch/issues/75>.
    // #[error("validator not in committee: {validator_index}")]
    // ValidatorNotInCommittee { validator_index: ValidatorIndex },
}

impl ApiError for Error {
    fn sources(&self) -> impl Iterator<Item = &dyn StdError> {
        let first: &dyn StdError = self;

        let skip_duplicates = || match self {
            Self::InvalidQuery(_) => first.source()?.source()?.source(),
            _ => first.source(),
        };

        let mut next = skip_duplicates();

        core::iter::once(first).chain(core::iter::from_fn(move || {
            let source = next?.source();
            core::mem::replace(&mut next, source)
        }))
    }
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
        let extension = Extension(Arc::new(self));
        (status_code, extension, body).into_response()
    }
}

impl Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidJsonBody(json_rejection)
            | Self::InvalidValidatorIndices(json_rejection) => json_rejection.status(),
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
            | Self::InvalidColumnIndex(_)
            | Self::InvalidRequestConsensusHeader(_)
            | Self::InvalidContributionAndProofs(_)
            | Self::InvalidEpoch(_)
            | Self::InvalidQuery(_)
            | Self::InvalidPeerId(_)
            | Self::InvalidProposerSlashing(_)
            | Self::InvalidSignedVoluntaryExit(_)
            | Self::InvalidStateId(_)
            | Self::InvalidSignedBlsToExecutionChanges(_)
            | Self::InvalidSyncCommitteeMessages(_)
            | Self::InvalidRandaoReveal
            | Self::InvalidValidatorId(_)
            | Self::InvalidValidatorSignatures(_)
            | Self::ProposalSlotNotLaterThanStateSlot
            | Self::SlotNotInEpoch
            | Self::StatePreCapella
            | Self::StatePreElectra
            | Self::UnableToPublishBlock => StatusCode::BAD_REQUEST,
            // | Self::ValidatorNotInCommittee { .. }
            Self::Internal(_)
            | Self::Canceled(_)
            | Self::ExecutionPayloadNotAvailable
            | Self::LivenessTrackingNotEnabled
            | Self::SlotHeadNotAvailable
            | Self::TaskJoinFailed(_)
            | Self::UnableToProduceAttestation { .. }
            | Self::UnableToProduceBeaconBlock
            | Self::UnableToProduceBlindedBlock => StatusCode::INTERNAL_SERVER_ERROR,
            Self::EndpointNotImplemented => StatusCode::NOT_IMPLEMENTED,
            Self::BlockNotValidatedForAggregation { .. }
            | Self::HeadFarBehind { .. }
            | Self::HeadIsOptimistic
            | Self::NodeIsSyncing => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn body(&self) -> EthErrorResponse {
        EthErrorResponse {
            code: self.status_code().as_u16(),
            message: self,
            failures: self.failures(),
        }
    }

    #[expect(clippy::missing_const_for_fn, reason = "false positive")]
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

#[expect(
    clippy::needless_pass_by_value,
    reason = "Refactoring worsens readability, which is more important in tests."
)]
#[cfg(test)]
mod tests {
    use axum::extract::rejection::MissingJsonContentType;
    use itertools::Itertools as _;
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

    // Old versions of `axum::extract::rejection::JsonRejection` duplicate error sources.
    // The underlying bug in `axum-core` was fixed in <https://github.com/tokio-rs/axum/pull/2030>.
    // The fix was backported in <https://github.com/tokio-rs/axum/pull/2098> but not released.
    #[test]
    fn error_sources_does_not_yield_duplicates_from_json_rejection() {
        let error = Error::InvalidJsonBody(JsonRejection::from(MissingJsonContentType::default()));

        assert_eq!(
            error.sources().map(ToString::to_string).collect_vec(),
            [
                "invalid JSON body",
                "Expected request with `Content-Type: application/json`",
            ],
        );
    }
}
