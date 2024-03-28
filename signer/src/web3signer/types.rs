use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use types::{phase0::primitives::H256, preset::Preset};

use crate::types::{ForkInfo, SigningMessage};

#[derive(Debug, Serialize)]
#[serde(bound = "")]
pub struct SigningRequest<'block, P: Preset> {
    // `type` is a keyword in Rust.
    #[serde(rename = "type")]
    message_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    fork_info: Option<ForkInfo<P>>,
    #[serde(rename = "signingRoot")]
    signing_root: H256,
    #[serde(flatten)]
    message: SigningMessage<'block, P>,
}

impl<'block, P: Preset> SigningRequest<'block, P> {
    pub const fn new(
        message: SigningMessage<'block, P>,
        signing_root: H256,
        fork_info: Option<ForkInfo<P>>,
    ) -> Self {
        let message_type = match message {
            SigningMessage::AggregationSlot { .. } => MessageType::AggregationSlot,
            SigningMessage::AggregateAndProof(_) => MessageType::AggregateAndProof,
            SigningMessage::Attestation(_) => MessageType::Attestation,
            SigningMessage::BeaconBlock { .. } => MessageType::BlockV2,
            SigningMessage::RandaoReveal { .. } => MessageType::RandaoReveal,
            SigningMessage::SyncCommitteeMessage { .. } => MessageType::SyncCommitteeMessage,
            SigningMessage::SyncAggregatorSelectionData(_) => {
                MessageType::SyncCommitteeSelectionProof
            }
            SigningMessage::ContributionAndProof(_) => {
                MessageType::SyncCommitteeContributionAndProof
            }
            SigningMessage::ValidatorRegistration(_) => MessageType::ValidatorRegistration,
            SigningMessage::VoluntaryExit(_) => MessageType::VoluntaryExit,
        };

        Self {
            message_type,
            fork_info,
            signing_root,
            message,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(test, derive(Clone, Copy, Deserialize))]
enum MessageType {
    AggregationSlot,
    AggregateAndProof,
    Attestation,
    BlockV2,
    RandaoReveal,
    SyncCommitteeMessage,
    SyncCommitteeSelectionProof,
    SyncCommitteeContributionAndProof,
    ValidatorRegistration,
    VoluntaryExit,
}

#[derive(Debug, Deserialize)]
pub struct SigningResponse {
    pub signature: SignatureBytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    // This exists mainly to ensure `MessageType::BlockV2` is renamed correctly.
    #[test]
    fn message_type_is_serialized_correctly() {
        assert_eq!(
            serde_aux::serde_introspection::serde_introspect::<MessageType>(),
            [
                "AGGREGATION_SLOT",
                "AGGREGATE_AND_PROOF",
                "ATTESTATION",
                "BLOCK_V2",
                "RANDAO_REVEAL",
                "SYNC_COMMITTEE_MESSAGE",
                "SYNC_COMMITTEE_SELECTION_PROOF",
                "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
                "VALIDATOR_REGISTRATION",
                "VOLUNTARY_EXIT",
            ],
        );
    }
}
