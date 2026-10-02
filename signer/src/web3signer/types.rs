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
            SigningMessage::ExecutionPayloadEnvelope(_) => MessageType::ExecutionPayloadEnvelope,
            SigningMessage::RandaoReveal { .. } => MessageType::RandaoReveal,
            SigningMessage::PayloadAttestation(_) => MessageType::PayloadAttestation,
            SigningMessage::SyncCommitteeMessage { .. } => MessageType::SyncCommitteeMessage,
            SigningMessage::SyncAggregatorSelectionData(_) => {
                MessageType::SyncCommitteeSelectionProof
            }
            SigningMessage::ContributionAndProof(_) => {
                MessageType::SyncCommitteeContributionAndProof
            }
            SigningMessage::ValidatorRegistration(_) => MessageType::ValidatorRegistration,
            SigningMessage::VoluntaryExit(_) => MessageType::VoluntaryExit,
            SigningMessage::ProposerPreferences(_) => MessageType::ProposerPreferences,
            SigningMessage::BuilderRequestAuth(_) => MessageType::BuilderRequestAuth,
        };

        Self {
            message_type,
            fork_info,
            signing_root,
            message,
        }
    }
}

// TODO(gloas): Currently, Web3signer only plans to support payload attestation message signing,
// See this PR for details: https://github.com/Consensys/web3signer/pull/1159, but we expect them
// to add support for builder message signing in the future. When that happens, we can remove this.
// TODO
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(test, derive(Clone, Copy, Deserialize))]
enum MessageType {
    AggregationSlot,
    AggregateAndProof,
    Attestation,
    BlockV2,
    ExecutionPayloadEnvelope,
    RandaoReveal,
    PayloadAttestation,
    SyncCommitteeMessage,
    SyncCommitteeSelectionProof,
    SyncCommitteeContributionAndProof,
    ValidatorRegistration,
    VoluntaryExit,
    ProposerPreferences,
    BuilderRequestAuth,
}

#[derive(Debug, Deserialize)]
pub struct SigningResponse {
    pub signature: SignatureBytes,
}

#[cfg(test)]
mod tests {
    use builder_api::gloas::containers::BuilderRequestAuth;
    use serde_json::json;
    use types::preset::Mainnet;

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
                "EXECUTION_PAYLOAD_ENVELOPE",
                "RANDAO_REVEAL",
                "PAYLOAD_ATTESTATION",
                "SYNC_COMMITTEE_MESSAGE",
                "SYNC_COMMITTEE_SELECTION_PROOF",
                "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
                "VALIDATOR_REGISTRATION",
                "VOLUNTARY_EXIT",
                "PROPOSER_PREFERENCES",
                "BUILDER_REQUEST_AUTH",
            ],
        );
    }

    // from <https://github.com/ethereum/remote-signing-api/blob/master/signing/paths/sign.yaml>
    #[test]
    fn builder_request_auth_request_matches_the_remote_signing_api() {
        let builder_request_auth = BuilderRequestAuth {
            data: b"builder.example.org"
                .to_vec()
                .try_into()
                .expect("auth data fits in MaxBuilderAuthDataSize"),
            slot: 32,
        };

        let request = SigningRequest::<Mainnet>::new(
            SigningMessage::from(builder_request_auth),
            H256::zero(),
            None,
        );

        assert_eq!(
            serde_json::to_value(request).expect("request should serialize"),
            json!({
                "type": "BUILDER_REQUEST_AUTH",
                "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "builder_request_auth": {
                    "version": "GLOAS",
                    "data": {
                        "data": "0x6275696c6465722e6578616d706c652e6f7267",
                        "slot": "32",
                    },
                },
            }),
        );
    }
}
