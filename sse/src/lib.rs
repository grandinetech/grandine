//! Server-sent event types for the Eth Beacon Node API event stream
//! (`GET /eth/v1/events`).
//!
//! This crate holds the wire-format data-transfer objects, the [`Event`] and
//! [`Topic`] enums, and the constructors that build the DTOs from in-process
//! values. They derive both `Serialize` and `Deserialize` so a consumer (e.g.
//! the standalone builder client) can decode the stream without depending on
//! the fork-choice stack.
//!
//! The fork-choice-coupled constructors (chain reorg, head) and the
//! `EventChannels` broadcast wiring live in `fork_choice_control`, since they
//! depend on `fork_choice_store`.

use std::sync::Arc;

use duplicate::duplicate_item;
use execution_engine::{
    PayloadAttributes, PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3,
    PayloadAttributesV4, WithdrawalV1,
};
use helper_functions::misc;
use serde::{Deserialize, Serialize};
use serde_with::DeserializeFromStr;
use ssz::ContiguousList;
use strum::{AsRefStr, EnumString};
use types::{
    altair::containers::SignedContributionAndProof,
    bellatrix::primitives::Gas,
    capella::{
        containers::{SignedBlsToExecutionChange, Withdrawal},
        primitives::WithdrawalIndex,
    },
    combined::{Attestation, AttesterSlashing, DataColumnSidecar},
    deneb::{
        containers::BlobSidecar,
        primitives::{BlobIndex, KzgCommitment, VersionedHash},
    },
    electra::containers::SingleAttestation,
    fulu::primitives::ColumnIndex,
    gloas::{
        containers::{
            PayloadAttestationMessage, SignedExecutionPayloadBid, SignedProposerPreferences,
        },
        primitives::BuilderIndex,
    },
    nonstandard::{PayloadPresence, Phase},
    phase0::{
        containers::{ProposerSlashing, SignedVoluntaryExit},
        primitives::{
            Epoch, ExecutionAddress, ExecutionBlockHash, ExecutionBlockNumber, Gwei, H256, Slot,
            UnixSeconds, ValidatorIndex,
        },
    },
    preset::Preset,
};

#[derive(Clone, Copy, AsRefStr, EnumString, DeserializeFromStr)]
#[strum(serialize_all = "snake_case")]
pub enum Topic {
    Attestation,
    AttesterSlashing,
    BlobSidecar,
    Block,
    BlockGossip,
    BlsToExecutionChange,
    ChainReorg,
    ContributionAndProof,
    DataColumnSidecar,
    ExecutionPayload,
    ExecutionPayloadBid,
    ExecutionPayloadAvailable,
    ExecutionPayloadGossip,
    FinalizedCheckpoint,
    Head,
    HeadV2,
    PayloadAttestationMessage,
    PayloadAttributes,
    ProposerPreferences,
    ProposerSlashing,
    SingleAttestation,
    VoluntaryExit,
}

#[derive(Clone, Debug)]
pub enum Event<P: Preset> {
    Attestation(Arc<Attestation<P>>),
    AttesterSlashing(Box<AttesterSlashing<P>>),
    BlobSidecar(BlobSidecarEvent),
    Block(BlockEvent),
    BlockGossip(BlockGossipEvent),
    BlsToExecutionChange(Box<SignedBlsToExecutionChange>),
    ChainReorg(ChainReorgEvent),
    ContributionAndProof(Box<SignedContributionAndProof<P>>),
    DataColumnSidecar(DataColumnSidecarEvent<P>),
    ExecutionPayload(ExecutionPayloadEvent),
    ExecutionPayloadAvailable(ExecutionPayloadAvailableEvent),
    ExecutionPayloadBid(ExecutionPayloadBidEvent<P>),
    ExecutionPayloadGossip(ExecutionPayloadGossipEvent),
    FinalizedCheckpoint(FinalizedCheckpointEvent),
    Head(HeadEvent),
    HeadV2(HeadV2Event),
    PayloadAttestation(PayloadAttestationEvent),
    PayloadAttributes(PayloadAttributesEvent),
    ProposerPreferences(ProposerPreferencesEvent),
    ProposerSlashing(Box<ProposerSlashing>),
    SingleAttestation(SingleAttestation),
    VoluntaryExit(Box<SignedVoluntaryExit>),
}

impl<P: Preset> Event<P> {
    #[must_use]
    pub const fn topic(&self) -> Topic {
        match self {
            Self::Attestation(_) => Topic::Attestation,
            Self::AttesterSlashing(_) => Topic::AttesterSlashing,
            Self::BlobSidecar(_) => Topic::BlobSidecar,
            Self::Block(_) => Topic::Block,
            Self::BlockGossip(_) => Topic::BlockGossip,
            Self::BlsToExecutionChange(_) => Topic::BlsToExecutionChange,
            Self::ChainReorg(_) => Topic::ChainReorg,
            Self::ContributionAndProof(_) => Topic::ContributionAndProof,
            Self::DataColumnSidecar(_) => Topic::DataColumnSidecar,
            Self::ExecutionPayload(_) => Topic::ExecutionPayload,
            Self::ExecutionPayloadAvailable(_) => Topic::ExecutionPayloadAvailable,
            Self::ExecutionPayloadBid(_) => Topic::ExecutionPayloadBid,
            Self::ExecutionPayloadGossip(_) => Topic::ExecutionPayloadGossip,
            Self::FinalizedCheckpoint(_) => Topic::FinalizedCheckpoint,
            Self::Head(_) => Topic::Head,
            Self::HeadV2(_) => Topic::HeadV2,
            Self::PayloadAttestation(_) => Topic::PayloadAttestationMessage,
            Self::PayloadAttributes(_) => Topic::PayloadAttributes,
            Self::ProposerPreferences(_) => Topic::ProposerPreferences,
            Self::ProposerSlashing(_) => Topic::ProposerSlashing,
            Self::SingleAttestation(_) => Topic::SingleAttestation,
            Self::VoluntaryExit(_) => Topic::VoluntaryExit,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BlobSidecarEvent {
    pub block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub index: BlobIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub kzg_commitment: KzgCommitment,
    pub versioned_hash: VersionedHash,
}

impl BlobSidecarEvent {
    #[must_use]
    pub fn new<P: Preset>(block_root: H256, blob_sidecar: &BlobSidecar<P>) -> Self {
        let kzg_commitment = blob_sidecar.kzg_commitment;

        Self {
            block_root,
            index: blob_sidecar.index,
            slot: blob_sidecar.slot(),
            kzg_commitment,
            versioned_hash: misc::kzg_commitment_to_versioned_hash(kzg_commitment),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BlockEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub block: H256,
    pub execution_optimistic: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BlockGossipEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub block: H256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DataColumnSidecarEvent<P: Preset> {
    pub block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub index: ColumnIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kzg_commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
}

impl<P: Preset> DataColumnSidecarEvent<P> {
    #[must_use]
    pub fn new(block_root: H256, data_column_sidecar: &DataColumnSidecar<P>) -> Self {
        Self {
            block_root,
            index: data_column_sidecar.index(),
            slot: data_column_sidecar.slot(),
            kzg_commitments: data_column_sidecar.kzg_commitments().cloned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ExecutionPayloadEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_index: BuilderIndex,
    pub block_hash: ExecutionBlockHash,
    pub block_root: H256,
    pub execution_optimistic: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ExecutionPayloadGossipEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_index: BuilderIndex,
    pub block_hash: ExecutionBlockHash,
    pub block_root: H256,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ExecutionPayloadAvailableEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub block_root: H256,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ChainReorgEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub depth: u64,
    pub old_head_block: H256,
    pub new_head_block: H256,
    pub old_head_state: H256,
    pub new_head_state: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
    pub execution_optimistic: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct FinalizedCheckpointEvent {
    pub block: H256,
    pub state: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
    pub execution_optimistic: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct HeadEvent {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub block: H256,
    pub state: H256,
    pub epoch_transition: bool,
    pub previous_duty_dependent_root: H256,
    pub current_duty_dependent_root: H256,
    pub execution_optimistic: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct HeadV2Event {
    pub version: Phase,
    pub data: HeadV2EventData,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct HeadV2EventData {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub block: H256,
    pub state: H256,
    pub payload_status: PayloadPresence,
    pub epoch_transition: bool,
    pub current_epoch_dependent_root: H256,
    pub next_epoch_dependent_root: H256,
    pub execution_optimistic: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PayloadAttestationEvent {
    pub version: Phase,
    pub data: PayloadAttestationMessage,
}

impl PayloadAttestationEvent {
    #[must_use]
    pub fn new(phase: Phase, payload_attestation: &Arc<PayloadAttestationMessage>) -> Self {
        Self {
            version: phase,
            data: PayloadAttestationMessage {
                validator_index: payload_attestation.validator_index,
                data: payload_attestation.data,
                signature: payload_attestation.signature,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ExecutionPayloadBidEvent<P: Preset> {
    pub version: Phase,
    pub data: Arc<SignedExecutionPayloadBid<P>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposerPreferencesEvent {
    pub version: Phase,
    pub data: Arc<SignedProposerPreferences>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "version", content = "data", rename_all = "lowercase")]
pub enum PayloadAttributesEvent {
    Bellatrix(PayloadAttributesEventData<PayloadAttributesEventDataV1>),
    Capella(PayloadAttributesEventData<PayloadAttributesEventDataV2>),
    Deneb(PayloadAttributesEventData<PayloadAttributesEventDataV3>),
    Electra(PayloadAttributesEventData<PayloadAttributesEventDataV3>),
    Fulu(PayloadAttributesEventData<PayloadAttributesEventDataV3>),
    Gloas(PayloadAttributesEventData<PayloadAttributesEventDataV4>),
}

impl PayloadAttributesEvent {
    #[must_use]
    pub fn new<P: Preset>(
        proposal_slot: Slot,
        parent_block_root: H256,
        parent_block_number: Option<ExecutionBlockNumber>,
        parent_block_hash: ExecutionBlockHash,
        proposer_index: ValidatorIndex,
        payload_attributes: PayloadAttributes<P>,
    ) -> Self {
        macro_rules! data {
            ($body: expr) => {
                PayloadAttributesEventData {
                    proposal_slot,
                    parent_block_root,
                    parent_block_number,
                    parent_block_hash,
                    proposer_index,
                    payload_attributes: $body,
                }
            };
        }

        match payload_attributes {
            PayloadAttributes::Bellatrix(attrs) => Self::Bellatrix(data!(attrs.into())),
            PayloadAttributes::Capella(attrs) => Self::Capella(data!(attrs.into())),
            PayloadAttributes::Deneb(attrs) => Self::Deneb(data!(attrs.into())),
            PayloadAttributes::Electra(attrs) => Self::Electra(data!(attrs.into())),
            PayloadAttributes::Fulu(attrs) => Self::Fulu(data!(attrs.into())),
            PayloadAttributes::Gloas(attrs) => Self::Gloas(data!(attrs.into())),
        }
    }

    #[must_use]
    pub const fn version(&self) -> Phase {
        match self {
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
            Self::Fulu(_) => Phase::Fulu,
            Self::Gloas(_) => Phase::Gloas,
        }
    }
}

#[duplicate_item(
    method                 return_type;
    [proposal_slot]        [Slot];
    [parent_block_root]    [H256];
    [parent_block_number]  [Option<ExecutionBlockNumber>];
    [parent_block_hash]    [ExecutionBlockHash];
    [proposer_index]       [ValidatorIndex];
)]
impl PayloadAttributesEvent {
    #[must_use]
    pub fn method(&self) -> return_type {
        match self {
            Self::Bellatrix(data) => data.method,
            Self::Capella(data) => data.method,
            Self::Deneb(data) => data.method,
            Self::Electra(data) => data.method,
            Self::Fulu(data) => data.method,
            Self::Gloas(data) => data.method,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadAttributesEventData<PA: PayloadAttributesData> {
    #[serde(with = "serde_utils::string_or_native")]
    pub proposal_slot: Slot,
    pub parent_block_root: H256,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::string_or_native_option"
    )]
    pub parent_block_number: Option<ExecutionBlockNumber>,
    pub parent_block_hash: ExecutionBlockHash,
    #[serde(with = "serde_utils::string_or_native")]
    pub proposer_index: ValidatorIndex,
    pub payload_attributes: PA,
}

pub trait PayloadAttributesData: Clone {
    fn timestamp(&self) -> UnixSeconds;
    fn prev_randao(&self) -> H256;
    fn suggested_fee_recipient(&self) -> ExecutionAddress;
    fn withdrawals(&self) -> Option<&Vec<WithdrawalEventDataV1>>;
    fn parent_beacon_block_root(&self) -> Option<H256>;
    fn slot_number(&self) -> Option<Slot>;
    fn target_gas_limit(&self) -> Option<Gas>;
}

#[duplicate_item(
    implementor                     get_withdrawals            get_parent                             get_slot                    get_target;
    [PayloadAttributesEventDataV1]  [None]                     [None]                                 [None]                      [None];
    [PayloadAttributesEventDataV2]  [Some(&self.withdrawals)]  [None]                                 [None]                      [None];
    [PayloadAttributesEventDataV3]  [Some(&self.withdrawals)]  [Some(self.parent_beacon_block_root)]  [None]                      [None];
    [PayloadAttributesEventDataV4]  [Some(&self.withdrawals)]  [Some(self.parent_beacon_block_root)]  [Some(self.slot_number)]    [Some(self.target_gas_limit)];
)]
impl PayloadAttributesData for implementor {
    fn timestamp(&self) -> UnixSeconds {
        self.timestamp
    }

    fn prev_randao(&self) -> H256 {
        self.prev_randao
    }

    fn suggested_fee_recipient(&self) -> ExecutionAddress {
        self.suggested_fee_recipient
    }

    fn withdrawals(&self) -> Option<&Vec<WithdrawalEventDataV1>> {
        get_withdrawals
    }

    fn parent_beacon_block_root(&self) -> Option<H256> {
        get_parent
    }

    fn slot_number(&self) -> Option<Slot> {
        get_slot
    }

    fn target_gas_limit(&self) -> Option<Gas> {
        get_target
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PayloadAttributesEventDataV1 {
    #[serde(with = "serde_utils::string_or_native")]
    pub timestamp: UnixSeconds,
    pub prev_randao: H256,
    pub suggested_fee_recipient: ExecutionAddress,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadAttributesEventDataV2 {
    #[serde(with = "serde_utils::string_or_native")]
    pub timestamp: UnixSeconds,
    pub prev_randao: H256,
    pub suggested_fee_recipient: ExecutionAddress,
    pub withdrawals: Vec<WithdrawalEventDataV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadAttributesEventDataV3 {
    #[serde(with = "serde_utils::string_or_native")]
    pub timestamp: UnixSeconds,
    pub prev_randao: H256,
    pub suggested_fee_recipient: ExecutionAddress,
    pub withdrawals: Vec<WithdrawalEventDataV1>,
    pub parent_beacon_block_root: H256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadAttributesEventDataV4 {
    #[serde(with = "serde_utils::string_or_native")]
    pub timestamp: UnixSeconds,
    pub prev_randao: H256,
    pub suggested_fee_recipient: ExecutionAddress,
    pub withdrawals: Vec<WithdrawalEventDataV1>,
    pub parent_beacon_block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot_number: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub target_gas_limit: Gas,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct WithdrawalEventDataV1 {
    #[serde(with = "serde_utils::string_or_native")]
    pub index: WithdrawalIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub address: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
}

impl From<WithdrawalEventDataV1> for Withdrawal {
    fn from(withdrawal: WithdrawalEventDataV1) -> Self {
        let WithdrawalEventDataV1 {
            index,
            validator_index,
            address,
            amount,
        } = withdrawal;

        Self {
            index,
            validator_index,
            address,
            amount,
        }
    }
}

impl From<WithdrawalV1> for WithdrawalEventDataV1 {
    fn from(withdrawal: WithdrawalV1) -> Self {
        let WithdrawalV1 {
            index,
            validator_index,
            address,
            amount,
        } = withdrawal;

        Self {
            index,
            validator_index,
            address,
            amount,
        }
    }
}

impl From<WithdrawalEventDataV1> for WithdrawalV1 {
    fn from(withdrawal: WithdrawalEventDataV1) -> Self {
        let WithdrawalEventDataV1 {
            index,
            validator_index,
            address,
            amount,
        } = withdrawal;

        Self {
            index,
            validator_index,
            address,
            amount,
        }
    }
}

impl From<PayloadAttributesV1> for PayloadAttributesEventDataV1 {
    fn from(payload_attributes: PayloadAttributesV1) -> Self {
        let PayloadAttributesV1 {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
        } = payload_attributes;

        Self {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
        }
    }
}

impl<P: Preset> From<PayloadAttributesV2<P>> for PayloadAttributesEventDataV2 {
    fn from(payload_attributes: PayloadAttributesV2<P>) -> Self {
        let PayloadAttributesV2 {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            withdrawals,
        } = payload_attributes;

        Self {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            withdrawals: withdrawals.into_iter().map(Into::into).collect::<Vec<_>>(),
        }
    }
}

impl<P: Preset> From<PayloadAttributesV3<P>> for PayloadAttributesEventDataV3 {
    fn from(payload_attributes: PayloadAttributesV3<P>) -> Self {
        let PayloadAttributesV3 {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            withdrawals,
            parent_beacon_block_root,
        } = payload_attributes;

        Self {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            withdrawals: withdrawals.into_iter().map(Into::into).collect::<Vec<_>>(),
            parent_beacon_block_root,
        }
    }
}

impl<P: Preset> From<PayloadAttributesV4<P>> for PayloadAttributesEventDataV4 {
    fn from(payload_attributes: PayloadAttributesV4<P>) -> Self {
        let PayloadAttributesV4 {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            withdrawals,
            parent_beacon_block_root,
            slot_number,
            target_gas_limit,
        } = payload_attributes;

        Self {
            timestamp,
            prev_randao,
            suggested_fee_recipient,
            withdrawals: withdrawals.into_iter().map(Into::into).collect::<Vec<_>>(),
            parent_beacon_block_root,
            slot_number,
            target_gas_limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use types::nonstandard::Phase;

    use super::PayloadAttributesEvent;

    // Inner `payload_attributes` bodies, one per wire schema version. Each higher
    // version is a strict superset of the one before, which is exactly what breaks
    // naive `untagged` deserialization.
    const V1_BODY: &str = r#"{
        "timestamp": "1700000000",
        "prev_randao": "0x0101010101010101010101010101010101010101010101010101010101010101",
        "suggested_fee_recipient": "0x0202020202020202020202020202020202020202"
    }"#;

    const V2_BODY: &str = r#"{
        "timestamp": "1700000000",
        "prev_randao": "0x0101010101010101010101010101010101010101010101010101010101010101",
        "suggested_fee_recipient": "0x0202020202020202020202020202020202020202",
        "withdrawals": []
    }"#;

    const V3_BODY: &str = r#"{
        "timestamp": "1700000000",
        "prev_randao": "0x0101010101010101010101010101010101010101010101010101010101010101",
        "suggested_fee_recipient": "0x0202020202020202020202020202020202020202",
        "withdrawals": [],
        "parent_beacon_block_root": "0x0303030303030303030303030303030303030303030303030303030303030303"
    }"#;

    const V4_BODY: &str = r#"{
        "timestamp": "1700000000",
        "prev_randao": "0x0101010101010101010101010101010101010101010101010101010101010101",
        "suggested_fee_recipient": "0x0202020202020202020202020202020202020202",
        "withdrawals": [],
        "parent_beacon_block_root": "0x0303030303030303030303030303030303030303030303030303030303030303",
        "slot_number": "12345",
        "target_gas_limit": "30000000"
    }"#;

    fn event_json(version: &str, payload_attributes: &str) -> String {
        format!(
            r#"{{
                "version": "{version}",
                "data": {{
                    "proposal_slot": "999",
                    "parent_block_root": "0x0404040404040404040404040404040404040404040404040404040404040404",
                    "parent_block_hash": "0x0505050505050505050505050505050505050505050505050505050505050505",
                    "proposer_index": "7",
                    "payload_attributes": {payload_attributes}
                }}
            }}"#
        )
    }

    fn parse(version: &str, body: &str) -> PayloadAttributesEvent {
        serde_json::from_str(&event_json(version, body)).expect("event should deserialize")
    }

    /// Serialize `event`, deserialize the result, and assert the trip is lossless
    /// at the JSON level. Returns the reparsed event so callers can assert on it
    /// knowing their assertions survive a full serialize/deserialize cycle — the
    /// adjacently-tagged `Serialize`/`Deserialize` derives are exact inverses.
    fn round_trip(event: &PayloadAttributesEvent) -> PayloadAttributesEvent {
        let json = serde_json::to_value(event).expect("event should serialize");
        let reparsed: PayloadAttributesEvent =
            serde_json::from_value(json.clone()).expect("serialized event should deserialize");
        let reserialized =
            serde_json::to_value(&reparsed).expect("reparsed event should serialize");
        assert_eq!(
            json, reserialized,
            "serialize/deserialize round trip must be lossless"
        );
        reparsed
    }

    fn variant_name(event: &PayloadAttributesEvent) -> &'static str {
        match event {
            PayloadAttributesEvent::Bellatrix(_) => "Bellatrix",
            PayloadAttributesEvent::Capella(_) => "Capella",
            PayloadAttributesEvent::Deneb(_) => "Deneb",
            PayloadAttributesEvent::Electra(_) => "Electra",
            PayloadAttributesEvent::Fulu(_) => "Fulu",
            PayloadAttributesEvent::Gloas(_) => "Gloas",
        }
    }

    #[test]
    fn version_selects_matching_variant_for_each_fork() {
        for (version, body, expected) in [
            ("bellatrix", V1_BODY, "Bellatrix"),
            ("capella", V2_BODY, "Capella"),
            ("deneb", V3_BODY, "Deneb"),
            ("electra", V3_BODY, "Electra"),
            ("fulu", V3_BODY, "Fulu"),
            ("gloas", V4_BODY, "Gloas"),
        ] {
            // The variant must survive a full serialize/deserialize round trip,
            // not just the initial parse.
            let event = round_trip(&parse(version, body));
            assert_eq!(variant_name(&event), expected);
        }
    }

    /// Deneb, Electra, and Fulu share one body schema (`V3`), so `version` is the
    /// only thing that can tell them apart — a purely structural scheme cannot.
    /// Serializing must re-emit `version`, so the round trip preserves the variant.
    #[test]
    fn identical_v3_body_disambiguated_by_version() {
        assert_eq!(variant_name(&round_trip(&parse("deneb", V3_BODY))), "Deneb");
        assert_eq!(
            variant_name(&round_trip(&parse("electra", V3_BODY))),
            "Electra"
        );
        assert_eq!(variant_name(&round_trip(&parse("fulu", V3_BODY))), "Fulu");
    }

    /// A Gloas body is a superset of every earlier variant's shape, so naive
    /// `untagged` matching would pick `Bellatrix` (the least-specific fit). Prove
    /// the version-driven deserializer picks `Gloas` and parses the V4-only fields,
    /// and that all of it survives a serialize/deserialize round trip.
    #[test]
    fn gloas_body_selects_gloas_and_parses_v4_fields() {
        let event = round_trip(&parse("gloas", V4_BODY));

        assert_eq!(event.version(), Phase::Gloas);
        assert_eq!(event.proposal_slot(), 999);
        assert_eq!(event.proposer_index(), 7);

        let PayloadAttributesEvent::Gloas(data) = &event else {
            panic!("expected Gloas variant");
        };
        let v4 = &data.payload_attributes;

        assert_eq!(v4.timestamp, 1_700_000_000);
        assert_eq!(v4.slot_number, 12_345);
        assert_eq!(v4.target_gas_limit, 30_000_000);
    }

    /// Pre-Bellatrix phases carry no execution payload attributes, so such an
    /// event has no variant to map to and must fail rather than parse silently.
    /// Take the serialized form of a valid event, rewrite `version` to a
    /// pre-Bellatrix phase, and confirm deserialization on the round trip rejects
    /// it — the version check guards the decode path, not just hand-written JSON.
    #[test]
    fn pre_bellatrix_version_is_rejected() {
        let mut json =
            serde_json::to_value(&parse("gloas", V4_BODY)).expect("event should serialize");
        json["version"] = serde_json::Value::String("phase0".to_owned());

        let result: Result<PayloadAttributesEvent, _> = serde_json::from_value(json);

        assert!(
            result.is_err(),
            "pre-Bellatrix payload_attributes event must be rejected",
        );
    }
}
