use core::marker::PhantomData;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use ssz::{BitVector, ContiguousList, Hc, ProgressiveBitList, ProgressiveList, Ssz};
use xmss::{XmssPublicKey, XmssSignature};

use crate::{
    deneb::primitives::{Blob, KzgProof},
    electra::containers::{ConsolidationRequest, DepositRequest, WithdrawalRequest},
    gloas::{
        containers::{
            BuilderDepositRequest, BuilderExitRequest, ExecutionPayload, ExecutionPayloadBid,
            ExecutionPayloadHeader, PayloadAttestationData, ProposerPreferences,
        },
        primitives::BuilderIndex,
    },
    phase0::{
        containers::{AttestationData, BeaconBlockHeader, Deposit, Eth1Data},
        primitives::{CommitteeIndex, Epoch, ExecutionAddress, Gwei, H256, Slot, ValidatorIndex},
    },
    pq::primitives::{AttestationProof, VrfProof},
    preset::Preset,
};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct AggregateAndProof<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation<P>,
    pub proof: AttestationProof<P>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedAggregateAndProof<P: Preset> {
    pub message: AggregateAndProof<P>,
    pub signature: XmssSignature,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1, 1, 0, 1]))]
pub struct Attestation<P: Preset> {
    pub aggregation_bits: ProgressiveBitList<P::MaxAttestersPerSlot>,
    pub data: AttestationData,
    pub committee_bits: BitVector<P::MaxCommitteesPerSlotPq>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct AttesterSlashing<P: Preset> {
    pub attestation_1: IndexedAttestation<P>,
    pub attestation_2: IndexedAttestation<P>,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 3]))]
pub struct IndexedAttestation<P: Preset> {
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub attesting_indices: ProgressiveList<ValidatorIndex>,
    pub data: AttestationData,
    pub proof: AttestationProof<P>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BeaconBlock<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub proposer_index: ValidatorIndex,
    pub parent_root: H256,
    pub state_root: H256,
    pub body: BeaconBlockBody<P>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1]))]
pub struct BeaconBlockBody<P: Preset> {
    // A `VrfProof` is 1 KiB, so it is kept out of line like `ExecutionPayload.extra_data`.
    pub randao_reveal: Arc<VrfProof>,
    pub eth1_data: Eth1Data,
    pub graffiti: H256,
    pub proposer_slashings: ProgressiveList<ProposerSlashing>,
    pub attester_slashings: ProgressiveList<AttesterSlashing<P>>,
    pub attestations: ProgressiveList<Attestation<P>>,
    pub deposits: ProgressiveList<Deposit>,
    pub signed_execution_payload_bid: SignedExecutionPayloadBid<P>,
    pub parent_execution_requests: ExecutionRequests<P>,
    pub proof: AttestationProof<P>,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct Builder {
    pub pubkey: XmssPublicKey,
    #[serde(with = "serde_utils::string_or_native")]
    pub version: u8,
    pub execution_address: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    pub balance: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub deposit_epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    pub withdrawable_epoch: Epoch,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct BuilderPreregistration {
    pub pubkey: XmssPublicKey,
    pub withdrawal_credentials: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub expiry_slot: Slot,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct BuilderPreregistrationRequest {
    pub pubkey: XmssPublicKey,
    pub withdrawal_credentials: H256,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 5]))]
pub struct ExecutionPayloadEnvelope<P: Preset> {
    pub payload: ExecutionPayload<P>,
    pub execution_requests: ExecutionRequests<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_index: BuilderIndex,
    pub beacon_block_root: H256,
    pub parent_beacon_block_root: H256,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Ssz)]
#[ssz(stable(active = [1; 5]))]
pub struct BlindedExecutionPayloadEnvelope<P: Preset> {
    pub payload_header: ExecutionPayloadHeader<P>,
    pub execution_requests: ExecutionRequests<P>,
    pub builder_index: BuilderIndex,
    pub beacon_block_root: H256,
    pub parent_beacon_block_root: H256,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1, 1, 1, 1, 1, 0, 0, 1, 1, 1]))]
pub struct ExecutionRequests<P: Preset> {
    pub deposits: ProgressiveList<DepositRequest>,
    pub withdrawals: ProgressiveList<WithdrawalRequest>,
    pub consolidations: ProgressiveList<ConsolidationRequest>,
    pub builder_deposits: ProgressiveList<BuilderDepositRequest>,
    pub builder_exits: ProgressiveList<BuilderExitRequest>,
    pub validator_preregistrations: ProgressiveList<ValidatorPreregistrationRequest>,
    pub builder_preregistrations: ProgressiveList<BuilderPreregistrationRequest>,
    pub voluntary_exits: ProgressiveList<VoluntaryExitRequest>,
    #[ssz(skip)]
    #[serde(skip)]
    pub phantom: PhantomData<P>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Hash, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct PayloadAttestationMessage {
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub data: PayloadAttestationData,
    pub signature: XmssSignature,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedBeaconBlock<P: Preset> {
    pub message: Hc<BeaconBlock<P>>,
    pub signature: XmssSignature,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: XmssSignature,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedExecutionPayloadBid<P: Preset> {
    pub message: ExecutionPayloadBid<P>,
    pub signature: XmssSignature,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedExecutionPayloadEnvelope<P: Preset> {
    pub message: ExecutionPayloadEnvelope<P>,
    pub signature: XmssSignature,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Ssz)]
pub struct SignedBlindedExecutionPayloadEnvelope<P: Preset> {
    pub message: BlindedExecutionPayloadEnvelope<P>,
    pub signature: XmssSignature,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedExecutionPayloadEnvelopeContents<P: Preset> {
    pub signed_execution_payload_envelope: SignedExecutionPayloadEnvelope<P>,
    pub kzg_proofs: ContiguousList<KzgProof, P::MaxCellProofsPerBlock>,
    pub blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedProposerPreferences {
    pub message: ProposerPreferences,
    pub signature: XmssSignature,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Hash, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SingleAttestation {
    #[serde(with = "serde_utils::string_or_native")]
    pub committee_index: CommitteeIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub attester_index: ValidatorIndex,
    pub data: AttestationData,
    pub signature: XmssSignature,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    pub pubkey: XmssPublicKey,
    pub vrf_root: H256,
    pub withdrawal_credentials: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub effective_balance: Gwei,
    pub slashed: bool,
    #[serde(with = "serde_utils::string_or_native")]
    pub activation_eligibility_epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    pub activation_epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    pub exit_epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    pub withdrawable_epoch: Epoch,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ValidatorPreregistration {
    pub pubkey: XmssPublicKey,
    pub withdrawal_credentials: H256,
    pub vrf_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub expiry_slot: Slot,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ValidatorPreregistrationRequest {
    pub pubkey: XmssPublicKey,
    pub withdrawal_credentials: H256,
    pub vrf_root: H256,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct VoluntaryExitRequest {
    pub pubkey: XmssPublicKey,
}
