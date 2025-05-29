use bls::{AggregateSignatureBytes, PublicKeyBytes, SignatureBytes};
use serde::{Deserialize, Serialize};
use ssz::{BitList, BitVector, ContiguousList, ContiguousVector, Ssz};
use typenum::Log2;

use crate::{
    altair::containers::{SyncAggregate, SyncCommittee},
    capella::{consts::ExecutionPayloadIndex, containers::SignedBlsToExecutionChange},
    deneb::{
        containers::{ExecutionPayload, ExecutionPayloadHeader},
        primitives::KzgCommitment,
    },
    electra::consts::{CurrentSyncCommitteeIndex, FinalizedRootIndex, NextSyncCommitteeIndex},
    phase0::{
        containers::{
            AttestationData, BeaconBlockHeader, Deposit, Eth1Data, ProposerSlashing,
            SignedVoluntaryExit,
        },
        primitives::{CommitteeIndex, Epoch, ExecutionAddress, Gwei, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct AggregateAndProof<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation<P>,
    pub selection_proof: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct Attestation<P: Preset> {
    pub aggregation_bits: BitList<P::MaxAttestersPerSlot>,
    pub data: AttestationData,
    pub signature: AggregateSignatureBytes,
    pub committee_bits: BitVector<P::MaxCommitteesPerSlot>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct AttesterSlashing<P: Preset> {
    pub attestation_1: IndexedAttestation<P>,
    pub attestation_2: IndexedAttestation<P>,
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
pub struct BeaconBlockBody<P: Preset> {
    pub randao_reveal: SignatureBytes,
    pub eth1_data: Eth1Data,
    pub graffiti: H256,
    pub proposer_slashings: ContiguousList<ProposerSlashing, P::MaxProposerSlashings>,
    pub attester_slashings: ContiguousList<AttesterSlashing<P>, P::MaxAttesterSlashingsElectra>,
    pub attestations: ContiguousList<Attestation<P>, P::MaxAttestationsElectra>,
    pub deposits: ContiguousList<Deposit, P::MaxDeposits>,
    pub voluntary_exits: ContiguousList<SignedVoluntaryExit, P::MaxVoluntaryExits>,
    pub sync_aggregate: SyncAggregate<P>,
    pub execution_payload: ExecutionPayload<P>,
    pub bls_to_execution_changes:
        ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges>,
    pub blob_kzg_commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
    pub execution_requests: ExecutionRequests<P>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BlindedBeaconBlock<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub proposer_index: ValidatorIndex,
    pub parent_root: H256,
    pub state_root: H256,
    pub body: BlindedBeaconBlockBody<P>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BlindedBeaconBlockBody<P: Preset> {
    pub randao_reveal: SignatureBytes,
    pub eth1_data: Eth1Data,
    pub graffiti: H256,
    pub proposer_slashings: ContiguousList<ProposerSlashing, P::MaxProposerSlashings>,
    pub attester_slashings: ContiguousList<AttesterSlashing<P>, P::MaxAttesterSlashingsElectra>,
    pub attestations: ContiguousList<Attestation<P>, P::MaxAttestationsElectra>,
    pub deposits: ContiguousList<Deposit, P::MaxDeposits>,
    pub voluntary_exits: ContiguousList<SignedVoluntaryExit, P::MaxVoluntaryExits>,
    pub sync_aggregate: SyncAggregate<P>,
    pub execution_payload_header: ExecutionPayloadHeader<P>,
    pub bls_to_execution_changes:
        ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges>,
    pub blob_kzg_commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
    pub execution_requests: ExecutionRequests<P>,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct DepositRequest {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
    pub signature: SignatureBytes,
    #[serde(with = "serde_utils::string_or_native")]
    pub index: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalRequest {
    pub source_address: ExecutionAddress,
    pub validator_pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct ExecutionRequests<P: Preset> {
    pub deposits: ContiguousList<DepositRequest, P::MaxDepositRequestsPerPayload>,
    pub withdrawals: ContiguousList<WithdrawalRequest, P::MaxWithdrawalRequestsPerPayload>,
    pub consolidations: ContiguousList<ConsolidationRequest, P::MaxConsolidationRequestsPerPayload>,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct IndexedAttestation<P: Preset> {
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub attesting_indices: ContiguousList<ValidatorIndex, P::MaxAttestersPerSlot>,
    pub data: AttestationData,
    pub signature: AggregateSignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientBootstrap<P: Preset> {
    pub header: LightClientHeader<P>,
    pub current_sync_committee: SyncCommittee<P>,
    pub current_sync_committee_branch: ContiguousVector<H256, Log2<CurrentSyncCommitteeIndex>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientFinalityUpdate<P: Preset> {
    pub attested_header: LightClientHeader<P>,
    pub finalized_header: LightClientHeader<P>,
    pub finality_branch: ContiguousVector<H256, Log2<FinalizedRootIndex>>,
    pub sync_aggregate: SyncAggregate<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub signature_slot: Slot,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientHeader<P: Preset> {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeader<P>,
    pub execution_branch: ContiguousVector<H256, Log2<ExecutionPayloadIndex>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientOptimisticUpdate<P: Preset> {
    pub attested_header: LightClientHeader<P>,
    pub sync_aggregate: SyncAggregate<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub signature_slot: Slot,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientUpdate<P: Preset> {
    pub attested_header: LightClientHeader<P>,
    pub next_sync_committee: SyncCommittee<P>,
    pub next_sync_committee_branch: ContiguousVector<H256, Log2<NextSyncCommitteeIndex>>,
    pub finalized_header: LightClientHeader<P>,
    pub finality_branch: ContiguousVector<H256, Log2<FinalizedRootIndex>>,
    pub sync_aggregate: SyncAggregate<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub signature_slot: Slot,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct PendingDeposit {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
    pub signature: SignatureBytes,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct PendingConsolidation {
    #[serde(with = "serde_utils::string_or_native")]
    pub source_index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub target_index: ValidatorIndex,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct PendingPartialWithdrawal {
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub withdrawable_epoch: Epoch,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedAggregateAndProof<P: Preset> {
    pub message: AggregateAndProof<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedBeaconBlock<P: Preset> {
    pub message: BeaconBlock<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedBlindedBeaconBlock<P: Preset> {
    pub message: BlindedBeaconBlock<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SingleAttestation {
    #[serde(with = "serde_utils::string_or_native")]
    pub committee_index: CommitteeIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub attester_index: ValidatorIndex,
    pub data: AttestationData,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationRequest {
    pub source_address: ExecutionAddress,
    pub source_pubkey: PublicKeyBytes,
    pub target_pubkey: PublicKeyBytes,
}
