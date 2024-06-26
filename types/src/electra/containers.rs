use std::sync::Arc;

use bls::{AggregateSignatureBytes, PublicKeyBytes, SignatureBytes};
use serde::{Deserialize, Serialize};
use ssz::{BitList, BitVector, ByteList, ByteVector, ContiguousList, ContiguousVector, Ssz};
use typenum::Log2;

use crate::{
    altair::containers::{SyncAggregate, SyncCommittee},
    bellatrix::primitives::{Gas, Transaction},
    capella::{
        consts::ExecutionPayloadIndex,
        containers::{SignedBlsToExecutionChange, Withdrawal},
    },
    deneb::primitives::KzgCommitment,
    electra::consts::{CurrentSyncCommitteeIndex, FinalizedRootIndex, NextSyncCommitteeIndex},
    phase0::{
        containers::{
            AttestationData, BeaconBlockHeader, Deposit, Eth1Data, ProposerSlashing,
            SignedVoluntaryExit,
        },
        primitives::{
            Epoch, ExecutionAddress, ExecutionBlockHash, ExecutionBlockNumber, Gwei, Slot, Uint256,
            UnixSeconds, ValidatorIndex, H256,
        },
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
    pub aggregation_bits: BitList<P::MaxAggregatorsPerSlot>,
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
pub struct ExecutionPayload<P: Preset> {
    pub parent_hash: ExecutionBlockHash,
    pub fee_recipient: ExecutionAddress,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: ByteVector<P::BytesPerLogsBloom>,
    pub prev_randao: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub block_number: ExecutionBlockNumber,
    #[serde(with = "serde_utils::string_or_native")]
    pub gas_limit: Gas,
    #[serde(with = "serde_utils::string_or_native")]
    pub gas_used: Gas,
    #[serde(with = "serde_utils::string_or_native")]
    pub timestamp: UnixSeconds,
    // TODO(Grandine Team): Try removing the `Arc` when we have data for benchmarking Bellatrix.
    //                      The cost of cloning `ByteList<MaxExtraDataBytes>` may be negligible.
    pub extra_data: Arc<ByteList<P::MaxExtraDataBytes>>,
    pub base_fee_per_gas: Uint256,
    pub block_hash: ExecutionBlockHash,
    // TODO(Grandine Team): Consider removing the `Arc`. It can be removed with no loss of performance
    //                      at the cost of making `ExecutionPayloadV1` more complicated.
    pub transactions: Arc<ContiguousList<Transaction<P>, P::MaxTransactionsPerPayload>>,
    pub withdrawals: ContiguousList<Withdrawal, P::MaxWithdrawalsPerPayload>,
    #[serde(with = "serde_utils::string_or_native")]
    pub blob_gas_used: Gas,
    #[serde(with = "serde_utils::string_or_native")]
    pub excess_blob_gas: Gas,
    pub deposit_requests: ContiguousList<DepositRequest, P::MaxDepositRequestsPerPayload>,
    pub withdrawal_requests: ContiguousList<WithdrawalRequest, P::MaxWithdrawalRequestsPerPayload>,
    pub consolidation_requests:
        ContiguousList<ConsolidationRequest, P::MaxConsolidationRequestsPerPayload>,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPayloadHeader<P: Preset> {
    pub parent_hash: ExecutionBlockHash,
    pub fee_recipient: ExecutionAddress,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: ByteVector<P::BytesPerLogsBloom>,
    pub prev_randao: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub block_number: ExecutionBlockNumber,
    #[serde(with = "serde_utils::string_or_native")]
    pub gas_limit: Gas,
    #[serde(with = "serde_utils::string_or_native")]
    pub gas_used: Gas,
    #[serde(with = "serde_utils::string_or_native")]
    pub timestamp: UnixSeconds,
    // TODO(Grandine Team): Try removing the `Arc` when we have data for benchmarking Bellatrix.
    //                      The cost of cloning `ByteList<MaxExtraDataBytes>` may be negligible.
    pub extra_data: Arc<ByteList<P::MaxExtraDataBytes>>,
    pub base_fee_per_gas: Uint256,
    pub block_hash: ExecutionBlockHash,
    pub transactions_root: H256,
    pub withdrawals_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub blob_gas_used: Gas,
    #[serde(with = "serde_utils::string_or_native")]
    pub excess_blob_gas: Gas,
    pub deposit_requests_root: H256,
    pub withdrawal_requests_root: H256,
    pub consolidation_requests_root: H256,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct IndexedAttestation<P: Preset> {
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub attesting_indices: ContiguousList<ValidatorIndex, P::MaxAggregatorsPerSlot>,
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
pub struct PendingBalanceDeposit {
    #[serde(with = "serde_utils::string_or_native")]
    pub index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
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
    pub index: ValidatorIndex,
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

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationRequest {
    pub source_address: ExecutionAddress,
    pub source_pubkey: PublicKeyBytes,
    pub target_pubkey: PublicKeyBytes,
}
