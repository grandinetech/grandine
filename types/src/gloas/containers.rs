use core::marker::PhantomData;
use std::sync::Arc;

use bls::{AggregateSignatureBytes, PublicKeyBytes, SignatureBytes};
use derive_more::From;
use serde::{Deserialize, Serialize};
use ssz::{
    BitVector, ByteList, ByteVector, ContiguousList, ContiguousVector, Hc, ProgressiveBitList,
    ProgressiveList, Ssz,
};
use typenum::Log2;

use crate::{
    altair::containers::{SyncAggregate, SyncCommittee},
    bellatrix::primitives::Gas,
    capella::containers::{SignedBlsToExecutionChange, Withdrawal},
    deneb::primitives::{Blob, KzgCommitment, KzgProof},
    electra::containers::{ConsolidationRequest, DepositRequest, WithdrawalRequest},
    fulu::primitives::{Cell, ColumnIndex},
    gloas::consts::{
        CurrentSyncCommitteeGindexGloas, ExecutionBlockHashGindexGloas, FinalizedRootGindexGloas,
        NextSyncCommitteeGindexGloas,
    },
    gloas::primitives::{BlockAccessList, BuilderIndex, PayloadStatus, Transaction},
    phase0::{
        containers::{
            AttestationData, BeaconBlockHeader, Deposit, Eth1Data, ProposerSlashing,
            SignedVoluntaryExit,
        },
        primitives::{
            Epoch, ExecutionAddress, ExecutionBlockHash, ExecutionBlockNumber, Gwei, H256, Slot,
            Uint256, UnixSeconds, ValidatorIndex,
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

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedAggregateAndProof<P: Preset> {
    pub message: AggregateAndProof<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
#[ssz(stable(active = [1; 4]))]
pub struct Attestation<P: Preset> {
    pub aggregation_bits: ProgressiveBitList<P::MaxAttestersPerSlot>,
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

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 3]))]
pub struct IndexedAttestation<P: Preset> {
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub attesting_indices: ProgressiveList<ValidatorIndex>,
    pub data: AttestationData,
    pub signature: AggregateSignatureBytes,
    #[ssz(skip)]
    #[serde(skip)]
    pub phantom: PhantomData<P>,
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
#[ssz(stable(active = [1; 13]))]
pub struct BeaconBlockBody<P: Preset> {
    pub randao_reveal: SignatureBytes,
    pub eth1_data: Eth1Data,
    pub graffiti: H256,
    pub proposer_slashings: ProgressiveList<ProposerSlashing>,
    pub attester_slashings: ProgressiveList<AttesterSlashing<P>>,
    pub attestations: ProgressiveList<Attestation<P>>,
    pub deposits: ProgressiveList<Deposit>,
    pub voluntary_exits: ProgressiveList<SignedVoluntaryExit>,
    pub sync_aggregate: SyncAggregate<P>,
    pub bls_to_execution_changes: ProgressiveList<SignedBlsToExecutionChange>,
    pub signed_execution_payload_bid: SignedExecutionPayloadBid<P>,
    pub payload_attestations: ProgressiveList<PayloadAttestation<P>>,
    pub parent_execution_requests: ExecutionRequests<P>,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct Builder {
    pub pubkey: PublicKeyBytes,
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

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct BuilderDepositMessage {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct BuilderDepositRequest {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct BuilderExitRequest {
    pub source_address: ExecutionAddress,
    pub pubkey: PublicKeyBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BuilderPendingPayment {
    #[serde(with = "serde_utils::string_or_native")]
    pub weight: Gwei,
    pub withdrawal: BuilderPendingWithdrawal,
    #[serde(with = "serde_utils::string_or_native")]
    pub proposer_index: ValidatorIndex,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BuilderPendingWithdrawal {
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_index: BuilderIndex,
}

#[derive(Clone, PartialEq, Eq, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct DataColumnSidecar<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub index: ColumnIndex,
    pub column: ProgressiveList<Cell<P>>,
    pub kzg_proofs: ProgressiveList<KzgProof>,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub beacon_block_root: H256,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 19]))]
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
    pub transactions: Arc<ProgressiveList<Transaction<P>>>,
    pub withdrawals: ProgressiveList<Withdrawal>,
    #[serde(with = "serde_utils::string_or_native")]
    pub blob_gas_used: Gas,
    #[serde(with = "serde_utils::string_or_native")]
    pub excess_blob_gas: Gas,
    pub block_access_list: Arc<BlockAccessList<P>>,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot_number: Slot,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 12]))]
pub struct ExecutionPayloadBid<P: Preset> {
    pub parent_block_hash: ExecutionBlockHash,
    pub parent_block_root: H256,
    pub block_hash: ExecutionBlockHash,
    pub prev_randao: H256,
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    pub gas_limit: Gas,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_index: BuilderIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub value: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub execution_payment: Gwei,
    pub blob_kzg_commitments: ProgressiveList<KzgCommitment>,
    pub execution_requests_root: H256,
    #[ssz(skip)]
    #[serde(skip)]
    pub phantom: PhantomData<P>,
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

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 5]))]
pub struct ExecutionRequests<P: Preset> {
    pub deposits: ProgressiveList<DepositRequest>,
    pub withdrawals: ProgressiveList<WithdrawalRequest>,
    pub consolidations: ProgressiveList<ConsolidationRequest>,
    pub builder_deposits: ProgressiveList<BuilderDepositRequest>,
    pub builder_exits: ProgressiveList<BuilderExitRequest>,
    #[ssz(skip)]
    #[serde(skip)]
    pub phantom: PhantomData<P>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct ForkChoiceNode {
    pub root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub payload_status: PayloadStatus,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 3]))]
pub struct IndexedPayloadAttestation<P: Preset> {
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub attesting_indices: ContiguousList<ValidatorIndex, P::PtcSize>,
    pub data: PayloadAttestationData,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Hash, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct PayloadAttestationData {
    pub beacon_block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub payload_present: bool,
    pub blob_data_available: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 3]))]
pub struct PayloadAttestation<P: Preset> {
    pub aggregation_bits: BitVector<P::PtcSize>,
    pub data: PayloadAttestationData,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct ProposerPreferences {
    pub dependent_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub proposal_slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    pub target_gas_limit: Gas,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Hash, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct PayloadAttestationMessage {
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub data: PayloadAttestationData,
    pub signature: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientBootstrap<P: Preset> {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee<P>,
    pub current_sync_committee_branch:
        ContiguousVector<H256, Log2<CurrentSyncCommitteeGindexGloas>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientFinalityUpdate<P: Preset> {
    pub attested_header: LightClientHeader,
    pub finalized_header: LightClientHeader,
    pub finality_branch: ContiguousVector<H256, Log2<FinalizedRootGindexGloas>>,
    pub sync_aggregate: SyncAggregate<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub signature_slot: Slot,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution_block_hash: ExecutionBlockHash,
    pub execution_branch: ContiguousVector<H256, Log2<ExecutionBlockHashGindexGloas>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientOptimisticUpdate<P: Preset> {
    pub attested_header: LightClientHeader,
    pub sync_aggregate: SyncAggregate<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub signature_slot: Slot,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientUpdate<P: Preset> {
    pub attested_header: LightClientHeader,
    pub next_sync_committee: SyncCommittee<P>,
    pub next_sync_committee_branch: ContiguousVector<H256, Log2<NextSyncCommitteeGindexGloas>>,
    pub finalized_header: LightClientHeader,
    pub finality_branch: ContiguousVector<H256, Log2<FinalizedRootGindexGloas>>,
    pub sync_aggregate: SyncAggregate<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub signature_slot: Slot,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedBeaconBlock<P: Preset> {
    pub message: Hc<BeaconBlock<P>>,
    pub signature: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedExecutionPayloadBid<P: Preset> {
    pub message: ExecutionPayloadBid<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedExecutionPayloadEnvelope<P: Preset> {
    pub message: ExecutionPayloadEnvelope<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedExecutionPayloadEnvelopeContents<P: Preset> {
    pub signed_execution_payload_envelope: SignedExecutionPayloadEnvelope<P>,
    pub kzg_proofs: ContiguousList<KzgProof, P::MaxCellProofsPerBlock>,
    pub blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedProposerPreferences {
    pub message: ProposerPreferences,
    pub signature: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, From)]
pub enum CombinedPayloadAttestation<P: Preset> {
    Attestation(PayloadAttestation<P>),
    Message(Arc<PayloadAttestationMessage>),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct PayloadEnvelopeIdentifier {
    pub beacon_block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_index: BuilderIndex,
}
