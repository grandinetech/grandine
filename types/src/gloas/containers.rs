use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz::{BitVector, ContiguousList, ContiguousVector, Ssz};
use typenum::Log2;

use crate::{
    altair::containers::{SyncAggregate, SyncCommittee},
    bellatrix::primitives::Gas,
    capella::{consts::ExecutionPayloadIndex, containers::SignedBlsToExecutionChange},
    deneb::{
        containers::{ExecutionPayload, ExecutionPayloadHeader},
        primitives::{KzgCommitment, KzgProof},
    },
    electra::{
        consts::{CurrentSyncCommitteeIndex, FinalizedRootIndex, NextSyncCommitteeIndex},
        containers::{Attestation, AttesterSlashing, ExecutionRequests},
    },
    fulu::primitives::{Cell, ColumnIndex},
    gloas::primitives::PayloadStatus,
    phase0::{
        containers::{BeaconBlockHeader, Deposit, Eth1Data, ProposerSlashing, SignedVoluntaryExit},
        primitives::{
            Epoch, ExecutionAddress, ExecutionBlockHash, Gwei, Slot, ValidatorIndex, H256,
        },
    },
    preset::Preset,
};

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
    pub bls_to_execution_changes:
        ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges>,
    pub signed_execution_payload_bid: SignedExecutionPayloadBid,
    pub payload_attestations: ContiguousList<PayloadAttestation<P>, P::MaxPayloadAttestation>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BuilderPendingPayment {
    #[serde(with = "serde_utils::string_or_native")]
    pub weight: Gwei,
    pub withdrawal: BuilderPendingWithdrawal,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BuilderPendingWithdrawal {
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub withdrawable_epoch: Epoch,
}

#[derive(Clone, PartialEq, Eq, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct DataColumnSidecar<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub index: ColumnIndex,
    pub column: ContiguousList<Cell<P>, P::MaxBlobCommitmentsPerBlock>,
    pub kzg_commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
    pub kzg_proofs: ContiguousList<KzgProof, P::MaxBlobCommitmentsPerBlock>,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub beacon_block_root: H256,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct ExecutionPayloadBid {
    pub parent_block_hash: ExecutionBlockHash,
    pub parent_block_root: H256,
    pub block_hash: ExecutionBlockHash,
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    pub gas_limit: Gas,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub value: Gwei,
    pub blob_kzg_commitments_root: H256,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct ExecutionPayloadEnvelope<P: Preset> {
    pub payload: ExecutionPayload<P>,
    pub execution_requests: ExecutionRequests<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_index: ValidatorIndex,
    pub beacon_block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub blob_kzg_commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
    pub state_root: H256,
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
pub struct IndexedPayloadAttestation<P: Preset> {
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub attesting_indices: ContiguousList<ValidatorIndex, P::PtcSize>,
    pub data: PayloadAttestationData,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
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
pub struct PayloadAttestation<P: Preset> {
    pub aggregation_bits: BitVector<P::PtcSize>,
    pub data: PayloadAttestationData,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
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

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedBeaconBlock<P: Preset> {
    pub message: BeaconBlock<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedExecutionPayloadBid {
    pub message: ExecutionPayloadBid,
    pub signature: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedExecutionPayloadEnvelope<P: Preset> {
    pub message: ExecutionPayloadEnvelope<P>,
    pub signature: SignatureBytes,
}
