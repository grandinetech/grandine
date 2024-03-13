use bls::{AggregateSignatureBytes, CachedPublicKey, PublicKeyBytes, SignatureBytes};
use serde::{Deserialize, Serialize};
use ssz::{BitList, ContiguousList, ProofWithLength, Ssz};

use crate::{
    collections::RecentRoots,
    phase0::{
        consts::DepositContractTreeDepth,
        primitives::{
            CommitteeIndex, DepositIndex, Epoch, ExecutionBlockHash, Gwei, Slot, ValidatorIndex,
            Version, H256,
        },
    },
    preset::Preset,
};

// We use `SignatureBytes` to represent signatures in container types and only decompress them when
// verifying them. We do so because some of the `ssz_static` test cases contain invalid signatures.
// The same must be done with public keys even outside of tests for a combination of reasons.

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
    pub aggregation_bits: BitList<P::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    pub signature: AggregateSignatureBytes,
}

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Deserialize, Serialize, Ssz,
)]
#[serde(deny_unknown_fields)]
pub struct AttestationData {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub index: CommitteeIndex,
    pub beacon_block_root: H256,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct AttesterSlashing<P: Preset> {
    pub attestation_1: IndexedAttestation<P>,
    pub attestation_2: IndexedAttestation<P>,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
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

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BeaconBlockBody<P: Preset> {
    pub randao_reveal: SignatureBytes,
    pub eth1_data: Eth1Data,
    pub graffiti: H256,
    pub proposer_slashings: ContiguousList<ProposerSlashing, P::MaxProposerSlashings>,
    pub attester_slashings: ContiguousList<AttesterSlashing<P>, P::MaxAttesterSlashings>,
    pub attestations: ContiguousList<Attestation<P>, P::MaxAttestations>,
    pub deposits: ContiguousList<Deposit, P::MaxDeposits>,
    pub voluntary_exits: ContiguousList<SignedVoluntaryExit, P::MaxVoluntaryExits>,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct BeaconBlockHeader {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub proposer_index: ValidatorIndex,
    pub parent_root: H256,
    pub state_root: H256,
    pub body_root: H256,
}

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Deserialize, Serialize, Ssz,
)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
    pub root: H256,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct Deposit {
    pub proof: ProofWithLength<DepositContractTreeDepth>,
    pub data: DepositData,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct DepositData {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct DepositMessage {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub amount: Gwei,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct Eth1Data {
    pub deposit_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub deposit_count: DepositIndex,
    pub block_hash: ExecutionBlockHash,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct Fork {
    pub previous_version: Version,
    pub current_version: Version,
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ForkData {
    pub current_version: Version,
    pub genesis_validators_root: H256,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct HistoricalBatch<P: Preset> {
    pub block_roots: RecentRoots<P>,
    pub state_roots: RecentRoots<P>,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct IndexedAttestation<P: Preset> {
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub attesting_indices: ContiguousList<ValidatorIndex, P::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    pub signature: AggregateSignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct PendingAttestation<P: Preset> {
    pub aggregation_bits: BitList<P::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    #[serde(with = "serde_utils::string_or_native")]
    pub inclusion_delay: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub proposer_index: ValidatorIndex,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedAggregateAndProof<P: Preset> {
    pub message: AggregateAndProof<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedBeaconBlock<P: Preset> {
    pub message: BeaconBlock<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SigningData {
    pub object_root: H256,
    pub domain: H256,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    pub pubkey: CachedPublicKey,
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
pub struct VoluntaryExit {
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
}
