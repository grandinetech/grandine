//! Bellatrix containers from [`consensus-specs`] and [`builder-specs`].
//!
//! [`consensus-specs`]: https://github.com/ethereum/consensus-specs/tree/9839ed49346a85f95af4f8b0cb9c4d98b2308af8/specs/bellatrix
//! [`builder-specs`]:   https://github.com/ethereum/builder-specs/blob/d246d57ba2a0c2378c1de4a2bdaff7cd438e99ee/specs/builder.md#bellatrix

use std::sync::Arc;

use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz::{ByteList, ByteVector, ContiguousList, Ssz};

use crate::{
    altair::containers::SyncAggregate,
    bellatrix::primitives::{Difficulty, Gas, Transaction, Wei},
    phase0::{
        containers::{
            Attestation, AttesterSlashing, Deposit, Eth1Data, ProposerSlashing, SignedVoluntaryExit,
        },
        primitives::{
            ExecutionAddress, ExecutionBlockHash, ExecutionBlockNumber, H256, Slot, UnixSeconds,
            ValidatorIndex,
        },
    },
    preset::Preset,
};

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
    pub sync_aggregate: SyncAggregate<P>,
    pub execution_payload: ExecutionPayload<P>,
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
    pub attester_slashings: ContiguousList<AttesterSlashing<P>, P::MaxAttesterSlashings>,
    pub attestations: ContiguousList<Attestation<P>, P::MaxAttestations>,
    pub deposits: ContiguousList<Deposit, P::MaxDeposits>,
    pub voluntary_exits: ContiguousList<SignedVoluntaryExit, P::MaxVoluntaryExits>,
    pub sync_aggregate: SyncAggregate<P>,
    pub execution_payload_header: ExecutionPayloadHeader<P>,
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
    pub base_fee_per_gas: Wei,
    pub block_hash: ExecutionBlockHash,
    // TODO(Grandine Team): Consider removing the `Arc`. It can be removed with no loss of performance
    //                      at the cost of making `ExecutionPayloadV1` more complicated.
    pub transactions: Arc<ContiguousList<Transaction<P>, P::MaxTransactionsPerPayload>>,
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
    pub base_fee_per_gas: Wei,
    pub block_hash: ExecutionBlockHash,
    pub transactions_root: H256,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct PowBlock {
    pub block_hash: ExecutionBlockHash,
    pub parent_hash: ExecutionBlockHash,
    pub total_difficulty: Difficulty,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
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
