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

#[cfg(test)]
mod tests {
    use ssz::{Size, SszSize as _, BYTES_PER_LENGTH_OFFSET as OFFSET};
    use test_case::test_case;
    use typenum::Unsigned as _;

    use crate::preset::{Mainnet, SlotsPerHistoricalRoot};

    use super::*;

    // TODO(feature/ssz-size-improvements): Clean up tests for standard container sizes.

    const BOOL: usize = 1;
    const UINT: usize = 8;
    const HASH: usize = 32;

    const PUBLIC_KEY: usize = 48;
    const SIGNATURE: usize = 96;

    const VERSION: usize = 4;

    const AGGREGATION_BITS_MIN: usize = 1;
    const AGGREGATION_BITS_MAX: usize =
        <Mainnet as Preset>::MaxValidatorsPerCommittee::USIZE / 8 + 1;

    const DEPOSIT_PROOF: usize = (DepositContractTreeDepth::USIZE + 1) * HASH;
    const RECENT_ROOTS: usize = SlotsPerHistoricalRoot::<Mainnet>::USIZE * HASH;

    const ANY_LIST_MIN: usize = 0;
    const ATTESTATION_LIST_MAX: usize =
        <Mainnet as Preset>::MaxAttestations::USIZE * (OFFSET + ATTESTATION_MAX);
    const ATTESTER_SLASHING_LIST_MAX: usize =
        <Mainnet as Preset>::MaxAttesterSlashings::USIZE * (OFFSET + ATTESTER_SLASHING_MAX);
    const DEPOSIT_LIST_MAX: usize = <Mainnet as Preset>::MaxDeposits::USIZE * DEPOSIT;
    const PROPOSER_SLASHING_LIST_MAX: usize =
        <Mainnet as Preset>::MaxProposerSlashings::USIZE * PROPOSER_SLASHING;
    const SIGNED_VOLUNTARY_EXIT_LIST_MAX: usize =
        <Mainnet as Preset>::MaxVoluntaryExits::USIZE * SIGNED_VOLUNTARY_EXIT;
    const VALIDATOR_INDEX_LIST_MAX: usize =
        <Mainnet as Preset>::MaxValidatorsPerCommittee::USIZE * UINT;

    const AGGREGATE_AND_PROOF_MIN: usize = UINT + OFFSET + SIGNATURE + ATTESTATION_MIN;
    const AGGREGATE_AND_PROOF_MAX: usize = UINT + OFFSET + SIGNATURE + ATTESTATION_MAX;
    const ATTESTATION_MIN: usize = OFFSET + ATTESTATION_DATA + SIGNATURE + AGGREGATION_BITS_MIN;
    const ATTESTATION_MAX: usize = OFFSET + ATTESTATION_DATA + SIGNATURE + AGGREGATION_BITS_MAX;
    const ATTESTATION_DATA: usize = UINT + UINT + HASH + CHECKPOINT + CHECKPOINT;
    const ATTESTER_SLASHING_MIN: usize =
        OFFSET + OFFSET + INDEXED_ATTESTATION_MIN + INDEXED_ATTESTATION_MIN;
    const ATTESTER_SLASHING_MAX: usize =
        OFFSET + OFFSET + INDEXED_ATTESTATION_MAX + INDEXED_ATTESTATION_MAX;
    const BEACON_BLOCK_MIN: usize = UINT + UINT + HASH + HASH + OFFSET + BEACON_BLOCK_BODY_MIN;
    const BEACON_BLOCK_MAX: usize = UINT + UINT + HASH + HASH + OFFSET + BEACON_BLOCK_BODY_MAX;
    const BEACON_BLOCK_BODY_MIN: usize = SIGNATURE
        + ETH1_DATA
        + HASH
        + OFFSET
        + OFFSET
        + OFFSET
        + OFFSET
        + OFFSET
        + ANY_LIST_MIN
        + ANY_LIST_MIN
        + ANY_LIST_MIN
        + ANY_LIST_MIN
        + ANY_LIST_MIN;
    const BEACON_BLOCK_BODY_MAX: usize = SIGNATURE
        + ETH1_DATA
        + HASH
        + OFFSET
        + OFFSET
        + OFFSET
        + OFFSET
        + OFFSET
        + PROPOSER_SLASHING_LIST_MAX
        + ATTESTER_SLASHING_LIST_MAX
        + ATTESTATION_LIST_MAX
        + DEPOSIT_LIST_MAX
        + SIGNED_VOLUNTARY_EXIT_LIST_MAX;
    const BEACON_BLOCK_HEADER: usize = UINT + UINT + HASH + HASH + HASH;
    const CHECKPOINT: usize = UINT + HASH;
    const DEPOSIT: usize = DEPOSIT_PROOF + DEPOSIT_DATA;
    const DEPOSIT_DATA: usize = PUBLIC_KEY + HASH + UINT + SIGNATURE;
    const DEPOSIT_MESSAGE: usize = PUBLIC_KEY + HASH + UINT;
    const ETH1_DATA: usize = HASH + UINT + HASH;
    const FORK: usize = VERSION + VERSION + UINT;
    const FORK_DATA: usize = VERSION + HASH;
    const HISTORICAL_BATCH: usize = RECENT_ROOTS + RECENT_ROOTS;
    const INDEXED_ATTESTATION_MIN: usize = OFFSET + ATTESTATION_DATA + SIGNATURE + ANY_LIST_MIN;
    const INDEXED_ATTESTATION_MAX: usize =
        OFFSET + ATTESTATION_DATA + SIGNATURE + VALIDATOR_INDEX_LIST_MAX;
    const PENDING_ATTESTATION_MIN: usize =
        OFFSET + ATTESTATION_DATA + UINT + UINT + AGGREGATION_BITS_MIN;
    const PENDING_ATTESTATION_MAX: usize =
        OFFSET + ATTESTATION_DATA + UINT + UINT + AGGREGATION_BITS_MAX;
    const PROPOSER_SLASHING: usize = SIGNED_BEACON_BLOCK_HEADER + SIGNED_BEACON_BLOCK_HEADER;
    const SIGNED_AGGREGATE_AND_PROOF_MIN: usize = OFFSET + SIGNATURE + AGGREGATE_AND_PROOF_MIN;
    const SIGNED_AGGREGATE_AND_PROOF_MAX: usize = OFFSET + SIGNATURE + AGGREGATE_AND_PROOF_MAX;
    const SIGNED_BEACON_BLOCK_MIN: usize = OFFSET + SIGNATURE + BEACON_BLOCK_MIN;
    const SIGNED_BEACON_BLOCK_MAX: usize = OFFSET + SIGNATURE + BEACON_BLOCK_MAX;
    const SIGNED_BEACON_BLOCK_HEADER: usize = BEACON_BLOCK_HEADER + SIGNATURE;
    const SIGNED_VOLUNTARY_EXIT: usize = VOLUNTARY_EXIT + SIGNATURE;
    const SIGNING_DATA: usize = HASH + HASH;
    const VALIDATOR: usize = PUBLIC_KEY + HASH + UINT + BOOL + UINT + UINT + UINT + UINT;
    const VOLUNTARY_EXIT: usize = UINT + UINT;

    #[test_case(bool::SIZE, Size::Fixed { size: BOOL })]
    #[test_case(u64::SIZE,  Size::Fixed { size: UINT })]
    #[test_case(H256::SIZE, Size::Fixed { size: HASH })]
    #[test_case(AggregateSignatureBytes::SIZE, Size::Fixed { size: SIGNATURE  })]
    #[test_case(CachedPublicKey::SIZE,         Size::Fixed { size: PUBLIC_KEY })]
    #[test_case(SignatureBytes::SIZE,          Size::Fixed { size: SIGNATURE  })]
    #[test_case(CommitteeIndex::SIZE,     Size::Fixed { size: UINT })]
    #[test_case(DepositIndex::SIZE,       Size::Fixed { size: UINT })]
    #[test_case(Epoch::SIZE,              Size::Fixed { size: UINT })]
    #[test_case(ExecutionBlockHash::SIZE, Size::Fixed { size: HASH })]
    #[test_case(Gwei::SIZE,               Size::Fixed { size: UINT })]
    #[test_case(Slot::SIZE,               Size::Fixed { size: UINT })]
    #[test_case(ValidatorIndex::SIZE,     Size::Fixed { size: UINT })]
    #[test_case(BitList::<<Mainnet as Preset>::MaxValidatorsPerCommittee>::SIZE, Size::Variable { minimum: AGGREGATION_BITS_MIN, maximum: Ok(AGGREGATION_BITS_MAX) })]
    #[test_case(ProofWithLength::<DepositContractTreeDepth>::SIZE, Size::Fixed { size: DEPOSIT_PROOF })]
    #[test_case(RecentRoots::<Mainnet>::SIZE,                      Size::Fixed { size: RECENT_ROOTS  })]
    #[test_case(ContiguousList::<Attestation<Mainnet>,      <Mainnet as Preset>::MaxAttestations>::SIZE,           Size::Variable { minimum: ANY_LIST_MIN, maximum: Ok(ATTESTATION_LIST_MAX) })]
    #[test_case(ContiguousList::<AttesterSlashing<Mainnet>, <Mainnet as Preset>::MaxAttesterSlashings>::SIZE,      Size::Variable { minimum: ANY_LIST_MIN, maximum: Ok(ATTESTER_SLASHING_LIST_MAX) })]
    #[test_case(ContiguousList::<Deposit,                   <Mainnet as Preset>::MaxDeposits>::SIZE,               Size::Variable { minimum: ANY_LIST_MIN, maximum: Ok(DEPOSIT_LIST_MAX) })]
    #[test_case(ContiguousList::<ProposerSlashing,          <Mainnet as Preset>::MaxProposerSlashings>::SIZE,      Size::Variable { minimum: ANY_LIST_MIN, maximum: Ok(PROPOSER_SLASHING_LIST_MAX) })]
    #[test_case(ContiguousList::<SignedVoluntaryExit,       <Mainnet as Preset>::MaxVoluntaryExits>::SIZE,         Size::Variable { minimum: ANY_LIST_MIN, maximum: Ok(SIGNED_VOLUNTARY_EXIT_LIST_MAX) })]
    #[test_case(ContiguousList::<ValidatorIndex,            <Mainnet as Preset>::MaxValidatorsPerCommittee>::SIZE, Size::Variable { minimum: ANY_LIST_MIN, maximum: Ok(VALIDATOR_INDEX_LIST_MAX) })]
    #[test_case(AggregateAndProof::<Mainnet>::SIZE,       Size::Variable { minimum: AGGREGATE_AND_PROOF_MIN,        maximum: Ok(AGGREGATE_AND_PROOF_MAX)        })]
    #[test_case(Attestation::<Mainnet>::SIZE,             Size::Variable { minimum: ATTESTATION_MIN,                maximum: Ok(ATTESTATION_MAX)                })]
    #[test_case(AttestationData::SIZE,                    Size::Fixed    { size: ATTESTATION_DATA                                                               })]
    #[test_case(AttesterSlashing::<Mainnet>::SIZE,        Size::Variable { minimum: ATTESTER_SLASHING_MIN,          maximum: Ok(ATTESTER_SLASHING_MAX)          })]
    #[test_case(BeaconBlock::<Mainnet>::SIZE,             Size::Variable { minimum: BEACON_BLOCK_MIN,               maximum: Ok(BEACON_BLOCK_MAX)               })]
    #[test_case(BeaconBlockBody::<Mainnet>::SIZE,         Size::Variable { minimum: BEACON_BLOCK_BODY_MIN,          maximum: Ok(BEACON_BLOCK_BODY_MAX)          })]
    #[test_case(BeaconBlockHeader::SIZE,                  Size::Fixed    { size: BEACON_BLOCK_HEADER                                                            })]
    #[test_case(Checkpoint::SIZE,                         Size::Fixed    { size: CHECKPOINT                                                                     })]
    #[test_case(Deposit::SIZE,                            Size::Fixed    { size: DEPOSIT                                                                        })]
    #[test_case(DepositData::SIZE,                        Size::Fixed    { size: DEPOSIT_DATA                                                                   })]
    #[test_case(DepositMessage::SIZE,                     Size::Fixed    { size: DEPOSIT_MESSAGE                                                                })]
    #[test_case(Eth1Data::SIZE,                           Size::Fixed    { size: ETH1_DATA                                                                      })]
    #[test_case(Fork::SIZE,                               Size::Fixed    { size: FORK                                                                           })]
    #[test_case(ForkData::SIZE,                           Size::Fixed    { size: FORK_DATA                                                                      })]
    #[test_case(HistoricalBatch::<Mainnet>::SIZE,         Size::Fixed    { size: HISTORICAL_BATCH                                                               })]
    #[test_case(IndexedAttestation::<Mainnet>::SIZE,      Size::Variable { minimum: INDEXED_ATTESTATION_MIN,        maximum: Ok(INDEXED_ATTESTATION_MAX)        })]
    #[test_case(PendingAttestation::<Mainnet>::SIZE,      Size::Variable { minimum: PENDING_ATTESTATION_MIN,        maximum: Ok(PENDING_ATTESTATION_MAX)        })]
    #[test_case(ProposerSlashing::SIZE,                   Size::Fixed    { size: PROPOSER_SLASHING                                                              })]
    #[test_case(SignedAggregateAndProof::<Mainnet>::SIZE, Size::Variable { minimum: SIGNED_AGGREGATE_AND_PROOF_MIN, maximum: Ok(SIGNED_AGGREGATE_AND_PROOF_MAX) })]
    #[test_case(SignedBeaconBlock::<Mainnet>::SIZE,       Size::Variable { minimum: SIGNED_BEACON_BLOCK_MIN,        maximum: Ok(SIGNED_BEACON_BLOCK_MAX)        })]
    #[test_case(SignedBeaconBlockHeader::SIZE,            Size::Fixed    { size: SIGNED_BEACON_BLOCK_HEADER                                                     })]
    #[test_case(SignedVoluntaryExit::SIZE,                Size::Fixed    { size: SIGNED_VOLUNTARY_EXIT                                                          })]
    #[test_case(SigningData::SIZE,                        Size::Fixed    { size: SIGNING_DATA                                                                   })]
    #[test_case(Validator::SIZE,                          Size::Fixed    { size: VALIDATOR                                                                      })]
    #[test_case(VoluntaryExit::SIZE,                      Size::Fixed    { size: VOLUNTARY_EXIT                                                                 })]
    fn ssz_size(actual: Size, expected: Size) {
        assert_eq!(actual, expected);
    }
}
