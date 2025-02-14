use bls::{AggregatePublicKeyBytes, AggregateSignatureBytes, CachedPublicKey, SignatureBytes};
use serde::{Deserialize, Serialize};
use ssz::{BitVector, ContiguousList, ContiguousVector, Ssz};
use typenum::Log2;

use crate::{
    altair::{
        consts::{CurrentSyncCommitteeIndex, FinalizedRootIndex, NextSyncCommitteeIndex},
        primitives::SubcommitteeIndex,
    },
    phase0::{
        containers::{
            Attestation, AttesterSlashing, BeaconBlockHeader, Deposit, Eth1Data, ProposerSlashing,
            SignedVoluntaryExit,
        },
        primitives::{Slot, ValidatorIndex, H256},
    },
    preset::{Preset, SyncSubcommitteeSize},
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
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct ContributionAndProof<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub aggregator_index: ValidatorIndex,
    pub contribution: SyncCommitteeContribution<P>,
    pub selection_proof: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientBootstrap<P: Preset> {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee<P>,
    pub current_sync_committee_branch: ContiguousVector<H256, Log2<CurrentSyncCommitteeIndex>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct LightClientFinalityUpdate<P: Preset> {
    pub attested_header: LightClientHeader,
    pub finalized_header: LightClientHeader,
    pub finality_branch: ContiguousVector<H256, Log2<FinalizedRootIndex>>,
    pub sync_aggregate: SyncAggregate<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub signature_slot: Slot,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
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
    pub next_sync_committee_branch: ContiguousVector<H256, Log2<NextSyncCommitteeIndex>>,
    pub finalized_header: LightClientHeader,
    pub finality_branch: ContiguousVector<H256, Log2<FinalizedRootIndex>>,
    pub sync_aggregate: SyncAggregate<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub signature_slot: Slot,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedBeaconBlock<P: Preset> {
    pub message: BeaconBlock<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedContributionAndProof<P: Preset> {
    pub message: ContributionAndProof<P>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SyncAggregate<P: Preset> {
    pub sync_committee_bits: BitVector<P::SyncCommitteeSize>,
    pub sync_committee_signature: AggregateSignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SyncAggregatorSelectionData {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub subcommittee_index: SubcommitteeIndex,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SyncCommittee<P: Preset> {
    // The vector has to be boxed because it's large enough to cause stack overflows when not in
    // release mode.
    pub pubkeys: Box<ContiguousVector<CachedPublicKey, P::SyncCommitteeSize>>,
    pub aggregate_pubkey: AggregatePublicKeyBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Hash, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SyncCommitteeContribution<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub beacon_block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub subcommittee_index: SubcommitteeIndex,
    pub aggregation_bits: BitVector<SyncSubcommitteeSize<P>>,
    pub signature: AggregateSignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SyncCommitteeMessage {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub beacon_block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub signature: SignatureBytes,
}

#[cfg(test)]
mod tests {
    use ssz::{Size, SszSize as _, BYTES_PER_LENGTH_OFFSET as OFFSET};
    use test_case::test_case;
    use typenum::Unsigned as _;

    use crate::{phase0::consts::DepositContractTreeDepth, preset::Mainnet};

    use super::*;

    // TODO(feature/ssz-size-improvements): Clean up tests for standard container sizes.

    const UINT: usize = 8;
    const HASH: usize = 32;

    const PUBLIC_KEY: usize = 48;
    const SIGNATURE: usize = 96;

    const AGGREGATION_BITS_MAX: usize =
        <Mainnet as Preset>::MaxValidatorsPerCommittee::USIZE / 8 + 1;

    const DEPOSIT_PROOF: usize = (DepositContractTreeDepth::USIZE + 1) * HASH;

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

    const ATTESTATION_MAX: usize = OFFSET + ATTESTATION_DATA + SIGNATURE + AGGREGATION_BITS_MAX;
    const ATTESTATION_DATA: usize = UINT + UINT + HASH + CHECKPOINT + CHECKPOINT;
    const ATTESTER_SLASHING_MAX: usize =
        OFFSET + OFFSET + INDEXED_ATTESTATION_MAX + INDEXED_ATTESTATION_MAX;
    const BEACON_BLOCK_HEADER: usize = UINT + UINT + HASH + HASH + HASH;
    const CHECKPOINT: usize = UINT + HASH;
    const DEPOSIT: usize = DEPOSIT_PROOF + DEPOSIT_DATA;
    const DEPOSIT_DATA: usize = PUBLIC_KEY + HASH + UINT + SIGNATURE;
    const ETH1_DATA: usize = HASH + UINT + HASH;
    const INDEXED_ATTESTATION_MAX: usize =
        OFFSET + ATTESTATION_DATA + SIGNATURE + VALIDATOR_INDEX_LIST_MAX;
    const PROPOSER_SLASHING: usize = SIGNED_BEACON_BLOCK_HEADER + SIGNED_BEACON_BLOCK_HEADER;
    const SIGNED_BEACON_BLOCK_HEADER: usize = BEACON_BLOCK_HEADER + SIGNATURE;
    const SIGNED_VOLUNTARY_EXIT: usize = VOLUNTARY_EXIT + SIGNATURE;
    const VOLUNTARY_EXIT: usize = UINT + UINT;

    const AGGREGATION_BITS: usize = SyncSubcommitteeSize::<Mainnet>::USIZE / 8;
    const SYNC_COMMITTEE_BITS: usize = <Mainnet as Preset>::SyncCommitteeSize::USIZE / 8;

    const CURRENT_SYNC_COMMITTEE_BRANCH: usize = Log2::<CurrentSyncCommitteeIndex>::USIZE * HASH;
    const FINALITY_BRANCH: usize = Log2::<FinalizedRootIndex>::USIZE * HASH;
    const NEXT_SYNC_COMMITTEE_BRANCH: usize = Log2::<NextSyncCommitteeIndex>::USIZE * HASH;
    const PUBKEYS: usize = <Mainnet as Preset>::SyncCommitteeSize::USIZE * PUBLIC_KEY;

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
        + SYNC_AGGREGATE
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
        + SYNC_AGGREGATE
        + PROPOSER_SLASHING_LIST_MAX
        + ATTESTER_SLASHING_LIST_MAX
        + ATTESTATION_LIST_MAX
        + DEPOSIT_LIST_MAX
        + SIGNED_VOLUNTARY_EXIT_LIST_MAX;
    const CONTRIBUTION_AND_PROOF: usize = UINT + SYNC_COMMITTEE_CONTRIBUTION + SIGNATURE;
    const LIGHT_CLIENT_BOOTSTRAP: usize =
        LIGHT_CLIENT_HEADER + SYNC_COMMITTEE + CURRENT_SYNC_COMMITTEE_BRANCH;
    const LIGHT_CLIENT_FINALITY_UPDATE: usize =
        LIGHT_CLIENT_HEADER + LIGHT_CLIENT_HEADER + FINALITY_BRANCH + SYNC_AGGREGATE + UINT;
    const LIGHT_CLIENT_HEADER: usize = BEACON_BLOCK_HEADER;
    const LIGHT_CLIENT_OPTIMISTIC_UPDATE: usize = LIGHT_CLIENT_HEADER + SYNC_AGGREGATE + UINT;
    const LIGHT_CLIENT_UPDATE: usize = LIGHT_CLIENT_HEADER
        + SYNC_COMMITTEE
        + NEXT_SYNC_COMMITTEE_BRANCH
        + LIGHT_CLIENT_HEADER
        + FINALITY_BRANCH
        + SYNC_AGGREGATE
        + UINT;
    const SIGNED_BEACON_BLOCK_MIN: usize = OFFSET + SIGNATURE + BEACON_BLOCK_MIN;
    const SIGNED_BEACON_BLOCK_MAX: usize = OFFSET + SIGNATURE + BEACON_BLOCK_MAX;
    const SIGNED_CONTRIBUTION_AND_PROOF: usize = CONTRIBUTION_AND_PROOF + SIGNATURE;
    const SYNC_AGGREGATE: usize = SYNC_COMMITTEE_BITS + SIGNATURE;
    const SYNC_AGGREGATOR_SELECTION_DATA: usize = UINT + UINT;
    const SYNC_COMMITTEE: usize = PUBKEYS + PUBLIC_KEY;
    const SYNC_COMMITTEE_CONTRIBUTION: usize = UINT + HASH + UINT + AGGREGATION_BITS + SIGNATURE;
    const SYNC_COMMITTEE_MESSAGE: usize = UINT + HASH + UINT + SIGNATURE;

    #[test_case(BitVector::<SyncSubcommitteeSize<Mainnet>>::SIZE,          Size::Fixed { size: AGGREGATION_BITS    })]
    #[test_case(BitVector::<<Mainnet as Preset>::SyncCommitteeSize>::SIZE, Size::Fixed { size: SYNC_COMMITTEE_BITS })]
    #[test_case(ContiguousVector::<H256, Log2<CurrentSyncCommitteeIndex>>::SIZE,                        Size::Fixed { size: CURRENT_SYNC_COMMITTEE_BRANCH })]
    #[test_case(ContiguousVector::<H256, Log2<FinalizedRootIndex>>::SIZE,                               Size::Fixed { size: FINALITY_BRANCH               })]
    #[test_case(ContiguousVector::<H256, Log2<NextSyncCommitteeIndex>>::SIZE,                           Size::Fixed { size: NEXT_SYNC_COMMITTEE_BRANCH    })]
    #[test_case(Box::<ContiguousVector<CachedPublicKey, <Mainnet as Preset>::SyncCommitteeSize>>::SIZE, Size::Fixed { size: PUBKEYS                       })]
    #[test_case(BeaconBlock::<Mainnet>::SIZE,                 Size::Variable { minimum: BEACON_BLOCK_MIN,        maximum: Ok(BEACON_BLOCK_MAX)        })]
    #[test_case(BeaconBlockBody::<Mainnet>::SIZE,             Size::Variable { minimum: BEACON_BLOCK_BODY_MIN,   maximum: Ok(BEACON_BLOCK_BODY_MAX)   })]
    #[test_case(ContributionAndProof::<Mainnet>::SIZE,        Size::Fixed    { size: CONTRIBUTION_AND_PROOF                                           })]
    #[test_case(LightClientBootstrap::<Mainnet>::SIZE,        Size::Fixed    { size: LIGHT_CLIENT_BOOTSTRAP                                           })]
    #[test_case(LightClientFinalityUpdate::<Mainnet>::SIZE,   Size::Fixed    { size: LIGHT_CLIENT_FINALITY_UPDATE                                     })]
    #[test_case(LightClientHeader::SIZE,                      Size::Fixed    { size: LIGHT_CLIENT_HEADER                                              })]
    #[test_case(LightClientOptimisticUpdate::<Mainnet>::SIZE, Size::Fixed    { size: LIGHT_CLIENT_OPTIMISTIC_UPDATE                                   })]
    #[test_case(LightClientUpdate::<Mainnet>::SIZE,           Size::Fixed    { size: LIGHT_CLIENT_UPDATE                                              })]
    #[test_case(SignedBeaconBlock::<Mainnet>::SIZE,           Size::Variable { minimum: SIGNED_BEACON_BLOCK_MIN, maximum: Ok(SIGNED_BEACON_BLOCK_MAX) })]
    #[test_case(SignedContributionAndProof::<Mainnet>::SIZE,  Size::Fixed    { size: SIGNED_CONTRIBUTION_AND_PROOF                                    })]
    #[test_case(SyncAggregate::<Mainnet>::SIZE,               Size::Fixed    { size: SYNC_AGGREGATE                                                   })]
    #[test_case(SyncAggregatorSelectionData::SIZE,            Size::Fixed    { size: SYNC_AGGREGATOR_SELECTION_DATA                                   })]
    #[test_case(SyncCommittee::<Mainnet>::SIZE,               Size::Fixed    { size: SYNC_COMMITTEE                                                   })]
    #[test_case(SyncCommitteeContribution::<Mainnet>::SIZE,   Size::Fixed    { size: SYNC_COMMITTEE_CONTRIBUTION                                      })]
    #[test_case(SyncCommitteeMessage::SIZE,                   Size::Fixed    { size: SYNC_COMMITTEE_MESSAGE                                           })]
    fn ssz_size(actual: Size, expected: Size) {
        assert_eq!(actual, expected);
    }
}
