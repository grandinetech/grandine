use bls::{PublicKeyBytes, SignatureBytes};
use ssz::{BitVector, H256};
use types::{
    altair::consts::SyncCommitteeSubnetCount, combined::SignedBeaconBlock,
    phase0::primitives::ValidatorIndex, preset::Preset,
};

#[expect(clippy::struct_field_names)]
pub struct Aggregator {
    pub aggregator_index: ValidatorIndex,
    pub position_in_committee: usize,
    pub public_key: PublicKeyBytes,
    pub selection_proof: SignatureBytes,
}

pub struct SyncCommitteeMember {
    pub validator_index: ValidatorIndex,
    pub public_key: PublicKeyBytes,
    pub subnets: BitVector<SyncCommitteeSubnetCount>,
}

pub enum SignedBeaconBlockOrBlockRoot<P: Preset> {
    Block(Box<SignedBeaconBlock<P>>),
    Root(H256),
}
