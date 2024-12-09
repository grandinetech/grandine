use bls::{PublicKeyBytes, SignatureBytes};
use ssz::BitVector;
use types::{altair::consts::SyncCommitteeSubnetCount, phase0::primitives::ValidatorIndex};

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
