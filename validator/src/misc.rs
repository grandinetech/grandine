use core::num::NonZeroU64;

use bls::{PublicKeyBytes, SignatureBytes};
use nonzero_ext::nonzero;
use serde::{Deserialize, Serialize};
use ssz::{BitVector, Size, SszHash, SszSize, SszWrite, WriteError, H256};
use typenum::U1;
use types::{
    altair::consts::SyncCommitteeSubnetCount,
    combined::{BeaconBlock, BlindedBeaconBlock, ExecutionPayload},
    nonstandard::Phase,
    phase0::primitives::{ValidatorIndex, H160},
    preset::Preset,
    traits::{BeaconBlock as _, PostDenebBeaconBlockBody},
};

pub const DEFAULT_BUILDER_BOOST_FACTOR: NonZeroU64 = nonzero!(100_u64);

#[allow(clippy::struct_field_names)]
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

#[derive(Deserialize)]
pub struct ProposerData {
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub fee_recipient: H160,
}

#[derive(Clone, Serialize)]
#[serde(bound = "", untagged)]
pub enum ValidatorBlindedBlock<P: Preset> {
    BlindedBeaconBlock {
        #[serde(flatten)]
        blinded_block: BlindedBeaconBlock<P>,
        #[serde(skip)]
        execution_payload: Box<ExecutionPayload<P>>,
    },
    BeaconBlock(BeaconBlock<P>),
}

impl<P: Preset> SszSize for ValidatorBlindedBlock<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size =
        Size::for_untagged_union([BlindedBeaconBlock::<P>::SIZE, BeaconBlock::<P>::SIZE]);
}

impl<P: Preset> SszHash for ValidatorBlindedBlock<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::BlindedBeaconBlock { blinded_block, .. } => blinded_block.hash_tree_root(),
            Self::BeaconBlock(block) => block.hash_tree_root(),
        }
    }
}

impl<P: Preset> SszWrite for ValidatorBlindedBlock<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::BlindedBeaconBlock { blinded_block, .. } => blinded_block.write_variable(bytes),
            Self::BeaconBlock(block) => block.write_variable(bytes),
        }
    }
}

impl<P: Preset> ValidatorBlindedBlock<P> {
    #[must_use]
    pub fn into_blinded(self) -> Self {
        let Self::BeaconBlock(block) = self else {
            return self;
        };

        let Some(body) = block.body().post_bellatrix() else {
            return Self::BeaconBlock(block);
        };

        let execution_payload = block
            .clone()
            .execution_payload()
            .expect("post-Bellatrix blocks should have execution payload");

        let kzg_commitments = block
            .body()
            .post_deneb()
            .map(PostDenebBeaconBlockBody::blob_kzg_commitments)
            .cloned();

        let payload_header = body.execution_payload().to_header();
        let blinded_block = block
            .into_blinded(payload_header, kzg_commitments)
            .expect("phases should match because payload header was taken from block");

        Self::BlindedBeaconBlock {
            blinded_block,
            execution_payload: Box::new(execution_payload),
        }
    }

    #[must_use]
    pub const fn phase(&self) -> Phase {
        match self {
            Self::BlindedBeaconBlock { blinded_block, .. } => blinded_block.phase(),
            Self::BeaconBlock(block) => block.phase(),
        }
    }

    #[must_use]
    pub const fn is_blinded(&self) -> bool {
        matches!(self, Self::BlindedBeaconBlock { .. })
    }
}
