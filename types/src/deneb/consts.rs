use hex_literal::hex;
use ssz::MerkleElements;
use typenum::U32;

use crate::{deneb::primitives::KzgCommitment, preset::Preset};

pub const VERSIONED_HASH_VERSION_KZG: &[u8] = &hex!("01");

pub type BytesPerFieldElement = U32;

pub type BlobCommitmentTreeDepth<P> = <
    <P as Preset>::MaxBlobCommitmentsPerBlock as MerkleElements<KzgCommitment>
>::UnpackedMerkleTreeDepth;
