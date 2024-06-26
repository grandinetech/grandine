use hex_literal::hex;
use ssz::MerkleElements;
use typenum::{U32, U6};

use crate::{deneb::primitives::KzgCommitment, preset::Preset};

pub const VERSIONED_HASH_VERSION_KZG: &[u8] = &hex!("01");

// TODO(feature/deneb): Can `BlobSidecarSubnetCount` be a `const`?
//                      It's never used as a type even in `eth2_libp2p`.
pub type BlobSidecarSubnetCount = U6;
pub type BytesPerFieldElement = U32;

pub type BlobCommitmentTreeDepth<P> = <
    <P as Preset>::MaxBlobCommitmentsPerBlock as MerkleElements<KzgCommitment>
>::UnpackedMerkleTreeDepth;
