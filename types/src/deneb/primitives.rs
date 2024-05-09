use primitive_types::H384;
use ssz::{ByteVector, ContiguousVector};

use crate::{phase0::primitives::H256, preset::Preset};

// TODO(feature/deneb): KZG-related types should be in the `bls` crate,
//                      like the types for public keys and signatures.
//                      We will probably need two types: `KzgCommitment` and `KzgCommitmentBytes`.
//                      See `types::phase0::containers` for an explanation why.
//                      The one aliased to `H384` here should be named `KzgCommitmentBytes`.
//                      Copying `PublicKey` and `PublicKeyBytes` is probably best for now.
pub type Blob<P> = Box<ByteVector<<P as Preset>::BytesPerBlob>>;
pub type BlobIndex = u64;
pub type KzgCommitment = H384;
pub type KzgProof = H384;
pub type VersionedHash = H256;

pub type BlobCommitmentInclusionProof<P> =
    ContiguousVector<H256, <P as Preset>::KzgCommitmentInclusionProofDepth>;
