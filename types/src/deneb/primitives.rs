use primitive_types::H384;
use ssz::{ByteVector, ContiguousList, ContiguousVector};

use crate::{
    phase0::primitives::H256,
    preset::{BytesPerBlob, Preset},
};

// TODO(feature/deneb): KZG-related types should be in the `bls` crate,
//                      like the types for public keys and signatures.
//                      We will probably need two types: `KzgCommitment` and `KzgCommitmentBytes`.
//                      See `types::phase0::containers` for an explanation why.
//                      The one aliased to `H384` here should be named `KzgCommitmentBytes`.
//                      Copying `PublicKey` and `PublicKeyBytes` is probably best for now.
pub type Blob<P> = Box<ByteVector<BytesPerBlob<P>>>;
pub type BlobIndex = u64;
pub type KzgCommitment = H384;
pub type KzgProof = H384;
pub type VersionedHash = H256;

pub type BlobCommitmentInclusionProof<P> =
    ContiguousVector<H256, <P as Preset>::KzgCommitmentInclusionProofDepth>;

// We choose max length of KZG proofs to be maximum possible cells per ext blob, where each cell is
// a single field element. this is for future proof, if we want to make cells smaller without
// needing to update the structure every increment.
//
// NOTE: this might be diverge from the specs (Deneb limits on `P::MaxBlobCommitmentsPerBlock` while
// in Fulu limits on `P::MaxCellsProofsPerBlock`), we should chose to use the maximum possible
// value on the length limits to avoid complicated types conversion in `builder_api`.
pub type KzgProofs<P> = ContiguousList<KzgProof, <P as Preset>::MaxCellProofsPerBlock>;
