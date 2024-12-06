use ssz::{ByteVector, ContiguousVector};

use crate::{
    fulu::consts::{BytesPerCell, KzgCommitmentsInclusionProofDepth},
    phase0::primitives::H256,
};

pub type RowIndex = u64;
pub type ColumnIndex = u64;
pub type Cell = Box<ByteVector<BytesPerCell>>;
pub type BlobCommitmentsInclusionProof = ContiguousVector<H256, KzgCommitmentsInclusionProofDepth>;
