use ssz::{ByteVector, ContiguousVector};

use crate::{
    deneb::primitives::KzgProof,
    phase0::primitives::H256,
    preset::{BytesPerCell, Preset},
};

pub type RowIndex = u64;
pub type CellIndex = u64;
pub type ColumnIndex = u64;
pub type CustodyIndex = u64;
pub type Cell<P> = Box<ByteVector<BytesPerCell<P>>>;
pub type ExtCells<P> = ContiguousVector<Cell<P>, <P as Preset>::CellsPerExtBlob>;
pub type BlobCommitmentsInclusionProof<P> =
    ContiguousVector<H256, <P as Preset>::KzgCommitmentsInclusionProofDepth>;
pub type CellsAndKzgProofs<P> = (
    ExtCells<P>,
    ContiguousVector<KzgProof, <P as Preset>::CellsPerExtBlob>,
);
