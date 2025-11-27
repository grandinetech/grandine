use ssz::H256;
use thiserror::Error;
use types::phase0::primitives::Slot;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cell proofs length is invalid: {proofs_length} expected: {expected}")]
    InvalidCellsProofsLength {
        expected: usize,
        proofs_length: usize,
    },
    #[error(
        "custody group count is invalid: {custody_group_count} expected <= {number_of_custody_groups}", 
    )]
    InvalidCustodyGroupCount {
        custody_group_count: u64,
        number_of_custody_groups: u64,
    },
    #[error("custody group is invalid: {custody_group} expected < {number_of_custody_groups}")]
    InvalidCustodyGroup {
        custody_group: u64,
        number_of_custody_groups: u64,
    },
    #[error("number of blobs {blob_count} does not match commitment length {commitments_length}")]
    BlobCommitmentsLengthMismatch {
        blob_count: usize,
        commitments_length: usize,
    },
    #[error(
        "attempted to construct data column sidecars for pre-Fulu block: slot: {slot}, root: {root:?}"
    )]
    DataColumnSidecarsForPreFuluBlock { root: H256, slot: Slot },
    #[error(
        "attempted to construct fulu data column sidecars for post-Gloas block: slot: {slot}, root: {root:?}"
    )]
    FuluDataColumnSidecarsForPostGloasBlock { root: H256, slot: Slot },
    #[error(
        "attempted to construct gloas data column sidecars for pre-Gloas block: slot: {slot}, root: {root:?}"
    )]
    GloasDataColumnSidecarsForPreGloasBlock { root: H256, slot: Slot },
}
