pub mod tree;
pub mod eip_4881;

pub use tree::DepositTree;
pub use eip_4881::deposit_tree::DepositDataTree;
pub use eip_4881::merkle_tree::{EIP4881MerkleTree, EIP4881MerkleTreeError, MAX_TREE_DEPTH, EMPTY_SLICE};
pub use eip_4881::snapshot::{DepositTreeSnapshot, FinalizedDeposit};
