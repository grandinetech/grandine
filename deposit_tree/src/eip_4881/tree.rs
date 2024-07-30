use ssz::MerkleTree;
use types::phase0::{consts::DepositContractTreeDepth, containers::Eth1Data, primitives::ExecutionBlockNumber};

use crate::DepositTreeSnapshot;

pub struct DepositTree {
    pub merkle_tree: MerkleTree<DepositContractTreeDepth>,
    pub mix_in_length: u64,
}