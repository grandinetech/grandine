use std::ops::Add;
use core::ops::Range;

use anyhow::{ensure, Result};
use thiserror::Error;
use typenum::Unsigned as _;
use ssz::{mix_in_length, Ssz, SszHash, H256};
use types::phase0::{
    consts::DepositContractTreeDepth,
    containers::DepositData,
    primitives::DepositIndex
};

use crate::DepositTreeSnapshot;

use super::{
    merkle_tree::{EIP4881MerkleTree, EIP4881MerkleTreeError},
    snapshot::FinalizedExecutionBlock
};

const MAX_DEPOSITS: DepositIndex = 1 << DepositContractTreeDepth::USIZE;

#[derive(Clone, Default, Ssz)]
pub struct DepositDataTree {
    pub tree: EIP4881MerkleTree,
    pub length: DepositIndex,
    pub finalized_execution_block: FinalizedExecutionBlock,
    pub depth: u32
}

impl DepositDataTree {
    #[must_use]
    pub fn create(leaves: &[H256], length: DepositIndex, depth: u32) -> Self {
        Self {
            tree: EIP4881MerkleTree::create(leaves, depth),
            length,
            finalized_execution_block: FinalizedExecutionBlock::default(),
            depth,
        }
    }

    /// Retrieve the root hash of this Merkle tree with the length mixed in.
    #[must_use]
    pub fn root(&self) -> H256 {
        mix_in_length(self.tree.hash(), self.length as usize)
    }

    /// Return the leaf at `index` and a Merkle proof of its inclusion.
    ///
    /// The Merkle proof is in "bottom-up" order, starting with a leaf node
    /// and moving up the tree. Its length will be exactly equal to `depth + 1`.
    pub fn generate_proof(&self, index: DepositIndex) -> Result<(H256, Vec<H256>), EIP4881MerkleTreeError> {
        let (root, mut proof) = self.tree.generate_proof(index, self.depth)?;
        proof.push(self.root());
        Ok((root, proof))
    }

    /// Add a deposit to the merkle tree.
    pub fn push_leaf(&mut self, leaf: H256) -> Result<(), EIP4881MerkleTreeError> {
        self.tree.push_leaf(leaf, self.depth)?;
        self.length = self.length.add(1);
        Ok(())
    }

    /// Finalize deposits up to `finalized_execution_block.deposit_count`
    pub fn finalize(
        &mut self,
        finalized_execution_block: FinalizedExecutionBlock
    ) -> Result<(), EIP4881MerkleTreeError> {
        self.tree
            .finalize_deposits(finalized_execution_block.deposit_count, self.depth)?;
        self.finalized_execution_block = finalized_execution_block;
        Ok(())
    }

    pub fn push(&mut self, index: DepositIndex, data: DepositData) -> Result<H256> {
        features::log!(
            DebugEth1,
            "DepositDataTree::push_and_compute_root \
             (self.deposit_count: {}, index: {index}, data: {data:?})",
            self.length,
        );

        self.validate_index(index)?;
        let chunk = data.hash_tree_root();
        let _ = self.push_leaf(chunk);
        Ok(self.root())
    }

    pub fn push_and_compute_root(
        &mut self,
        index: DepositIndex,
        data: DepositData
    ) -> Result<H256> {
        self.push(index, data)?;
        Ok(self.root())
    }

    /// Get snapshot of finalized deposit tree (if tree is finalized)
    #[must_use]
    pub fn get_snapshot(&self) -> Option<DepositTreeSnapshot> {
        let finalized_execution_block = self.finalized_execution_block;
        Some(DepositTreeSnapshot {
            finalized: self.tree.get_finalized_hashes(),
            execution_block: FinalizedExecutionBlock {
                deposit_root: finalized_execution_block.deposit_root,
                deposit_count: finalized_execution_block.deposit_count,
                block_hash: finalized_execution_block.block_hash,
                block_height: finalized_execution_block.block_height,
            }
        })
    }

    /// Create a new Merkle tree from a snapshot
    pub fn from_snapshot(
        snapshot: &DepositTreeSnapshot,
        depth: u32,
    ) -> Result<Self, EIP4881MerkleTreeError> {
        Ok(Self {
            tree: EIP4881MerkleTree::from_finalized_snapshot(
                &snapshot.finalized.into_iter().map(|hash| *hash).collect(),
                snapshot.execution_block.deposit_count,
                depth,
            )?,
            length: snapshot.execution_block.deposit_count,
            finalized_execution_block: snapshot.into(),
            depth,
        })
    }

    fn validate_index(&self, index: DepositIndex) -> Result<usize> {
        Self::validate_index_fits(index)?;
        self.validate_index_expected(index)?;
        index.try_into().map_err(Into::into)
    }

    fn validate_index_fits(index: DepositIndex) -> Result<()> {
        ensure!(index < MAX_DEPOSITS, Error::Full { index });
        Ok(())
    }

    fn validate_index_expected(&self, index: DepositIndex) -> Result<()> {
        let expected = self.length;
        let actual = index;

        ensure!(
            actual == expected,
            Error::UnexpectedIndex { expected, actual },
        );

        Ok(())
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("attempted to add deposit with index {index} to full deposit tree")]
    Full { index: DepositIndex },
    #[error("expected deposit with index {expected}, received deposit with index {actual}")]
    UnexpectedIndex {
        expected: DepositIndex,
        actual: DepositIndex,
    },
    #[error(
        "index ranges are invalid \
         (deposit_indices: {deposit_indices:?}, proof_indices: {proof_indices:?})"
    )]
    InvalidIndexRanges {
        deposit_indices: Range<DepositIndex>,
        proof_indices: Range<DepositIndex>,
    },
    #[error(
        "deposit data count ({data_count}) does not match deposit index count ({index_count})"
    )]
    CountMismatch {
        data_count: usize,
        index_count: usize,
    },
}
