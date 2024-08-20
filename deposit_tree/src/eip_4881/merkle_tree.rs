use hashing::{hash_256_256, ZERO_HASHES};
use typenum::Unsigned;
use types::phase0::consts::DepositContractTreeDepth;
use ssz::H256;
use lazy_static::lazy_static;

use crate::FinalizedDeposit;

lazy_static! {
    static ref ZERO_NODES: Vec<EIP4881MerkleTree> = {
        (0..=MAX_TREE_DEPTH).map(EIP4881MerkleTree::Zero).collect()
    };
}

pub const MAX_TREE_DEPTH: usize = DepositContractTreeDepth::USIZE;
pub const EMPTY_SLICE: &[H256] = &[];

/// Right-sparse Merkle tree.
///
/// Efficiently represents a Merkle tree of fixed depth where only the first N
/// indices are populated by non-zero leaves (perfect for the deposit contract tree).
#[derive(Debug, PartialEq, Clone)]
pub enum EIP4881MerkleTree {
    Zero(usize),
    Leaf(H256),
    Node(H256, Box<Self>, Box<Self>),
    Finalized(H256)
}

impl Default for EIP4881MerkleTree {
    fn default() -> Self {
        Self::Zero(MAX_TREE_DEPTH)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum EIP4881MerkleTreeError {
    // Trying to push in a leaf
    LeafReached,
    // No more space in the MerkleTree
    MerkleTreeFull,
    // MerkleTree is invalid
    Invalid,
    // Incorrect Depth provided
    DepthTooSmall,
    // Overflow occurred
    ArithError,
    // Can't finalize a zero node
    ZeroNodeFinalized,
    // Can't push to finalized node
    FinalizedNodePushed,
    // Invalid Snapshot
    InvalidSnapshot(InvalidSnapshot),
    // Can't proof a finalized node
    ProofEncounteredFinalizedNode,
    // This should never happen
    PleaseNotifyTheDevs,
}

#[derive(Debug, PartialEq, Clone)]
pub enum InvalidSnapshot {
    // Branch hashes are empty but deposits are not
    EmptyBranchWithNonZeroDeposits(usize),
    // End of tree reached but deposits != 1
    EndOfTree,
}

impl EIP4881MerkleTree {
    #[must_use]
    pub fn create(leaves: &[H256], depth: usize) -> Self {
        use EIP4881MerkleTree::{Leaf, Node, Zero};
        if leaves.is_empty() {
            return Zero(depth);
        }

        match depth {
            0 => {
                debug_assert_eq!(leaves.len(), 1);
                Leaf(leaves[0])
            },
            _ => {
                let subtree_capacity = 2usize.pow(depth as u32 - 1);
                let (left_leaves, right_leaves) = if leaves.len() <= subtree_capacity {
                    (leaves, EMPTY_SLICE)
                } else {
                    leaves.split_at(subtree_capacity)
                };

                let left_subtree = Self::create(left_leaves, depth - 1);
                let right_subtree = Self::create(right_leaves, depth - 1);
                let hash = hash_256_256(left_subtree.hash(), right_subtree.hash());

                Node(hash, Box::new(left_subtree), Box::new(right_subtree))
            }
        }
    }

    pub fn push_leaf(&mut self, elem: H256, depth: usize) -> Result<(), EIP4881MerkleTreeError> {
        use EIP4881MerkleTree::{Finalized, Leaf, Node, Zero};

        if depth == 0 {
            return Err(EIP4881MerkleTreeError::DepthTooSmall);
        }

        match self {
            Leaf(_) => return Err(EIP4881MerkleTreeError::LeafReached),
            Zero(_) => {
                *self = Self::create(&[elem], depth)
            }
            Node(ref mut hash, ref mut left, ref mut right) => {
                let left: &mut Self = &mut *left;
                let right: &mut Self = &mut *right;
                match (&*left, &*right) {
                    (Leaf(_) | Finalized(_), Leaf(_)) => {
                        return Err(EIP4881MerkleTreeError::MerkleTreeFull);
                    }
                    // There is a right node so insert in right node
                    (Node(_, _, _) | Finalized(_), Node(_, _, _)) => {
                        right.push_leaf(elem, depth - 1)?;
                    }
                    (Zero(_), Zero(_)) => {
                        *left = Self::create(&[elem], depth - 1);
                    }
                    (Leaf(_) | Finalized(_), Zero(_)) => {
                        *right = Self::create(&[elem], depth - 1);
                    }
                    // Try inserting on the left node -> if it fails because it is full, insert in right side.
                    (Node(_, _, _), Zero(_)) => {
                        match left.push_leaf(elem, depth - 1) {
                            Ok(()) => (),
                            // Left node is full, insert in right node
                            Err(EIP4881MerkleTreeError::MerkleTreeFull) => {
                                *right = Self::create(&[elem], depth - 1);
                            }
                            Err(e) => return Err(e),
                        };
                    },
                    (_, _) => return Err(EIP4881MerkleTreeError::Invalid),
                }
                *hash = hash_256_256(left.hash(), right.hash());
            },
            Finalized(_) => return Err(EIP4881MerkleTreeError::FinalizedNodePushed),
        }

        Ok(())
    }

    #[must_use]
    pub const fn hash(&self) -> H256 {
        use EIP4881MerkleTree::{Finalized, Leaf, Node, Zero};
        match *self {
            Zero(depth) => ZERO_HASHES[depth],
            Leaf(hash) | Node(hash, _, _) | Finalized(hash) => hash,
        }
    }

    /// Get a reference to the left and right subtrees if they exist.
    #[must_use]
    pub fn left_and_right_branches(&self) -> Option<(&Self, &Self)> {
        use EIP4881MerkleTree::{Finalized, Leaf, Node, Zero};
        match *self {
            Finalized(_) | Leaf(_) | Zero(0) => None,
            Node(_, ref l, ref r) => Some((l, r)),
            Zero(depth) => Some((&ZERO_NODES[depth - 1], &ZERO_NODES[depth - 1])),
        }
    }

    /// Is this Merkle tree a leaf?
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf(_))
    }

    /// Finalize deposits up to deposit with count = deposits_to_finalize
    pub fn finalize_deposits(
        &mut self,
        deposits_to_finalize: usize,
        level: usize,
    ) -> Result<(), EIP4881MerkleTreeError> {
        use EIP4881MerkleTree::{Finalized, Leaf, Node, Zero};
        match self {
            Finalized(_) => Ok(()),
            Zero(_) => Err(EIP4881MerkleTreeError::ZeroNodeFinalized),
            Leaf(hash) => {
                if level != 0 { 
                    // This shouldn't happen but this is a sanity check
                    return Err(EIP4881MerkleTreeError::PleaseNotifyTheDevs);
                }
                *self = Finalized(*hash);
                Ok(())
            }
            Node(hash, left, right) => {
                if level == 0 {
                    // this shouldn't happen but we'll put it here for safety
                    return Err(EIP4881MerkleTreeError::PleaseNotifyTheDevs);
                }
                let deposits = 0x1 << level;
                if deposits <= deposits_to_finalize {
                    *self = Self::Finalized(*hash);
                    return Ok(());
                }
                left.finalize_deposits(deposits_to_finalize, level - 1)?;
                if deposits_to_finalize > deposits / 2 {
                    let remaining = deposits_to_finalize - deposits / 2;
                    right.finalize_deposits(remaining, level - 1)?;
                }
                Ok(())
            }
        }
    }


    fn append_finalized_hashes(&self, result: &mut FinalizedDeposit) {
        match self {
            Self::Zero(_) | Self::Leaf(_) => {}
            Self::Finalized(h) => { result.push(*h); },
            Self::Node(_, left, right) => {
                left.append_finalized_hashes(result);
                right.append_finalized_hashes(result);
            }
        }
    }

    #[must_use]
    pub fn get_finalized_hashes(&self) -> FinalizedDeposit {
        let mut result = FinalizedDeposit::default();
        self.append_finalized_hashes(&mut result);
        result
    }

    pub fn from_finalized_snapshot(
        finalized_branch: &Vec<H256>,
        deposit_count: usize,
        level: usize,
    ) -> Result<Self, EIP4881MerkleTreeError> {
        if finalized_branch.is_empty() {
            return if deposit_count == 0 {
                Ok(Self::Zero(level))
            } else {
                Err(InvalidSnapshot::EmptyBranchWithNonZeroDeposits(deposit_count).into())
            };
        }

        if deposit_count == (0x1 << level) {
            return Ok(Self::Finalized(
                *finalized_branch.first().ok_or(EIP4881MerkleTreeError::PleaseNotifyTheDevs)?
            ));
        }
        if level == 0 {
            return Err(InvalidSnapshot::EndOfTree.into());
        }

        let (left, right) = match deposit_count.checked_sub(0x1 << (level - 1)) {
            // left tree is fully finalized
            Some(right_deposits) => {
                let (left_hash, right_branch) = finalized_branch
                    .split_first()
                    .ok_or(EIP4881MerkleTreeError::PleaseNotifyTheDevs)?;
                (
                    Self::Finalized(*left_hash),
                    Self::from_finalized_snapshot(
                        &right_branch.into(),
                        right_deposits, 
                        level - 1
                    )?,
                )
            }
            // left tree is not fully finalized -> right tree is zero
            None => (
                Self::from_finalized_snapshot(finalized_branch, deposit_count, level - 1)?,
                Self::Zero(level - 1),
            ),
        };

        let hash = hash_256_256(left.hash(), right.hash());
        Ok(Self::Node(hash, Box::new(left), Box::new(right)))
    }

    /// Return the leaf at `index` and a Merkle proof of its inclusion.
    ///
    /// The Merkle proof is in "bottom-up" order, starting with a leaf node
    /// and moving up the tree. Its length will be exactly equal to `depth`.
    pub fn generate_proof(
        &self,
        index: usize,
        depth: usize,
    ) -> Result<(H256, Vec<H256>), EIP4881MerkleTreeError> {
        let mut proof = vec![];
        let mut current_node = self;
        let mut current_depth = depth;
        while current_depth > 0 {
            let ith_bit = (index >> (current_depth - 1)) & 0x01;
            if let &Self::Finalized(_) = current_node {
                return Err(EIP4881MerkleTreeError::ProofEncounteredFinalizedNode);
            }
            // Note: unwrap is safe because leaves are only ever constructed at depth == 0.
            let (left, right) = current_node.left_and_right_branches().unwrap();

            // Go right, include the left branch in the proof.
            if ith_bit == 1 {
                proof.push(left.hash());
                current_node = right;
            } else {
                proof.push(right.hash());
                current_node = left;
            }
            current_depth -= 1;
        }

        debug_assert_eq!(proof.len(), depth);
        debug_assert!(current_node.is_leaf());

        // Put proof in bottom-up order.
        proof.reverse();

        Ok((current_node.hash(), proof))
    }

    /// useful for debugging
    pub fn print_node(&self, mut space: u32) {
        const SPACES: u32 = 10;
        space += SPACES;
        let (pair, text) = match self {
            Self::Node(hash, left, right) => (Some((left, right)), format!("Node({})", hash)),
            Self::Leaf(hash) => (None, format!("Leaf({})", hash)),
            Self::Zero(depth) => (
                None,
                format!("Z[{}]({})", depth, ZERO_HASHES[*depth]),
            ),
            Self::Finalized(hash) => (None, format!("Finl({})", hash)),
        };
        if let Some((_, right)) = pair {
            right.print_node(space);
        }
        println!();
        for _i in SPACES..space {
            print!(" ");
        }
        println!("{}", text);
        if let Some((left, _)) = pair {
            left.print_node(space);
        }
    }
}

/// Verify a proof that `leaf` exists at `index` in a Merkle tree rooted at `root`.
///
/// The `branch` argument is the main component of the proof: it should be a list of internal
/// node hashes such that the root can be reconstructed (in bottom-up order).
pub fn verify_merkle_proof(
    leaf: H256,
    branch: &[H256],
    depth: usize,
    index: usize,
    root: H256,
) -> bool {
    if branch.len() == depth {
        merkle_root_from_branch(leaf, branch, depth, index) == root
    } else {
        false
    }
}

/// Compute a root hash from a leaf and a Merkle proof.
pub fn merkle_root_from_branch(leaf: H256, branch: &[H256], depth: usize, index: usize) -> H256 {
    assert_eq!(branch.len(), depth, "proof length should equal depth");

    let mut merkle_root = leaf.clone();

    for (i, leaf) in branch.iter().enumerate().take(depth) {
        let ith_bit = (index >> i) & 0x01;
        if ith_bit == 1 {
            merkle_root = hash_256_256(*leaf, merkle_root);
        } else {
            merkle_root = hash_256_256(merkle_root, *leaf);
        }
    }

    merkle_root
}

impl From<InvalidSnapshot> for EIP4881MerkleTreeError {
    fn from(e: InvalidSnapshot) -> Self {
        EIP4881MerkleTreeError::InvalidSnapshot(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    /// Check that we can:
    /// 1. Build a MerkleTree from arbitrary leaves and an arbitrary depth.
    /// 2. Generate valid proofs for all of the leaves of this MerkleTree.
    #[quickcheck]
    fn quickcheck_create_and_verify(int_leaves: Vec<u64>, depth: usize) -> TestResult {
        if depth > MAX_TREE_DEPTH || int_leaves.len() > 2usize.pow(depth as u32) {
            return TestResult::discard();
        }

        let leaves: Vec<_> = int_leaves.into_iter().map(H256::from_low_u64_be).collect();
        let merkle_tree = EIP4881MerkleTree::create(&leaves, depth);
        let merkle_root = merkle_tree.hash();

        let proofs_ok = (0..leaves.len()).all(|i| {
            let (leaf, branch) = merkle_tree
                .generate_proof(i, depth)
                .expect("should generate proof");
            leaf == leaves[i] && verify_merkle_proof(leaf, &branch, depth, i, merkle_root)
        });

        TestResult::from_bool(proofs_ok)
    }

    #[quickcheck]
    fn quickcheck_push_leaf_and_verify(int_leaves: Vec<u64>, depth: usize) -> TestResult {
        if depth == 0 || depth > MAX_TREE_DEPTH || int_leaves.len() > 2usize.pow(depth as u32) {
            return TestResult::discard();
        }

        let leaves_iter = int_leaves.into_iter().map(H256::from_low_u64_be);

        let mut merkle_tree = EIP4881MerkleTree::create(&[], depth);

        let proofs_ok = leaves_iter.enumerate().all(|(i, leaf)| {
            assert_eq!(merkle_tree.push_leaf(leaf, depth), Ok(()));
            let (stored_leaf, branch) = merkle_tree
                .generate_proof(i, depth)
                .expect("should generate proof");
            stored_leaf == leaf && verify_merkle_proof(leaf, &branch, depth, i, merkle_tree.hash())
        });

        TestResult::from_bool(proofs_ok)
    }

    #[test]
    fn sparse_zero_correct() {
        let depth = 2;
        let zero = H256::from([0x00; 32]);
        let dense_tree = EIP4881MerkleTree::create(&[zero, zero, zero, zero], depth);
        let sparse_tree = EIP4881MerkleTree::create(&[], depth);
        assert_eq!(dense_tree.hash(), sparse_tree.hash());
    }

    #[test]
    fn create_small_example() {
        // Construct a small merkle tree manually and check that it's consistent with
        // the MerkleTree type.
        let leaf_b00 = H256::from([0xAA; 32]);
        let leaf_b01 = H256::from([0xBB; 32]);
        let leaf_b10 = H256::from([0xCC; 32]);
        let leaf_b11 = H256::from([0xDD; 32]);

        let node_b0x = hash_256_256(leaf_b00, leaf_b01);
        let node_b1x = hash_256_256(leaf_b10, leaf_b11);

        let root = hash_256_256(node_b0x, node_b1x);

        let tree = EIP4881MerkleTree::create(&[leaf_b00, leaf_b01, leaf_b10, leaf_b11], 2);
        assert_eq!(tree.hash(), root);
    }

    #[test]
    fn verify_small_example() {
        // Construct a small merkle tree manually
        let leaf_b00 = H256::from([0xAA; 32]);
        let leaf_b01 = H256::from([0xBB; 32]);
        let leaf_b10 = H256::from([0xCC; 32]);
        let leaf_b11 = H256::from([0xDD; 32]);

        let node_b0x = hash_256_256(leaf_b00, leaf_b01);
        let node_b1x = hash_256_256(leaf_b10, leaf_b11);

        let root = hash_256_256(node_b0x, node_b1x);

        // Run some proofs
        assert!(verify_merkle_proof(
            leaf_b00,
            &[leaf_b01, node_b1x],
            2,
            0b00,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b01,
            &[leaf_b00, node_b1x],
            2,
            0b01,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b10,
            &[leaf_b11, node_b0x],
            2,
            0b10,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b11,
            &[leaf_b10, node_b0x],
            2,
            0b11,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b11,
            &[leaf_b10],
            1,
            0b11,
            node_b1x
        ));

        // Ensure that incorrect proofs fail
        // Zero-length proof
        assert!(!verify_merkle_proof(leaf_b01, &[], 2, 0b01, root));
        // Proof in reverse order
        assert!(!verify_merkle_proof(
            leaf_b01,
            &[node_b1x, leaf_b00],
            2,
            0b01,
            root
        ));
        // Proof too short
        assert!(!verify_merkle_proof(leaf_b01, &[leaf_b00], 2, 0b01, root));
        // Wrong index
        assert!(!verify_merkle_proof(
            leaf_b01,
            &[leaf_b00, node_b1x],
            2,
            0b10,
            root
        ));
        // Wrong root
        assert!(!verify_merkle_proof(
            leaf_b01,
            &[leaf_b00, node_b1x],
            2,
            0b01,
            node_b1x
        ));
    }

    #[test]
    fn verify_zero_depth() {
        let leaf = H256::from([0xD6; 32]);
        let junk = H256::from([0xD7; 32]);
        assert!(verify_merkle_proof(leaf, &[], 0, 0, leaf));
        assert!(!verify_merkle_proof(leaf, &[], 0, 7, junk));
    }

    #[test]
    fn push_complete_example() {
        let depth = 2;
        let mut tree = EIP4881MerkleTree::create(&[], depth);

        let leaf_b00 = H256::from([0xAA; 32]);

        let res = tree.push_leaf(leaf_b00, 0);
        assert_eq!(res, Err(EIP4881MerkleTreeError::DepthTooSmall));
        let expected_tree = EIP4881MerkleTree::create(&[], depth);
        assert_eq!(tree.hash(), expected_tree.hash());

        tree.push_leaf(leaf_b00, depth)
            .expect("Pushing in empty tree failed");
        let expected_tree = EIP4881MerkleTree::create(&[leaf_b00], depth);
        assert_eq!(tree.hash(), expected_tree.hash());

        let leaf_b01 = H256::from([0xBB; 32]);
        tree.push_leaf(leaf_b01, depth)
            .expect("Pushing in left then right node failed");
        let expected_tree = EIP4881MerkleTree::create(&[leaf_b00, leaf_b01], depth);
        assert_eq!(tree.hash(), expected_tree.hash());

        let leaf_b10 = H256::from([0xCC; 32]);
        tree.push_leaf(leaf_b10, depth)
            .expect("Pushing in right then left node failed");
        let expected_tree = EIP4881MerkleTree::create(&[leaf_b00, leaf_b01, leaf_b10], depth);
        assert_eq!(tree.hash(), expected_tree.hash());

        let leaf_b11 = H256::from([0xDD; 32]);
        tree.push_leaf(leaf_b11, depth)
            .expect("Pushing in outtermost leaf failed");
        let expected_tree = EIP4881MerkleTree::create(&[leaf_b00, leaf_b01, leaf_b10, leaf_b11], depth);
        assert_eq!(tree.hash(), expected_tree.hash());

        let leaf_b12 = H256::from([0xEE; 32]);
        let res = tree.push_leaf(leaf_b12, depth);
        assert_eq!(res, Err(EIP4881MerkleTreeError::MerkleTreeFull));
        assert_eq!(tree.hash(), expected_tree.hash());
    }
}