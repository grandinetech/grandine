//! The VRF tree of a validator ([`compute_vrf_root`] and [`compute_vrf_proof`]).
//!
//! A tree of depth `VRF_TREE_DEPTH` has `2^31` leaves, so building it takes billions of hashes.
//! [`VrfTree`] builds it once and keeps the nodes at [`CACHE_HEIGHT`]. A proof rebuilds only the
//! subtree under the cached node above its leaf.
//!
//! [`compute_vrf_root`]: https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/validator.md#new-compute_vrf_root
//! [`compute_vrf_proof`]: https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/validator.md#new-compute_vrf_proof

use anyhow::{Result, ensure};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use ssz::H256;
use try_from_iterator::TryFromIterator as _;
use types::{
    phase0::primitives::Slot,
    pq::{consts::VRF_TREE_DEPTH, primitives::VrfProof},
};

use crate::pq::keccak256;

/// The height of the nodes a [`VrfTree`] keeps. A proof rebuilds a subtree of `2^CACHE_HEIGHT`
/// leaves, and a tree of depth `VRF_TREE_DEPTH` keeps `2^11` nodes (64 KiB).
pub const CACHE_HEIGHT: u32 = 20;

/// [`compute_vrf_leaf`](https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/validator.md#new-compute_vrf_leaf)
#[must_use]
pub fn compute_vrf_leaf(vrf_seed: H256, index: u64) -> H256 {
    keccak256(&[vrf_seed.as_bytes(), &index.to_le_bytes()])
}

pub struct VrfTree {
    vrf_seed: H256,
    depth: u32,
    cache_height: u32,
    // The nodes at `cache_height`, left to right.
    cached_nodes: Vec<H256>,
}

impl VrfTree {
    /// Builds the tree of depth `VRF_TREE_DEPTH`. Takes minutes. Do not call on an async executor
    /// thread.
    #[must_use]
    pub fn build(vrf_seed: H256) -> Self {
        Self::build_with_depth(vrf_seed, depth(), CACHE_HEIGHT)
    }

    /// A tree whose cached nodes were saved by [`Self::cached_nodes`].
    pub fn from_cached_nodes(vrf_seed: H256, cached_nodes: Vec<H256>) -> Result<Self> {
        Self::from_cached_nodes_with_depth(vrf_seed, depth(), CACHE_HEIGHT, cached_nodes)
    }

    fn build_with_depth(vrf_seed: H256, depth: u32, cache_height: u32) -> Self {
        let cache_height = cache_height.min(depth);
        let cached_node_count = 1_u64 << depth.saturating_sub(cache_height);

        let cached_nodes = (0..cached_node_count)
            .into_par_iter()
            .map(|index| compute_node(vrf_seed, cache_height, index, None, &mut []))
            .collect();

        Self {
            vrf_seed,
            depth,
            cache_height,
            cached_nodes,
        }
    }

    fn from_cached_nodes_with_depth(
        vrf_seed: H256,
        depth: u32,
        cache_height: u32,
        cached_nodes: Vec<H256>,
    ) -> Result<Self> {
        let cache_height = cache_height.min(depth);
        let expected = 1_usize << depth.saturating_sub(cache_height);

        ensure!(
            cached_nodes.len() == expected,
            "expected {expected} cached VRF tree nodes, found {}",
            cached_nodes.len(),
        );

        Ok(Self {
            vrf_seed,
            depth,
            cache_height,
            cached_nodes,
        })
    }

    #[must_use]
    pub fn cached_nodes(&self) -> &[H256] {
        &self.cached_nodes
    }

    /// [`compute_vrf_root`](https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/validator.md#new-compute_vrf_root)
    #[must_use]
    pub fn root(&self) -> H256 {
        let mut level = self.cached_nodes.clone();

        while level.len() > 1 {
            level = parents(&level);
        }

        level.first().copied().unwrap_or_default()
    }

    /// [`compute_vrf_proof`](https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/validator.md#new-compute_vrf_proof)
    pub fn proof(&self, slot: Slot) -> Result<VrfProof> {
        VrfProof::try_from_iter(self.leaf_and_branch(slot)?).map_err(Into::into)
    }

    fn leaf_and_branch(&self, slot: Slot) -> Result<Vec<H256>> {
        ensure!(
            slot >> self.depth == 0,
            "slot {slot} is past the VRF tree of depth {}",
            self.depth,
        );

        let mut lower_branch = vec![H256::zero(); usize::try_from(self.cache_height)?];

        compute_node(
            self.vrf_seed,
            self.cache_height,
            slot >> self.cache_height,
            Some(slot),
            &mut lower_branch,
        );

        let mut upper_branch = vec![];
        let mut level = self.cached_nodes.clone();
        let mut index = usize::try_from(slot >> self.cache_height)?;

        while level.len() > 1 {
            if let Some(sibling) = level.get(index ^ 1) {
                upper_branch.push(*sibling);
            }

            level = parents(&level);
            index >>= 1;
        }

        Ok(core::iter::once(compute_vrf_leaf(self.vrf_seed, slot))
            .chain(lower_branch)
            .chain(upper_branch)
            .collect())
    }
}

fn depth() -> u32 {
    u32::try_from(VRF_TREE_DEPTH).expect("VRF_TREE_DEPTH fits in u32")
}

fn parents(level: &[H256]) -> Vec<H256> {
    let (pairs, _) = level.as_chunks::<2>();

    pairs
        .iter()
        .map(|[left, right]| keccak256(&[left.as_bytes(), right.as_bytes()]))
        .collect()
}

// The spec's `compute_vrf_node`, which also records the siblings on the path to the leaf at
// `path` when the node is above it. `branch[height]` is the sibling at `height`.
fn compute_node(
    vrf_seed: H256,
    height: u32,
    index: u64,
    path: Option<u64>,
    branch: &mut [H256],
) -> H256 {
    let Some(child_height) = height.checked_sub(1) else {
        return compute_vrf_leaf(vrf_seed, index);
    };

    let left_index = index << 1;
    let right_index = left_index | 1;

    let left = compute_node(vrf_seed, child_height, left_index, path, branch);
    let right = compute_node(vrf_seed, child_height, right_index, path, branch);

    if let Some(path) = path {
        let child = path >> child_height;

        if child >> 1 == index
            && let Some(sibling) = usize::try_from(child_height)
                .ok()
                .and_then(|child_height| branch.get_mut(child_height))
        {
            *sibling = if child & 1 == 0 { right } else { left };
        }
    }

    keccak256(&[left.as_bytes(), right.as_bytes()])
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::pq::vrf_root_from_branch;

    use super::*;

    // The spec's `compute_vrf_node`, transcribed.
    fn spec_compute_vrf_node(vrf_seed: H256, height: u32, index: u64) -> H256 {
        let Some(child_height) = height.checked_sub(1) else {
            return compute_vrf_leaf(vrf_seed, index);
        };

        let left = spec_compute_vrf_node(vrf_seed, child_height, index << 1);
        let right = spec_compute_vrf_node(vrf_seed, child_height, (index << 1) | 1);

        keccak256(&[left.as_bytes(), right.as_bytes()])
    }

    #[test]
    fn small_trees_match_the_spec_and_their_proofs_verify() -> Result<()> {
        let vrf_seed = H256::repeat_byte(7);

        for (depth, cache_height) in [(1, 0), (5, 2), (6, 3), (6, 6), (6, 20)] {
            let tree = VrfTree::build_with_depth(vrf_seed, depth, cache_height);
            let root = spec_compute_vrf_node(vrf_seed, depth, 0);

            assert_eq!(tree.root(), root);

            for slot in 0..1 << depth {
                let proof = tree.leaf_and_branch(slot)?;

                let expected_branch = (0..depth)
                    .map(|height| spec_compute_vrf_node(vrf_seed, height, (slot >> height) ^ 1))
                    .collect::<Vec<_>>();

                assert_eq!(proof[0], compute_vrf_leaf(vrf_seed, slot));
                assert_eq!(proof[1..], expected_branch);
                assert_eq!(vrf_root_from_branch(proof[0], slot, &proof[1..]), root);
            }

            let reloaded = VrfTree::from_cached_nodes_with_depth(
                vrf_seed,
                depth,
                cache_height,
                tree.cached_nodes().to_vec(),
            )?;

            assert_eq!(reloaded.root(), root);
        }

        Ok(())
    }

    // The vector pinned by the pq-devnet-0 genesis tool (`ethpandaops/eth-beacon-genesis@ff42fce`,
    // `validators/vrf_test.go`), which built the VRF roots in the devnet genesis.
    #[test]
    fn nodes_match_the_genesis_tool() {
        let vrf_seed = H256(hex!(
            "543fc5a4d86e79a434e9741770f7ee17c25bdc31be8d61436d7f9836538b03df"
        ));

        assert_eq!(
            compute_node(vrf_seed, 18, 1, None, &mut []),
            H256(hex!(
                "a8e932e0dd6ec363635fdb0b30ea60d24cc1a861904c879e236c0e77f9efa562"
            )),
        );
    }

    #[test]
    fn proofs_past_the_tree_are_refused() {
        let tree = VrfTree::build_with_depth(H256::zero(), 4, 2);

        tree.leaf_and_branch(16)
            .expect_err("a tree of depth 4 has 16 leaves");
    }
}
