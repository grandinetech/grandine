use ssz::{hashing::ZERO_HASHES, PersistentList, Ssz};
use typenum::Unsigned;
use types::phase0::{
    consts::DepositContractTreeDepth,
    primitives::{DepositIndex, ExecutionBlockNumber, H256},
};
use hashing::hash_256_256;

pub type FinalizedDeposit = PersistentList<H256, DepositContractTreeDepth>;

#[derive(Clone, Default, Ssz, Copy, PartialEq)]
pub struct FinalizedExecutionBlock {
    pub deposit_root: H256,
    pub deposit_count: DepositIndex,
    pub block_hash: H256,
    pub block_height: ExecutionBlockNumber,
}

// This is an implementation of a deposit tree snapshot described in EIP-4881
// ref: https://eips.ethereum.org/EIPS/eip-4881#reference-implementation
#[derive(Clone, Default, Ssz, PartialEq)]
#[ssz(derive_hash = false)]
pub struct DepositTreeSnapshot {
    // proof of the latest finalized deposit
    pub finalized: FinalizedDeposit,
    pub execution_block: FinalizedExecutionBlock,
}

impl DepositTreeSnapshot {
    #[must_use]
    pub fn calculate_root(&self) -> H256 {
        let mut size = self.execution_block.deposit_count;
        let mut index = self.finalized.len_u64();
        let mut root = ZERO_HASHES[0];
        ZERO_HASHES
            .iter()
            .take(DepositContractTreeDepth::USIZE)
            .for_each(|zero_hash| {
                if size & 1 == 1 {
                    index -= 1;
                    // this is safe because index is never bigger than finalized.len() 
                    root = hash_256_256(*self.finalized.get(index).unwrap(), root);
                } else {
                    root = hash_256_256(root, *zero_hash);
                }
                size >>= 1;
            });
        hash_256_256(root, H256::from_slice(&self.execution_block.deposit_count.to_le_bytes()))
    }

    #[must_use]
    pub fn from_tree_parts(
        finalized: FinalizedDeposit,
        deposit_count: DepositIndex,
        execution_block: (H256, ExecutionBlockNumber)
    ) -> Self {
        let mut snapshot = Self {
            finalized,
            execution_block: FinalizedExecutionBlock {
                deposit_root: ZERO_HASHES[0],
                deposit_count,
                block_hash: execution_block.0,
                block_height: execution_block.1
            }
        };
        snapshot.execution_block.deposit_root = snapshot.calculate_root();
        snapshot
    }
}

impl From<&DepositTreeSnapshot> for FinalizedExecutionBlock {
    fn from(snapshot: &DepositTreeSnapshot) -> Self {
        Self {
            deposit_root: snapshot.execution_block.deposit_root,
            deposit_count: snapshot.execution_block.deposit_count,
            block_hash: snapshot.execution_block.block_hash,
            block_height: snapshot.execution_block.block_height,
        }
    }
}