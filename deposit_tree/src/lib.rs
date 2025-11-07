use core::ops::Range;

use anyhow::{Result, ensure};
use itertools::Itertools as _;
use ssz::{MerkleTree, Ssz, SszHash as _};
use thiserror::Error;
use typenum::Unsigned as _;
use types::phase0::{
    consts::DepositContractTreeDepth,
    containers::{Deposit, DepositData},
    primitives::{DepositIndex, ExecutionBlockNumber, H256},
};

const MAX_DEPOSITS: DepositIndex = 1 << DepositContractTreeDepth::USIZE;

// We do not store the whole deposit tree, only hashes that are needed to construct proofs.
// These implementations appear to use the same algorithm:
// - <https://github.com/ethereum/research/blob/a4a600f2869feed5bfaab24b13ca1692069ef312/beacon_chain_impl/progressive_merkle_tree.py>
// - <https://github.com/ethereum/consensus-specs/blob/fbfe024e7ad13b62efd5c2d4c56a34c5b15b45a9/deposit_contract/contracts/validator_registration.vy>
// - <https://github.com/ethereum/consensus-specs/blob/270a66e36cc13787495d133ffcc909b377beefb5/solidity_deposit_contract/deposit_contract.sol>
//
// See the [reference implementation in EIP-4881] for another approach.
//
// [reference implementation in EIP-4881]: https://eips.ethereum.org/EIPS/eip-4881#reference-implementation
#[derive(Clone, Copy, Default, Ssz)]
#[ssz(derive_hash = false)]
pub struct DepositTree {
    pub merkle_tree: MerkleTree<DepositContractTreeDepth>,
    pub deposit_count: DepositIndex,
    // Latest Eth1 block from which deposits were added to deposit tree
    pub last_added_block_number: ExecutionBlockNumber,
}

impl DepositTree {
    pub fn push(&mut self, index: DepositIndex, data: DepositData) -> Result<()> {
        features::log!(
            DebugEth1,
            "DepositTree::push (self.deposit_count: {}, index: {index}, data: {data:?})",
            self.deposit_count,
        );

        let index = self.validate_index(index)?;
        let chunk = data.hash_tree_root();

        self.merkle_tree.push(index, chunk);
        self.deposit_count += 1;

        Ok(())
    }

    pub fn push_and_compute_root(
        &mut self,
        index: DepositIndex,
        data: DepositData,
    ) -> Result<H256> {
        features::log!(
            DebugEth1,
            "DepositTree::push_and_compute_root \
             (self.deposit_count: {}, index: {index}, data: {data:?})",
            self.deposit_count,
        );

        let index = self.validate_index(index)?;
        let chunk = data.hash_tree_root();
        let root = self.merkle_tree.push_and_compute_root(index, chunk);
        let root_with_length = ssz::mix_in_length(root, index + 1);

        self.deposit_count += 1;

        Ok(root_with_length)
    }

    pub fn extend_and_construct_proofs(
        &mut self,
        deposit_data: &[&DepositData],
        deposit_indices: Range<DepositIndex>,
        proof_indices: Range<DepositIndex>,
    ) -> Result<Vec<Deposit>> {
        ensure!(
            deposit_indices.start <= proof_indices.start
                && proof_indices.start < proof_indices.end
                && proof_indices.end <= deposit_indices.end,
            Error::InvalidIndexRanges {
                deposit_indices,
                proof_indices,
            },
        );

        Self::validate_index_fits(deposit_indices.end - 1)?;
        self.validate_index_expected(deposit_indices.start)?;

        let deposit_indices = deposit_indices.start.try_into()?..deposit_indices.end.try_into()?;
        let proof_indices = proof_indices.start.try_into()?..proof_indices.end.try_into()?;

        let data_count = deposit_data.len();
        let index_count = deposit_indices.len();

        ensure!(
            data_count == index_count,
            Error::CountMismatch {
                data_count,
                index_count,
            },
        );

        let chunks = deposit_data
            .iter()
            .copied()
            .map(DepositData::hash_tree_root);

        let deposit_data = proof_indices
            .clone()
            .map(|index| deposit_data[index - deposit_indices.start])
            .copied();

        let deposits = self
            .merkle_tree
            .extend_and_construct_proofs(chunks, deposit_indices.clone(), proof_indices)
            .zip_eq(deposit_data)
            .map(|(proof, data)| Deposit { proof, data })
            .collect();

        self.deposit_count = deposit_indices.end.try_into()?;

        Ok(deposits)
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
        let expected = self.deposit_count;
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
    #[error("deposit data count ({data_count}) does not match deposit index count ({index_count})")]
    CountMismatch {
        data_count: usize,
        index_count: usize,
    },
}

#[cfg(test)]
mod tests {
    use pubkey_cache::PubkeyCache;
    use spec_test_utils::Case;
    use std_ext::ArcExt as _;
    use test_generator::test_resources;
    use types::{
        config::Config,
        phase0::{containers::Eth1Data, primitives::ExecutionBlockHash},
        preset::{Minimal, Preset},
        traits::BeaconState as _,
    };

    use super::*;

    #[test]
    fn push_fails_when_tree_is_full() {
        let mut full_tree = DepositTree {
            deposit_count: MAX_DEPOSITS,
            ..DepositTree::default()
        };

        full_tree
            .push(MAX_DEPOSITS, DepositData::default())
            .expect_err("pushing to a full tree should fail");
    }

    #[test]
    fn push_fails_on_unexpected_index() {
        let mut deposit_tree = DepositTree::default();

        deposit_tree
            .push(1, DepositData::default())
            .expect_err("pushing with incorrect index should fail");
    }

    #[test]
    fn push_and_compute_root_fails_when_tree_is_full() {
        let mut full_tree = DepositTree {
            deposit_count: MAX_DEPOSITS,
            ..DepositTree::default()
        };

        full_tree
            .push_and_compute_root(MAX_DEPOSITS, DepositData::default())
            .expect_err("pushing to a full tree should fail");
    }

    #[test]
    fn push_and_compute_root_fails_on_unexpected_index() {
        let mut deposit_tree = DepositTree::default();

        deposit_tree
            .push_and_compute_root(1, DepositData::default())
            .expect_err("pushing with incorrect index should fail");
    }

    #[test]
    fn extend_and_construct_proofs_fails_on_empty_ranges() {
        let deposit_data = &[];
        let deposit_indices = 0..0;
        let proof_indices = deposit_indices.clone();

        let mut deposit_tree = DepositTree::default();

        deposit_tree
            .extend_and_construct_proofs(deposit_data, deposit_indices, proof_indices)
            .expect_err("extending with empty ranges should fail");
    }

    #[test]
    fn extend_and_construct_proofs_fails_when_tree_is_full() {
        let deposit_data = &[&DepositData::default()];
        let deposit_indices = MAX_DEPOSITS..MAX_DEPOSITS + 1;
        let proof_indices = deposit_indices.clone();

        let mut full_tree = DepositTree {
            deposit_count: MAX_DEPOSITS,
            ..DepositTree::default()
        };

        full_tree
            .extend_and_construct_proofs(deposit_data, deposit_indices, proof_indices)
            .expect_err("extending a full tree should fail");
    }

    #[test]
    fn extend_and_construct_proofs_fails_on_unexpected_index() {
        let deposit_data = &[&DepositData::default()];
        let deposit_indices = 1..2;
        let proof_indices = deposit_indices.clone();

        let mut deposit_tree = DepositTree::default();

        deposit_tree
            .extend_and_construct_proofs(deposit_data, deposit_indices, proof_indices)
            .expect_err("extending with incorrect index should fail");
    }

    // The tests based on `genesis/initialization` do not cover the multiple deposit case.
    // Deposits processed during genesis (in `initialize_beacon_state_from_eth1`) are supposed to
    // have proofs for the addition of each deposit individually. They do not contain hashes
    // computed from later deposits. This may have been intended as an optimization for genesis.
    // If the proofs included hashes computed from later deposits like they are supposed to after
    // genesis, all of them would have to be updated for every new deposit. On the other hand, proof
    // construction and verification can be avoided entirely during genesis, which is what we do in
    // our implementation.
    #[test]
    fn extend_and_construct_proofs_handles_vote_for_multiple_deposits() -> Result<()> {
        let config = Config::minimal();
        let pubkey_cache = PubkeyCache::default();

        let (mut state_0, deposit_tree_0) =
            factory::min_genesis_state::<Minimal>(&config, &pubkey_cache)?;

        // Enough deposits to fill block #1 and leave one for block #2.
        let block_0_count = state_0.eth1_deposit_index();
        let block_1_count = block_0_count + <Minimal as Preset>::MaxDeposits::U64;
        let block_2_count = block_1_count + 1;

        let new_deposit_data = (block_0_count..block_2_count)
            .map(interop::secret_key)
            .map(|secret_key| interop::quick_start_deposit_data::<Minimal>(&config, &secret_key))
            .collect_vec();

        let deposit_root_2 = new_deposit_data
            .iter()
            .copied()
            .zip_eq(block_0_count..block_2_count)
            .scan(deposit_tree_0, |deposit_tree, (data, index)| {
                Some(deposit_tree.push_and_compute_root(index, data))
            })
            .reduce(Result::and)
            .into_iter()
            .exactly_one()??;

        // Fake a successful `Eth1Data` vote for multiple new deposits.
        *state_0.make_mut().eth1_data_mut() = Eth1Data {
            deposit_root: deposit_root_2,
            deposit_count: block_2_count,
            block_hash: ExecutionBlockHash::default(),
        };

        let new_deposit_data = new_deposit_data.iter().collect_vec();
        let new_deposit_indices = block_0_count..block_2_count;
        let block_1_proof_indices = block_0_count..block_1_count;
        let block_2_proof_indices = block_1_count..block_2_count;

        let block_1_deposits = deposit_tree_0
            .clone()
            .extend_and_construct_proofs(
                new_deposit_data.as_slice(),
                new_deposit_indices.clone(),
                block_1_proof_indices,
            )?
            .try_into()?;

        let block_2_deposits = deposit_tree_0
            .clone()
            .extend_and_construct_proofs(
                new_deposit_data.as_slice(),
                new_deposit_indices,
                block_2_proof_indices,
            )?
            .try_into()?;

        let (_, state_1) =
            factory::block_with_deposits(&config, &pubkey_cache, state_0, 1, block_1_deposits)?;

        let (_, state_2) =
            factory::block_with_deposits(&config, &pubkey_cache, state_1, 2, block_2_deposits)?;

        assert_eq!(state_2.eth1_deposit_index(), block_2_count);

        Ok(())
    }

    #[test_resources("consensus-spec-tests/tests/*/phase0/genesis/initialization/*/*")]
    fn extend_and_construct_proofs_matches_proofs_in_genesis_initialization_tests(case: Case) {
        let deposits_count = case.meta().deposits_count;
        let deposits = case.numbered_default::<Deposit>("deposits", 0..deposits_count);

        let mut deposit_tree = DepositTree::default();

        for (expected_deposit, deposit_index) in deposits.zip(0..) {
            let deposit_data = &[&expected_deposit.data];
            let deposit_indices = deposit_index..deposit_index + 1;
            let proof_indices = deposit_indices.clone();

            let actual_deposit = deposit_tree
                .extend_and_construct_proofs(deposit_data, deposit_indices, proof_indices)
                .expect("deposits are not enough to fill tree and have correct indices")
                .into_iter()
                .exactly_one()
                .expect("exactly one proof is requested");

            assert_eq!(actual_deposit, expected_deposit);
        }
    }
}
