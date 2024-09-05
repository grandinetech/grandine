use core::{
    cmp::Reverse,
    ops::{Deref, DerefMut},
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLockReadGuard, RwLockWriteGuard},
};

use anyhow::{Context as _, Result};
use arithmetic::{NonZeroExt as _, U64Ext as _};
use deposit_tree::DepositTree;
use eth1::{DepositEvent, Eth1Block, Eth1Chain};
use helper_functions::misc::compute_timestamp_at_slot;
use itertools::Itertools as _;
use log::{error, warn};
use prometheus_metrics::Metrics;
use ssz::ContiguousList;
use thiserror::Error;
use typenum::Unsigned as _;
use types::{
    config::Config,
    phase0::{
        containers::{Deposit, Eth1Data},
        primitives::{DepositIndex, ExecutionBlockNumber, UnixSeconds},
    },
    preset::{Preset, SlotsPerEth1VotingPeriod},
    traits::BeaconState,
};

// Dependency injection for testing.
pub trait Eth1Storage {
    type UnfinalizedBlocks<'a>: Deref<Target = Vec<Eth1Block>>
    where
        Self: 'a;

    type UnfinalizedBlocksMut<'a>: DerefMut<Target = Vec<Eth1Block>>
    where
        Self: 'a;

    fn finalized_deposit_tree(&self) -> Result<DepositTree>;

    fn unfinalized_blocks(&self) -> Self::UnfinalizedBlocks<'_>;

    fn unfinalized_blocks_mut(&self) -> Self::UnfinalizedBlocksMut<'_>;

    fn add_deposits(
        &self,
        deposit_events: Vec<&DepositEvent>,
        block_number: ExecutionBlockNumber,
    ) -> Result<()>;

    /// [`get_eth1_vote`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#eth1-data)
    fn eth1_vote<P: Preset>(
        &self,
        config: &Config,
        metrics: Option<&Arc<Metrics>>,
        state_at_slot: &impl BeaconState<P>,
    ) -> Result<Eth1Data> {
        let _timer = metrics.map(|metrics| metrics.eth1_vote_times.start_timer());

        let eth1_data = state_at_slot.eth1_data();
        let period_start = voting_period_start_time(config, state_at_slot);

        let mut finalized_deposit_tree = self.finalized_deposit_tree()?;
        let mut valid_votes = HashMap::new();

        features::log!(DebugEth1, "Eth1 Vote Eth1 Data: {eth1_data:?}");
        features::log!(
            DebugEth1,
            "Finalized deposit tree: deposit_count {}, last_added_block_number: {}",
            finalized_deposit_tree.deposit_count,
            finalized_deposit_tree.last_added_block_number,
        );

        for (position, vote) in state_at_slot.eth1_data_votes().into_iter().enumerate() {
            let unfinalized_blocks = self.unfinalized_blocks();

            let Some(block_position) = unfinalized_blocks
                .iter()
                .position(|block| block.hash == vote.block_hash)
            else {
                continue;
            };

            features::log!(DebugEth1, "Block position: {block_position}");

            if !is_candidate_block(config, &unfinalized_blocks[block_position], period_start) {
                continue;
            }

            let deposit_count = unfinalized_blocks
                .iter()
                .take(block_position + 1)
                .rev()
                .find_map(|block| block.deposit_events.last())
                .map(|deposit_event| deposit_event.index)
                .unwrap_or(finalized_deposit_tree.deposit_count);

            features::log!(DebugEth1, "Deposit count: {deposit_count}");
            features::log!(
                DebugEth1,
                "Eth1 data deposit count: {:?}",
                eth1_data.deposit_count,
            );

            if deposit_count < eth1_data.deposit_count {
                // > Ensure cannot move back to earlier deposit contract states
                continue;
            }

            let (count, _) = valid_votes.entry(vote).or_insert((0, position));
            *count += 1;
        }

        if let Some(vote) = valid_votes
            .into_iter()
            .max_by_key(|(_, (count, position))| (*count, Reverse(*position)))
            .map(|(vote, _)| vote)
        {
            features::log!(DebugEth1, "Eth1 Vote: {vote:?}");
            return Ok(*vote);
        }

        let unfinalized_blocks = self.unfinalized_blocks();

        features::log!(
            DebugEth1,
            "Unfinalized blocks len: {} (from: {:?}, to {:?})",
            unfinalized_blocks.len(),
            unfinalized_blocks.first().map(|block| block.number),
            unfinalized_blocks.last().map(|block| block.number),
        );

        let candidate_eth1_blocks = unfinalized_blocks
            .iter()
            .filter(|eth1_block| is_candidate_block(config, eth1_block, period_start));

        if let Some(eth1_block) = candidate_eth1_blocks.last() {
            let eth1_blocks_to_catch_up = match unfinalized_blocks
                .iter()
                .position(|block| block.hash == eth1_block.hash)
            {
                Some(block_position) => {
                    unfinalized_blocks.iter().take(block_position + 1).collect()
                }
                None => vec![],
            };

            features::log!(
                DebugEth1,
                "Candidate eth1 block: {} - {}",
                eth1_block.hash,
                eth1_block.number,
            );

            let mut eth1_data = Eth1Data {
                block_hash: eth1_block.hash,
                ..eth1_data
            };

            for block in eth1_blocks_to_catch_up {
                for DepositEvent { data, index } in block.deposit_events.iter().copied() {
                    // It's possible for download manager to add deposits to finalized deposit tree on grandine restart
                    // while deposits are not yet finalized in eth2
                    if finalized_deposit_tree.deposit_count <= index {
                        eth1_data.deposit_root =
                            finalized_deposit_tree.push_and_compute_root(index, data)?;
                        eth1_data.deposit_count = finalized_deposit_tree.deposit_count;
                    }
                }
            }

            return Ok(eth1_data);
        }

        Ok(eth1_data)
    }

    fn pending_deposits<P: Preset>(
        &self,
        state: &impl BeaconState<P>,
        eth1_vote: Eth1Data,
        metrics: Option<&Arc<Metrics>>,
    ) -> Result<ContiguousList<Deposit, P::MaxDeposits>> {
        let _timer = metrics.map(|metrics| metrics.eth1_pending_deposits_times.start_timer());

        let existing_vote_count = state
            .eth1_data_votes()
            .into_iter()
            .filter(|vote| **vote == eth1_vote)
            .count();

        let eth1_data = if (existing_vote_count + 1) * 2 > SlotsPerEth1VotingPeriod::<P>::USIZE {
            eth1_vote
        } else {
            state.eth1_data()
        };

        let eth1_deposit_index = state.eth1_deposit_index();

        features::log!(DebugEth1, "state.eth1_deposit_index: {eth1_deposit_index}");
        features::log!(DebugEth1, "eth1_data: {eth1_data:?}");

        let expected_number_of_deposits =
            P::MaxDeposits::U64.min(eth1_data.deposit_count - eth1_deposit_index);

        features::log!(
            DebugEth1,
            "expected number of deposits: {expected_number_of_deposits}",
        );

        if expected_number_of_deposits == 0 {
            return Ok(ContiguousList::default());
        }

        let finalized_deposit_tree = self.finalized_deposit_tree()?;

        features::log!(
            DebugEth1,
            "finalized_deposit_tree.deposit_count: {}",
            finalized_deposit_tree.deposit_count,
        );
        features::log!(
            DebugEth1,
            "finalized_deposit_tree.last_added_block_number: {}",
            finalized_deposit_tree.last_added_block_number,
        );

        let unfinalized_blocks = self.unfinalized_blocks();

        features::log!(
            DebugEth1,
            "unfinalized_blocks.len(): {} (from: {:?} to {:?})",
            unfinalized_blocks.len(),
            unfinalized_blocks.first().map(|block| block.number),
            unfinalized_blocks.last().map(|block| block.number),
        );

        let mut deposit_events = unfinalized_blocks
            .iter()
            .flat_map(|block| block.deposit_events.iter())
            .take_while(|event| event.index < eth1_data.deposit_count)
            .peekable();

        let mut deposit_tree = finalized_deposit_tree;

        // This loop is an optimization.
        // Deposits before the ones that needs proofs can be processed using `DepositTree::push`.
        // Passing them to `DepositTree::extend_and_construct_proofs` with the rest would also work,
        // but it would likely be slower and would require a different value of `deposit_indices`.
        while let Some(DepositEvent { data, index }) = deposit_events
            .next_if(|event| event.index < eth1_deposit_index)
            .copied()
        {
            deposit_tree.push(index, data)?;
        }

        features::log!(
            DebugEth1,
            "deposit_tree.deposit_count after catching up: {}",
            deposit_tree.deposit_count,
        );

        let deposit_data = deposit_events.map(|event| &event.data).collect_vec();
        let deposit_indices = eth1_deposit_index..eth1_data.deposit_count;
        let proof_indices = eth1_deposit_index..eth1_deposit_index + expected_number_of_deposits;

        features::log!(DebugEth1, "deposit indices: {deposit_indices:?}");
        features::log!(DebugEth1, "proof indices: {proof_indices:?}");

        let deposits = deposit_tree
            .extend_and_construct_proofs(deposit_data.as_slice(), deposit_indices, proof_indices)
            .context(Error::NotEnoughDeposits)?;

        features::log!(DebugEth1, "deposits len: {}", deposits.len());

        deposits.try_into().map_err(Into::into)
    }

    fn finalize_deposits(&self, finalized_deposit_index: DepositIndex) -> Result<()> {
        features::log!(DebugEth1, "Finalizing deposits: {finalized_deposit_index}");

        let mut unfinalized_blocks = self.unfinalized_blocks_mut();

        let position = unfinalized_blocks.iter().position(|block| {
            block
                .deposit_events
                .iter()
                .any(|deposit| deposit.index == finalized_deposit_index)
        });

        let Some(block_position) = position else {
            return Ok(());
        };

        features::log!(
            DebugEth1,
            "Finalizing deposits: unfinalized blocks len: {} (from: {:?}, to {:?})",
            unfinalized_blocks.len(),
            unfinalized_blocks.first().map(|block| block.number),
            unfinalized_blocks.last().map(|block| block.number),
        );

        features::log!(
            DebugEth1,
            "Block position for split_off: {block_position}, {:?}",
            unfinalized_blocks.get(block_position),
        );

        let mut new_finalized_blocks = unfinalized_blocks.split_off(block_position);
        core::mem::swap(&mut *unfinalized_blocks, &mut new_finalized_blocks);

        if let Some(last_block) = new_finalized_blocks.last() {
            let deposit_events = new_finalized_blocks
                .iter()
                .flat_map(|block| block.deposit_events.iter())
                .collect_vec();

            features::log!(
                DebugEth1,
                "DepositEvent indices to add: [{}]",
                deposit_events.iter().map(|event| event.index).format(", "),
            );

            if let Err(error) = self.add_deposits(deposit_events, last_block.number) {
                warn!("{error:?}");
                new_finalized_blocks.append(&mut unfinalized_blocks);
                return Ok(());
            }
        }

        Ok(())
    }
}

impl Eth1Storage for Eth1Chain {
    type UnfinalizedBlocks<'a> = RwLockReadGuard<'a, Vec<Eth1Block>>;
    type UnfinalizedBlocksMut<'a> = RwLockWriteGuard<'a, Vec<Eth1Block>>;

    fn finalized_deposit_tree(&self) -> Result<DepositTree> {
        self.load_deposit_tree()
    }

    fn unfinalized_blocks(&self) -> Self::UnfinalizedBlocks<'_> {
        self.unfinalized_blocks()
            .read()
            .expect("unfinalized blocks lock is poisoned")
    }

    fn unfinalized_blocks_mut(&self) -> Self::UnfinalizedBlocksMut<'_> {
        self.unfinalized_blocks()
            .write()
            .expect("unfinalized blocks lock is poisoned")
    }

    fn add_deposits(
        &self,
        deposit_events: Vec<&DepositEvent>,
        block_number: ExecutionBlockNumber,
    ) -> Result<()> {
        self.add_deposits(deposit_events, block_number)
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("not enough deposits")]
    NotEnoughDeposits,
}

/// [`is_candidate_block`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#eth1-data)
fn is_candidate_block(config: &Config, eth1_block: &Eth1Block, period_start: UnixSeconds) -> bool {
    let range_width = config.seconds_per_eth1_block * config.eth1_follow_distance;
    let low = eth1_block.timestamp + range_width;
    let high = eth1_block.timestamp + range_width * 2;
    (low..=high).contains(&period_start)
}

/// [`voting_period_start_time`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#eth1-data)
fn voting_period_start_time<P: Preset>(
    config: &Config,
    state_at_slot: &impl BeaconState<P>,
) -> UnixSeconds {
    let eth1_voting_period_start_slot = state_at_slot
        .slot()
        .prev_multiple_of(SlotsPerEth1VotingPeriod::<P>::non_zero());

    compute_timestamp_at_slot(config, state_at_slot, eth1_voting_period_start_slot)
}

#[cfg(test)]
mod tests {
    use std_ext::ArcExt as _;
    use tap::Pipe as _;
    use try_from_iterator::TryFromIterator as _;
    use types::{
        phase0::{consts::GENESIS_SLOT, primitives::ExecutionBlockHash},
        preset::Minimal,
    };

    use super::*;

    #[derive(Default)]
    struct TestEth1Storage {
        finalized_deposit_tree: DepositTree,
        unfinalized_blocks: Vec<Eth1Block>,
    }

    impl Eth1Storage for TestEth1Storage {
        type UnfinalizedBlocks<'a> = &'a Vec<Eth1Block>;
        type UnfinalizedBlocksMut<'a> = &'a mut Vec<Eth1Block>;

        fn finalized_deposit_tree(&self) -> Result<DepositTree> {
            Ok(self.finalized_deposit_tree)
        }

        fn unfinalized_blocks(&self) -> Self::UnfinalizedBlocks<'_> {
            &self.unfinalized_blocks
        }

        fn unfinalized_blocks_mut(&self) -> Self::UnfinalizedBlocksMut<'_> {
            unimplemented!("Eth1Storage::unfinalized_blocks_mut is not used in tests")
        }

        fn add_deposits(
            &self,
            _deposit_events: Vec<&DepositEvent>,
            _block_number: ExecutionBlockNumber,
        ) -> Result<()> {
            unimplemented!("Eth1Storage::add_deposits is not used in tests")
        }
    }

    #[test]
    fn pending_deposits_constructs_valid_proofs_after_vote_for_multiple_deposits() -> Result<()> {
        let config = Config::minimal();

        let (mut state_0, deposit_tree_0) = factory::min_genesis_state::<Minimal>(&config)?;

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

        let new_deposit_indices = block_0_count..block_2_count;

        let eth1_storage = TestEth1Storage {
            finalized_deposit_tree: deposit_tree_0,
            unfinalized_blocks: vec![Eth1Block {
                deposit_events: new_deposit_data
                    .iter()
                    .copied()
                    .zip_eq(new_deposit_indices)
                    .map(|(data, index)| DepositEvent { data, index })
                    .pipe(ContiguousList::try_from_iter)?,
                ..Eth1Block::default()
            }],
        };

        let block_1_deposits =
            eth1_storage.pending_deposits(&state_0, state_0.eth1_data(), None)?;
        let (_, state_1) = factory::block_with_deposits(&config, state_0, 1, block_1_deposits)?;
        let block_2_deposits =
            eth1_storage.pending_deposits(&state_1, state_1.eth1_data(), None)?;
        let (_, state_2) = factory::block_with_deposits(&config, state_1, 2, block_2_deposits)?;

        assert_eq!(state_2.eth1_deposit_index(), block_2_count);
        assert!(eth1_storage
            .pending_deposits(&state_2, state_2.eth1_data(), None)?
            .is_empty());

        Ok(())
    }

    #[test]
    fn pending_deposits_does_not_process_deposits_past_eth1_data_vote() -> Result<()> {
        let config = Config::minimal();

        let (mut state_0, deposit_tree_0) = factory::min_genesis_state::<Minimal>(&config)?;

        // Enough deposits to fill block #1 and leave one for block #2.
        let block_0_count = state_0.eth1_deposit_index();
        let block_1_count = block_0_count + <Minimal as Preset>::MaxDeposits::U64;
        let block_2_count = block_1_count + 1;
        let unvoted_count = block_2_count + 1;

        let new_deposit_data = (block_0_count..unvoted_count)
            .map(interop::secret_key)
            .map(|secret_key| interop::quick_start_deposit_data::<Minimal>(&config, &secret_key))
            .collect_vec();

        let deposit_root_2 = new_deposit_data
            .iter()
            .copied()
            .zip(block_0_count..block_2_count)
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

        let new_deposit_data_2 = &new_deposit_data[..(block_2_count - block_0_count).try_into()?];
        let new_deposit_data_x = &new_deposit_data[(block_2_count - block_0_count).try_into()?..];
        let new_deposit_indices_2 = block_0_count..block_2_count;
        let new_deposit_indices_x = block_2_count..unvoted_count;

        let eth1_storage = TestEth1Storage {
            finalized_deposit_tree: deposit_tree_0,
            unfinalized_blocks: vec![
                Eth1Block {
                    deposit_events: new_deposit_data_2
                        .iter()
                        .copied()
                        .zip_eq(new_deposit_indices_2)
                        .map(|(data, index)| DepositEvent { data, index })
                        .pipe(ContiguousList::try_from_iter)?,
                    ..Eth1Block::default()
                },
                Eth1Block {
                    deposit_events: new_deposit_data_x
                        .iter()
                        .copied()
                        .zip_eq(new_deposit_indices_x)
                        .map(|(data, index)| DepositEvent { data, index })
                        .pipe(ContiguousList::try_from_iter)?,
                    ..Eth1Block::default()
                },
            ],
        };

        let block_1_deposits =
            eth1_storage.pending_deposits(&state_0, state_0.eth1_data(), None)?;
        let (_, state_1) = factory::block_with_deposits(&config, state_0, 1, block_1_deposits)?;
        let block_2_deposits =
            eth1_storage.pending_deposits(&state_1, state_1.eth1_data(), None)?;
        let (_, state_2) = factory::block_with_deposits(&config, state_1, 2, block_2_deposits)?;

        assert_eq!(state_2.eth1_deposit_index(), block_2_count);
        assert!(eth1_storage
            .pending_deposits(&state_2, state_2.eth1_data(), None)?
            .is_empty());

        Ok(())
    }

    #[test]
    fn pending_deposits_succeeds_if_no_deposits_are_expected() -> Result<()> {
        let config = Config::minimal();
        let (state_0, _) = factory::min_genesis_state::<Minimal>(&config)?;
        let eth1_storage = TestEth1Storage::default();

        assert!(eth1_storage
            .pending_deposits(&state_0, state_0.eth1_data(), None)?
            .is_empty());

        Ok(())
    }

    #[test]
    fn pending_deposits_fails_if_unfinalized_blocks_do_not_contain_enough_deposits() -> Result<()> {
        let config = Config::minimal();

        let (mut state_0, deposit_tree_0) = factory::min_genesis_state::<Minimal>(&config)?;

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

        let new_deposit_indices = block_0_count..block_2_count;

        let eth1_storage = TestEth1Storage {
            finalized_deposit_tree: deposit_tree_0,
            unfinalized_blocks: vec![Eth1Block {
                deposit_events: new_deposit_data
                    .iter()
                    .copied()
                    .zip_eq(new_deposit_indices)
                    .map(|(data, index)| DepositEvent { data, index })
                    .take(new_deposit_data.len() - 1)
                    .pipe(ContiguousList::try_from_iter)?,
                ..Eth1Block::default()
            }],
        };

        eth1_storage
            .pending_deposits(&state_0, state_0.eth1_data(), None)
            .expect_err(
                "Eth1Storage::pending_deposits should fail if \
                 unfinalized blocks do not contain enough deposits",
            );

        Ok(())
    }

    #[test]
    fn pending_deposits_includes_new_deposits_if_eth1_vote_passes() -> Result<()> {
        let config = Config::minimal();

        let (state_0, deposit_tree_0) = factory::min_genesis_state::<Minimal>(&config)?;

        // The timestamp of the next Eth1 block could be made as high as
        // `state_0.genesis_time() - config.seconds_per_eth1_block * config.eth1_follow_distance`.
        // We use a more realistic timestamp.
        let genesis_trigger_time = state_0.genesis_time() - config.genesis_delay;
        let next_eth1_block_time = genesis_trigger_time + config.seconds_per_eth1_block;

        let secret_key = interop::secret_key(64);
        let new_deposit_data = interop::quick_start_deposit_data::<Minimal>(&config, &secret_key);

        let eth1_storage = TestEth1Storage {
            finalized_deposit_tree: deposit_tree_0,
            unfinalized_blocks: vec![Eth1Block {
                timestamp: next_eth1_block_time,
                deposit_events: vec![DepositEvent {
                    data: new_deposit_data,
                    index: 64,
                }]
                .try_into()?,
                ..Eth1Block::default()
            }],
        };

        // The genesis block cannot contain an `Eth1Data` vote.
        let first_slot = GENESIS_SLOT + 1;
        let half_of_voting_period = SlotsPerEth1VotingPeriod::<Minimal>::U64 / 2;
        let last_slot = first_slot + half_of_voting_period;

        assert_eq!(first_slot, 1);
        assert_eq!(last_slot, 17);

        let state_16 = (first_slot..last_slot).try_fold(state_0, |state, slot| -> Result<_> {
            let eth1_vote = eth1_storage.eth1_vote(&config, None, &state)?;
            let deposits = eth1_storage.pending_deposits(&state, eth1_vote, None)?;

            assert!(deposits.is_empty());

            let (_, new_state) = factory::block_with_eth1_vote_and_deposits(
                &config, state, slot, eth1_vote, deposits,
            )?;

            assert_eq!(new_state.eth1_deposit_index(), 64);

            Ok(new_state)
        })?;

        let block_17_eth1_vote = eth1_storage.eth1_vote(&config, None, &state_16)?;
        let block_17_deposits =
            eth1_storage.pending_deposits(&state_16, block_17_eth1_vote, None)?;

        assert_eq!(block_17_deposits.len(), 1);

        let (_, state_17) = factory::block_with_eth1_vote_and_deposits(
            &config,
            state_16,
            last_slot,
            block_17_eth1_vote,
            block_17_deposits,
        )?;

        assert_eq!(state_17.eth1_deposit_index(), 65);
        assert!(eth1_storage
            .pending_deposits(&state_17, state_17.eth1_data(), None)?
            .is_empty());

        Ok(())
    }
}
