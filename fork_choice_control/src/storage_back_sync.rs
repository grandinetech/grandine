use std::sync::Arc;

use anyhow::Result;
use arithmetic::U64Ext as _;
use features::Feature;
use genesis::AnchorCheckpointProvider;
use helper_functions::misc;
use log::{info, warn};
use ssz::SszHash as _;
use std_ext::ArcExt as _;
use transition_functions::combined;
use types::{
    combined::SignedBeaconBlock,
    nonstandard::{FinalizedCheckpoint, WithOrigin},
    phase0::primitives::Slot,
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::{
    storage::{
        serialize, BlockRootBySlot, Error, FinalizedBlockByRoot, SlotByStateRoot, StateByBlockRoot,
    },
    Storage,
};

impl<P: Preset> Storage<P> {
    pub(crate) fn archive_back_sync_states(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
    ) -> Result<()> {
        let WithOrigin { value, origin } = anchor_checkpoint_provider.checkpoint();

        let FinalizedCheckpoint {
            state: anchor_state,
            block: anchor_block,
        } = value;

        let anchor_block_slot = anchor_block.message().slot();
        let anchor_block_root = anchor_block.message().hash_tree_root();

        let mut state = if start_slot == anchor_block_slot {
            if origin.is_checkpoint_sync() {
                warn!("unable to back sync to genesis state as it not available");
            }

            anchor_state
        } else {
            self.stored_state(start_slot)?.ok_or(Error::StateNotFound {
                state_slot: start_slot,
            })?
        };

        let mut batch = vec![];
        let mut previous_block = None;

        let state_transition = if Feature::TrustBackSyncBlocks.is_enabled() {
            combined::trusted_state_transition
        } else {
            combined::untrusted_state_transition
        };

        if start_slot == anchor_block_slot {
            batch.push(serialize(StateByBlockRoot(anchor_block_root), &state)?);
        }

        for slot in (start_slot + 1)..=end_slot {
            if let Some((block, _)) = self.finalized_block_by_slot(slot)? {
                state_transition(self.config(), state.make_mut(), &block)?;
                previous_block = Some(block);
            } else {
                combined::process_slots(self.config(), state.make_mut(), slot)?;
            }

            batch.push(serialize(SlotByStateRoot(state.hash_tree_root()), slot)?);

            let state_epoch = Self::epoch_at_slot(slot);
            let append_state = misc::is_epoch_start::<P>(slot)
                && state_epoch.is_multiple_of(self.archival_epoch_interval);

            if let Some(block) = previous_block.as_ref() {
                if append_state {
                    info!("archiving back sync state in slot {slot}");

                    let block_root = block.message().hash_tree_root();
                    batch.push(serialize(StateByBlockRoot(block_root), &state)?);
                }
            }
        }

        self.database.put_batch(batch)?;

        info!(
            "back sync state archival completed (start_slot: {start_slot}, end_slot: {end_slot})",
        );

        Ok(())
    }

    pub(crate) fn store_back_sync_blocks(
        &self,
        blocks: impl IntoIterator<Item = Arc<SignedBeaconBlock<P>>>,
    ) -> Result<()> {
        let mut batch = vec![];

        for block in blocks {
            let slot = block.message().slot();
            let block_root = block.message().hash_tree_root();

            batch.push(serialize(BlockRootBySlot(slot), block_root)?);
            batch.push(serialize(FinalizedBlockByRoot(block_root), block)?);
        }

        self.database.put_batch(batch)
    }
}

#[cfg(test)]
#[cfg(feature = "eth2-cache")]
mod tests {
    use core::num::NonZeroU64;

    use anyhow::anyhow;
    use database::Database;
    use eth2_cache_utils::mainnet;
    use itertools::{EitherOrBoth, Itertools as _};
    use types::phase0::consts::GENESIS_SLOT;

    use super::*;

    #[test]
    fn test_archive_back_sync_states() -> Result<()> {
        let genesis_state = mainnet::GENESIS_BEACON_STATE.force().clone_arc();
        let blocks = mainnet::BEACON_BLOCKS_UP_TO_SLOT_128.force();
        let storage = build_test_storage();

        let roots = |slot| {
            blocks
                .binary_search_by_key(&slot, |block| block.message().slot())
                .map(|index| {
                    let block = &blocks[index];
                    let block_root = block.message().hash_tree_root();
                    let state_root = block.message().state_root();
                    (block_root, state_root)
                })
                .map_err(|_| anyhow!("no block found at slot {slot}"))
        };

        let (block_1_root, state_1_root) = roots(1)?;
        let (block_22_root, state_22_root) = roots(22)?;
        let (block_96_root, state_96_root) = roots(96)?;
        let (block_128_root, state_128_root) = roots(128)?;

        storage.store_back_sync_blocks(blocks.iter().cloned())?;

        let empty_slots = (GENESIS_SLOT..=128)
            .merge_join_by(blocks, |slot, block| slot.cmp(&block.message().slot()))
            .filter_map(|either_or_both| match either_or_both {
                EitherOrBoth::Both(_, _) => None,
                EitherOrBoth::Left(slot) => Some(slot),
                EitherOrBoth::Right(_) => unreachable!(),
            })
            .collect_vec();

        assert_eq!(empty_slots.len(), 23);

        for empty_slot in empty_slots {
            assert_eq!(storage.block_root_by_slot(empty_slot)?, None);
        }

        // Assert that blocks are stored.
        assert_eq!(storage.block_root_by_slot(1)?, Some(block_1_root));
        assert_eq!(storage.block_root_by_slot(22)?, Some(block_22_root));
        assert_eq!(storage.block_root_by_slot(96)?, Some(block_96_root));
        assert_eq!(storage.block_root_by_slot(128)?, Some(block_128_root));

        for block_root in [block_1_root, block_22_root, block_96_root, block_128_root] {
            assert_eq!(
                storage
                    .finalized_block_by_root(block_root)?
                    .map(|block| block.message().hash_tree_root()),
                Some(block_root),
            );
        }

        storage.archive_back_sync_states(
            0,
            128,
            &AnchorCheckpointProvider::custom_from_genesis(genesis_state),
        )?;

        // Assert that the mappings from state root to slot are stored.
        assert_eq!(storage.slot_by_state_root(state_1_root)?, Some(1));
        assert_eq!(storage.slot_by_state_root(state_22_root)?, Some(22));
        assert_eq!(storage.slot_by_state_root(state_96_root)?, Some(96));
        assert_eq!(storage.slot_by_state_root(state_128_root)?, Some(128));

        // Assert that the stored state is accessible by state root.
        for state_root in [state_1_root, state_22_root, state_96_root, state_128_root] {
            assert_eq!(
                storage
                    .stored_state_by_state_root(state_root)?
                    .map(|state| state.hash_tree_root()),
                Some(state_root),
            );
        }

        Ok(())
    }

    fn build_test_storage<P: Preset>() -> Storage<P> {
        Storage::new(
            Arc::new(P::default_config()),
            Database::in_memory(),
            NonZeroU64::MIN,
            false,
        )
    }
}
