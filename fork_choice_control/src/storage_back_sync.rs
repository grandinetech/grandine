use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Error as AnyhowError, Result};
use database::Database;
use genesis::AnchorCheckpointProvider;
use helper_functions::misc;
use log::{debug, info, warn};
use ssz::SszHash as _;
use std_ext::ArcExt as _;
use transition_functions::combined;
use types::{
    combined::SignedBeaconBlock,
    deneb::containers::BlobSidecar,
    fulu::containers::DataColumnSidecar,
    nonstandard::{FinalizedCheckpoint, WithOrigin},
    phase0::primitives::Slot,
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::{
    storage::{
        get, serialize, BlockRootBySlot, Error, FinalizedBlockByRoot, SlotByStateRoot,
        StateByBlockRoot,
    },
    Storage,
};

const ARCHIVER_CHECKPOINT_KEY: &str = "carchiver";

// Retain archival data in memory until the number of ready beacon states
// reaches `ARCHIVED_STATES_BEFORE_FLUSH`. This approach minimizes unnecessary
// transactions and significantly reduces memory usage during the archiving
// of back-synced data.
const ARCHIVED_STATES_BEFORE_FLUSH: u64 = 5;

impl<P: Preset> Storage<P> {
    pub(crate) fn archive_back_sync_states(
        &self,
        mut start_slot: Slot,
        end_slot: Slot,
        anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
        is_exiting: &Arc<AtomicBool>,
    ) -> Result<()> {
        let WithOrigin { value, origin } = anchor_checkpoint_provider.checkpoint();

        let FinalizedCheckpoint {
            state: anchor_state,
            block: anchor_block,
        } = value;

        let anchor_block_slot = anchor_block.message().slot();
        let anchor_block_root = anchor_block.message().hash_tree_root();

        // check whether archiving was interrupted
        if let Some(slot) = get_latest_archived_slot(&self.database)? {
            if self.stored_state(slot)?.is_some() && slot > start_slot && slot <= end_slot {
                start_slot = slot;
                info!("resuming back-sync archival from {slot} slot");
            }
        }

        let mut state = if start_slot == anchor_block_slot {
            if origin.is_checkpoint_sync() {
                warn!("unable to back-sync to genesis state as it not available");
            }

            anchor_state
        } else {
            self.stored_state(start_slot)?.ok_or(Error::StateNotFound {
                state_slot: start_slot,
            })?
        };

        let mut previous_block = None;
        let mut batch = vec![];
        let mut states_in_batch = 0;

        if start_slot == anchor_block_slot {
            batch.push(serialize(StateByBlockRoot(anchor_block_root), &state)?);
        }

        for slot in (start_slot + 1)..=end_slot {
            if is_exiting.load(Ordering::Relaxed) {
                bail!(AnyhowError::msg("received a termination signal"));
            }

            if let Some((block, _)) = self.finalized_block_by_slot(slot)? {
                combined::untrusted_state_transition(
                    self.config(),
                    &self.pubkey_cache,
                    state.make_mut(),
                    &block,
                )?;
                previous_block = Some(block);
            } else {
                combined::process_slots(self.config(), &self.pubkey_cache, state.make_mut(), slot)?;
            }

            batch.push(serialize(SlotByStateRoot(state.hash_tree_root()), slot)?);

            let state_epoch = Self::epoch_at_slot(slot);
            let append_state = misc::is_epoch_start::<P>(slot)
                && state_epoch.is_multiple_of(self.archival_epoch_interval.into());

            if let Some(block) = previous_block.as_ref() {
                if append_state {
                    debug!("back-synced state in {slot} is ready for storage");

                    let block_root = block.message().hash_tree_root();

                    batch.push(serialize(StateByBlockRoot(block_root), &state)?);
                    batch.push(serialize(ARCHIVER_CHECKPOINT_KEY, slot)?);

                    states_in_batch += 1;

                    if states_in_batch == ARCHIVED_STATES_BEFORE_FLUSH {
                        info!("archiving back-sync data up to {slot} slot");

                        self.database.put_batch(batch)?;

                        batch = vec![];
                        states_in_batch = 0;
                    }
                }
            }
        }

        self.database.put_batch(batch)?;

        info!(
            "back-synced state archival completed (start_slot: {start_slot}, end_slot: {end_slot})",
        );

        Ok(())
    }

    pub(crate) fn store_back_sync_blob_sidecars(
        &self,
        blob_sidecars: impl IntoIterator<Item = Arc<BlobSidecar<P>>>,
    ) -> Result<()> {
        self.append_blob_sidecars(blob_sidecars.into_iter().map(Into::into))?;
        Ok(())
    }

    pub(crate) fn store_back_sync_data_column_sidecars(
        &self,
        data_column_sidecars: impl IntoIterator<Item = Arc<DataColumnSidecar<P>>>,
    ) -> Result<()> {
        self.append_data_column_sidecars(data_column_sidecars.into_iter().map(Into::into))?;
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

fn get_latest_archived_slot(database: &Database) -> Result<Option<Slot>> {
    get(database, ARCHIVER_CHECKPOINT_KEY)
}

#[cfg(test)]
#[cfg(feature = "eth2-cache")]
mod tests {
    use core::num::NonZeroU64;

    use anyhow::anyhow;
    use database::Database;
    use eth2_cache_utils::mainnet;
    use itertools::{EitherOrBoth, Itertools as _};
    use pubkey_cache::PubkeyCache;
    use types::phase0::consts::GENESIS_SLOT;

    use crate::StorageMode;

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
            &Arc::new(AtomicBool::new(false)),
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
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            NonZeroU64::MIN,
            StorageMode::Standard,
        )
    }
}
