use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result, bail};
use database::Database;
use genesis::AnchorCheckpointProvider;
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use ssz::SszHash as _;
use std_ext::ArcExt as _;
use transition_functions::combined;
use types::{
    combined::{DataColumnSidecar, SignedBeaconBlock},
    deneb::containers::BlobSidecar,
    gloas::containers::SignedExecutionPayloadEnvelope,
    nonstandard::{FinalizedCheckpoint, WithOrigin},
    phase0::primitives::Slot,
    preset::Preset,
    traits::{SignedBeaconBlock as _, SszValidatorList},
};

use crate::{
    Storage,
    storage::{
        ARCHIVED_STATES_BEFORE_FLUSH, BlockRootBySlot, Error, FinalizedBlockByRoot,
        SLOT_BY_STATE_ROOTS_BEFORE_FLUSH, SlotByStateRoot, get, serialize,
    },
};

const ARCHIVER_CHECKPOINT_KEY: &str = "carchiver";

impl<P: Preset> Storage<P> {
    #[expect(clippy::too_many_lines)]
    pub(crate) fn archive_back_sync_states(
        &self,
        mut start_slot: Slot,
        end_slot: Slot,
        anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
        is_exiting: &Arc<AtomicBool>,
        finalized_validators: &dyn SszValidatorList,
    ) -> Result<()> {
        let WithOrigin { value, origin } = anchor_checkpoint_provider.checkpoint();

        let FinalizedCheckpoint {
            state: anchor_state,
            block: anchor_block,
        } = value;

        let anchor_block_slot = anchor_block.message().slot();
        let anchor_block_root = anchor_block.message().hash_tree_root();

        // check whether archiving was interrupted
        if let Some(slot) = get_latest_archived_slot(&self.database)?
            && self
                .stored_state(slot, Some(finalized_validators))?
                .is_some()
            && slot > start_slot
            && slot <= end_slot
        {
            start_slot = slot;
            info_with_peers!("resuming back-sync archival from {slot} slot");
        }

        let mut state = if start_slot == anchor_block_slot {
            if origin.is_checkpoint_sync() {
                warn_with_peers!("unable to back-sync to genesis state as it not available");
            }

            anchor_state
        } else {
            self.stored_state(start_slot, Some(finalized_validators))?
                .ok_or(Error::StateNotFound {
                    state_slot: start_slot,
                })?
        };

        let anchor_slot = self.anchor_slot.load(Ordering::SeqCst);

        let spine = self.temporary_spine(anchor_slot);
        let mut batch = vec![];
        let mut deleted_keys = vec![];
        let mut update_finalized_validators = false;
        let mut states_in_batch: u64 = 0;
        let mut slot_by_state_roots_in_batch: u64 = 0;

        if start_slot == anchor_block_slot
            && let Some(to_delete) = self.append_finalized_state(
                state.clone_arc(),
                start_slot,
                anchor_block_root,
                anchor_slot,
                finalized_validators,
                &spine,
                &mut batch,
                &mut update_finalized_validators,
            )?
        {
            deleted_keys.push(to_delete);
        }

        for slot in start_slot.saturating_add(1)..=end_slot {
            if is_exiting.load(Ordering::Relaxed) {
                bail!(AnyhowError::msg("received a termination signal"));
            }

            let block_root = if let Some((block, root)) = self.finalized_block_by_slot(slot)? {
                combined::untrusted_state_transition(
                    self.config(),
                    &self.pubkey_cache,
                    state.make_mut(),
                    &block,
                )?;

                Some(root)
            } else {
                combined::process_slots(self.config(), &self.pubkey_cache, state.make_mut(), slot)?;
                None
            };

            batch.push(serialize(SlotByStateRoot(state.hash_tree_root()), slot)?);

            slot_by_state_roots_in_batch = slot_by_state_roots_in_batch.saturating_add(1);

            // A row goes in for every slot, but `states_in_batch` only counts the slots that carry
            // both a block and a hierarchy frame. Under a sparse hierarchy those are millions of
            // slots apart, so without a bound of their own these rows are what makes the batch
            // grow with the length of the run.
            if slot_by_state_roots_in_batch >= SLOT_BY_STATE_ROOTS_BEFORE_FLUSH {
                self.flush(
                    &mut batch,
                    &mut deleted_keys,
                    &mut update_finalized_validators,
                    finalized_validators,
                )?;

                slot_by_state_roots_in_batch = 0;
                states_in_batch = 0;
            }

            let Some(block_root) = block_root else {
                continue;
            };

            if !self
                .hierarchy
                .contains::<P>(self.config(), anchor_slot, slot)
            {
                continue;
            }

            debug_with_peers!("back-synced state in {slot} is ready for storage");

            if let Some(to_delete) = self.append_finalized_state(
                state.clone_arc(),
                slot,
                block_root,
                anchor_slot,
                finalized_validators,
                &spine,
                &mut batch,
                &mut update_finalized_validators,
            )? {
                deleted_keys.push(to_delete);
            }

            batch.push(serialize(ARCHIVER_CHECKPOINT_KEY, slot)?);

            states_in_batch = states_in_batch.saturating_add(1);

            if states_in_batch == ARCHIVED_STATES_BEFORE_FLUSH {
                info_with_peers!("archiving back-sync data up to {slot} slot");

                self.flush(
                    &mut batch,
                    &mut deleted_keys,
                    &mut update_finalized_validators,
                    finalized_validators,
                )?;

                states_in_batch = 0;
                slot_by_state_roots_in_batch = 0;
            }
        }

        self.flush(
            &mut batch,
            &mut deleted_keys,
            &mut update_finalized_validators,
            finalized_validators,
        )?;

        drop(spine);

        info_with_peers!(
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

        self.database.put_batch_raw(batch)
    }

    pub(crate) fn store_back_sync_execution_payload_envelopes(
        &self,
        execution_payload_envelopes: impl IntoIterator<Item = Arc<SignedExecutionPayloadEnvelope<P>>>,
    ) -> Result<()> {
        self.append_execution_payload_envelopes(execution_payload_envelopes)?;
        Ok(())
    }
}

fn get_latest_archived_slot(database: &Database) -> Result<Option<Slot>> {
    get(database, ARCHIVER_CHECKPOINT_KEY)
}

#[cfg(test)]
#[cfg(feature = "eth2-cache")]
mod tests {
    use anyhow::anyhow;
    use database::Database;
    use eth2_cache_utils::mainnet;
    use itertools::{EitherOrBoth, Itertools as _};
    use pubkey_cache::PubkeyCache;
    use types::{nonstandard::StorageMode, phase0::consts::GENESIS_SLOT, traits::BeaconState as _};

    use reqwest::Client;
    use ssz::{H256, SszRead as _, SszWrite as _};
    use types::{combined::BeaconState, preset::Mainnet};

    use super::*;
    use crate::{
        hierarchy::Hierarchy,
        state_storage_config::StateStorageConfig,
        storage::{StateHierarchyKey, StateLoadStrategy},
    };

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

        for empty_slot in &empty_slots {
            assert_eq!(storage.block_root_by_slot(*empty_slot)?, None);
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

        let finalized_validators = genesis_state.validators().clone_boxed();

        storage.archive_back_sync_states(
            0,
            128,
            &AnchorCheckpointProvider::custom_from_genesis(genesis_state),
            &Arc::new(AtomicBool::new(false)),
            &*finalized_validators,
        )?;

        // Assert that the mappings from state root to slot are stored.
        assert_eq!(storage.slot_by_state_root(state_1_root)?, Some(1));
        assert_eq!(storage.slot_by_state_root(state_22_root)?, Some(22));
        assert_eq!(storage.slot_by_state_root(state_96_root)?, Some(96));
        assert_eq!(storage.slot_by_state_root(state_128_root)?, Some(128));

        // `stored_state` caches the block's state root on the state it returns, so hashing that
        // state would just echo the expected value back. Re-encoding it drops the cached root, so
        // the root is recomputed from the contents the delta chain actually produced.
        let recomputed_root = |state: Arc<BeaconState<Mainnet>>| -> Result<H256> {
            Ok(
                BeaconState::<Mainnet>::from_ssz(&Mainnet::default_config(), state.to_ssz()?)?
                    .hash_tree_root(),
            )
        };

        // Assert that the stored state is accessible by state root.
        for state_root in [state_1_root, state_22_root, state_96_root, state_128_root] {
            let state = storage
                .stored_state_by_state_root(state_root, &*finalized_validators)?
                .expect("state should be stored");

            assert_eq!(recomputed_root(state)?, state_root);
        }

        // Assert that the stored state is accessible by slot. This is the path the beacon API takes
        // for slots below finalization.
        for (slot, state_root) in [
            (1, state_1_root),
            (22, state_22_root),
            (96, state_96_root),
            (128, state_128_root),
        ] {
            let state = storage
                .stored_state(slot, Some(&*finalized_validators))?
                .expect("state should be stored");

            assert_eq!(state.slot(), slot);
            assert_eq!(recomputed_root(state)?, state_root);
        }

        // The same states, read again with nothing warm: the spine and the frame cache are what
        // the assertions above may have been served from, so clearing them forces the whole delta
        // chain to be walked and applied off disk.
        storage.clear_caches();

        for (slot, state_root) in [
            (1, state_1_root),
            (22, state_22_root),
            (96, state_96_root),
            (128, state_128_root),
        ] {
            let state = storage
                .stored_state(slot, Some(&*finalized_validators))?
                .expect("state should be stored");

            assert_eq!(recomputed_root(state)?, state_root);
        }

        // Slots without a block are served by transitioning the nearest stored state forward.
        for empty_slot in empty_slots {
            assert_eq!(
                storage
                    .stored_state(empty_slot, Some(&*finalized_validators))?
                    .map(|state| state.slot()),
                Some(empty_slot),
            );
        }

        Ok(())
    }

    #[test]
    fn archive_back_sync_states_runs_on_a_store_initialized_through_load() -> Result<()> {
        let genesis_state = mainnet::GENESIS_BEACON_STATE.force().clone_arc();
        let finalized_validators = genesis_state.validators().clone_boxed();
        let blocks = mainnet::BEACON_BLOCKS_UP_TO_SLOT_128.force();
        let storage = build_test_storage::<Mainnet>();

        let anchor_checkpoint_provider =
            AnchorCheckpointProvider::custom_from_genesis(genesis_state);

        let FinalizedCheckpoint {
            state: anchor_state,
            block: anchor_block,
        } = anchor_checkpoint_provider.checkpoint().value;

        futures::executor::block_on(storage.load(
            &Client::new(),
            StateLoadStrategy::Anchor {
                block: anchor_block,
                state: anchor_state,
            },
        ))?;

        storage.store_back_sync_blocks(blocks.iter().cloned())?;

        storage.archive_back_sync_states(
            0,
            128,
            &anchor_checkpoint_provider,
            &Arc::new(AtomicBool::new(false)),
            &*finalized_validators,
        )?;

        assert_eq!(
            get::<Hierarchy>(&storage.database, StateHierarchyKey)?
                .expect("`load` records the configured hierarchy")
                .exponents(),
            StateStorageConfig::default().hierarchy.exponents(),
        );

        assert_eq!(
            storage
                .stored_state(128, Some(&*finalized_validators))?
                .map(|state| state.slot()),
            Some(128),
        );

        Ok(())
    }

    fn build_test_storage<P: Preset>() -> Storage<P> {
        Storage::new(
            Arc::new(P::default_config()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
            None,
        )
    }
}
