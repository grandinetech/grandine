use core::{
    mem,
    sync::atomic::{AtomicU64, Ordering},
};
use std::{borrow::Cow, collections::HashSet, sync::Arc, thread::Builder};

use anyhow::{Context as _, Error as AnyhowError, Result, bail, ensure};
use database::{Database, PrefixableKey, decompress};
use derive_more::Display;
use diff::{BeaconStatePatch, Patch as _, PatchConfig};
use fork_choice_store::{ChainLink, Store};
use genesis::AnchorCheckpointProvider;
use helper_functions::{accessors, deposit_signatures, misc};
use itertools::Itertools as _;
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use pubkey_cache::PubkeyCache;
use reqwest::Client;
use ssz::{Ssz, SszRead, SszReadDefault, SszWrite};
use std_ext::ArcExt as _;
use thiserror::Error;
use tracing::info;
use transition_functions::combined;
use typenum::Unsigned as _;
use types::{
    combined::{BeaconState, DataColumnSidecar, SignedBeaconBlock},
    config::Config,
    deneb::{
        containers::{BlobIdentifier, BlobSidecar},
        primitives::BlobIndex,
    },
    fulu::{containers::DataColumnIdentifier, primitives::ColumnIndex},
    gloas::containers::SignedExecutionPayloadEnvelope,
    nonstandard::{
        BlobSidecarWithId, DataColumnSidecarWithId, FinalizedCheckpoint, Phase, PubkeyList,
        StorageMode,
    },
    phase0::{
        consts::{FAR_FUTURE_EPOCH, GENESIS_SLOT},
        primitives::{Epoch, H256, Slot},
    },
    preset::Preset,
    redacting_url::RedactingUrl,
    traits::{BeaconState as _, SignedBeaconBlock as _, SszValidatorList},
};

use crate::{
    checkpoint_sync, frame_cache::FrameCache, hierarchy::Hierarchy, spine::Spine,
    state_storage_config::StateStorageConfig,
};

pub const MAX_DATA_COLUMN_EPOCHS_TO_PRUNE: usize = 100;

// Retain archival data in memory until the number of ready beacon states
// reaches `ARCHIVED_STATES_BEFORE_FLUSH`. This approach minimizes unnecessary
// transactions and bounds how much a single archival pass holds in memory.
pub const ARCHIVED_STATES_BEFORE_FLUSH: u64 = 5;

pub const SLOT_BY_STATE_ROOTS_BEFORE_FLUSH: u64 = 100_000;

pub enum StateLoadStrategy<P: Preset> {
    Auto {
        state_slot: Option<Slot>,
        checkpoint_sync_url: Option<RedactingUrl>,
        anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    },
    Remote {
        checkpoint_sync_url: RedactingUrl,
    },
    Anchor {
        block: Arc<SignedBeaconBlock<P>>,
        state: Arc<BeaconState<P>>,
    },
}

#[expect(clippy::struct_field_names)]
#[derive(Clone)]
pub struct Storage<P: Preset> {
    config: Arc<Config>,
    pub(crate) database: Arc<Database>,
    storage_mode: StorageMode,
    pub(crate) pubkey_cache: Arc<PubkeyCache>,
    pub(crate) hierarchy: Hierarchy,
    pub(crate) compression_level: i32,
    pub(crate) anchor_slot: Arc<AtomicU64>,
    frame_cache: FrameCache<P>,
    forward_spine: Arc<Spine<P>>,
}

impl<P: Preset> Storage<P> {
    /// Verifies the `pending_deposits` signatures of the anchor state. Runs in the background.
    /// Deposits from later blocks are handled by `CacheDepositSignaturesTask`.
    fn spawn_deposit_signature_caching(&self, anchor_state: &Arc<BeaconState<P>>) {
        if self.config.gloas_fork_epoch == FAR_FUTURE_EPOCH || anchor_state.phase() >= Phase::Gloas
        {
            return;
        }

        let config = self.config.clone_arc();
        let pubkey_cache = self.pubkey_cache.clone_arc();
        let state = anchor_state.clone_arc();

        let result = Builder::new()
            .name("deposit-signature-cache".to_owned())
            .spawn(move || {
                let verified = deposit_signatures::cache_pending_deposit_signatures(
                    &config,
                    &pubkey_cache,
                    &state,
                );

                debug_with_peers!(
                    "verified {verified} pending deposit signatures from the anchor state",
                );
            });

        if let Err(error) = result {
            warn_with_peers!("failed to spawn deposit signature caching thread: {error:?}");
        }
    }

    #[must_use]
    pub fn new(
        config: Arc<Config>,
        pubkey_cache: Arc<PubkeyCache>,
        database: Database,
        storage_mode: StorageMode,
        state_storage_config: StateStorageConfig,
    ) -> Self {
        let StateStorageConfig {
            hierarchy,
            cache_sizes,
            compression_level,
        } = state_storage_config;

        // `FrameCache` needs one entry per layer, but `cache_sizes` may list only the shallowest
        // ones. The layers left unlisted are uncached.
        let cache_sizes = cache_sizes
            .into_iter()
            .chain(core::iter::repeat(0))
            .take(hierarchy.depth());

        let anchor_slot = Arc::new(AtomicU64::new(GENESIS_SLOT));

        let forward_spine = Arc::new(Spine::new(
            config.clone_arc(),
            hierarchy.clone(),
            anchor_slot.clone_arc(),
        ));

        Self {
            config,
            pubkey_cache,
            database: Arc::new(database),
            storage_mode,
            hierarchy,
            compression_level,
            anchor_slot,
            frame_cache: FrameCache::new(cache_sizes)
                .expect("unexpected error occurred, while instantiating storage cache"),
            forward_spine,
        }
    }

    #[must_use]
    pub(crate) const fn config(&self) -> &Arc<Config> {
        &self.config
    }

    #[cfg(test)]
    pub(crate) fn forward_spine(&self) -> &Spine<P> {
        &self.forward_spine
    }

    /// Forget everything a read could be served from without touching the database.
    #[cfg(test)]
    pub(crate) fn clear_caches(&self) {
        self.forward_spine.clear();
        self.frame_cache.clear();
    }

    /// A spine local to the caller, for archival passes that walk a range of
    /// slots unrelated to what forward sync is persisting.
    pub(crate) fn temporary_spine(&self, anchor_slot: Slot) -> Spine<P> {
        Spine::new(
            self.config.clone_arc(),
            self.hierarchy.clone(),
            Arc::new(AtomicU64::new(anchor_slot)),
        )
    }

    #[must_use]
    pub const fn archive_storage_enabled(&self) -> bool {
        self.storage_mode.is_archive()
    }

    #[must_use]
    pub const fn prune_storage_enabled(&self) -> bool {
        self.storage_mode.is_prune()
    }

    #[expect(clippy::too_many_lines)]
    pub async fn load(
        &self,
        client: &Client,
        state_load_strategy: StateLoadStrategy<P>,
    ) -> Result<(StateStorage<'_, P>, bool)> {
        // A mismatch is fatal rather than a warning: pruning derives its retention set from the
        // configured layout, so running against chains written under a different one deletes
        // frames those chains depend on.
        match self.get::<Hierarchy>(StateHierarchyKey)? {
            Some(stored) => ensure!(
                stored.exponents() == self.hierarchy.exponents(),
                Error::StateHierarchyMismatch {
                    stored: stored.to_string(),
                    configured: self.hierarchy.to_string(),
                },
            ),
            None => save(&self.database, StateHierarchyKey, &self.hierarchy)?,
        }

        let anchor_block;
        let anchor_state;
        let unfinalized_blocks: UnfinalizedBlocks<P>;
        let loaded_from_remote;

        match state_load_strategy {
            StateLoadStrategy::Auto {
                state_slot,
                checkpoint_sync_url,
                anchor_checkpoint_provider,
            } => 'block: {
                // Attempt to load local state first: either latest or from specified slot.
                let local_state_storage = match state_slot {
                    Some(slot) => self.load_state_by_iteration(slot, None, true)?,
                    None => self.load_latest_state(None)?,
                };

                if let Some(url) = checkpoint_sync_url {
                    if local_state_storage.is_none() {
                        let result = if let Some(checkpoint) =
                            anchor_checkpoint_provider.checkpoint().checkpoint_synced()
                        {
                            info_with_peers!(
                                "anchor checkpoint is already loaded from remote checkpoint sync server"
                            );
                            Ok(checkpoint)
                        } else {
                            checkpoint_sync::load_finalized_from_remote(&self.config, client, &url)
                                .await
                                .context(Error::CheckpointSyncFailed)
                        };

                        match result {
                            Ok(FinalizedCheckpoint { block, state }) => {
                                anchor_block = block;
                                anchor_state = state;
                                unfinalized_blocks = Box::new(core::iter::empty());
                                loaded_from_remote = true;
                                break 'block;
                            }
                            Err(error) => warn_with_peers!("{error:#}"),
                        }
                    } else {
                        warn_with_peers!(
                            "skipping checkpoint sync: existing database found; \
                             pass --force-checkpoint-sync to force checkpoint sync",
                        );
                    }
                }

                match local_state_storage {
                    OptionalStateStorage::Full(state_storage) => {
                        (anchor_state, anchor_block, unfinalized_blocks) = state_storage;
                    }
                    // State might not be found but unfinalized blocks could be present.
                    OptionalStateStorage::UnfinalizedOnly(local_unfinalized_blocks) => {
                        let FinalizedCheckpoint { block, state } =
                            anchor_checkpoint_provider.checkpoint().value;

                        anchor_block = block;
                        anchor_state = state;
                        unfinalized_blocks = local_unfinalized_blocks;
                    }
                    OptionalStateStorage::None => {
                        let FinalizedCheckpoint { block, state } =
                            anchor_checkpoint_provider.checkpoint().value;

                        anchor_block = block;
                        anchor_state = state;
                        unfinalized_blocks = Box::new(core::iter::empty());
                    }
                }

                loaded_from_remote = false;
            }
            StateLoadStrategy::Remote {
                checkpoint_sync_url,
            } => {
                let FinalizedCheckpoint { block, state } =
                    checkpoint_sync::load_finalized_from_remote(
                        &self.config,
                        client,
                        &checkpoint_sync_url,
                    )
                    .await
                    .context(Error::CheckpointSyncFailed)?;

                anchor_block = block;
                anchor_state = state;
                unfinalized_blocks = Box::new(core::iter::empty());
                loaded_from_remote = true;
            }
            StateLoadStrategy::Anchor { block, state } => {
                anchor_block = block;
                anchor_state = state;
                unfinalized_blocks = Box::new(core::iter::empty());
                loaded_from_remote = false;
            }
        }

        // decompress and load all missing anchor state pubkeys into cache
        if let Err(error) = self.pubkey_cache.load_and_persist_state_keys(&anchor_state) {
            warn_with_peers!(
                "error occurred while loading anchor state keys into pubkey_cache: {error:?}"
            );
        }

        self.spawn_deposit_signature_caching(&anchor_state);

        let anchor_slot = anchor_block.message().slot();
        let anchor_block_root = anchor_block.message().hash_tree_root();
        let anchor_state_root = anchor_block.message().state_root();

        info_with_peers!("loaded state at slot {anchor_slot}");

        let anchor_validators = anchor_state.validators();

        let mut batch = vec![
            serialize(FinalizedBlockByRoot(anchor_block_root), &anchor_block)?,
            serialize(BlockRootBySlot(anchor_slot), anchor_block_root)?,
            serialize(SlotByStateRoot(anchor_state_root), anchor_slot)?,
        ];

        let mut delete_batch = Vec::new();

        if !loaded_from_remote && let Some(hierarchy_anchor) = self.get::<Slot>(StateAnchorKey)? {
            self.anchor_slot.store(hierarchy_anchor, Ordering::SeqCst);

            let mut update_finalized_validators = false;
            let to_delete = self.append_finalized_state(
                anchor_state.clone_arc(),
                anchor_slot,
                anchor_block_root,
                hierarchy_anchor,
                anchor_validators,
                &self.temporary_spine(hierarchy_anchor),
                &mut batch,
                &mut update_finalized_validators,
            )?;

            if let Some(to_delete) = to_delete {
                delete_batch.push(to_delete);
            }
        } else {
            batch.push(serialize(StateAnchorKey, anchor_slot)?);

            self.anchor_slot.store(anchor_slot, Ordering::SeqCst);

            let snapshot_key = StateByBlockRoot::snapshot(anchor_block_root);

            // Any other row for this block root - a delta, or a snappy snapshot from an older
            // release - sorts before the snapshot key written below, so the reader would keep
            // finding it and never see the snapshot. Drop it in favour of the snapshot, which
            // does not depend on a chain that may have been pruned.
            if let Some(stored_key) = self.state_key_by_block_root(anchor_block_root)?
                && stored_key.to_string() != snapshot_key.to_string()
            {
                delete_batch.push(stored_key);
            }

            let (serialized_key, serialized_frame) = serialize_zstd(
                snapshot_key,
                prepare_state(anchor_state.clone_arc(), anchor_validators.len_usize()),
                self.compression_level,
            )?;

            batch.push((serialized_key, serialized_frame));
        }

        self.append_finalized_validator_pubkeys_to_batch(&mut batch, anchor_validators)?;

        // Written before deleted, for the same reason `flush` commits in that
        // order: a crash in between leaves a duplicate copy of the anchor state
        // rather than none at all.
        self.database.put_batch_raw(batch)?;
        self.database
            .delete_batch(delete_batch.into_iter().map(|key| key.to_string()))?;

        // Seed the spine so that the first state forward sync persists has a
        // delta parent without reading it back from disk.
        if let Some(key) = self.state_key_by_block_root(anchor_block_root)? {
            self.forward_spine
                .insert(anchor_slot, key, anchor_state.clone_arc());
        }

        let state_storage = (anchor_state, anchor_block, unfinalized_blocks);

        Ok((state_storage, loaded_from_remote))
    }

    fn load_latest_state(
        &self,
        finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<OptionalStateStorage<'_, P>> {
        if let Some((state, block, blocks)) =
            self.load_state_and_blocks_from_checkpoint(finalized_validators)?
        {
            Ok(OptionalStateStorage::Full((state, block, blocks)))
        } else {
            info_with_peers!(
                "latest state checkpoint was not found; \
                 attempting to find stored state by iteration",
            );

            self.load_state_by_iteration(Slot::MAX, finalized_validators, true)
        }
    }

    #[inline]
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_finalized_state(
        &self,
        state: Arc<BeaconState<P>>,
        slot: Slot,
        block_root: H256,
        anchor_slot: Slot,
        finalized_validators: &dyn SszValidatorList,
        spine: &Spine<P>,
        batch: &mut Vec<(String, Vec<u8>)>,
        update_finalized_validators: &mut bool,
    ) -> Result<Option<StateByBlockRoot>> {
        let stored_key = self.state_key_by_block_root(block_root)?;

        // We have to check, if state was already persisted, and if so, how:
        let to_replace = match stored_key {
            // the state is already stored using delta-encoding
            Some(key) if !key.parents.is_empty() => return Ok(None),
            // the state was persisted as a snapshot, when unloading unfinalized
            // states - now we need to remove it, and save with delta-encoding.
            Some(key)
                if self
                    .hierarchy
                    .parent_of::<P>(&self.config, anchor_slot, slot)
                    .is_some() =>
            {
                Some(key)
            }
            // the state belongs to the top of hierarchy, so it doesn't require
            // re-encoding
            Some(_) => return Ok(None),
            // the state isn't written yet
            None => None,
        };

        let mut ancestor_slot = self
            .hierarchy
            .parent_of::<P>(&self.config, anchor_slot, slot);

        // A top-level node has no hierarchy parent at all, as opposed to one whose parent state
        // failed to turn up. The two reach the same snapshot branch below for opposite reasons.
        let snapshot_reason = if ancestor_slot.is_some() {
            "no hierarchy ancestor is available"
        } else {
            "it is a top-level hierarchy node"
        };

        let mut parent_state = None;

        while let Some(candidate_slot) = ancestor_slot {
            let candidate = if let Some(value) = spine.get(candidate_slot) {
                Some(value)
            } else if let Some(candidate_block_root) = self.block_root_by_slot(candidate_slot)? {
                self.state_with_key_by_block_root(candidate_block_root, Some(finalized_validators))?
                    .inspect(|(key, ancestor_state)| {
                        spine.insert(candidate_slot, key.clone(), ancestor_state.clone_arc())
                    })
            } else {
                None
            };

            match candidate {
                Some((key, ancestor_state)) => {
                    parent_state = Some((key, ancestor_state));
                    break;
                }
                None => {
                    debug_with_peers!(
                        "hierarchy ancestor state at slot {candidate_slot} is missing from \
                            storage; checking next hierarchy ancestor"
                    );

                    ancestor_slot =
                        self.hierarchy
                            .parent_of::<P>(&self.config, anchor_slot, candidate_slot);
                }
            }
        }

        if let Some((parent_key, parent_state)) = parent_state {
            let patch_config = PatchConfig {
                compression_level: self.compression_level,
            };

            let key = parent_key.extend_chain(block_root);

            let patch = BeaconStatePatch::diff(patch_config, &parent_state, &state)?;

            let (serialized_key, serialized_patch) = serialize_raw(&key, patch)?;

            batch.push((serialized_key, serialized_patch));
            spine.insert(slot, key, state);

            if let Some(to_replace) = to_replace {
                Ok(Some(to_replace))
            } else {
                Ok(None)
            }
        } else {
            // Nothing can be delta-encoded without an ancestor, so this is the branch that writes
            // every snapshot. For a top-level node that is the routine case - the hierarchy's own
            // layer-0 frames, and the anchor, land here because `parent_of` returns `None` for
            // them by design. Below the top layer the ancestor is genuinely missing: a non-leaf
            // still falls back to a snapshot, a leaf is skipped, because a leaf snapshot would be
            // re-encoded as a delta the moment an ancestor shows up. Either way `to_replace` is
            // left alone: deleting the copy already on disk without writing a replacement would
            // lose the state outright.
            if to_replace.is_none() && !self.hierarchy.is_leaf::<P>(&self.config, anchor_slot, slot)
            {
                debug_with_peers!("saving state in slot {slot} as a snapshot: {snapshot_reason}");

                let key = StateByBlockRoot::snapshot(block_root);
                let (serialized_key, serialized_frame) = serialize_zstd(
                    &key,
                    prepare_state(state.clone_arc(), finalized_validators.len_usize()),
                    self.compression_level,
                )?;

                batch.push((serialized_key, serialized_frame));
                *update_finalized_validators = true;
                spine.insert(slot, key, state);
            }

            Ok(None)
        }
    }

    pub(crate) fn append<'cl>(
        &self,
        unfinalized: impl Iterator<Item = &'cl ChainLink<P>>,
        finalized: impl DoubleEndedIterator<Item = &'cl ChainLink<P>>,
        store: &Store<P, Self>,
    ) -> Result<AppendedBlockSlots> {
        let mut slots = AppendedBlockSlots::default();
        let mut store_head_slot = 0;
        let mut checkpoint_state_appended = false;
        let mut batch = vec![];

        let finalized_validators = store.finalized_validators();

        let unfinalized = unfinalized.zip(core::iter::repeat(false));
        let finalized = finalized.rev().zip(core::iter::repeat(true));

        let mut chain = unfinalized
            .chain(finalized)
            .filter(|(chain_link, is_finalized)| *is_finalized || chain_link.is_valid())
            .peekable();

        if let Some(StateCheckpoint { head_slot, .. }) =
            self.load_state_checkpoint(Some(&*finalized_validators))?
        {
            store_head_slot = head_slot;
        }

        if let Some((chain_link, _)) = chain.peek() {
            store_head_slot = chain_link.slot().max(store_head_slot);
        }

        debug_with_peers!("saving store head slot: {store_head_slot}");

        let anchor_slot = self.anchor_slot.load(Ordering::SeqCst);
        let mut update_finalized_validators = false;
        let mut states_to_save = Vec::new();

        for (chain_link, finalized) in chain {
            let block_root = chain_link.block_root;
            let block = &chain_link.block;
            let state_slot = chain_link.slot();

            if !self.prune_storage_enabled() {
                if finalized && !self.contains_finalized_block(block_root)? {
                    slots.finalized.push(state_slot);
                    batch.push(serialize(FinalizedBlockByRoot(block_root), block)?);
                } else if !self.contains_unfinalized_block(block_root)? {
                    slots.unfinalized.push(state_slot);
                    batch.push(serialize(UnfinalizedBlockByRoot(block_root), block)?);
                }

                batch.push(serialize(BlockRootBySlot(state_slot), block_root)?);
            }

            if finalized {
                if !self.prune_storage_enabled() {
                    batch.push(serialize(
                        SlotByStateRoot(block.message().state_root()),
                        state_slot,
                    )?);
                }

                let is_epoch_start = misc::is_epoch_start::<P>(state_slot);
                let is_hierarchy_slot =
                    self.hierarchy
                        .contains::<P>(&self.config, anchor_slot, state_slot);

                // The checkpoint is loaded back as the fork choice anchor, which has to be at
                // an epoch start. Hierarchy slots need not be - the deepest layer may be written
                // several times per epoch.
                if !checkpoint_state_appended
                    && is_epoch_start
                    && (store.is_forward_synced() || is_hierarchy_slot)
                {
                    info_with_peers!("saving checkpoint block & state in slot {state_slot}");

                    batch.push(serialize(
                        BlockCheckpoint::<P>::KEY,
                        BlockCheckpoint {
                            block: block.clone_arc(),
                        },
                    )?);

                    batch.push(serialize(
                        StateCheckpoint::<P>::KEY,
                        StateCheckpoint {
                            block_root,
                            head_slot: store_head_slot,
                            state: prepare_state(
                                chain_link.state(store),
                                finalized_validators.len_usize(),
                            ),
                        },
                    )?);

                    checkpoint_state_appended = true;
                    update_finalized_validators = true;
                }

                if !self.prune_storage_enabled() && is_hierarchy_slot {
                    info_with_peers!("saving state in slot {state_slot}");

                    // The chain link is kept rather than the state itself: `ChainLink::state` may
                    // have to reconstruct an unloaded state, and materialising every state here
                    // would hold the whole run resident at once.
                    states_to_save.push((state_slot, block_root, chain_link));

                    update_finalized_validators = true;
                }
            }
        }

        self.append_finalized_states(
            states_to_save
                .into_iter()
                .rev()
                .map(|(slot, block_root, chain_link)| (slot, block_root, chain_link.state(store))),
            anchor_slot,
            &*finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        Ok(slots)
    }

    /// Persists `states` and everything already accumulated in `batch`, committing every
    /// `ARCHIVED_STATES_BEFORE_FLUSH` states so that neither the batch nor the states waiting to be
    /// encoded grow with the length of the run.
    fn append_finalized_states(
        &self,
        states: impl IntoIterator<Item = (Slot, H256, Arc<BeaconState<P>>)>,
        anchor_slot: Slot,
        finalized_validators: &dyn SszValidatorList,
        batch: &mut Vec<(String, Vec<u8>)>,
        update_finalized_validators: &mut bool,
    ) -> Result<()> {
        // States are tracked in a spine local to this call and published into
        // the forward spine only once the batch holding them is committed.
        // Publishing earlier would let this run - or a concurrent one, since the
        // forward spine is shared by every archival thread - delta-encode
        // against a parent that a later failure or a crash leaves unwritten.
        let spine = self.temporary_spine(anchor_slot);
        self.forward_spine.copy_into(&spine);

        let mut deleted_keys = Vec::new();
        let mut states_in_batch: u64 = 0;

        for (slot, block_root, state) in states {
            let to_delete = self.append_finalized_state(
                state,
                slot,
                block_root,
                anchor_slot,
                finalized_validators,
                &spine,
                batch,
                update_finalized_validators,
            )?;

            if let Some(to_delete) = to_delete {
                deleted_keys.push(to_delete);
            }

            states_in_batch = states_in_batch.saturating_add(1);

            if states_in_batch == ARCHIVED_STATES_BEFORE_FLUSH {
                self.flush(
                    batch,
                    &mut deleted_keys,
                    update_finalized_validators,
                    finalized_validators,
                )?;

                spine.copy_into(&self.forward_spine);

                states_in_batch = 0;
            }
        }

        self.flush(
            batch,
            &mut deleted_keys,
            update_finalized_validators,
            finalized_validators,
        )?;

        spine.copy_into(&self.forward_spine);

        Ok(())
    }

    /// Commits `batch` and `deleted_keys`, in that order. Per the crash-consistency choice made for
    /// the delta store, a crash between the two leaves a duplicate copy of a state rather than
    /// risking a missing one.
    pub(crate) fn flush(
        &self,
        batch: &mut Vec<(String, Vec<u8>)>,
        deleted_keys: &mut Vec<StateByBlockRoot>,
        update_finalized_validators: &mut bool,
        finalized_validators: &dyn SszValidatorList,
    ) -> Result<()> {
        if *update_finalized_validators {
            self.append_finalized_validator_pubkeys_to_batch(batch, finalized_validators)?;
            *update_finalized_validators = false;
        }

        self.database.put_batch_raw(mem::take(batch))?;
        self.database
            .delete_batch(mem::take(deleted_keys).into_iter().map(serialize_key))
    }

    pub(crate) fn append_blob_sidecars(
        &self,
        blob_sidecars: impl IntoIterator<Item = BlobSidecarWithId<P>>,
    ) -> Result<Vec<BlobIdentifier>> {
        let mut batch = vec![];
        let mut persisted_blob_ids = vec![];

        for blob_sidecar_with_id in blob_sidecars {
            let BlobSidecarWithId {
                blob_sidecar,
                blob_id,
            } = blob_sidecar_with_id;

            let BlobIdentifier { block_root, index } = blob_id;

            let slot = blob_sidecar.signed_block_header.message.slot;

            batch.push(serialize(
                BlobSidecarByBlobId(block_root, index),
                blob_sidecar,
            )?);

            batch.push(serialize(SlotBlobId(slot, block_root, index), blob_id)?);

            persisted_blob_ids.push(blob_id);
        }

        self.database.put_batch_raw(batch)?;

        Ok(persisted_blob_ids)
    }

    pub(crate) fn append_states(
        &self,
        states_with_block_roots: impl Iterator<Item = (Arc<BeaconState<P>>, H256)>,
        finalized_validators: &dyn SszValidatorList,
    ) -> Result<Vec<Slot>> {
        let mut slots = vec![];
        let mut batch = vec![];
        let mut update_finalized_validators = false;

        for (state, block_root) in states_with_block_roots {
            if !self.contains_prefixed_key(StateByBlockRoot::prefix(block_root))? {
                let archival_state = state.clone_arc();

                let (serialized_key, serialized_frame) = serialize_zstd(
                    StateByBlockRoot::snapshot(block_root),
                    prepare_state(archival_state, finalized_validators.len_usize()),
                    self.compression_level,
                )?;

                slots.push(state.slot());
                batch.push((serialized_key, serialized_frame));

                update_finalized_validators = true;
            }
        }

        if update_finalized_validators {
            self.append_finalized_validator_pubkeys_to_batch(&mut batch, finalized_validators)?;
        }

        self.database.put_batch_raw(batch)?;

        Ok(slots)
    }

    pub(crate) fn blob_sidecar_by_id(
        &self,
        blob_id: BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<P>>>> {
        let BlobIdentifier { block_root, index } = blob_id;

        self.get(BlobSidecarByBlobId(block_root, index))
    }

    pub(crate) fn prune_old_blob_sidecars(&self, up_to_slot: Slot) -> Result<()> {
        let results = self
            .database
            .iterator_descending(..=SlotBlobId(up_to_slot, H256::zero(), 0).to_string())?;

        let (mut keys_to_remove, blobs_to_remove): (Vec<_>, Vec<_>) =
            itertools::process_results(results, |iter| {
                iter.take_while(|(key_bytes, _)| SlotBlobId::has_prefix(key_bytes))
                    .unzip()
            })?;

        for blob_bytes in blobs_to_remove {
            let BlobIdentifier { block_root, index } =
                BlobIdentifier::from_ssz_default(blob_bytes)?;

            keys_to_remove.push(BlobSidecarByBlobId(block_root, index).to_string().into());
        }

        self.database.delete_batch(keys_to_remove)
    }

    /// Hierarchy nodes at or below the prune boundary that states written
    /// after the boundary are delta-encoded against. Deleting any of them
    /// makes those states unreadable, so both prune passes must skip them.
    pub(crate) fn retained_prune_slots(&self, up_to_slot: Slot) -> Vec<Slot> {
        let Some(pruned_up_to_slot) = up_to_slot.checked_sub(1) else {
            return vec![];
        };

        let anchor_slot = self.anchor_slot.load(Ordering::SeqCst);

        let mut retained = self
            .hierarchy
            .spine::<P>(&self.config, anchor_slot, pruned_up_to_slot);

        // `spine` returns a slot's ancestors, never the slot itself, but the
        // boundary is a delta parent like any other when it is a node.
        if self
            .hierarchy
            .contains::<P>(&self.config, anchor_slot, pruned_up_to_slot)
        {
            retained.push(pruned_up_to_slot);
        }

        retained
    }

    pub(crate) fn prune_old_blocks_and_states(
        &self,
        up_to_slot: Slot,
        retained_slots: &[Slot],
    ) -> Result<()> {
        let Some(pruned_up_to_slot) = up_to_slot.checked_sub(1) else {
            return Ok(());
        };

        let results = self
            .database
            .iterator_descending(..=BlockRootBySlot(pruned_up_to_slot).to_string())?;

        let entries = itertools::process_results(results, |iter| {
            iter.take_while(|(key_bytes, _)| BlockRootBySlot::has_prefix(key_bytes))
                .collect::<Vec<_>>()
        })?;

        let mut keys_to_remove = Vec::new();

        for (key_bytes, block_root_bytes) in entries {
            let BlockRootBySlot(slot) = Cow::from(key_bytes.as_slice()).try_into()?;

            if retained_slots.contains(&slot) {
                continue;
            }

            let block_root = H256::from_ssz_default(block_root_bytes)?;

            keys_to_remove.push(key_bytes);
            keys_to_remove.push(FinalizedBlockByRoot(block_root).to_string().into());

            let state_prefix = StateByBlockRoot::prefix(block_root);
            let state_keys = self.database.keys_ascending(state_prefix.as_bytes()..)?;

            keys_to_remove.extend(itertools::process_results(state_keys, |keys| {
                keys.take_while(|key| key.starts_with(state_prefix.as_bytes()))
                    .collect::<Vec<_>>()
            })?);
        }

        // Pruning deletes states the spine may track, which would make every
        // state delta-encoded against them unreadable. The retained ones are
        // still on disk and stay usable as delta parents - dropping those too
        // would leave the spine empty for most of forward sync, since pruning
        // runs about as often as archival does.
        self.forward_spine
            .remove_pruned(pruned_up_to_slot, retained_slots);

        // Retained slots keep their blocks and states, but the blocks between
        // them are gone, so a retained state is no longer a valid base for
        // replaying the chain up to an arbitrary older slot. Record how far
        // pruning went so the read path can refuse those states.
        //
        // This is committed *before* the deletions, in its own transaction, because the two
        // cannot share one. Written afterwards, a crash in between - or a failure of the second
        // write - would leave the blocks gone and the boundary still pointing at the old slot,
        // and the read path would replay across the holes and return a state that never existed.
        // In this order the marker can only ever run ahead of the deletions, which makes reads
        // below it fail closed and costs nothing: the next pass sweeps the rows up, because it
        // deletes everything below its own boundary rather than only what this one missed.
        if self.pruned_up_to_slot()? < up_to_slot {
            save(&self.database, PrunedUpToKey, up_to_slot)?;
        }

        self.database.delete_batch(keys_to_remove)?;

        Ok(())
    }

    fn pruned_up_to_slot(&self) -> Result<Slot> {
        Ok(self.get::<Slot>(PrunedUpToKey)?.unwrap_or(GENESIS_SLOT))
    }

    pub(crate) fn prune_old_state_roots(
        &self,
        up_to_slot: Slot,
        retained_slots: &[Slot],
    ) -> Result<()> {
        let mut keys_to_remove = vec![];

        let results = self
            .database
            .iterator_ascending_raw(SlotByStateRoot(H256::zero()).to_string()..)?;

        let results = itertools::process_results(results, |iter| {
            iter.take_while(|(key_bytes, _)| SlotByStateRoot::has_prefix(key_bytes))
                .collect::<Vec<_>>()
        })?;

        for (key_bytes, value_bytes) in results {
            let slot = Slot::from_ssz_default(decompress(&value_bytes)?)?;

            if slot < up_to_slot && !retained_slots.contains(&slot) {
                keys_to_remove.push(key_bytes);
            }
        }

        self.database.delete_batch(keys_to_remove)
    }

    pub(crate) fn prune_unfinalized_blocks(&self, last_finalized_slot: Slot) -> Result<Vec<Slot>> {
        let mut slots = vec![];
        let mut keys_to_remove = vec![];

        let results = self
            .database
            .iterator_ascending_raw(serialize_key(UnfinalizedBlockByRoot(H256::zero()))..)?;

        let results = itertools::process_results(results, |iter| {
            iter.take_while(|(key_bytes, _)| UnfinalizedBlockByRoot::has_prefix(key_bytes))
                .collect::<Vec<_>>()
        })?;

        for (key_bytes, value_bytes) in results {
            let unfinalized_block =
                SignedBeaconBlock::<P>::from_ssz(&self.config, decompress(&value_bytes)?)?;
            let block_slot = unfinalized_block.message().slot();

            if block_slot <= last_finalized_slot {
                slots.push(block_slot);
                keys_to_remove.push(key_bytes);
            }
        }

        for slot in &slots {
            if let Some(block_root) = self.block_root_by_slot(*slot)? {
                // remove only if slot -> root points to unfinalized block
                if !self.contains_finalized_block(block_root)? {
                    keys_to_remove
                        .push(serialize_key(BlockRootBySlot(*slot)).as_bytes().to_owned());
                }
            }
        }

        self.database.delete_batch(keys_to_remove)?;

        Ok(slots)
    }

    pub(crate) fn append_data_column_sidecars(
        &self,
        data_column_sidecars: impl IntoIterator<Item = DataColumnSidecarWithId<P>>,
    ) -> Result<Vec<DataColumnIdentifier>> {
        let mut batch = vec![];
        let mut persisted_data_column_ids = vec![];

        for data_column_sidecar_with_id in data_column_sidecars {
            let DataColumnSidecarWithId {
                data_column_sidecar,
                data_column_id,
            } = data_column_sidecar_with_id;

            let DataColumnIdentifier { block_root, index } = data_column_id;

            let slot = data_column_sidecar.slot();

            batch.push(serialize(
                DataColumnSidecarByColumnId(block_root, index),
                data_column_sidecar,
            )?);

            batch.push(serialize(
                SlotColumnId(slot, block_root, index),
                data_column_id,
            )?);

            persisted_data_column_ids.push(data_column_id);
        }

        self.database.put_batch_raw(batch)?;

        Ok(persisted_data_column_ids)
    }

    pub(crate) fn append_execution_payload_envelopes(
        &self,
        envelopes: impl IntoIterator<Item = Arc<SignedExecutionPayloadEnvelope<P>>>,
    ) -> Result<Vec<H256>> {
        let mut batch = vec![];
        let mut persisted_block_roots = vec![];

        for envelope in envelopes {
            let block_root = envelope.block_root();
            let slot = envelope.slot();

            batch.push(serialize(EnvelopeByBlockRoot(block_root), envelope)?);
            batch.push(serialize(EnvelopeRootBySlot(slot, block_root), block_root)?);

            persisted_block_roots.push(block_root);
        }

        self.database.put_batch_raw(batch)?;

        Ok(persisted_block_roots)
    }

    pub(crate) fn data_column_sidecar_by_id(
        &self,
        data_column_id: DataColumnIdentifier,
    ) -> Result<Option<Arc<DataColumnSidecar<P>>>> {
        let DataColumnIdentifier { block_root, index } = data_column_id;

        self.get(DataColumnSidecarByColumnId(block_root, index))
    }

    pub(crate) fn execution_payload_envelope_by_root(
        &self,
        block_root: H256,
    ) -> Result<Option<Arc<SignedExecutionPayloadEnvelope<P>>>> {
        self.get(EnvelopeByBlockRoot(block_root))
    }

    pub(crate) fn prune_old_data_column_sidecars(&self, up_to_slot: Slot) -> Result<()> {
        let results = self
            .database
            .iterator_descending(..=SlotColumnId(up_to_slot, H256::zero(), 0).to_string())?;

        let (mut keys_to_remove, columns_to_remove): (Vec<_>, Vec<_>) =
            itertools::process_results(results, |iter| {
                iter.take_while(|(key_bytes, _)| SlotColumnId::has_prefix(key_bytes))
                    .take(
                        // Limit number of entries to prune per single transaction
                        MAX_DATA_COLUMN_EPOCHS_TO_PRUNE
                            .saturating_mul(P::SlotsPerEpoch::USIZE)
                            .saturating_mul(P::NumberOfColumns::USIZE),
                    )
                    .unzip()
            })?;

        for column_bytes in columns_to_remove {
            let DataColumnIdentifier { block_root, index } =
                DataColumnIdentifier::from_ssz_default(column_bytes)?;

            keys_to_remove.push(
                DataColumnSidecarByColumnId(block_root, index)
                    .to_string()
                    .into(),
            )
        }

        self.database.delete_batch(keys_to_remove)
    }

    pub(crate) fn checkpoint_state_slot(
        &self,
        finalized_validators: &dyn SszValidatorList,
    ) -> Result<Option<Slot>> {
        if let Some(StateCheckpoint { head_slot, .. }) =
            self.load_state_checkpoint(Some(finalized_validators))?
        {
            return Ok(Some(head_slot));
        }

        Ok(None)
    }

    pub(crate) fn prune_old_execution_payload_envelopes(&self, up_to_slot: Slot) -> Result<()> {
        let results = self
            .database
            .iterator_descending(..=EnvelopeRootBySlot(up_to_slot, H256::zero()).to_string())?;

        let (mut keys_to_remove, envelopes_to_remove): (Vec<_>, Vec<_>) =
            itertools::process_results(results, |iter| {
                iter.take_while(|(key_bytes, _)| EnvelopeRootBySlot::has_prefix(key_bytes))
                    .unzip()
            })?;

        for value_bytes in envelopes_to_remove {
            let block_root = H256::from_ssz_default(value_bytes)?;

            keys_to_remove.push(EnvelopeByBlockRoot(block_root).to_string().into());
        }

        self.database.delete_batch(keys_to_remove)
    }

    pub(crate) fn genesis_block_root(&self, store: &Store<P, Self>) -> Result<H256> {
        self.block_root_by_slot_with_store(store, GENESIS_SLOT)?
            .ok_or(Error::GenesisBlockRootNotFound)
            .map_err(Into::into)
    }

    pub(crate) fn contains_finalized_block(&self, block_root: H256) -> Result<bool> {
        self.contains_key(FinalizedBlockByRoot(block_root))
    }

    pub(crate) fn contains_unfinalized_block(&self, block_root: H256) -> Result<bool> {
        self.contains_key(UnfinalizedBlockByRoot(block_root))
    }

    pub(crate) fn finalized_block_by_root(
        &self,
        block_root: H256,
    ) -> Result<Option<Arc<SignedBeaconBlock<P>>>> {
        self.get(FinalizedBlockByRoot(block_root))
    }

    pub(crate) fn unfinalized_block_by_root(
        &self,
        block_root: H256,
    ) -> Result<Option<Arc<SignedBeaconBlock<P>>>> {
        self.get(UnfinalizedBlockByRoot(block_root))
    }

    pub(crate) fn block_root_by_slot(&self, slot: Slot) -> Result<Option<H256>> {
        self.get(BlockRootBySlot(slot))
    }

    fn state_with_key_by_block_root(
        &self,
        block_root: H256,
        finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<Option<(StateByBlockRoot, Arc<BeaconState<P>>)>> {
        let Some(key) = self.state_key_by_block_root(block_root)? else {
            return Ok(None);
        };

        let mut items = Vec::new();
        let mut visited = HashSet::new();
        let mut frame = None;
        let mut next_row_key = Some(key.clone());

        // We iterate from deepest value back to the top of hierarchy. We do it
        // this way, just because we'd like to short-circuit once we find cached
        // value, to avoid reading unnecessary values from disk.
        //
        // The chain is followed as it is on disk - through each row's own key -
        // rather than through the chain recorded in the queried state's key,
        // because a state that was written as a snapshot is re-encoded as a
        // delta once a hierarchy ancestor of it shows up, which leaves the
        // chains recorded in its children stale.
        while let Some(row_key) = next_row_key.take() {
            ensure!(
                visited.insert(row_key.block_root),
                "unable to reconstruct state: delta chain revisits block root {:?}",
                row_key.block_root,
            );

            // How many ancestors a row's own key names is its layer, which is
            // how both `frame_cache` and the forward spine index layers.
            let layer = row_key.parents.len();

            // Probed before the row's value is read, so that a hit skips
            // reading the frame off disk, decompressing it and applying deltas
            // alike. Snapshot rows are hundreds of megabytes on Mainnet, so
            // reading one only to discard it would defeat the cache.
            if let Some(spine_frame) = self.forward_spine.get_by_block_root(row_key.block_root) {
                frame = Some(spine_frame);
                break;
            }

            // We check additionally if layer doesn't exceed hierarchy depth, to
            // be sure that frame_cache won't error out due to requesting
            // non-existent layer. Although this is sign that something gone
            // wrong (hierarchy changed, or anchor point drifted somehow), we
            // still want to reconstruct this state.
            if layer >= self.hierarchy.depth() {
                warn_with_peers!("state reconstruction chain is larger than hierarchy");
            } else if let Some(cached_frame) = self.frame_cache.get(layer, &row_key.block_root)? {
                frame = Some(cached_frame);
                break;
            }

            let Some(raw_value) = self.database.get_raw(row_key.to_string())? else {
                // The row was read as a key just above, so it can only be gone
                // if pruning deleted it in between. Treated like a chain cut
                // short by pruning, which the caller falls back from.
                warn_with_peers!(
                    "state {:?} cannot be reconstructed: \
                     the row for {:?} was deleted while it was being read",
                    block_root,
                    row_key.block_root,
                );

                return Ok(None);
            };

            let value = match row_key.compression {
                CompressionType::None => raw_value,
                CompressionType::Zstd => zstd::decode_all(raw_value.as_slice())?,
                CompressionType::LegacySnappy => {
                    snap::raw::Decoder::new().decompress_vec(&raw_value)?
                }
            };

            items.push((value, layer, row_key.block_root));

            // A row that names no parents is the frame the chain is rooted at.
            let Some(&parent_root) = row_key.parents.first() else {
                break;
            };

            let Some(parent_key) = self.state_key_by_block_root(parent_root)? else {
                // The chain a state is encoded against can be cut short by pruning - most
                // plausibly for a state written under a previous anchor, whose delta parents are
                // not in the retention set the pruner computes from the current one. Report the
                // state as absent so that callers fall back to replaying blocks from an older
                // one, instead of failing the whole read.
                warn_with_peers!(
                    "state {:?} cannot be reconstructed: \
                     its delta parent {parent_root:?} is no longer stored",
                    block_root,
                );

                return Ok(None);
            };

            next_row_key = Some(parent_key);
        }

        // We've collected items in order, that allows to stop as soon as we
        // find cached value. Now, to reconstruct queried state, we have to go
        // in reverse - start from hierarchy top (snapshots), down to our state,
        // applying all necessary deltas in our way.
        items.reverse();

        let (mut frame, deltas) = if let Some(frame) = frame {
            // If we've found value from cache, no decoding needed - just take the frame
            (frame, items.as_slice())
        } else {
            let Some(((frame_bytes, layer, block_root), deltas)) = items.split_first() else {
                unreachable!("items cannot be empty");
            };

            let mut frame = Arc::<BeaconState<P>>::from_ssz(&self.config, frame_bytes)?;

            self.restore_validators_to_state(frame.make_mut(), finalized_validators, 0)?;

            if *layer < self.hierarchy.depth() {
                self.frame_cache
                    .set(*layer, *block_root, frame.clone_arc())?;
            }

            (frame, deltas)
        };

        for (delta, layer, block_root) in deltas {
            let patch = BeaconStatePatch::from_ssz(&self.config, delta)?;
            let validators_before = frame.validators().len_u64();

            patch.apply(&mut frame)?;

            if frame.validators().len_u64() != validators_before {
                self.restore_validators_to_state(
                    frame.make_mut(),
                    finalized_validators,
                    validators_before.try_into()?,
                )?;
            }

            if *layer < self.hierarchy.depth() {
                self.frame_cache
                    .set(*layer, *block_root, frame.clone_arc())?;
            }
        }

        Ok(Some((key, frame)))
    }

    fn state_by_block_root(
        &self,
        block_root: H256,
        finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        Ok(self
            .state_with_key_by_block_root(block_root, finalized_validators)?
            .map(|(_, state)| state))
    }

    pub(crate) fn slot_by_state_root(&self, state_root: H256) -> Result<Option<Slot>> {
        self.get(SlotByStateRoot(state_root))
    }

    // Like `block_root_by_slot`, but looks for the root in `store` first.
    pub(crate) fn block_root_by_slot_with_store(
        &self,
        store: &Store<P, Self>,
        slot: Slot,
    ) -> Result<Option<H256>> {
        if let Some(chain_link) = store.chain_link_before_or_at(slot) {
            let slot_matches = chain_link.slot() == slot;
            return Ok(slot_matches.then_some(chain_link.block_root));
        }

        self.block_root_by_slot(slot)
    }

    pub(crate) fn block_root_before_or_at_slot(&self, slot: Slot) -> Result<Option<H256>> {
        let results = self
            .database
            .iterator_descending(..=BlockRootBySlot(slot).to_string())?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| BlockRootBySlot::has_prefix(key_bytes))
                .map(|(_, value_bytes)| H256::from_ssz_default(value_bytes))
                .next()
                .transpose()
        })?
        .map_err(Into::into)
    }

    pub(crate) fn finalized_block_by_slot(
        &self,
        slot: Slot,
    ) -> Result<Option<(Arc<SignedBeaconBlock<P>>, H256)>> {
        let Some(block_root) = self.block_root_by_slot(slot)? else {
            return Ok(None);
        };

        let Some(block) = self.finalized_block_by_root(block_root)? else {
            return Ok(None);
        };

        Ok(Some((block, block_root)))
    }

    pub(crate) fn stored_state(
        &self,
        slot: Slot,
        finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        let (mut state, state_block, blocks) =
            match self.load_state_by_iteration(slot, finalized_validators, false)? {
                OptionalStateStorage::None | OptionalStateStorage::UnfinalizedOnly(_) => {
                    return Ok(None);
                }
                OptionalStateStorage::Full(state_storage) => state_storage,
            };

        state.set_cached_root(state_block.message().state_root());

        // State may be persisted only once in several epochs.
        // `blocks` here are needed to transition state closer to `slot`.
        for result in blocks.rev() {
            let block = result?;
            combined::trusted_state_transition(
                &self.config,
                &self.pubkey_cache,
                state.make_mut(),
                &block,
            )?;
        }

        if state.slot() < slot {
            combined::process_slots(&self.config, &self.pubkey_cache, state.make_mut(), slot)?;
        }

        Ok(Some(state))
    }

    pub(crate) fn state_post_block(
        &self,
        mut block_root: H256,
        finalized_validators: &dyn SszValidatorList,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        let mut blocks = vec![];

        let mut state = loop {
            if let Some(state) = self.state_by_block_root(block_root, Some(finalized_validators))? {
                break state;
            }

            if let Some(block) = self.finalized_block_by_root(block_root)? {
                block_root = block.message().parent_root();
                blocks.push(block);
                continue;
            }

            if let Some(block) = self.unfinalized_block_by_root(block_root)? {
                block_root = block.message().parent_root();
                blocks.push(block);
                continue;
            }

            return Ok(None);
        };

        for block in blocks.into_iter().rev() {
            combined::trusted_state_transition(
                &self.config,
                &self.pubkey_cache,
                state.make_mut(),
                &block,
            )?;
        }

        Ok(Some(state))
    }

    pub(crate) fn stored_state_by_state_root(
        &self,
        state_root: H256,
        finalized_validators: &dyn SszValidatorList,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        if let Some(state_slot) = self.slot_by_state_root(state_root)? {
            return self.stored_state(state_slot, Some(finalized_validators));
        }

        Ok(None)
    }

    pub(crate) fn dependent_root(
        &self,
        store: &Store<P, Self>,
        state: &BeaconState<P>,
        epoch: Epoch,
    ) -> Result<H256> {
        let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);

        match start_slot.checked_sub(1) {
            Some(root_slot) => accessors::get_block_root_at_slot(state, root_slot),
            None => self.genesis_block_root(store),
        }
        .context(Error::DependentRootLookupFailed)
    }

    fn load_state_and_blocks_from_checkpoint(
        &self,
        finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<Option<StateStorage<'_, P>>> {
        if let Some(checkpoint) = self.load_state_checkpoint(finalized_validators)? {
            let StateCheckpoint {
                block_root, state, ..
            } = checkpoint;

            let block = if let Some(block_checkpoint) = self.load_block_checkpoint()? {
                let BlockCheckpoint { block } = block_checkpoint;
                let requested = block_root;
                let computed = block.message().hash_tree_root();

                ensure!(
                    requested == computed,
                    Error::CheckpointBlockRootMismatch {
                        requested,
                        computed,
                    },
                );

                block
            } else {
                self.finalized_block_by_root(block_root)?
                    .ok_or(Error::BlockNotFound { block_root })?
            };

            ensure!(
                misc::is_epoch_start::<P>(state.slot()),
                Error::PersistedSlotCannotContainAnchor { slot: state.slot() },
            );

            let results = self.database.iterator_ascending_raw(
                BlockRootBySlot(state.slot().saturating_add(1)).to_string()..,
            )?;

            let block_roots = itertools::process_results(results, |pairs| {
                pairs
                    .take_while(|(key_bytes, _)| BlockRootBySlot::has_prefix(key_bytes))
                    .map(|(_, value_bytes)| {
                        H256::from_ssz_default(decompress(&value_bytes)?).map_err(AnyhowError::from)
                    })
                    .try_collect()
            })??;

            let blocks = self.blocks_by_roots(block_roots);

            return Ok(Some((state, block, blocks)));
        }

        Ok(None)
    }

    /// Finds the newest persisted state at or below `start_from_slot`, along with the blocks
    /// needed to replay it forward. `epoch_start_only` restricts the search to states that can
    /// serve as a fork choice anchor.
    fn load_state_by_iteration(
        &self,
        start_from_slot: Slot,
        finalized_validators: Option<&dyn SszValidatorList>,
        epoch_start_only: bool,
    ) -> Result<OptionalStateStorage<'_, P>> {
        let results = self
            .database
            .iterator_descending(..=BlockRootBySlot(start_from_slot).to_string())?;

        // Below this slot only hierarchy nodes retained as delta parents
        // survive. Their states are intact, but the blocks that connect them
        // to any other slot are not, so replaying from one of them would skip
        // real blocks and yield a state that never existed.
        let pruned_up_to_slot = self.pruned_up_to_slot()?;

        let mut block_roots = vec![];

        for result in results {
            let (key_bytes, value_bytes) = result?;

            if !BlockRootBySlot::has_prefix(&key_bytes) {
                break;
            }

            let BlockRootBySlot(slot) = Cow::from(key_bytes.as_slice()).try_into()?;

            if slot < pruned_up_to_slot {
                break;
            }

            let block_root = H256::from_ssz_default(value_bytes)?;

            if self.contains_prefixed_key(StateByBlockRoot::prefix(block_root))? {
                let Some(block) = self.finalized_block_by_root(block_root)? else {
                    // States are also persisted from unfinalized chain
                    continue;
                };

                if let Some(state) = self.state_by_block_root(block_root, finalized_validators)?
                    && (!epoch_start_only || misc::is_epoch_start::<P>(state.slot()))
                {
                    let blocks = self.blocks_by_roots(block_roots);

                    return Ok(OptionalStateStorage::Full((state, block, blocks)));
                }
            }

            block_roots.push(block_root);
        }

        if block_roots.is_empty() {
            return Ok(OptionalStateStorage::None);
        }

        Ok(OptionalStateStorage::UnfinalizedOnly(
            self.blocks_by_roots(block_roots),
        ))
    }

    fn load_block_checkpoint(&self) -> Result<Option<BlockCheckpoint<P>>> {
        self.get(BlockCheckpoint::<P>::KEY)
    }

    fn load_state_checkpoint(
        &self,
        finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<Option<StateCheckpoint<P>>> {
        let Some(mut checkpoint) = self.get::<StateCheckpoint<P>>(StateCheckpoint::<P>::KEY)?
        else {
            return Ok(None);
        };

        // Restore validators if they were removed
        self.restore_validators_to_state(checkpoint.state.make_mut(), finalized_validators, 0)?;

        Ok(Some(checkpoint))
    }

    fn contains_key(&self, key: impl core::fmt::Display) -> Result<bool> {
        let key_string = key.to_string();

        self.database.contains_key(key_string)
    }

    fn contains_prefixed_key(&self, key: impl core::fmt::Display) -> Result<bool> {
        let key_string = key.to_string();

        self.database.contains_prefixed_key(key_string)
    }

    /// Read the key a state is actually stored under - which names the ancestors it is currently
    /// delta-encoded against, and may differ from the chain its children recorded.
    ///
    /// Only the key is read: a state row holds a whole frame or delta, so the value is fetched
    /// separately, once the caller knows it needs it.
    fn state_key_by_block_root(&self, block_root: H256) -> Result<Option<StateByBlockRoot>> {
        let prefix = StateByBlockRoot::prefix(block_root);

        // We don't know the full key of state, because full key contains
        // additional metadata as well, so we query any key that is
        // lexicographically larger than, or equal to, our prefix.
        let Some(full_key) = self.database.next_key(&prefix)? else {
            return Ok(None);
        };

        // We received key that is lexicographically larger than our prefix - it
        // may not actually start from prefix, so we have to verify it.
        if !full_key.starts_with(prefix.as_bytes()) {
            return Ok(None);
        }

        full_key.as_slice().try_into().map(Some)
    }

    fn get<V: SszRead<Config>>(&self, key: impl core::fmt::Display) -> Result<Option<V>> {
        let key_string = key.to_string();

        if let Some(value_bytes) = self.database.get(key_string)? {
            let value = V::from_ssz(&self.config, value_bytes)?;
            return Ok(Some(value));
        }

        Ok(None)
    }

    fn blocks_by_roots(&self, block_roots: Vec<H256>) -> UnfinalizedBlocks<'_, P> {
        Box::new(block_roots.into_iter().map(|block_root| {
            if let Some(block) = self.finalized_block_by_root(block_root)? {
                return Ok(block);
            }

            if let Some(block) = self.unfinalized_block_by_root(block_root)? {
                return Ok(block);
            }

            bail!(Error::BlockNotFound { block_root })
        }))
    }

    fn restore_validators_to_state(
        &self,
        state: &mut BeaconState<P>,
        finalized_validators: Option<&dyn SszValidatorList>,
        first_missing: usize,
    ) -> Result<()> {
        match finalized_validators {
            Some(validators) => {
                state
                    .validators_mut()
                    .set_pubkeys_from(validators.pubkeys(), first_missing)
                    .context("invalid finalized validators list")?;
            }
            None => {
                info_with_peers!("loading validators from disk");

                let Some(pubkeys) = self.get::<PubkeyList>(FinalizedValidators)? else {
                    bail!(
                        "unable to restore validators into state - no saved validators on disk found."
                    );
                };

                state
                    .validators_mut()
                    .set_pubkeys_from(&pubkeys, first_missing)
                    .context("invalid finalized validators list loaded from disk")?;
            }
        }

        Ok(())
    }

    pub(crate) fn append_finalized_validator_pubkeys_to_batch(
        &self,
        batch: &mut Vec<(String, Vec<u8>)>,
        validators: &dyn SszValidatorList,
    ) -> Result<()> {
        let current_validator_count = self.get::<u64>(FinalizedValidatorCount)?.unwrap_or(0);

        if validators.len_u64() <= current_validator_count {
            return Ok(());
        }

        batch.extend_from_slice(&[
            serialize(FinalizedValidatorCount, validators.len_u64())?,
            serialize(FinalizedValidators, validators.pubkeys())?,
        ]);

        Ok(())
    }
}

#[cfg(test)]
impl<P: Preset> Storage<P> {
    pub fn block_root_by_slot_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending_raw(BlockRootBySlot(0).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| BlockRootBySlot::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn finalized_block_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending_raw(FinalizedBlockByRoot(H256::zero()).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| FinalizedBlockByRoot::has_prefix(key_bytes))
                .filter(|(key_bytes, _)| !UnfinalizedBlockByRoot::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn unfinalized_block_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending_raw(UnfinalizedBlockByRoot(H256::zero()).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| UnfinalizedBlockByRoot::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn slot_by_state_root_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending_raw(SlotByStateRoot(H256::zero()).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| SlotByStateRoot::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn slot_by_blob_id_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending_raw(SlotBlobId(0, H256::zero(), 0).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| SlotBlobId::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn state_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending_raw(StateByBlockRoot::prefix(H256::zero())..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| StateByBlockRoot::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn blob_sidecar_by_blob_id_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending_raw(BlobSidecarByBlobId(H256::zero(), 0).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| BlobSidecarByBlobId::has_prefix(key_bytes))
                .count()
        })
    }
}

impl<P: Preset> fork_choice_store::Storage<P> for Storage<P> {
    fn storage_mode(&self) -> StorageMode {
        self.storage_mode
    }

    fn stored_state_by_block_root(
        &self,
        block_root: H256,
        finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        self.state_by_block_root(block_root, finalized_validators)
    }
}

#[derive(Default, Debug)]
pub struct AppendedBlockSlots {
    pub finalized: Vec<Slot>,
    pub unfinalized: Vec<Slot>,
}

type UnfinalizedBlocks<'storage, P> =
    Box<dyn DoubleEndedIterator<Item = Result<Arc<SignedBeaconBlock<P>>>> + Send + 'storage>;

// Internal type for state storage that can be missing or have missing elements.
// E.g. non-finalized storage that has only unfinalized blocks stored.
enum OptionalStateStorage<'storage, P: Preset> {
    None,
    UnfinalizedOnly(UnfinalizedBlocks<'storage, P>),
    Full(StateStorage<'storage, P>),
}

impl<P: Preset> OptionalStateStorage<'_, P> {
    const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

type StateStorage<'storage, P> = (
    Arc<BeaconState<P>>,
    Arc<SignedBeaconBlock<P>>,
    UnfinalizedBlocks<'storage, P>,
);

#[derive(Ssz)]
// A `bound_for_read` attribute like this must be added when deriving `SszRead` for any type that
// contains a block or state. The name of the `C` type parameter is hardcoded in `ssz_derive`.
#[ssz(bound_for_read = "BeaconState<P>: SszRead<C>", derive_hash = false)]
pub struct StateCheckpoint<P: Preset> {
    block_root: H256,
    head_slot: Slot,
    state: Arc<BeaconState<P>>,
}

impl<P: Preset> PrefixableKey for StateCheckpoint<P> {
    const PREFIX: &'static str = Self::KEY;
}

impl<P: Preset> StateCheckpoint<P> {
    // This was renamed from `cstate` for compatibility with old schema versions.
    const KEY: &'static str = "cstate2";
}

#[derive(Ssz)]
// A `bound_for_read` attribute like this must be added when deriving `SszRead` for any type that
// contains a block or state. The name of the `C` type parameter is hardcoded in `ssz_derive`.
#[ssz(
    bound_for_read = "SignedBeaconBlock<P>: SszRead<C>",
    derive_hash = false,
    transparent
)]
pub struct BlockCheckpoint<P: Preset> {
    block: Arc<SignedBeaconBlock<P>>,
}

impl<P: Preset> PrefixableKey for BlockCheckpoint<P> {
    const PREFIX: &'static str = Self::KEY;
}

impl<P: Preset> BlockCheckpoint<P> {
    const KEY: &'static str = "cblock";
}

#[derive(Display)]
#[display("{}{_0:020}", Self::PREFIX)]
pub struct BlockRootBySlot(pub Slot);

impl TryFrom<Cow<'_, [u8]>> for BlockRootBySlot {
    type Error = AnyhowError;

    fn try_from(bytes: Cow<[u8]>) -> Result<Self> {
        let payload =
            bytes
                .strip_prefix(Self::PREFIX.as_bytes())
                .ok_or_else(|| Error::IncorrectPrefix {
                    bytes: bytes.to_vec(),
                })?;

        let string = core::str::from_utf8(payload)?;
        let slot = string.parse()?;

        Ok(Self(slot))
    }
}

impl PrefixableKey for BlockRootBySlot {
    const PREFIX: &'static str = "r";
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
pub struct FinalizedBlockByRoot(pub H256);

impl PrefixableKey for FinalizedBlockByRoot {
    const PREFIX: &'static str = "b";
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
pub struct UnfinalizedBlockByRoot(pub H256);

impl PrefixableKey for UnfinalizedBlockByRoot {
    const PREFIX: &'static str = "b_nf";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressionType {
    Zstd,
    LegacySnappy,
    None,
}

#[derive(Debug, Clone)]
pub struct StateByBlockRoot {
    pub(crate) block_root: H256,
    parents: Vec<H256>,
    compression: CompressionType,
}

impl PrefixableKey for StateByBlockRoot {
    const PREFIX: &'static str = "s";
}

impl core::fmt::Display for StateByBlockRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}{:x}", Self::PREFIX, self.block_root)?;
        for i in &self.parents {
            write!(f, "{i:x}")?;
        }
        if matches!(self.compression, CompressionType::Zstd) {
            write!(f, "z")?;
        }
        Ok(())
    }
}

impl TryFrom<&'_ [u8]> for StateByBlockRoot {
    type Error = anyhow::Error;

    fn try_from(value: &'_ [u8]) -> Result<Self, Self::Error> {
        let Some(stripped) = value.strip_prefix(Self::PREFIX.as_bytes()) else {
            bail!("Invalid prefix");
        };

        let (stripped, has_zstd_suffix) = match stripped.strip_suffix(b"z") {
            Some(stripped) => (stripped, true),
            None => (stripped, false),
        };

        let hashes_iter = stripped.chunks_exact(H256::len_bytes().saturating_mul(2));
        ensure!(hashes_iter.remainder().is_empty(), "Invalid parents");
        let mut hashes = hashes_iter.map(|root| {
            let root_str = str::from_utf8(root)?;
            let mut root = H256::default();

            hex::decode_to_slice(root_str, &mut root.0)?;
            Ok(root)
        });

        let Some(block_root) = hashes.next() else {
            bail!("Block root hash is missing");
        };

        let parents = hashes.collect::<Result<Vec<_>>>()?;

        let compression = match (has_zstd_suffix, parents.is_empty()) {
            // State frames are compressed with zstd
            (true, true) => CompressionType::Zstd,
            // State deltas aren't compressed - compression happens within
            (false, false) => CompressionType::None,
            // Legacy states are compressed with snappy
            (false, true) => CompressionType::LegacySnappy,
            // State deltas cannot be compressed with zstd
            (true, false) => bail!("invalid state key: state deltas cannot have `z` suffix"),
        };

        Ok(Self {
            block_root: block_root?,
            parents,
            compression,
        })
    }
}

impl StateByBlockRoot {
    pub(crate) const fn snapshot(block_root: H256) -> Self {
        Self {
            block_root,
            parents: Vec::new(),
            compression: CompressionType::Zstd,
        }
    }

    fn prefix(block_root: H256) -> String {
        format!("{}{:x}", Self::PREFIX, block_root)
    }

    #[cfg(test)]
    const fn legacy_snapshot(block_root: H256) -> Self {
        Self {
            block_root,
            parents: Vec::new(),
            compression: CompressionType::LegacySnappy,
        }
    }

    /// Create a key for a state, that depends on this value.
    fn extend_chain(mut self, block_root: H256) -> Self {
        self.parents.insert(0, self.block_root);

        Self {
            block_root,
            parents: self.parents,
            compression: CompressionType::None,
        }
    }
}

#[derive(Display)]
#[display("{}", Self::PREFIX)]
pub struct StateAnchorKey;

impl PrefixableKey for StateAnchorKey {
    const PREFIX: &'static str = "anchor";
}

#[derive(Display)]
#[display("{}", Self::PREFIX)]
pub struct StateHierarchyKey;

impl PrefixableKey for StateHierarchyKey {
    const PREFIX: &'static str = "hierarchy";
}

#[derive(Display)]
#[display("{}", Self::PREFIX)]
pub struct PrunedUpToKey;

impl PrefixableKey for PrunedUpToKey {
    const PREFIX: &'static str = "pruned";
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
pub struct SlotByStateRoot(pub H256);

impl PrefixableKey for SlotByStateRoot {
    const PREFIX: &'static str = "t";
}

#[derive(Display)]
#[display("{}", Self::PREFIX)]
pub struct FinalizedValidators;

impl FinalizedValidators {
    const KEY: &'static str = "finalized_validators";
}

impl PrefixableKey for FinalizedValidators {
    const PREFIX: &'static str = Self::KEY;
}

#[derive(Display)]
#[display("{}", Self::PREFIX)]
pub struct FinalizedValidatorCount;

impl FinalizedValidatorCount {
    const KEY: &'static str = "finalized_validator_count";
}

impl PrefixableKey for FinalizedValidatorCount {
    const PREFIX: &'static str = Self::KEY;
}

#[derive(Display)]
#[display("{}{_0:x}{_1}", Self::PREFIX)]
pub struct BlobSidecarByBlobId(pub H256, pub BlobIndex);

impl PrefixableKey for BlobSidecarByBlobId {
    const PREFIX: &'static str = "o";

    #[cfg(test)]
    fn has_prefix(bytes: &[u8]) -> bool {
        bytes.starts_with(Self::PREFIX.as_bytes())
    }
}

#[derive(Display)]
#[display("{}{_0:020}{_1:x}{_2}", Self::PREFIX)]
pub struct SlotBlobId(pub Slot, pub H256, pub BlobIndex);

impl PrefixableKey for SlotBlobId {
    const PREFIX: &'static str = "i";
}

#[derive(Display)]
#[display("{}{_0:x}{_1}", Self::PREFIX)]
pub struct DataColumnSidecarByColumnId(pub H256, pub ColumnIndex);

impl PrefixableKey for DataColumnSidecarByColumnId {
    const PREFIX: &'static str = "d";

    #[cfg(test)]
    fn has_prefix(bytes: &[u8]) -> bool {
        bytes.starts_with(Self::PREFIX.as_bytes())
    }
}

#[derive(Display)]
#[display("{}{_0:020}{_1:x}{_2}", Self::PREFIX)]
pub struct SlotColumnId(pub Slot, pub H256, pub ColumnIndex);

impl PrefixableKey for SlotColumnId {
    const PREFIX: &'static str = "c";
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
pub struct EnvelopeByBlockRoot(pub H256);

impl PrefixableKey for EnvelopeByBlockRoot {
    const PREFIX: &'static str = "e";

    #[cfg(test)]
    fn has_prefix(bytes: &[u8]) -> bool {
        bytes.starts_with(Self::PREFIX.as_bytes())
    }
}

#[derive(Display)]
#[display("{}{_0:020}{_1:x}", Self::PREFIX)]
pub struct EnvelopeRootBySlot(pub Slot, pub H256);

impl PrefixableKey for EnvelopeRootBySlot {
    const PREFIX: &'static str = "v";

    #[cfg(test)]
    fn has_prefix(bytes: &[u8]) -> bool {
        bytes.starts_with(Self::PREFIX.as_bytes())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("checkpoint sync failed")]
    CheckpointSyncFailed,
    #[error("failed to look up dependent root")]
    DependentRootLookupFailed,
    #[error("genesis block root not found in storage")]
    GenesisBlockRootNotFound,
    #[error("block not found in storage: {block_root:?}")]
    BlockNotFound { block_root: H256 },
    #[error("state not found in storage: {state_slot}")]
    StateNotFound { state_slot: Slot },
    #[error(
        "checkpoint block root does not match state checkpoint \
         (requested: {requested:?}, computed: {computed:?})"
    )]
    CheckpointBlockRootMismatch { requested: H256, computed: H256 },
    #[error("persisted slot cannot contain anchor: {slot}")]
    PersistedSlotCannotContainAnchor { slot: Slot },
    #[error("storage key has incorrect prefix: {bytes:?}")]
    IncorrectPrefix { bytes: Vec<u8> },
    #[error(
        "database was written with state hierarchy {stored}, \
         but {configured} is configured; \
         pass --state-hierarchy {stored} to keep using this database \
         or --force-reset-beacon-db to discard it"
    )]
    StateHierarchyMismatch { stored: String, configured: String },
}

pub fn save(database: &Database, key: impl core::fmt::Display, value: impl SszWrite) -> Result<()> {
    database.put(serialize_key(key), serialize_value(value)?)
}

pub fn get<V: SszReadDefault>(
    database: &Database,
    key: impl core::fmt::Display,
) -> Result<Option<V>> {
    database
        .get(serialize_key(key))?
        .map(V::from_ssz_default)
        .transpose()
        .map_err(Into::into)
}

fn serialize_key(key: impl core::fmt::Display) -> String {
    key.to_string()
}

fn serialize_value(value: impl SszWrite) -> Result<Vec<u8>> {
    value.to_ssz().map_err(Into::into)
}

fn serialize_raw(key: impl core::fmt::Display, value: impl SszWrite) -> Result<(String, Vec<u8>)> {
    Ok((serialize_key(key), serialize_value(value)?))
}

pub fn serialize(key: impl core::fmt::Display, value: impl SszWrite) -> Result<(String, Vec<u8>)> {
    let value = serialize_value(value)?;
    let compressed = snap::raw::Encoder::new().compress_vec(&value)?;

    Ok((serialize_key(key), compressed))
}

pub fn serialize_zstd(
    key: impl core::fmt::Display,
    value: impl SszWrite,
    compression_level: i32,
) -> Result<(String, Vec<u8>)> {
    let value = serialize_value(value)?;
    let compressed_value = zstd::encode_all(value.as_slice(), compression_level)?;

    Ok((serialize_key(key), compressed_value))
}

// Add more info when needed
pub fn print_beacon_database_info(database: &Database) -> Result<()> {
    info!("beacon_fork_choice database info:");

    match database
        .iterator_ascending_raw(SlotColumnId(0, H256::zero(), 0).to_string()..)?
        .next()
        .transpose()?
    {
        Some((key_bytes, value_bytes)) if SlotColumnId::has_prefix(&key_bytes) => {
            info!(
                "oldest data column entry: {:?}",
                DataColumnIdentifier::from_ssz_default(decompress(&value_bytes)?)?,
            );
        }
        _ => info!("no data column entries found"),
    }

    Ok(())
}

fn prepare_state<P: Preset>(
    mut state: Arc<BeaconState<P>>,
    finalized_validator_list_len: usize,
) -> Arc<BeaconState<P>> {
    let state_mut = state.make_mut();

    // pubkeys never change, so they can be restored later from the finalized
    // validator list; zero out the leading (finalized) prefix to shrink the
    // serialized state.
    state_mut
        .validators_mut()
        .clear_pubkeys(finalized_validator_list_len);

    state
}

#[cfg(test)]
mod tests {
    use bls::PublicKeyBytes;
    use bytesize::ByteSize;
    use database::DatabaseMode;
    use ssz::SszHash as _;
    use tempfile::TempDir;
    use try_from_iterator::TryFromIterator as _;
    use types::{
        Validators,
        phase0::{
            beacon_state::BeaconState as Phase0BeaconState,
            containers::{
                BeaconBlock as Phase0BeaconBlock, SignedBeaconBlock as Phase0SignedBeaconBlock,
                Validator,
            },
        },
        preset::Mainnet,
    };

    use super::*;

    fn block_with_slot(slot: Slot) -> SignedBeaconBlock<Mainnet> {
        SignedBeaconBlock::<Mainnet>::Phase0(Phase0SignedBeaconBlock {
            message: Phase0BeaconBlock {
                slot,
                ..Phase0BeaconBlock::default()
            }
            .into(),
            ..Phase0SignedBeaconBlock::default()
        })
    }

    fn storage_with_hierarchy(
        directory: &TempDir,
        exponents: impl IntoIterator<Item = u8>,
    ) -> Result<Storage<Mainnet>> {
        let database = Database::persistent(
            "test_db",
            directory,
            ByteSize::mib(10),
            DatabaseMode::ReadWrite,
            None,
        )?;

        let hierarchy = Hierarchy::new(exponents)?;
        let cache_sizes = vec![0; hierarchy.depth()];

        Ok(Storage::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            StorageMode::default(),
            StateStorageConfig {
                hierarchy,
                cache_sizes,
                ..StateStorageConfig::default()
            },
        ))
    }

    fn load_anchor(storage: &Storage<Mainnet>, state: Arc<BeaconState<Mainnet>>) -> Result<()> {
        futures::executor::block_on(storage.load(
            &Client::new(),
            StateLoadStrategy::Anchor {
                block: Arc::new(block_with_slot(state.slot())),
                state,
            },
        ))?;

        Ok(())
    }

    #[test]
    fn loading_records_the_configured_hierarchy_in_a_fresh_database() -> Result<()> {
        let directory = TempDir::new()?;
        let storage = storage_with_hierarchy(&directory, [11, 9, 5])?;

        assert_eq!(
            storage
                .get::<Hierarchy>(StateHierarchyKey)?
                .map(|hierarchy| hierarchy.to_string()),
            None,
        );

        load_anchor(&storage, state_with_slot(0))?;

        let stored = storage
            .get::<Hierarchy>(StateHierarchyKey)?
            .expect("the hierarchy must be recorded");

        assert_eq!(stored.exponents(), [11, 9, 5]);

        Ok(())
    }

    #[test]
    fn loading_accepts_a_matching_hierarchy_repeatedly() -> Result<()> {
        let directory = TempDir::new()?;

        // LMDB refuses a second concurrent open of the same environment, so
        // every reopen has to outlive the previous one.
        for _ in 0..3 {
            let storage = storage_with_hierarchy(&directory, [11, 9, 5])?;
            load_anchor(&storage, state_with_slot(0))?;
        }

        let storage = storage_with_hierarchy(&directory, [11, 9, 5])?;

        assert_eq!(
            storage
                .get::<Hierarchy>(StateHierarchyKey)?
                .expect("the hierarchy must be recorded")
                .exponents(),
            [11, 9, 5],
        );

        Ok(())
    }

    #[test]
    fn loading_over_a_database_with_a_different_anchor_succeeds() -> Result<()> {
        let directory = TempDir::new()?;

        {
            let storage = storage_with_hierarchy(&directory, [11, 9, 5])?;
            load_anchor(&storage, state_with_slot(0))?;
        }

        let storage = storage_with_hierarchy(&directory, [11, 9, 5])?;
        let block = Arc::new(block_with_slot(2048));
        let block_root = block.message().hash_tree_root();

        futures::executor::block_on(storage.load(
            &Client::new(),
            StateLoadStrategy::Anchor {
                block,
                state: state_with_slot(2048),
            },
        ))?;

        // States written under the old anchor stay where they are, so the recorded
        // anchor keeps describing them.
        assert_eq!(storage.get::<Slot>(StateAnchorKey)?, Some(0));

        assert!(storage.state_key_by_block_root(block_root)?.is_some());

        Ok(())
    }

    #[test]
    fn loading_rejects_a_mismatched_hierarchy() -> Result<()> {
        let directory = TempDir::new()?;

        {
            let storage = storage_with_hierarchy(&directory, [11, 9, 5])?;
            load_anchor(&storage, state_with_slot(0))?;
        }

        let storage = storage_with_hierarchy(&directory, [13, 9, 5])?;

        let error = load_anchor(&storage, state_with_slot(0))
            .expect_err("a mismatched hierarchy must be rejected");

        assert_eq!(
            error.to_string(),
            "database was written with state hierarchy 11,9,5, \
             but 13,9,5 is configured; \
             pass --state-hierarchy 11,9,5 to keep using this database \
             or --force-reset-beacon-db to discard it",
        );

        assert!(matches!(
            error.downcast_ref::<Error>(),
            Some(Error::StateHierarchyMismatch { .. }),
        ));

        // The stored hierarchy must survive a rejected open.
        assert_eq!(
            storage
                .get::<Hierarchy>(StateHierarchyKey)?
                .expect("the hierarchy must be recorded")
                .exponents(),
            [11, 9, 5],
        );

        Ok(())
    }

    #[test]
    fn test_prune_unfinalized_blocks() -> Result<()> {
        let database = Database::persistent(
            "test_db",
            TempDir::new()?,
            ByteSize::mib(10),
            DatabaseMode::ReadWrite,
            None,
        )?;

        let block_1 = block_with_slot(1);
        let block_3 = block_with_slot(3);
        let block_5 = block_with_slot(5);
        let block_6 = block_with_slot(6);
        let block_10 = block_with_slot(10);

        database.put_batch_raw(vec![
            // Slot 1
            serialize(BlockRootBySlot(1), H256::repeat_byte(1))?,
            serialize(FinalizedBlockByRoot(H256::repeat_byte(1)), &block_1)?,
            serialize(SlotByStateRoot(H256::repeat_byte(1)), 1_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(1)),
                1_u64,
            )?,
            // Slot 3
            serialize(BlockRootBySlot(3), H256::repeat_byte(3))?,
            serialize(FinalizedBlockByRoot(H256::repeat_byte(3)), &block_3)?,
            // Slot 5
            serialize(BlockRootBySlot(5), H256::repeat_byte(5))?,
            serialize(UnfinalizedBlockByRoot(H256::repeat_byte(5)), &block_5)?,
            //Slot 6
            serialize(BlockRootBySlot(6), H256::repeat_byte(6))?,
            serialize(FinalizedBlockByRoot(H256::repeat_byte(6)), &block_6)?,
            serialize(UnfinalizedBlockByRoot(H256::repeat_byte(6)), &block_6)?,
            serialize(SlotByStateRoot(H256::repeat_byte(6)), 6_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(6)),
                6_u64,
            )?,
            // Slot 10, test case that "10" < "3" is not true
            serialize(BlockRootBySlot(10), H256::repeat_byte(10))?,
            serialize(UnfinalizedBlockByRoot(H256::repeat_byte(10)), &block_10)?,
            serialize(SlotByStateRoot(H256::repeat_byte(10)), 10_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(10)),
                10_u64,
            )?,
        ])?;

        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        // slots 1, 3, 10
        assert_eq!(storage.finalized_block_count()?, 3);
        // slots 1, 3, 5, 6, 10
        assert_eq!(storage.unfinalized_block_count()?, 3);
        assert_eq!(storage.block_root_by_slot_count()?, 5);
        assert_eq!(storage.slot_by_state_root_count()?, 3);
        assert_eq!(storage.state_count()?, 3);

        storage.prune_unfinalized_blocks(6)?;

        // slots 1, 3, 10
        assert_eq!(storage.finalized_block_count()?, 3);
        // slots 10
        assert_eq!(storage.unfinalized_block_count()?, 1);
        assert_eq!(storage.block_root_by_slot_count()?, 4);
        assert_eq!(storage.slot_by_state_root_count()?, 3);
        assert_eq!(storage.state_count()?, 3);

        Ok(())
    }

    #[test]
    fn test_prune_old_blocks_and_states() -> Result<()> {
        let database = Database::persistent(
            "test_db",
            TempDir::new()?,
            ByteSize::mib(10),
            DatabaseMode::ReadWrite,
            None,
        )?;

        let block = SignedBeaconBlock::<Mainnet>::Phase0(Phase0SignedBeaconBlock::default());

        database.put_batch_raw(vec![
            // Slot 1
            serialize(BlockRootBySlot(1), H256::repeat_byte(1))?,
            serialize(FinalizedBlockByRoot(H256::repeat_byte(1)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(1)), 1_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(1)),
                1_u64,
            )?,
            // Slot 3
            serialize(BlockRootBySlot(3), H256::repeat_byte(3))?,
            serialize(FinalizedBlockByRoot(H256::repeat_byte(3)), &block)?,
            // Slot 5
            serialize(BlockRootBySlot(5), H256::repeat_byte(5))?,
            serialize(UnfinalizedBlockByRoot(H256::repeat_byte(5)), &block)?,
            //Slot 6
            serialize(BlockRootBySlot(6), H256::repeat_byte(6))?,
            serialize(UnfinalizedBlockByRoot(H256::repeat_byte(6)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(6)), 6_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(6)),
                6_u64,
            )?,
            // Slot 10, test case that "10" < "3" is not true
            serialize(BlockRootBySlot(10), H256::repeat_byte(10))?,
            serialize(UnfinalizedBlockByRoot(H256::repeat_byte(10)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(10)), 10_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(10)),
                10_u64,
            )?,
        ])?;

        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        assert_eq!(storage.finalized_block_count()?, 2);
        assert_eq!(storage.unfinalized_block_count()?, 3);
        assert_eq!(storage.block_root_by_slot_count()?, 5);
        assert_eq!(storage.slot_by_state_root_count()?, 3);
        assert_eq!(storage.state_count()?, 3);

        let retained_slots = storage.retained_prune_slots(5);

        storage.prune_old_blocks_and_states(5, &retained_slots)?;

        assert_eq!(storage.finalized_block_count()?, 0);
        assert_eq!(storage.unfinalized_block_count()?, 3);
        assert_eq!(storage.block_root_by_slot_count()?, 3);
        assert_eq!(storage.slot_by_state_root_count()?, 3);
        assert_eq!(storage.state_count()?, 2);

        storage.prune_old_state_roots(5, &retained_slots)?;

        assert_eq!(storage.slot_by_state_root_count()?, 2);

        Ok(())
    }

    #[test]
    fn test_prune_keeps_the_boundary_state() -> Result<()> {
        let database = Database::persistent(
            "test_db",
            TempDir::new()?,
            ByteSize::mib(10),
            DatabaseMode::ReadWrite,
            None,
        )?;

        let block = SignedBeaconBlock::<Mainnet>::Phase0(Phase0SignedBeaconBlock::default());

        database.put_batch_raw(vec![
            // Slot 0 - the anchor, a hierarchy node below the boundary.
            serialize(BlockRootBySlot(0), H256::repeat_byte(0))?,
            serialize(FinalizedBlockByRoot(H256::repeat_byte(0)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(0)), 0_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(0)),
                0_u64,
            )?,
            // Slot 8 - not a hierarchy node.
            serialize(BlockRootBySlot(8), H256::repeat_byte(8))?,
            serialize(FinalizedBlockByRoot(H256::repeat_byte(8)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(8)), 8_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(8)),
                8_u64,
            )?,
            // Slot 32 - the prune boundary itself and a hierarchy node.
            serialize(BlockRootBySlot(32), H256::repeat_byte(32))?,
            serialize(FinalizedBlockByRoot(H256::repeat_byte(32)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(32)), 32_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(32)),
                32_u64,
            )?,
        ])?;

        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        let retained_slots = storage.retained_prune_slots(33);

        assert!(retained_slots.contains(&0));
        assert!(retained_slots.contains(&32));

        storage.prune_old_blocks_and_states(33, &retained_slots)?;
        storage.prune_old_state_roots(33, &retained_slots)?;

        assert_eq!(storage.block_root_by_slot(32)?, Some(H256::repeat_byte(32)),);
        assert_eq!(storage.slot_by_state_root(H256::repeat_byte(32))?, Some(32));
        assert_eq!(storage.block_root_by_slot(0)?, Some(H256::zero()));
        assert_eq!(storage.slot_by_state_root(H256::repeat_byte(0))?, Some(0));

        // Slot 8 is not a hierarchy node, so nothing is delta-encoded against
        // it and it is pruned as usual.
        assert_eq!(storage.block_root_by_slot(8)?, None);
        assert_eq!(storage.slot_by_state_root(H256::repeat_byte(8))?, None);

        assert_eq!(storage.finalized_block_count()?, 2);
        assert_eq!(storage.block_root_by_slot_count()?, 2);
        assert_eq!(storage.slot_by_state_root_count()?, 2);
        assert_eq!(storage.state_count()?, 2);

        Ok(())
    }

    /// Retained hierarchy nodes keep their states, but the blocks between them
    /// are pruned, so replaying from one of them would silently skip real
    /// blocks. Reads below the prune boundary must fail instead.
    #[test]
    fn stored_state_refuses_a_retained_state_below_the_prune_boundary() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let anchor_root = H256::repeat_byte(1);
        let pruned_root = H256::repeat_byte(4);
        let block = SignedBeaconBlock::<Mainnet>::Phase0(Phase0SignedBeaconBlock::default());

        storage.database.put_batch_raw(vec![
            // Slot 0 - a hierarchy node, retained by pruning.
            serialize(BlockRootBySlot(0), anchor_root)?,
            serialize(FinalizedBlockByRoot(anchor_root), &block)?,
            // Slot 4 - an ordinary block between the node and slot 8.
            serialize(BlockRootBySlot(4), pruned_root)?,
            serialize(FinalizedBlockByRoot(pruned_root), &block)?,
        ])?;

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        storage.append_finalized_states(
            [(0, anchor_root, state_with_slot(0))],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        assert!(
            matches!(
                storage.load_state_by_iteration(8, Some(finalized_validators), false)?,
                OptionalStateStorage::Full(_),
            ),
            "before pruning the whole chain up to slot 8 is on disk",
        );

        let retained_slots = storage.retained_prune_slots(33);

        assert!(retained_slots.contains(&0));

        storage.prune_old_blocks_and_states(33, &retained_slots)?;

        assert_eq!(storage.block_root_by_slot(4)?, None);
        assert!(
            storage
                .state_by_block_root(anchor_root, Some(finalized_validators))?
                .is_some()
        );

        assert!(
            storage
                .stored_state(8, Some(finalized_validators))?
                .is_none(),
            "the block at slot 4 is gone, so the retained state at slot 0 \
             cannot be replayed to slot 8",
        );

        Ok(())
    }

    /// A sub-epoch deepest layer persists states in the middle of an epoch. Those are readable
    /// like any other, but the fork choice anchor still has to sit at an epoch start, so the
    /// anchor search walks past them.
    #[test]
    fn a_mid_epoch_hierarchy_state_is_readable_but_is_never_picked_as_an_anchor() -> Result<()> {
        let directory = TempDir::new()?;
        let storage = storage_with_hierarchy(&directory, [9, 3])?;

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let epoch_start_root = H256::repeat_byte(1);
        let mid_epoch_root = H256::repeat_byte(2);

        storage.database.put_batch_raw(vec![
            serialize(BlockRootBySlot(0), epoch_start_root)?,
            serialize(FinalizedBlockByRoot(epoch_start_root), block_with_slot(0))?,
            serialize(BlockRootBySlot(8), mid_epoch_root)?,
            serialize(FinalizedBlockByRoot(mid_epoch_root), block_with_slot(8))?,
        ])?;

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        storage.append_finalized_states(
            [
                (0, epoch_start_root, state_with_slot(0)),
                (8, mid_epoch_root, state_with_slot(8)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        assert_eq!(
            storage
                .stored_state(8, Some(finalized_validators))?
                .map(|state| state.slot()),
            Some(8),
        );

        let OptionalStateStorage::Full((anchor_state, _, _)) =
            storage.load_state_by_iteration(8, Some(finalized_validators), true)?
        else {
            panic!("the state at slot 0 must be found");
        };

        assert_eq!(anchor_state.slot(), 0);

        let OptionalStateStorage::Full((nearest_state, _, _)) =
            storage.load_state_by_iteration(8, Some(finalized_validators), false)?
        else {
            panic!("the state at slot 8 must be found");
        };

        assert_eq!(nearest_state.slot(), 8);

        Ok(())
    }

    #[test]
    #[expect(clippy::similar_names)]
    fn test_prune_old_blob_sidecars() -> Result<()> {
        let database = Database::persistent(
            "test_db",
            TempDir::new()?,
            ByteSize::mib(10),
            DatabaseMode::ReadWrite,
            None,
        )?;

        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        let blob_id_0 = BlobIdentifier {
            block_root: H256::zero(),
            index: 0,
        };

        // slot 5
        let blob_id_5 = BlobIdentifier {
            block_root: H256::zero(),
            index: 1,
        };

        let mut blob_sidecar_5 = BlobSidecar::default();
        blob_sidecar_5.signed_block_header.message.slot = 5;

        // slot 10
        let blob_id_10 = BlobIdentifier {
            block_root: H256::zero(),
            index: 2,
        };

        let mut blob_sidecar_10 = BlobSidecar::default();
        blob_sidecar_10.signed_block_header.message.slot = 10;

        let blob_sidecars = vec![
            BlobSidecarWithId {
                blob_sidecar: Arc::new(BlobSidecar::default()),
                blob_id: blob_id_0,
            },
            BlobSidecarWithId {
                blob_sidecar: Arc::new(blob_sidecar_5),
                blob_id: blob_id_5,
            },
            BlobSidecarWithId {
                blob_sidecar: Arc::new(blob_sidecar_10),
                blob_id: blob_id_10,
            },
        ];

        let persisted = storage.append_blob_sidecars(blob_sidecars)?;

        assert_eq!(persisted, vec![blob_id_0, blob_id_5, blob_id_10]);
        assert_eq!(storage.slot_by_blob_id_count()?, 3);
        assert_eq!(storage.blob_sidecar_by_blob_id_count()?, 3);

        storage.prune_old_blob_sidecars(6)?;

        assert_eq!(storage.slot_by_blob_id_count()?, 1);
        assert_eq!(storage.blob_sidecar_by_blob_id_count()?, 1);

        Ok(())
    }

    #[test]
    fn test_append_execution_payload_envelopes() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
        );
        let envelope = Arc::new(SignedExecutionPayloadEnvelope::default());
        let block_root = envelope.block_root();

        assert_eq!(
            storage.append_execution_payload_envelopes([envelope.clone_arc()])?,
            [block_root],
        );
        assert_eq!(
            storage.execution_payload_envelope_by_root(block_root)?,
            Some(envelope),
        );

        Ok(())
    }

    fn state_with_slot(slot: Slot) -> Arc<BeaconState<Mainnet>> {
        Arc::new(BeaconState::Phase0(
            Phase0BeaconState {
                slot,
                ..Phase0BeaconState::default()
            }
            .into(),
        ))
    }

    #[test]
    fn append_finalized_state_resolves_the_delta_parent_from_the_spine() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        let anchor_block_root = H256::repeat_byte(1);
        let anchor_state = state_with_slot(0);

        storage.forward_spine().insert(
            0,
            StateByBlockRoot::snapshot(anchor_block_root),
            anchor_state.clone_arc(),
        );

        let block_root = H256::repeat_byte(2);
        let state = state_with_slot(32);
        let validators = state.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        // The database is empty, so the only place the parent can come from is
        // the spine.
        let to_delete = storage.append_finalized_state(
            state.clone_arc(),
            32,
            block_root,
            0,
            validators,
            storage.forward_spine(),
            &mut batch,
            &mut update_finalized_validators,
        )?;

        assert!(to_delete.is_none());

        let [(key, _)] = batch.as_slice() else {
            panic!("exactly one state must have been written, got {batch:?}");
        };

        let key = StateByBlockRoot::try_from(key.as_bytes())?;

        assert_eq!(key.block_root, block_root);
        assert_eq!(key.parents, vec![anchor_block_root]);

        // The state just written is the one later states delta-encode against.
        assert!(storage.forward_spine().get(32).is_some());

        Ok(())
    }

    #[test]
    fn append_finalized_state_skips_a_leaf_with_an_unseeded_spine() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        let state = state_with_slot(32);
        let validators = state.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let to_delete = storage.append_finalized_state(
            state.clone_arc(),
            32,
            H256::repeat_byte(2),
            0,
            validators,
            storage.forward_spine(),
            &mut batch,
            &mut update_finalized_validators,
        )?;

        assert!(to_delete.is_none());
        assert!(batch.is_empty());
        assert!(storage.forward_spine().get(32).is_none());

        Ok(())
    }

    #[test]
    fn append_finalized_state_keeps_a_leaf_snapshot_it_cannot_replace() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        let state = state_with_slot(32);
        let validators = state.validators();
        let block_root = H256::repeat_byte(2);

        // Slot 32 is a leaf whose hierarchy parent exists but is not stored, so the state cannot
        // be re-encoded as a delta. A snapshot of it is already on disk, as the unloading of
        // unfinalized states leaves behind.
        assert!(storage.hierarchy.is_leaf::<Mainnet>(&storage.config, 0, 32));

        let snapshot_key = StateByBlockRoot::snapshot(block_root);

        storage.database.put_batch_raw(vec![serialize_zstd(
            &snapshot_key,
            prepare_state(state.clone_arc(), validators.len_usize()),
            storage.compression_level,
        )?])?;

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let to_delete = storage.append_finalized_state(
            state.clone_arc(),
            32,
            block_root,
            0,
            validators,
            storage.forward_spine(),
            &mut batch,
            &mut update_finalized_validators,
        )?;

        // Nothing was written, so nothing may be deleted either. Returning the snapshot key here
        // would have the caller drop the only copy of the state.
        assert!(batch.is_empty());
        assert!(to_delete.is_none());

        assert!(
            storage
                .database
                .get_raw(snapshot_key.to_string())?
                .is_some(),
        );

        Ok(())
    }

    #[test]
    fn append_finalized_states_commits_as_the_run_progresses() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        storage.forward_spine().insert(
            0,
            StateByBlockRoot::snapshot(H256::repeat_byte(1)),
            state_with_slot(0),
        );

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        // Every one of these slots is a hierarchy slot whose parent is the
        // anchor already seeded into the spine, so each yields exactly one
        // written state.
        let total = 2 * ARCHIVED_STATES_BEFORE_FLUSH + 2;

        let states = (1..=total).map(|index| {
            let committed =
                (index - 1) / ARCHIVED_STATES_BEFORE_FLUSH * ARCHIVED_STATES_BEFORE_FLUSH;

            assert_eq!(
                storage
                    .state_count()
                    .expect("counting states in an in-memory database does not fail"),
                usize::try_from(committed).expect("state counts in tests are small"),
                "states appended before slot {index} must already be committed",
            );

            // The forward spine must never name a state that is not committed
            // yet, or a failure here would leave later states delta-encoded
            // against a parent that was never written.
            assert!(
                storage.forward_spine().get((index - 1) * 32).is_none() || committed >= index - 1,
                "the forward spine tracks slot {} before it is committed",
                (index - 1) * 32,
            );

            let slot = index * 32;

            (slot, H256::from_low_u64_be(index), state_with_slot(slot))
        });

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        storage.append_finalized_states(
            states,
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        assert!(batch.is_empty());
        assert_eq!(
            storage.state_count()?,
            usize::try_from(total).expect("state counts in tests are small"),
        );

        Ok(())
    }

    #[test]
    fn prune_old_blocks_and_states_forgets_only_the_spine_states_it_deleted() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        let spine = storage.forward_spine();

        spine.insert(
            0,
            StateByBlockRoot::snapshot(H256::repeat_byte(1)),
            state_with_slot(0),
        );

        spine.insert(
            512,
            StateByBlockRoot::snapshot(H256::repeat_byte(2)),
            state_with_slot(512),
        );

        spine.insert(
            544,
            StateByBlockRoot::snapshot(H256::repeat_byte(3)),
            state_with_slot(544),
        );

        // 0 is below the boundary but retained, 512 is below it and deleted,
        // 544 is above it.
        storage.prune_old_blocks_and_states(521, &[0])?;

        assert!(spine.get(0).is_some());
        assert!(spine.get(512).is_none());
        assert!(spine.get(544).is_some());

        Ok(())
    }

    /// Writes a snapshot and a delta against it, then reads the delta back
    /// from the database with the spine cleared, so the reconstruction path
    /// runs for real.
    fn append_and_read_back_states() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        // Slot 512 has no ancestor on disk and is not a leaf, so it is written
        // as a snapshot; slot 544 then delta-encodes against it.
        let snapshot_root = H256::repeat_byte(1);
        let delta_root = H256::repeat_byte(2);

        storage.append_finalized_states(
            [
                (512, snapshot_root, state_with_slot(512)),
                (544, delta_root, state_with_slot(544)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        storage.forward_spine().clear();

        let (key, state) = storage
            .state_with_key_by_block_root(delta_root, Some(finalized_validators))?
            .expect("the delta-encoded state must be readable");

        assert_eq!(key.parents, vec![snapshot_root]);
        assert_eq!(state.slot(), 544);

        Ok(())
    }

    #[test]
    fn appends_and_reads_back_states() -> Result<()> {
        append_and_read_back_states()
    }

    /// The spine short-circuits the delta-chain walk, bypassing both the
    /// reconstruction and the pubkey restoration the disk path performs, so it
    /// has to return exactly what the disk path does.
    #[test]
    fn a_warm_spine_and_a_cleared_one_reconstruct_the_same_state() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let snapshot_root = H256::repeat_byte(1);
        let delta_root = H256::repeat_byte(2);

        storage.append_finalized_states(
            [
                (512, snapshot_root, state_with_slot(512)),
                (544, delta_root, state_with_slot(544)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        assert!(storage.forward_spine().get(544).is_some());

        let (warm_key, warm_state) = storage
            .state_with_key_by_block_root(delta_root, Some(finalized_validators))?
            .expect("the delta-encoded state must be readable from the spine");

        // The intermediate frame only: the leaf is resolved from disk, but its
        // parent is still short-circuited.
        storage.forward_spine().remove_pruned(544, &[512]);

        let (partial_key, partial_state) = storage
            .state_with_key_by_block_root(delta_root, Some(finalized_validators))?
            .expect("the delta-encoded state must be readable through the spine parent");

        storage.forward_spine().clear();

        let (cold_key, cold_state) = storage
            .state_with_key_by_block_root(delta_root, Some(finalized_validators))?
            .expect("the delta-encoded state must be readable from disk");

        assert_eq!(warm_key.to_string(), cold_key.to_string());
        assert_eq!(partial_key.to_string(), cold_key.to_string());
        assert_eq!(warm_state.to_ssz()?, cold_state.to_ssz()?);
        assert_eq!(partial_state.to_ssz()?, cold_state.to_ssz()?);

        Ok(())
    }

    /// Anchor 0, 512 and 544 are consecutive hierarchy ancestors under the
    /// default hierarchy, so appending them in this order yields a snapshot
    /// followed by two deltas.
    fn storage_for_chain_reads() -> Storage<Mainnet> {
        Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig::default(),
        )
    }

    fn state_with_validators(
        slot: Slot,
        count: u8,
        balance_offset: u64,
    ) -> Arc<BeaconState<Mainnet>> {
        let validator = |index: u8| Validator {
            pubkey: PublicKeyBytes::repeat_byte(index.saturating_add(1)),
            withdrawal_credentials: H256::repeat_byte(index),
            effective_balance: 32_000_000_000_u64
                .saturating_add(index.into())
                .saturating_add(balance_offset),
            slashed: false,
            activation_eligibility_epoch: index.into(),
            activation_epoch: index.into(),
            exit_epoch: u64::MAX,
            withdrawable_epoch: u64::MAX,
        };

        Arc::new(BeaconState::Phase0(
            Phase0BeaconState {
                slot,
                validators: Validators::<Mainnet>::try_from_iter((0..count).map(validator))
                    .expect("the registry limit is far above the test validator count"),
                ..Phase0BeaconState::default()
            }
            .into(),
        ))
    }

    #[test]
    fn a_delta_chain_of_states_with_validators_round_trips() -> Result<()> {
        // Snapshots are written with their leading pubkeys zeroed and restored on read, and the
        // validator registry is the only field encoded by `ValidatorListPatch`. Neither is
        // exercised by the default states the other chain tests use, which hold no validators.
        let storage = storage_for_chain_reads();

        let validator_source = state_with_validators(0, 6, 0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        let anchor_state = state_with_validators(0, 6, 0);
        let parent_state = state_with_validators(512, 6, 1_000);
        let child_state = state_with_validators(544, 6, 2_000);

        storage.append_finalized_states(
            [
                (0, anchor_root, anchor_state.clone_arc()),
                (512, parent_root, parent_state.clone_arc()),
                (544, child_root, child_state.clone_arc()),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        storage.clear_caches();

        for (block_root, expected) in [
            (anchor_root, &anchor_state),
            (parent_root, &parent_state),
            (child_root, &child_state),
        ] {
            let (_, state) = storage
                .state_with_key_by_block_root(block_root, Some(finalized_validators))?
                .expect("every state in the chain must be readable");

            assert_eq!(state.to_ssz()?, expected.to_ssz()?);

            // A state read back from disk carries no cached root, so this hashes its contents.
            assert_eq!(state.hash_tree_root(), expected.hash_tree_root());

            for index in 0..finalized_validators.len_u64() {
                assert_eq!(
                    state.validators().pubkey(index)?,
                    finalized_validators.pubkey(index)?,
                    "pubkeys stripped before the write must be restored on the read",
                );
            }
        }

        Ok(())
    }

    #[test]
    fn a_delta_chain_that_appends_validators_restores_their_pubkeys() -> Result<()> {
        // `ValidatorListPatch` encodes an appended validator without its pubkey, so a delta puts
        // one into the reconstructed list with a zero pubkey. Restoring only on the decoded
        // snapshot would leave every validator appended further down the chain zeroed, and the
        // round-trip test above cannot catch it because it holds the validator count fixed.
        let storage = storage_for_chain_reads();

        let validator_source = state_with_validators(0, 8, 0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        let anchor_state = state_with_validators(0, 6, 0);
        let parent_state = state_with_validators(512, 7, 1_000);
        let child_state = state_with_validators(544, 8, 2_000);

        storage.append_finalized_states(
            [
                (0, anchor_root, anchor_state.clone_arc()),
                (512, parent_root, parent_state.clone_arc()),
                (544, child_root, child_state.clone_arc()),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        storage.clear_caches();

        for (block_root, expected) in [
            (anchor_root, &anchor_state),
            (parent_root, &parent_state),
            (child_root, &child_state),
        ] {
            let (_, state) = storage
                .state_with_key_by_block_root(block_root, Some(finalized_validators))?
                .expect("every state in the chain must be readable");

            assert_eq!(state.to_ssz()?, expected.to_ssz()?);
            assert_eq!(state.hash_tree_root(), expected.hash_tree_root());

            for index in 0..state.validators().len_u64() {
                assert_eq!(
                    state.validators().pubkey(index)?,
                    finalized_validators.pubkey(index)?,
                    "a validator appended by a delta must have its pubkey restored too",
                );
            }
        }

        Ok(())
    }

    #[test]
    fn a_cached_frame_reached_through_a_delta_still_restores_pubkeys() -> Result<()> {
        // A frame is only cached once its pubkeys are correct, so a read served from the frame
        // cache must come back with them too - restoring is skipped entirely on that path.
        let storage = storage_for_chain_reads();

        let validator_source = state_with_validators(0, 8, 0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        let anchor_state = state_with_validators(0, 6, 0);
        let parent_state = state_with_validators(512, 7, 1_000);
        let child_state = state_with_validators(544, 8, 2_000);

        storage.append_finalized_states(
            [
                (0, anchor_root, anchor_state.clone_arc()),
                (512, parent_root, parent_state.clone_arc()),
                (544, child_root, child_state.clone_arc()),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        storage.clear_caches();

        // The first read populates the frame cache for every layer of the chain. Hashing what it
        // returns also warms the merkle roots of the frames it was reconstructed from, because
        // those frames share their cache nodes with it - which is what makes the tail restoration
        // below worth doing in the first place.
        let (_, first) = storage
            .state_with_key_by_block_root(child_root, Some(finalized_validators))?
            .expect("the child state must be readable");

        assert_eq!(first.hash_tree_root(), child_state.hash_tree_root());

        let (_, state) = storage
            .state_with_key_by_block_root(child_root, Some(finalized_validators))?
            .expect("the child state must be readable from the frame cache too");

        assert_eq!(state.to_ssz()?, child_state.to_ssz()?);
        assert_eq!(state.hash_tree_root(), child_state.hash_tree_root());

        for index in 0..state.validators().len_u64() {
            assert_eq!(
                state.validators().pubkey(index)?,
                finalized_validators.pubkey(index)?,
                "a read served from the frame cache must restore pubkeys as well",
            );
        }

        Ok(())
    }

    #[test]
    fn state_keys_round_trip_through_their_string_form() -> Result<()> {
        // The delta chain topology lives entirely in the key, and the walk fetches each row's
        // value by rendering the parsed key back into a string, so the two must agree exactly.
        let first = H256::repeat_byte(1);
        let second = H256::repeat_byte(2);
        let third = H256::repeat_byte(3);

        for key in [
            StateByBlockRoot::snapshot(first),
            StateByBlockRoot::legacy_snapshot(first),
            StateByBlockRoot::snapshot(first).extend_chain(second),
            StateByBlockRoot::snapshot(first)
                .extend_chain(second)
                .extend_chain(third),
        ] {
            let string = key.to_string();
            let parsed = StateByBlockRoot::try_from(string.as_bytes())?;

            assert_eq!(parsed.to_string(), string);
            assert_eq!(parsed.block_root, key.block_root);
            assert_eq!(parsed.parents, key.parents);
            assert_eq!(parsed.compression, key.compression);
        }

        Ok(())
    }

    #[test]
    fn malformed_state_keys_are_rejected() {
        let root = format!("{:x}", H256::repeat_byte(1));

        for (key, reason) in [
            (String::new(), "an empty key has no prefix"),
            (format!("x{root}"), "the prefix is wrong"),
            ("s".to_owned(), "the block root is missing"),
            (
                format!("s{root}0"),
                "the payload is not a whole number of roots",
            ),
            (format!("s{}", "g".repeat(64)), "the payload is not hex"),
            (
                format!("s{root}{root}z"),
                "a delta cannot carry the zstd suffix",
            ),
        ] {
            StateByBlockRoot::try_from(key.as_bytes()).expect_err(reason);
        }
    }

    #[test]
    fn a_snappy_compressed_state_written_by_an_older_release_is_still_readable() -> Result<()> {
        let storage = storage_for_chain_reads();

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let legacy_root = H256::repeat_byte(1);
        let child_root = H256::repeat_byte(2);

        // Older releases wrote whole states snappy-compressed, under a key with no parents and no
        // `z` suffix.
        let legacy_key = StateByBlockRoot::legacy_snapshot(legacy_root);

        storage.database.put_batch_raw(vec![serialize(
            &legacy_key,
            prepare_state(state_with_slot(0), finalized_validators.len_usize()),
        )?])?;

        let (key, state) = storage
            .state_with_key_by_block_root(legacy_root, Some(finalized_validators))?
            .expect("a legacy snapshot must still be readable");

        assert_eq!(key.compression, CompressionType::LegacySnappy);
        assert_eq!(state.to_ssz()?, state_with_slot(0).to_ssz()?);

        // A delta written by this release chains onto the legacy row like onto any other frame.
        let mut batch = vec![];
        let mut update_finalized_validators = false;
        let spine = storage.temporary_spine(0);

        spine.insert(0, legacy_key, state_with_slot(0));

        storage.append_finalized_state(
            state_with_slot(512),
            512,
            child_root,
            0,
            finalized_validators,
            &spine,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        storage.flush(
            &mut batch,
            &mut Vec::new(),
            &mut update_finalized_validators,
            finalized_validators,
        )?;

        storage.forward_spine().clear();

        let (key, state) = storage
            .state_with_key_by_block_root(child_root, Some(finalized_validators))?
            .expect("a delta against a legacy snapshot must be readable");

        assert_eq!(key.parents, vec![legacy_root]);
        assert_eq!(state.to_ssz()?, state_with_slot(512).to_ssz()?);

        Ok(())
    }

    #[test]
    fn loading_replaces_a_snappy_anchor_row_written_by_an_older_release() -> Result<()> {
        let storage = storage_for_chain_reads();

        let anchor_block = Arc::new(block_with_slot(0));
        let anchor_block_root = anchor_block.message().hash_tree_root();
        let anchor_state = state_with_slot(0);

        storage.database.put_batch_raw(vec![serialize(
            StateByBlockRoot::legacy_snapshot(anchor_block_root),
            prepare_state(
                anchor_state.clone_arc(),
                anchor_state.validators().len_usize(),
            ),
        )?])?;

        futures::executor::block_on(storage.load(
            &Client::new(),
            StateLoadStrategy::Anchor {
                block: anchor_block,
                state: anchor_state,
            },
        ))?;

        // The snappy key sorts before the zstd one, so leaving it in place would shadow the
        // snapshot just written and orphan a whole state on disk.
        let key = storage
            .state_key_by_block_root(anchor_block_root)?
            .expect("the anchor state must be stored");

        assert_eq!(key.compression, CompressionType::Zstd);
        assert!(key.parents.is_empty());

        Ok(())
    }

    #[test]
    fn a_chain_whose_frame_was_pruned_reads_as_absent_rather_than_failing() -> Result<()> {
        let storage = storage_for_chain_reads();

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let anchor_root = H256::repeat_byte(1);
        let child_root = H256::repeat_byte(2);

        storage.append_finalized_states(
            [
                (0, anchor_root, state_with_slot(0)),
                (512, child_root, state_with_slot(512)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        // Neither the spine nor the cache can stand in for the missing frame.
        storage.forward_spine().clear();
        storage
            .database
            .delete_batch(vec![StateByBlockRoot::snapshot(anchor_root).to_string()])?;

        assert!(
            storage
                .state_with_key_by_block_root(child_root, Some(finalized_validators))?
                .is_none(),
            "a chain cut short by pruning reads as absent, so callers fall back to block replay",
        );

        Ok(())
    }

    #[test]
    fn a_child_stays_readable_after_its_parent_is_re_encoded_as_a_delta() -> Result<()> {
        let storage = storage_for_chain_reads();

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        // The anchor is not on disk yet, so 512 is written as a snapshot and
        // 544 delta-encodes against it.
        storage.append_finalized_states(
            [
                (512, parent_root, state_with_slot(512)),
                (544, child_root, state_with_slot(544)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        assert_eq!(
            storage
                .state_key_by_block_root(parent_root)?
                .expect("slot 512 was just written")
                .parents,
            vec![],
        );

        storage.forward_spine().clear();

        // Now the anchor shows up, which turns the snapshot at 512 into a delta
        // against it and deletes the snapshot - leaving the chain recorded in
        // 544's key naming a row that is no longer a frame.
        storage.append_finalized_states(
            [
                (0, anchor_root, state_with_slot(0)),
                (512, parent_root, state_with_slot(512)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        assert_eq!(
            storage
                .state_key_by_block_root(parent_root)?
                .expect("slot 512 is still stored")
                .parents,
            vec![anchor_root],
        );

        storage.forward_spine().clear();

        let (key, state) = storage
            .state_with_key_by_block_root(child_root, Some(finalized_validators))?
            .expect("the child must still be readable after its parent is compacted");

        // The child's own key still names the pre-compaction chain; the walk
        // follows what is on disk instead.
        assert_eq!(key.parents, vec![parent_root]);
        assert_eq!(state.to_ssz()?, state_with_slot(544).to_ssz()?);

        Ok(())
    }

    #[test]
    fn a_snapshot_delta_delta_chain_reconstructs_from_disk() -> Result<()> {
        let storage = storage_for_chain_reads();

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        storage.append_finalized_states(
            [
                (0, anchor_root, state_with_slot(0)),
                (512, parent_root, state_with_slot(512)),
                (544, child_root, state_with_slot(544)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        storage.forward_spine().clear();

        let (key, state) = storage
            .state_with_key_by_block_root(child_root, Some(finalized_validators))?
            .expect("the deepest state in the chain must be readable");

        assert_eq!(key.parents, vec![parent_root, anchor_root]);
        assert_eq!(state.to_ssz()?, state_with_slot(544).to_ssz()?);

        // Every row is cached under the layer its own key names.
        assert!(storage.frame_cache.get(0, &anchor_root)?.is_some());
        assert!(storage.frame_cache.get(1, &parent_root)?.is_some());
        assert!(storage.frame_cache.get(2, &child_root)?.is_some());

        assert!(storage.frame_cache.get(1, &anchor_root)?.is_none());
        assert!(storage.frame_cache.get(0, &parent_root)?.is_none());

        Ok(())
    }

    #[test]
    fn cache_sizes_shorter_than_the_hierarchy_leave_the_deeper_layers_uncached() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig {
                cache_sizes: vec![5],
                ..StateStorageConfig::default()
            },
        );

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);

        storage.append_finalized_states(
            [
                (0, anchor_root, state_with_slot(0)),
                (512, parent_root, state_with_slot(512)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        storage.forward_spine().clear();

        storage
            .state_with_key_by_block_root(parent_root, Some(finalized_validators))?
            .expect("the state must be readable through the uncached layer");

        // The single configured size covers layer 0; the layers it does not name are padded with
        // zeros, which disables caching for them without making them invalid.
        assert!(storage.frame_cache.get(0, &anchor_root)?.is_some());
        assert!(storage.frame_cache.get(1, &parent_root)?.is_none());
        assert!(
            storage
                .frame_cache
                .get(Hierarchy::default().depth() - 1, &parent_root)?
                .is_none()
        );

        Ok(())
    }

    #[test]
    fn an_empty_cache_sizes_list_leaves_every_layer_uncached() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            StateStorageConfig {
                cache_sizes: vec![],
                ..StateStorageConfig::default()
            },
        );

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);

        storage.append_finalized_states(
            [
                (0, anchor_root, state_with_slot(0)),
                (512, parent_root, state_with_slot(512)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        storage.forward_spine().clear();

        let (_, state) = storage
            .state_with_key_by_block_root(parent_root, Some(finalized_validators))?
            .expect("the state must be readable with every layer uncached");

        assert_eq!(state.slot(), 512);

        for layer in 0..Hierarchy::default().depth() {
            assert!(storage.frame_cache.get(layer, &anchor_root)?.is_none());
            assert!(storage.frame_cache.get(layer, &parent_root)?.is_none());
        }

        Ok(())
    }

    #[test]
    fn a_frame_cache_hit_short_circuits_the_walk() -> Result<()> {
        let storage = storage_for_chain_reads();

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        storage.append_finalized_states(
            [
                (0, anchor_root, state_with_slot(0)),
                (512, parent_root, state_with_slot(512)),
                (544, child_root, state_with_slot(544)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        storage.forward_spine().clear();

        let expected = storage
            .state_with_key_by_block_root(child_root, Some(finalized_validators))?
            .expect("the deepest state in the chain must be readable")
            .1;

        // With the frame gone from disk, only the layer 0 cache entry the read
        // above populated can still resolve the chain.
        storage
            .database
            .delete_batch(vec![StateByBlockRoot::snapshot(anchor_root).to_string()])?;

        let (_, from_cache) = storage
            .state_with_key_by_block_root(child_root, Some(finalized_validators))?
            .expect("the frame must be served from the cache");

        assert_eq!(from_cache.to_ssz()?, expected.to_ssz()?);

        Ok(())
    }

    #[test]
    fn a_forward_spine_hit_short_circuits_the_walk() -> Result<()> {
        let storage = storage_for_chain_reads();

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let mut batch = vec![];
        let mut update_finalized_validators = false;

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        storage.append_finalized_states(
            [
                (0, anchor_root, state_with_slot(0)),
                (512, parent_root, state_with_slot(512)),
                (544, child_root, state_with_slot(544)),
            ],
            0,
            finalized_validators,
            &mut batch,
            &mut update_finalized_validators,
        )?;

        // Only the row of the queried state is left, so the frame it would be
        // reconstructed from can only come from the spine.
        storage
            .database
            .delete_batch(vec![StateByBlockRoot::snapshot(anchor_root).to_string()])?;

        let (key, state) = storage
            .state_with_key_by_block_root(child_root, Some(finalized_validators))?
            .expect("the state must be served from the spine");

        assert_eq!(key.parents, vec![parent_root, anchor_root]);
        assert_eq!(state.to_ssz()?, state_with_slot(544).to_ssz()?);

        Ok(())
    }

    #[test]
    fn a_delta_chain_that_loops_errors_instead_of_hanging() -> Result<()> {
        let storage = storage_for_chain_reads();

        let first = H256::repeat_byte(1);
        let second = H256::repeat_byte(2);

        storage.database.put_batch_raw(vec![
            (
                StateByBlockRoot::snapshot(second)
                    .extend_chain(first)
                    .to_string(),
                vec![0; 4],
            ),
            (
                StateByBlockRoot::snapshot(first)
                    .extend_chain(second)
                    .to_string(),
                vec![0; 4],
            ),
        ])?;

        let error = storage
            .state_with_key_by_block_root(first, None)
            .expect_err("a cyclic delta chain must be rejected");

        assert!(
            error.to_string().contains("delta chain revisits"),
            "unexpected error: {error}",
        );

        Ok(())
    }

    #[test]
    fn test_block_root_before_or_at_slot() -> Result<()> {
        let database = Database::in_memory();

        database.put_batch_raw(vec![
            serialize(BlockRootBySlot(2), H256::repeat_byte(2))?,
            serialize(BlockRootBySlot(6), H256::repeat_byte(6))?,
        ])?;

        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            StorageMode::default(),
            StateStorageConfig::default(),
        );

        assert_eq!(storage.block_root_before_or_at_slot(1)?, None);
        assert_eq!(
            storage.block_root_before_or_at_slot(2)?,
            Some(H256::repeat_byte(2)),
        );
        assert_eq!(
            storage.block_root_before_or_at_slot(3)?,
            Some(H256::repeat_byte(2)),
        );
        assert_eq!(
            storage.block_root_before_or_at_slot(6)?,
            Some(H256::repeat_byte(6)),
        );
        assert_eq!(
            storage.block_root_before_or_at_slot(9)?,
            Some(H256::repeat_byte(6)),
        );

        Ok(())
    }
}
