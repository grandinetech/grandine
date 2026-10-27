use core::{
    fmt, mem,
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
};
use std::{borrow::Cow, collections::HashSet, sync::Arc, thread::Builder};

use anyhow::{Context as _, Error as AnyhowError, Result, bail, ensure};
use bls::SignatureBytes;
use database::{Database, PrefixableKey, View, decompress};
use derive_more::Display;
use diff::{Patch as _, PatchConfig};
use fork_choice_store::{ChainLink, Store};
use genesis::AnchorCheckpointProvider;
use helper_functions::{accessors, deposit_signatures, misc};
use itertools::Itertools as _;
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use parking_lot::Mutex;
use pubkey_cache::PubkeyCache;
use reqwest::Client;
use ssz::{
    ReadError, Size, Ssz, SszHash as _, SszRead, SszReadDefault, SszSize, SszWrite, WriteError,
};
use std_ext::ArcExt as _;
use thiserror::Error;
use tracing::info;
use transition_functions::combined;
use typenum::Unsigned as _;
use types::{
    combined::{BeaconState, DataColumnSidecar, SignedBeaconBlock, SignedBlindedBeaconBlock},
    config::Config,
    deneb::{
        containers::{BlobIdentifier, BlobSidecar},
        primitives::BlobIndex,
    },
    fulu::{containers::DataColumnIdentifier, primitives::ColumnIndex},
    gloas::containers::{SignedBlindedExecutionPayloadEnvelope, SignedExecutionPayloadEnvelope},
    nonstandard::{
        BlobSidecarWithId, DataColumnSidecarWithId, ExecutionPayloadBody, FinalizedCheckpoint,
        Phase, PubkeyList, StorageMode,
    },
    phase0::{
        consts::{FAR_FUTURE_EPOCH, GENESIS_SLOT},
        containers::SignedBeaconBlockHeader,
        primitives::{Epoch, H256, Slot},
    },
    preset::Preset,
    redacting_url::RedactingUrl,
    storage::{
        BeaconStateFrame, BeaconStateFrameCursor, BeaconStatePatch, BeaconStatePatchCursor,
        SlotDiff, SlotDiffs,
    },
    traits::{self, BeaconBlock, BeaconState as _, SignedBeaconBlock as _, SszValidatorList},
};

use crate::{
    checkpoint_sync, frame_cache::FrameCache, hierarchy::Hierarchy, spine::Spine,
    state_storage_config::StateStorageConfig,
};

pub const DEFAULT_ZSTD_COMPRESSION_LEVEL: i32 = zstd::DEFAULT_COMPRESSION_LEVEL;
pub const MAX_DATA_COLUMN_EPOCHS_TO_PRUNE: usize = 100;

const UNSYNCED_CHECKPOINT_EPOCH_INTERVAL: u64 = 32;

// Retain archival data in memory until the number of ready beacon states
// reaches `ARCHIVED_STATES_BEFORE_FLUSH`. This approach minimizes unnecessary
// transactions and bounds how much a single archival pass holds in memory.
pub const ARCHIVED_STATES_BEFORE_FLUSH: u64 = 5;

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
    store_execution_payloads: bool,
    zstd_compression_level: i32,
    pub(crate) pubkey_cache: Arc<PubkeyCache>,
    pub(crate) hierarchy: Hierarchy,
    pub(crate) anchor_slot: Arc<AtomicU64>,
    frame_cache: FrameCache<P>,
    forward_spine: Arc<Spine<P>>,
    checkpoint_slot: Arc<Mutex<Option<Slot>>>,
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

    pub fn new(
        config: Arc<Config>,
        pubkey_cache: Arc<PubkeyCache>,
        database: Database,
        storage_mode: StorageMode,
        store_execution_payloads: bool,
        zstd_compression_level: i32,
        state_storage_config: StateStorageConfig,
    ) -> Result<Self> {
        let StateStorageConfig {
            hierarchy,
            cache_sizes,
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

        let frame_cache = FrameCache::new(cache_sizes)?;

        Ok(Self {
            config,
            pubkey_cache,
            database: Arc::new(database),
            storage_mode,
            store_execution_payloads,
            zstd_compression_level,
            hierarchy,
            anchor_slot,
            frame_cache,
            forward_spine,
            checkpoint_slot: Arc::new(Mutex::new(None)),
        })
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
    ) -> Result<(
        (
            Arc<BeaconState<P>>,
            Arc<SignedBeaconBlock<P>>,
            impl DoubleEndedIterator<Item = Result<Arc<SignedBeaconBlock<P>>>> + Send + '_,
        ),
        bool,
    )> {
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
                                anchor_block = StoredBlock::Full(block);
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
                    OptionalStateStorage::Blockless(state, _) => {
                        bail!(Error::PersistedSlotCannotContainAnchor { slot: state.slot() });
                    }
                    // State might not be found but unfinalized blocks could be present.
                    OptionalStateStorage::UnfinalizedOnly(local_unfinalized_blocks) => {
                        let FinalizedCheckpoint { block, state } =
                            anchor_checkpoint_provider.checkpoint().value;

                        anchor_block = StoredBlock::Full(block);
                        anchor_state = state;
                        unfinalized_blocks = local_unfinalized_blocks;
                    }
                    OptionalStateStorage::None => {
                        let FinalizedCheckpoint { block, state } =
                            anchor_checkpoint_provider.checkpoint().value;

                        anchor_block = StoredBlock::Full(block);
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

                anchor_block = StoredBlock::Full(block);
                anchor_state = state;
                unfinalized_blocks = Box::new(core::iter::empty());
                loaded_from_remote = true;
            }
            StateLoadStrategy::Anchor { block, state } => {
                anchor_block = StoredBlock::Full(block);
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

        let StoredBlock::Full(anchor_block) = anchor_block else {
            bail!(Error::PayloadPruned {
                block_root: anchor_block_root,
            });
        };

        info_with_peers!("loaded state at slot {anchor_slot}");

        let anchor_validators = anchor_state.validators();

        let mut batch = vec![
            serialize(
                BlockRootBySlot(anchor_slot),
                BlockRootBySlotValue::Block(anchor_block_root),
            )?,
            serialize(SlotByStateRoot(anchor_state_root), anchor_slot)?,
        ];

        self.append_finalized_block_to_batch(&mut batch, anchor_block_root, &anchor_block, true)?;

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

            let (snapshot_key, serialized_frame) =
                self.serialize_frame(anchor_block_root, &anchor_state, anchor_validators)?;

            // Any other row for this block root - a delta, or a snappy snapshot from an older
            // release - sorts before the snapshot key written below, so the reader would keep
            // finding it and never see the snapshot. Drop it in favour of the snapshot, which
            // does not depend on a chain that may have been pruned.
            if let Some(stored_key) = self.state_key_by_block_root(anchor_block_root)?
                && stored_key.to_string() != snapshot_key.to_string()
            {
                delete_batch.push(stored_key);
            }

            batch.push((serialize_key(snapshot_key), serialized_frame));
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

        let unfinalized_blocks = unfinalized_blocks.map(|result| match result? {
            StoredBlock::Full(block) => Ok(block),
            StoredBlock::Blinded(block) => bail!(Error::PayloadPruned {
                block_root: block.message().hash_tree_root(),
            }),
        });

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
    #[expect(clippy::too_many_arguments, clippy::too_many_lines)]
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
        let previous_slot = self.hierarchy.node_before_or_at::<P>(
            &self.config,
            anchor_slot,
            slot.saturating_sub(1),
        );

        let intermediate_slots = previous_slot.saturating_add(1)..slot;

        if !self.prune_storage_enabled()
            && !intermediate_slots.is_empty()
            && misc::compute_epoch_at_slot::<P>(previous_slot)
                == misc::compute_epoch_at_slot::<P>(slot.saturating_sub(1))
            && intermediate_slots.start >= self.pruned_up_to_slot()?
            && !self.contains_key(SlotDiffsBySlot(previous_slot))?
        {
            let previous_state = match spine.get(previous_slot) {
                Some((_, previous_state)) => Some(previous_state),
                None => match self.block_root_by_slot_value(previous_slot)? {
                    Some(value) => self
                        .state_with_key_by_block_root(
                            value.state_key_root(),
                            Some(finalized_validators),
                        )?
                        .map(|(_, previous_state)| previous_state),
                    None => None,
                },
            };

            if let Some(mut intermediate_state) = previous_state {
                let mut slot_diffs = vec![];
                let mut previous_root = accessors::get_block_root_at_slot(&*state, previous_slot)?;

                for intermediate_slot in intermediate_slots {
                    let base_state = intermediate_state.clone_arc();
                    let block_root = accessors::get_block_root_at_slot(&*state, intermediate_slot)?;

                    if block_root == previous_root {
                        combined::process_slots(
                            &self.config,
                            &self.pubkey_cache,
                            intermediate_state.make_mut(),
                            intermediate_slot,
                        )?;
                    } else {
                        match self
                            .finalized_block_by_root(block_root)?
                            .ok_or(Error::BlockNotFound { block_root })?
                        {
                            StoredBlock::Full(block) => combined::trusted_state_transition(
                                &self.config,
                                &self.pubkey_cache,
                                intermediate_state.make_mut(),
                                &block,
                            )?,
                            StoredBlock::Blinded(block) => {
                                combined::trusted_blinded_state_transition(
                                    &self.config,
                                    &self.pubkey_cache,
                                    intermediate_state.make_mut(),
                                    &block,
                                )?
                            }
                        }
                    }

                    previous_root = block_root;

                    slot_diffs.push(SlotDiff::diff(&base_state, &intermediate_state)?);
                }

                batch.push(serialize_raw(
                    SlotDiffsBySlot(previous_slot),
                    SlotDiffs::with_level(slot_diffs.try_into()?, self.zstd_compression_level),
                )?);
            }
        }

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

        let mut parent_state = None;

        while let Some(candidate_slot) = ancestor_slot {
            let candidate = if let Some(value) = spine.get(candidate_slot) {
                Some(value)
            } else if let Some(candidate_value) = self.block_root_by_slot_value(candidate_slot)? {
                self.state_with_key_by_block_root(
                    candidate_value.state_key_root(),
                    Some(finalized_validators),
                )?
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
                compression_level: self.zstd_compression_level,
            };

            let key = parent_key.extend_chain(block_root);
            let patch = BeaconStatePatch::diff(patch_config, &parent_state, &state)?;

            batch.push(serialize_raw(&key, patch)?);
            spine.insert(slot, key, state);

            Ok(to_replace)
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
                if self
                    .hierarchy
                    .parent_of::<P>(&self.config, anchor_slot, slot)
                    .is_some()
                {
                    warn_with_peers!(
                        "saving state in slot {slot} as a snapshot: no hierarchy ancestor is \
                            available"
                    );
                }

                let (key, serialized_frame) =
                    self.serialize_frame(block_root, &state, finalized_validators)?;

                batch.push((serialize_key(&key), serialized_frame));
                *update_finalized_validators = true;
                spine.insert(slot, key, state);
            }

            Ok(None)
        }
    }

    #[expect(clippy::too_many_lines)]
    pub(crate) fn append<'cl>(
        &self,
        unfinalized: impl Iterator<Item = &'cl ChainLink<P>>,
        finalized: impl DoubleEndedIterator<Item = &'cl ChainLink<P>>,
        store: &Store<P, Self>,
    ) -> Result<AppendedBlockSlots> {
        let mut slots = AppendedBlockSlots::default();
        let mut store_head_slot = 0;
        let mut checkpoint = None;
        let mut checkpoint_slot = None;
        let mut batch = vec![];

        let finalized_validators = store.finalized_validators();

        let unfinalized = unfinalized.zip(core::iter::repeat(false));
        let finalized = finalized.rev().zip(core::iter::repeat(true));

        let mut chain = unfinalized
            .chain(finalized)
            .filter(|(chain_link, is_finalized)| *is_finalized || chain_link.is_valid())
            .peekable();

        if let Some((chain_link, _)) = chain.peek() {
            store_head_slot = chain_link.slot();
        }

        debug_with_peers!("saving store head slot: {store_head_slot}");

        let anchor_slot = self.anchor_slot.load(Ordering::SeqCst);
        let mut update_finalized_validators = false;
        let mut states_to_save = Vec::new();
        let mut newer_finalized_slot = None;

        for (chain_link, finalized) in chain {
            let block_root = chain_link.block_root;
            let block = &chain_link.block;
            let state_slot = chain_link.slot();

            if !self.prune_storage_enabled() {
                if finalized && !self.contains_finalized_block(block_root)? {
                    slots.finalized.push(state_slot);
                    self.append_finalized_block_to_batch(
                        &mut batch,
                        block_root,
                        block,
                        checkpoint.is_none(),
                    )?;
                } else if !self.contains_unfinalized_block(block_root)? {
                    slots.unfinalized.push(state_slot);
                    batch.push(serialize(UnfinalizedBlockByRoot(block_root), block)?);
                }

                batch.push(serialize(
                    BlockRootBySlot(state_slot),
                    BlockRootBySlotValue::Block(block_root),
                )?);
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

                if checkpoint.is_none()
                    && is_epoch_start
                    && (store.is_forward_synced()
                        || misc::compute_epoch_at_slot::<P>(state_slot)
                            .is_multiple_of(UNSYNCED_CHECKPOINT_EPOCH_INTERVAL))
                {
                    info_with_peers!("saving checkpoint block & state in slot {state_slot}");

                    checkpoint = Some((block_root, block.clone_arc(), chain_link.state(store)));

                    checkpoint_slot = Some(state_slot);
                    update_finalized_validators = true;
                }

                let empty_hierarchy_slots = newer_finalized_slot
                    .replace(state_slot)
                    .filter(|_| !self.prune_storage_enabled())
                    .map(|newer_slot| {
                        (state_slot.saturating_add(1)..newer_slot)
                            .filter(|slot| {
                                self.hierarchy
                                    .contains::<P>(&self.config, anchor_slot, *slot)
                            })
                            .collect_vec()
                    })
                    .unwrap_or_default();

                let save_link_state = !self.prune_storage_enabled() && is_hierarchy_slot;

                if save_link_state {
                    info_with_peers!("saving state in slot {state_slot}");
                }

                if save_link_state || !empty_hierarchy_slots.is_empty() {
                    states_to_save.push((chain_link, save_link_state, empty_hierarchy_slots));

                    update_finalized_validators = true;
                }
            }
        }

        if update_finalized_validators {
            self.append_finalized_validator_pubkeys_to_batch(&mut batch, &*finalized_validators)?;
        }

        let mut stored_checkpoint_slot = self.checkpoint_slot.lock();

        if stored_checkpoint_slot.is_none()
            && let Some(value_bytes) = self.database.get(StateCheckpoint::<P>::KEY)?
        {
            let state_bytes = ssz::subslice(
                &value_bytes,
                StateCheckpoint::<P>::STATE_START..value_bytes.len(),
            )?;

            *stored_checkpoint_slot = Some(BeaconState::<P>::slot_from_ssz(state_bytes)?);
        }

        let checkpoint_appended = if let Some((block_root, block, state)) = checkpoint
            && stored_checkpoint_slot.is_none_or(|stored| stored < state.slot())
        {
            batch.push(serialize(
                BlockCheckpoint::<P>::KEY,
                BlockCheckpoint { block },
            )?);

            batch.push(serialize(
                StateCheckpoint::<P>::KEY,
                StateCheckpoint {
                    block_root,
                    head_slot: store_head_slot,
                    state: prepare_state(state, finalized_validators.len_usize()),
                },
            )?);

            true
        } else {
            false
        };

        self.database.put_batch_raw(batch)?;

        if checkpoint_appended {
            *stored_checkpoint_slot = checkpoint_slot;
        }

        drop(stored_checkpoint_slot);

        let states = self.materialize_finalized_states(states_to_save.into_iter().rev(), store);

        itertools::process_results(states, |states| {
            self.append_finalized_states(states, anchor_slot, &*finalized_validators)
        })??;

        if let Some(checkpoint_slot) = checkpoint_slot
            && !self.store_execution_payloads
        {
            self.prune_old_execution_payloads(checkpoint_slot)?;
        }

        Ok(slots)
    }

    fn materialize_finalized_states<'cl>(
        &'cl self,
        queued: impl Iterator<Item = (&'cl ChainLink<P>, bool, Vec<Slot>)> + 'cl,
        store: &'cl Store<P, Self>,
    ) -> impl Iterator<Item = Result<(Slot, Option<H256>, Arc<BeaconState<P>>)>> + 'cl {
        queued.flat_map(
            move |(chain_link, save_link_state, empty_hierarchy_slots)| {
                let state = chain_link.state(store);

                let link_state = save_link_state.then(|| {
                    Ok((
                        chain_link.slot(),
                        Some(chain_link.block_root),
                        state.clone_arc(),
                    ))
                });

                let empty_slot_states =
                    empty_hierarchy_slots
                        .into_iter()
                        .scan(state, |state, slot| {
                            let result = combined::process_slots(
                                &self.config,
                                &self.pubkey_cache,
                                state.make_mut(),
                                slot,
                            );

                            Some(result.map(|()| (slot, None, state.clone_arc())))
                        });

                link_state.into_iter().chain(empty_slot_states)
            },
        )
    }

    fn append_finalized_states(
        &self,
        states: impl IntoIterator<Item = (Slot, Option<H256>, Arc<BeaconState<P>>)>,
        anchor_slot: Slot,
        finalized_validators: &dyn SszValidatorList,
    ) -> Result<()> {
        // States are tracked in a spine local to this call and published into
        // the forward spine only once the batch holding them is committed.
        // Publishing earlier would let this run - or a concurrent one, since the
        // forward spine is shared by every archival thread - delta-encode
        // against a parent that a later failure or a crash leaves unwritten.
        let spine = self.temporary_spine(anchor_slot);
        self.forward_spine.copy_into(&spine);

        let mut batch = vec![];
        let mut deleted_keys = Vec::new();
        let mut update_finalized_validators = false;
        let mut states_in_batch: u64 = 0;

        for (slot, block_root, state) in states {
            let block_root = match block_root {
                Some(block_root) => block_root,
                None => {
                    let state_root = state.hash_tree_root();
                    let value = BlockRootBySlotValue::blockless(state_root);

                    batch.push(serialize(BlockRootBySlot(slot), value)?);
                    batch.push(serialize(SlotByStateRoot(state_root), slot)?);

                    value.state_key_root()
                }
            };

            let to_delete = self.append_finalized_state(
                state,
                slot,
                block_root,
                anchor_slot,
                finalized_validators,
                &spine,
                &mut batch,
                &mut update_finalized_validators,
            )?;

            if let Some(to_delete) = to_delete {
                deleted_keys.push(to_delete);
            }

            states_in_batch = states_in_batch.saturating_add(1);

            if states_in_batch == ARCHIVED_STATES_BEFORE_FLUSH {
                self.flush(
                    &mut batch,
                    &mut deleted_keys,
                    &mut update_finalized_validators,
                    finalized_validators,
                )?;

                spine.copy_into(&self.forward_spine);

                states_in_batch = 0;
            }
        }

        self.flush(
            &mut batch,
            &mut deleted_keys,
            &mut update_finalized_validators,
            finalized_validators,
        )?;

        spine.copy_into(&self.forward_spine);

        Ok(())
    }

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
                let (key, serialized_frame) =
                    self.serialize_frame(block_root, &state, finalized_validators)?;

                slots.push(state.slot());
                batch.push((serialize_key(key), serialized_frame));

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
            .iterator_descending_raw(..=SlotBlobId(up_to_slot, H256::zero(), 0).to_string())?;

        let (mut keys_to_remove, blobs_to_remove): (Vec<_>, Vec<_>) =
            itertools::process_results(results, |iter| {
                iter.take_while(|(key_bytes, _)| SlotBlobId::has_prefix(key_bytes))
                    .unzip()
            })?;

        for blob_bytes in blobs_to_remove {
            let BlobIdentifier { block_root, index } =
                BlobIdentifier::from_ssz_default(decompress(&blob_bytes)?)?;

            keys_to_remove.push(BlobSidecarByBlobId(block_root, index).to_string().into());
        }

        self.database.delete_batch(keys_to_remove)
    }

    fn retained_prune_slots(&self, up_to_slot: Slot) -> Vec<Slot> {
        let Some(pruned_up_to_slot) = up_to_slot.checked_sub(1) else {
            return vec![];
        };

        self.hierarchy.retained_by_pruning::<P>(
            &self.config,
            self.anchor_slot.load(Ordering::SeqCst),
            pruned_up_to_slot,
        )
    }

    pub(crate) fn prune_old_blocks_and_states(&self, up_to_slot: Slot) -> Result<()> {
        let Some(pruned_up_to_slot) = up_to_slot.checked_sub(1) else {
            return Ok(());
        };

        let retained_slots = self.retained_prune_slots(up_to_slot);

        let results = self
            .database
            .iterator_descending_raw(..=BlockRootBySlot(pruned_up_to_slot).to_string())?;

        let entries = itertools::process_results(results, |iter| {
            iter.take_while(|(key_bytes, _)| BlockRootBySlot::has_prefix(key_bytes))
                .collect::<Vec<_>>()
        })?;

        let mut keys_to_remove = Vec::new();

        for (key_bytes, value_bytes) in entries {
            let BlockRootBySlot(slot) = Cow::from(key_bytes.as_slice()).try_into()?;
            let value = BlockRootBySlotValue::from_ssz_default(decompress(&value_bytes)?)?;

            if let Some(block_root) = value.block_root() {
                keys_to_remove.push(FinalizedBlockByRoot::full(block_root).to_string().into());
                keys_to_remove.push(FinalizedBlockByRoot::blinded(block_root).to_string().into());
            }

            if retained_slots.contains(&slot) {
                continue;
            }

            keys_to_remove.push(key_bytes);
            keys_to_remove.push(SlotDiffsBySlot(slot).to_string().into());

            let state_prefix = StateByBlockRoot::prefix(value.state_key_root());
            let state_keys = self.database.keys_ascending(state_prefix.as_bytes()..)?;

            keys_to_remove.extend(itertools::process_results(state_keys, |keys| {
                keys.take_while(|key| key.starts_with(state_prefix.as_bytes()))
                    .collect::<Vec<_>>()
            })?);
        }

        self.forward_spine.remove_pruned(pruned_up_to_slot);

        if self.pruned_up_to_slot()? < up_to_slot {
            save(&self.database, PrunedUpToKey, up_to_slot)?;
        }

        self.database.delete_batch(keys_to_remove)?;

        self.prune_old_execution_payloads(up_to_slot)
    }

    pub(crate) fn prune_old_execution_payloads(&self, up_to_slot: Slot) -> Result<()> {
        self.database.delete_range(
            ExecutionPayloadBySlotAndRoot(GENESIS_SLOT, H256::zero()).to_string()
                ..ExecutionPayloadBySlotAndRoot(up_to_slot, H256::zero()).to_string(),
        )
    }

    pub(crate) fn pruned_up_to_slot(&self) -> Result<Slot> {
        Ok(self.get::<Slot>(PrunedUpToKey)?.unwrap_or(GENESIS_SLOT))
    }

    pub(crate) fn prune_old_state_roots(&self, up_to_slot: Slot) -> Result<()> {
        let retained_slots = self.retained_prune_slots(up_to_slot);
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

            let payload = envelope.execution_payload_body();

            batch.push(self.serialize_zstd(
                EnvelopeByBlockRoot::blinded(block_root),
                SignedBlindedExecutionPayloadEnvelope::from(Arc::unwrap_or_clone(envelope)),
            )?);
            batch.push(serialize(EnvelopeRootBySlot(slot, block_root), block_root)?);

            if self.store_execution_payloads {
                batch.push(
                    self.serialize_zstd(ExecutionPayloadBySlotAndRoot(slot, block_root), payload)?,
                );
            }

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

    pub(crate) fn envelope_by_root(&self, block_root: H256) -> Result<Option<StoredEnvelope<P>>> {
        let Some((key_bytes, value_bytes)) = self
            .database
            .next_raw(EnvelopeByBlockRoot::full(block_root).to_string())?
        else {
            return Ok(None);
        };

        // The next key may belong to another envelope or not be an envelope key at all.
        let Ok(key) = EnvelopeByBlockRoot::try_from(key_bytes.as_slice()) else {
            return Ok(None);
        };

        if key.block_root != block_root {
            return Ok(None);
        }

        if !key.blinded {
            return Ok(Some(StoredEnvelope::Full(Arc::from_ssz(
                self.config.as_ref(),
                decompress(&value_bytes)?,
            )?)));
        }

        let value_bytes = zstd::decode_all(value_bytes.as_slice())?;
        let envelope = SignedBlindedExecutionPayloadEnvelope::<P>::from_ssz_default(value_bytes)?;

        let payload_key =
            ExecutionPayloadBySlotAndRoot(envelope.message.payload_header.slot_number, block_root);

        let Some(payload_bytes) = self.database.get_raw(payload_key.to_string())? else {
            return Ok(Some(StoredEnvelope::Blinded(Arc::new(envelope))));
        };

        let payload_bytes = zstd::decode_all(payload_bytes.as_slice())?;
        let payload_body = ExecutionPayloadBody::from_ssz_default(payload_bytes)?;

        Ok(Some(StoredEnvelope::Full(Arc::new(
            envelope.unblind(payload_body)?,
        ))))
    }

    pub(crate) fn prune_old_data_column_sidecars(&self, up_to_slot: Slot) -> Result<()> {
        let results = self
            .database
            .iterator_descending_raw(..=SlotColumnId(up_to_slot, H256::zero(), 0).to_string())?;

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
                DataColumnIdentifier::from_ssz_default(decompress(&column_bytes)?)?;

            keys_to_remove.push(
                DataColumnSidecarByColumnId(block_root, index)
                    .to_string()
                    .into(),
            )
        }

        self.database.delete_batch(keys_to_remove)
    }

    pub(crate) fn prune_old_execution_payload_envelopes(&self, up_to_slot: Slot) -> Result<()> {
        let results = self
            .database
            .iterator_descending_raw(..=EnvelopeRootBySlot(up_to_slot, H256::zero()).to_string())?;

        let (mut keys_to_remove, envelopes_to_remove): (Vec<_>, Vec<_>) =
            itertools::process_results(results, |iter| {
                iter.take_while(|(key_bytes, _)| EnvelopeRootBySlot::has_prefix(key_bytes))
                    .unzip()
            })?;

        for value_bytes in envelopes_to_remove {
            let block_root = H256::from_ssz_default(decompress(&value_bytes)?)?;

            keys_to_remove.push(EnvelopeByBlockRoot::full(block_root).to_string().into());
            keys_to_remove.push(EnvelopeByBlockRoot::blinded(block_root).to_string().into());
        }

        self.database.delete_batch(keys_to_remove)
    }

    pub(crate) fn genesis_block_root(&self, store: &Store<P, Self>) -> Result<H256> {
        self.block_root_by_slot_with_store(store, GENESIS_SLOT)?
            .ok_or(Error::GenesisBlockRootNotFound)
            .map_err(Into::into)
    }

    pub(crate) fn contains_finalized_block(&self, block_root: H256) -> Result<bool> {
        let Some(key_bytes) = self
            .database
            .next_key(FinalizedBlockByRoot::full(block_root).to_string())?
        else {
            return Ok(false);
        };

        // The next key may belong to another block or not be a finalized block key at all.
        let Ok(key) = FinalizedBlockByRoot::try_from(key_bytes.as_slice()) else {
            return Ok(false);
        };

        Ok(key.block_root == block_root)
    }

    pub(crate) fn contains_unfinalized_block(&self, block_root: H256) -> Result<bool> {
        self.contains_key(UnfinalizedBlockByRoot(block_root))
    }

    pub(crate) fn finalized_block_by_root(
        &self,
        block_root: H256,
    ) -> Result<Option<StoredBlock<P>>> {
        let Some((key_bytes, value_bytes)) = self
            .database
            .next_raw(FinalizedBlockByRoot::full(block_root).to_string())?
        else {
            return Ok(None);
        };

        // The next key may belong to another block or not be a finalized block key at all.
        let Ok(key) = FinalizedBlockByRoot::try_from(key_bytes.as_slice()) else {
            return Ok(None);
        };

        if key.block_root != block_root {
            return Ok(None);
        }

        if !key.is_blinded() {
            return Ok(Some(StoredBlock::Full(Arc::from_ssz(
                self.config.as_ref(),
                decompress(&value_bytes)?,
            )?)));
        }

        let value_bytes = zstd::decode_all(value_bytes.as_slice())?;
        let blinded_block =
            SignedBlindedBeaconBlock::<P>::from_ssz(self.config.as_ref(), value_bytes)?;

        let payload_key = ExecutionPayloadBySlotAndRoot(blinded_block.message().slot(), block_root);

        let Some(payload_bytes) = self.database.get_raw(payload_key.to_string())? else {
            return Ok(Some(StoredBlock::Blinded(Arc::new(blinded_block))));
        };

        let payload_bytes = zstd::decode_all(payload_bytes.as_slice())?;
        let payload_body = ExecutionPayloadBody::<P>::from_ssz_default(payload_bytes)?;

        Ok(Some(StoredBlock::Full(Arc::new(
            blinded_block.unblind(payload_body)?,
        ))))
    }

    pub(crate) fn unfinalized_block_by_root(
        &self,
        block_root: H256,
    ) -> Result<Option<Arc<SignedBeaconBlock<P>>>> {
        self.get(UnfinalizedBlockByRoot(block_root))
    }

    pub(crate) fn block_root_by_slot(&self, slot: Slot) -> Result<Option<H256>> {
        Ok(self
            .block_root_by_slot_value(slot)?
            .and_then(BlockRootBySlotValue::block_root))
    }

    fn block_root_by_slot_value(&self, slot: Slot) -> Result<Option<BlockRootBySlotValue>> {
        self.get(BlockRootBySlot(slot))
    }

    #[expect(clippy::too_many_lines)]
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
            // how `frame_cache` indexes layers.
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

            // Frames have their fields compressed one by one, so they are left as they are -
            // `BeaconState::decompress` decodes them once they become the frame.
            let value = match row_key.encoding {
                StateEncoding::Frame | StateEncoding::Delta => raw_value,
                StateEncoding::LegacySnappy => {
                    snap::raw::Decoder::new().decompress_vec(&raw_value)?
                }
            };

            items.push((value, row_key.encoding, layer, row_key.block_root));

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

        let pubkeys_from_disk;

        let pubkeys = match finalized_validators {
            Some(validators) => validators.pubkeys(),
            None => {
                pubkeys_from_disk = self.finalized_pubkeys()?;
                &pubkeys_from_disk
            }
        };

        let (mut frame, deltas) = if let Some(frame) = frame {
            // If we've found value from cache, no decoding needed - just take the frame
            (frame, items.as_slice())
        } else {
            let Some(((frame_bytes, encoding, layer, block_root), deltas)) = items.split_first()
            else {
                unreachable!("items cannot be empty");
            };

            let frame = match encoding {
                StateEncoding::Frame => Arc::new(
                    BeaconStateFrame::<P>::from_ssz(&self.config, frame_bytes)?
                        .into_state(pubkeys)?,
                ),
                StateEncoding::LegacySnappy => {
                    let mut frame = Arc::<BeaconState<P>>::from_ssz(&self.config, frame_bytes)?;
                    Self::restore_pubkeys_to_state(frame.make_mut(), pubkeys, None)
                        .context("invalid finalized validators list")?;
                    frame
                }
                StateEncoding::Delta => {
                    unreachable!("the chain is rooted at a row with no parents")
                }
            };

            if *layer < self.hierarchy.depth() {
                self.frame_cache
                    .set(*layer, *block_root, frame.clone_arc())?;
            }

            (frame, deltas)
        };

        for (delta, _, layer, block_root) in deltas {
            let patch = BeaconStatePatch::from_ssz(&self.config, delta)?;

            let validators_before = frame.validators().len_usize();

            patch.apply(&mut frame)?;

            let appended = validators_before..frame.validators().len_usize();

            Self::restore_pubkeys_to_state(frame.make_mut(), pubkeys, Some(appended))
                .context("invalid finalized validators list")?;

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
            .iterator_descending_raw(..=BlockRootBySlot(slot).to_string())?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| BlockRootBySlot::has_prefix(key_bytes))
                .map(|(_, value_bytes)| -> Result<BlockRootBySlotValue> {
                    Ok(BlockRootBySlotValue::from_ssz_default(decompress(
                        &value_bytes,
                    )?)?)
                })
                .filter_map_ok(BlockRootBySlotValue::block_root)
                .next()
                .transpose()
        })?
    }

    pub(crate) fn block_root_after_slot(&self, slot: Slot) -> Result<Option<H256>> {
        let results = self
            .database
            .iterator_ascending_raw(BlockRootBySlot(slot.saturating_add(1)).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| BlockRootBySlot::has_prefix(key_bytes))
                .map(|(_, value_bytes)| -> Result<BlockRootBySlotValue> {
                    Ok(BlockRootBySlotValue::from_ssz_default(decompress(
                        &value_bytes,
                    )?)?)
                })
                .filter_map_ok(BlockRootBySlotValue::block_root)
                .next()
                .transpose()
        })?
    }

    /// The first finalized block after `slot`.
    pub(crate) fn finalized_block_after_slot(
        &self,
        slot: Slot,
    ) -> Result<Option<(StoredBlock<P>, H256)>> {
        let Some(block_root) = self.block_root_after_slot(slot)? else {
            return Ok(None);
        };

        let Some(block) = self.finalized_block_by_root(block_root)? else {
            return Ok(None);
        };

        Ok(Some((block, block_root)))
    }

    pub(crate) fn finalized_block_by_slot(
        &self,
        slot: Slot,
    ) -> Result<Option<(StoredBlock<P>, H256)>> {
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
        let (mut state, blocks) =
            match self.load_state_by_iteration(slot, finalized_validators, false)? {
                OptionalStateStorage::None | OptionalStateStorage::UnfinalizedOnly(_) => {
                    return Ok(None);
                }
                OptionalStateStorage::Full((state, state_block, blocks)) => {
                    state.set_cached_root(state_block.message().state_root());
                    (state, blocks)
                }
                OptionalStateStorage::Blockless(state, blocks) => (state, blocks),
            };

        // State may be persisted only once in several epochs.
        // `blocks` here are needed to transition state closer to `slot`.
        for result in blocks {
            match result? {
                StoredBlock::Full(block) => combined::trusted_state_transition(
                    &self.config,
                    &self.pubkey_cache,
                    state.make_mut(),
                    &block,
                )?,
                StoredBlock::Blinded(block) => combined::trusted_blinded_state_transition(
                    &self.config,
                    &self.pubkey_cache,
                    state.make_mut(),
                    &block,
                )?,
            }
        }

        if state.slot() < slot {
            combined::process_slots(&self.config, &self.pubkey_cache, state.make_mut(), slot)?;
        }

        Ok(Some(state))
    }

    pub(crate) fn state_rows_before_or_at(&self, slot: Slot) -> Result<Option<StateRows<'_, P>>> {
        let state_slot = self.hierarchy.node_before_or_at::<P>(
            &self.config,
            self.anchor_slot.load(Ordering::SeqCst),
            slot,
        );

        if state_slot < self.pruned_up_to_slot()? {
            return Ok(None);
        }

        let Some(value) = self.block_root_by_slot_value(state_slot)? else {
            return Ok(None);
        };

        Ok(Some(StateRows {
            storage: self,
            view: self.database.view()?,
            state_slot,
            next_block_root: Some(value.state_key_root()),
            visited: HashSet::new(),
        }))
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
                blocks.push(StoredBlock::Full(block));
                continue;
            }

            return Ok(None);
        };

        for block in blocks.into_iter().rev() {
            match block {
                StoredBlock::Full(block) => combined::trusted_state_transition(
                    &self.config,
                    &self.pubkey_cache,
                    state.make_mut(),
                    &block,
                )?,
                StoredBlock::Blinded(block) => combined::trusted_blinded_state_transition(
                    &self.config,
                    &self.pubkey_cache,
                    state.make_mut(),
                    &block,
                )?,
            }
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

                StoredBlock::Full(block)
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
                    .map(|(_, value_bytes)| -> Result<BlockRootBySlotValue> {
                        Ok(BlockRootBySlotValue::from_ssz_default(decompress(
                            &value_bytes,
                        )?)?)
                    })
                    .filter_map_ok(BlockRootBySlotValue::block_root)
                    .try_collect()
            })??;

            let blocks = self.blocks_by_roots(block_roots);

            return Ok(Some((state, block, blocks)));
        }

        Ok(None)
    }

    fn load_state_by_iteration(
        &self,
        start_from_slot: Slot,
        finalized_validators: Option<&dyn SszValidatorList>,
        epoch_start_only: bool,
    ) -> Result<OptionalStateStorage<'_, P>> {
        let results = self
            .database
            .iterator_descending_raw(..=BlockRootBySlot(start_from_slot).to_string())?;

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

            let value = BlockRootBySlotValue::from_ssz_default(decompress(&value_bytes)?)?;
            let state_key_root = value.state_key_root();

            if self.contains_prefixed_key(StateByBlockRoot::prefix(state_key_root))? {
                let block = match value {
                    BlockRootBySlotValue::Block(block_root) => {
                        let Some(block) = self.finalized_block_by_root(block_root)? else {
                            // States are also persisted from unfinalized chain
                            continue;
                        };

                        Some(block)
                    }
                    BlockRootBySlotValue::Blockless(_) if epoch_start_only => continue,
                    BlockRootBySlotValue::Blockless(_) => None,
                };

                if let Some(state) =
                    self.state_by_block_root(state_key_root, finalized_validators)?
                    && (!epoch_start_only || misc::is_epoch_start::<P>(state.slot()))
                {
                    block_roots.reverse();

                    let blocks = self.blocks_by_roots(block_roots);

                    return Ok(match block {
                        Some(block) => OptionalStateStorage::Full((state, block, blocks)),
                        None => OptionalStateStorage::Blockless(state, blocks),
                    });
                }
            }

            if let Some(block_root) = value.block_root() {
                block_roots.push(block_root);
            }
        }

        if block_roots.is_empty() {
            return Ok(OptionalStateStorage::None);
        }

        block_roots.reverse();

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
        self.restore_validators_to_state(checkpoint.state.make_mut(), finalized_validators)?;

        Ok(Some(checkpoint))
    }

    fn contains_key(&self, key: impl fmt::Display) -> Result<bool> {
        let key_string = key.to_string();

        self.database.contains_key(key_string)
    }

    fn contains_prefixed_key(&self, key: impl fmt::Display) -> Result<bool> {
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

    pub(crate) fn get<V: SszRead<Config>>(&self, key: impl fmt::Display) -> Result<Option<V>> {
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
                return Ok(StoredBlock::Full(block));
            }

            bail!(Error::BlockNotFound { block_root })
        }))
    }

    fn finalized_pubkeys(&self) -> Result<PubkeyList> {
        info_with_peers!("loading validators from disk");

        let Some(pubkeys) = self.get::<PubkeyList>(FinalizedValidators)? else {
            bail!("unable to restore validators into state - no saved validators on disk found.");
        };

        Ok(pubkeys)
    }

    fn restore_validators_to_state(
        &self,
        state: &mut BeaconState<P>,
        finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<()> {
        match finalized_validators {
            Some(validators) => {
                Self::restore_pubkeys_to_state(state, validators.pubkeys(), None)
                    .context("invalid finalized validators list")?;
            }
            None => {
                Self::restore_pubkeys_to_state(state, &self.finalized_pubkeys()?, None)
                    .context("invalid finalized validators list loaded from disk")?;
            }
        }

        Ok(())
    }

    pub(crate) fn append_finalized_block_to_batch(
        &self,
        batch: &mut Vec<(String, Vec<u8>)>,
        block_root: H256,
        block: &SignedBeaconBlock<P>,
        keep_payload: bool,
    ) -> Result<()> {
        let Some(payload) = block.clone().execution_payload_body() else {
            batch.push(serialize(FinalizedBlockByRoot::full(block_root), block)?);
            return Ok(());
        };

        let blinded_block = SignedBlindedBeaconBlock::try_from(block.clone())?;

        batch.push(self.serialize_zstd(FinalizedBlockByRoot::blinded(block_root), blinded_block)?);

        if keep_payload || self.store_execution_payloads {
            batch.push(self.serialize_zstd(
                ExecutionPayloadBySlotAndRoot(block.message().slot(), block_root),
                payload,
            )?);
        }

        Ok(())
    }

    /// Serializes `state` as a frame, along with the key it is stored under.
    ///
    /// Validators in `finalized_validators` are stored without their public keys, which readers
    /// take from the finalized validators.
    pub(crate) fn serialize_frame(
        &self,
        block_root: H256,
        state: &BeaconState<P>,
        finalized_validators: &dyn SszValidatorList,
    ) -> Result<(StateByBlockRoot, Vec<u8>)> {
        let frame = BeaconStateFrame::new(
            state,
            finalized_validators.len_usize(),
            self.zstd_compression_level,
        )
        .to_ssz()?;

        Ok((StateByBlockRoot::snapshot(block_root), frame))
    }

    fn serialize_zstd(
        &self,
        key: impl fmt::Display,
        value: impl SszWrite,
    ) -> Result<(String, Vec<u8>)> {
        let value = serialize_value(value)?;
        let compressed_value = zstd::encode_all(value.as_slice(), self.zstd_compression_level)?;

        Ok((serialize_key(key), compressed_value))
    }

    fn restore_pubkeys_to_state(
        state: &mut BeaconState<P>,
        pubkeys: &PubkeyList,
        range: Option<Range<usize>>,
    ) -> Result<()> {
        let validators = state.validators_mut();

        match range {
            Some(range) => validators.restore_pubkeys_in(pubkeys, range),
            None => validators.restore_pubkeys(pubkeys),
        }
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
    pub fn stored_block_root_by_slot_value(
        &self,
        slot: Slot,
    ) -> Result<Option<BlockRootBySlotValue>> {
        self.block_root_by_slot_value(slot)
    }

    pub fn contains_state_for_root(&self, block_root: H256) -> Result<bool> {
        Ok(self.state_key_by_block_root(block_root)?.is_some())
    }

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
            .iterator_ascending_raw(FinalizedBlockByRoot::full(H256::zero()).to_string()..)?;

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

pub enum StateRow<'row, P: Preset> {
    Delta(BeaconStatePatchCursor<'row, P>),
    Frame(BeaconStateFrameCursor<'row, P>),
    State(Arc<BeaconState<P>>),
}

pub struct StateRows<'storage, P: Preset> {
    storage: &'storage Storage<P>,
    view: View,
    state_slot: Slot,
    next_block_root: Option<H256>,
    visited: HashSet<H256>,
}

impl<P: Preset> StateRows<'_, P> {
    #[must_use]
    pub const fn state_slot(&self) -> Slot {
        self.state_slot
    }

    pub fn slot_diff(&self, slot: Slot) -> Result<Option<SlotDiff>> {
        let Some(position) = slot.checked_sub(self.state_slot.saturating_add(1)) else {
            return Ok(None);
        };

        let key = SlotDiffsBySlot(self.state_slot).to_string();

        let Some((full_key, row)) = self.view.next_raw(&key)? else {
            return Ok(None);
        };

        if full_key != key.as_bytes() {
            return Ok(None);
        }

        Ok(SlotDiffs::from_ssz(&self.storage.config, row)?
            .into_inner()
            .into_iter()
            .nth(usize::try_from(position)?))
    }

    pub fn next(&mut self) -> Result<Option<StateRow<'_, P>>> {
        let Some(block_root) = self.next_block_root.take() else {
            return Ok(None);
        };

        let prefix = StateByBlockRoot::prefix(block_root);

        let Some((full_key, row)) = self.view.next_raw(&prefix)? else {
            return Ok(None);
        };

        if !full_key.starts_with(prefix.as_bytes()) {
            return Ok(None);
        }

        let key = StateByBlockRoot::try_from(full_key)?;

        ensure!(
            self.visited.insert(block_root),
            "unable to read state rows: delta chain revisits block root {block_root:?}",
        );

        if let Some(state) = self.storage.forward_spine.get_by_block_root(block_root) {
            return Ok(Some(StateRow::State(state)));
        }

        let layer = key.parents.len();

        if layer < self.storage.hierarchy.depth()
            && let Some(state) = self.storage.frame_cache.get(layer, &block_root)?
        {
            return Ok(Some(StateRow::State(state)));
        }

        let is_frame = match key.encoding {
            StateEncoding::Frame => true,
            StateEncoding::Delta => false,
            StateEncoding::LegacySnappy => return Ok(None),
        };

        self.next_block_root = key.parents.first().copied();

        if is_frame {
            return Ok(Some(StateRow::Frame(BeaconStateFrameCursor::new(
                &self.storage.config,
                row,
            )?)));
        }

        Ok(Some(StateRow::Delta(BeaconStatePatchCursor::new(row)?)))
    }
}

#[derive(Clone, Debug)]
pub enum StoredBlock<P: Preset> {
    Full(Arc<SignedBeaconBlock<P>>),
    Blinded(Arc<SignedBlindedBeaconBlock<P>>),
}

#[derive(Clone, Debug)]
pub enum StoredEnvelope<P: Preset> {
    Full(Arc<SignedExecutionPayloadEnvelope<P>>),
    Blinded(Arc<SignedBlindedExecutionPayloadEnvelope<P>>),
}

impl<P: Preset> StoredBlock<P> {
    #[must_use]
    pub fn phase(&self) -> Phase {
        match self {
            Self::Full(block) => block.phase(),
            Self::Blinded(block) => block.phase(),
        }
    }

    #[must_use]
    pub fn to_header(&self) -> SignedBeaconBlockHeader {
        self.message().to_header().with_signature(self.signature())
    }
}

impl<P: Preset> traits::SignedBeaconBlock<P> for StoredBlock<P> {
    type Message = dyn BeaconBlock<P>;

    fn message(&self) -> &Self::Message {
        match self {
            Self::Full(block) => block.message(),
            Self::Blinded(block) => block.message(),
        }
    }

    fn signature(&self) -> SignatureBytes {
        match self {
            Self::Full(block) => block.signature(),
            Self::Blinded(block) => block.signature(),
        }
    }
}

#[derive(Default, Debug)]
pub struct AppendedBlockSlots {
    pub finalized: Vec<Slot>,
    pub unfinalized: Vec<Slot>,
}

type UnfinalizedBlocks<'storage, P> =
    Box<dyn DoubleEndedIterator<Item = Result<StoredBlock<P>>> + Send + 'storage>;

// Internal type for state storage that can be missing or have missing elements.
// E.g. non-finalized storage that has only unfinalized blocks stored.
enum OptionalStateStorage<'storage, P: Preset> {
    None,
    UnfinalizedOnly(UnfinalizedBlocks<'storage, P>),
    Full(StateStorage<'storage, P>),
    Blockless(Arc<BeaconState<P>>, UnfinalizedBlocks<'storage, P>),
}

impl<P: Preset> OptionalStateStorage<'_, P> {
    const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

type StateStorage<'storage, P> = (
    Arc<BeaconState<P>>,
    StoredBlock<P>,
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

    const STATE_START: usize = <H256 as SszSize>::SIZE
        .fixed_part()
        .saturating_add(<Slot as SszSize>::SIZE.fixed_part())
        .saturating_add(<BeaconState<P> as SszSize>::SIZE.fixed_part());
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockRootBySlotValue {
    Block(H256),
    Blockless(H256),
}

impl BlockRootBySlotValue {
    const BLOCKLESS_PREFIX: u8 = b'f';

    #[must_use]
    pub fn blockless(state_root: H256) -> Self {
        Self::Blockless(hashing::hash_256_8(state_root, Self::BLOCKLESS_PREFIX))
    }

    #[must_use]
    pub const fn block_root(self) -> Option<H256> {
        match self {
            Self::Block(block_root) => Some(block_root),
            Self::Blockless(_) => None,
        }
    }

    #[must_use]
    pub const fn state_key_root(self) -> H256 {
        match self {
            Self::Block(root) | Self::Blockless(root) => root,
        }
    }
}

impl SszSize for BlockRootBySlotValue {
    const SIZE: Size = Size::Variable {
        minimum_size: <H256 as SszSize>::SIZE.fixed_part(),
    };
}

impl<C> SszRead<C> for BlockRootBySlotValue {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        match bytes {
            [Self::BLOCKLESS_PREFIX, root @ ..] if root.len() == H256::len_bytes() => {
                H256::from_ssz(context, root).map(Self::Blockless)
            }
            _ if bytes.len() == H256::len_bytes() => {
                H256::from_ssz(context, bytes).map(Self::Block)
            }
            _ => Err(ReadError::Custom {
                message: "block root by slot value must be a block root \
                          or a blockless marker followed by a root",
            }),
        }
    }
}

impl SszWrite for BlockRootBySlotValue {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        if let Self::Blockless(_) = self {
            bytes.push(Self::BLOCKLESS_PREFIX);
        }

        bytes.extend_from_slice(self.state_key_root().as_bytes());

        Ok(())
    }
}

pub struct FinalizedBlockByRoot {
    block_root: H256,
    blinded: bool,
}

impl FinalizedBlockByRoot {
    // Appended to the key when the block is stored blinded, i.e. without its execution payload.
    const BLINDED_SUFFIX: &'static str = "b";
    const BLOCK_ROOT_HEX_LENGTH: usize = H256::len_bytes() * 2;

    #[must_use]
    pub const fn full(block_root: H256) -> Self {
        Self {
            block_root,
            blinded: false,
        }
    }

    #[must_use]
    pub const fn blinded(block_root: H256) -> Self {
        Self {
            block_root,
            blinded: true,
        }
    }

    #[must_use]
    pub const fn is_blinded(&self) -> bool {
        self.blinded
    }
}

impl TryFrom<&[u8]> for FinalizedBlockByRoot {
    type Error = AnyhowError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let payload =
            bytes
                .strip_prefix(Self::PREFIX.as_bytes())
                .ok_or_else(|| Error::IncorrectPrefix {
                    bytes: bytes.to_vec(),
                })?;

        let string = core::str::from_utf8(payload)?;

        // The suffix cannot be stripped blindly because the block root may end with the same character.
        let (block_root, blinded) = match string.split_at_checked(Self::BLOCK_ROOT_HEX_LENGTH) {
            Some((block_root, Self::BLINDED_SUFFIX)) => (block_root, true),
            _ => (string, false),
        };

        Ok(Self {
            block_root: block_root.parse()?,
            blinded,
        })
    }
}

impl PrefixableKey for FinalizedBlockByRoot {
    const PREFIX: &'static str = "b";
}

impl fmt::Display for FinalizedBlockByRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}{:x}", Self::PREFIX, self.block_root)?;

        if self.blinded {
            formatter.write_str(Self::BLINDED_SUFFIX)?;
        }

        Ok(())
    }
}

#[derive(Display)]
#[display("{}{_0:020}", Self::PREFIX)]
pub struct SlotDiffsBySlot(pub Slot);

impl PrefixableKey for SlotDiffsBySlot {
    const PREFIX: &'static str = "u";
}

#[derive(Display)]
#[display("{}{_0:020}{_1:x}", Self::PREFIX)]
pub struct ExecutionPayloadBySlotAndRoot(pub Slot, pub H256);

impl PrefixableKey for ExecutionPayloadBySlotAndRoot {
    const PREFIX: &'static str = "p";
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
pub struct UnfinalizedBlockByRoot(pub H256);

impl PrefixableKey for UnfinalizedBlockByRoot {
    const PREFIX: &'static str = "b_nf";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateEncoding {
    /// A whole state stored as a `BeaconStateFrame`, with its fields zstd-compressed one by one.
    Frame,
    /// A whole state written by an older release, snappy-compressed.
    LegacySnappy,
    /// A patch against the state of its first parent.
    Delta,
}

#[derive(Debug, Clone)]
pub struct StateByBlockRoot {
    pub(crate) block_root: H256,
    parents: Vec<H256>,
    encoding: StateEncoding,
}

impl PrefixableKey for StateByBlockRoot {
    const PREFIX: &'static str = "s";
}

impl fmt::Display for StateByBlockRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:x}", Self::PREFIX, self.block_root)?;
        for i in &self.parents {
            write!(f, "{i:x}")?;
        }
        match self.encoding {
            StateEncoding::Frame => write!(f, "z")?,
            StateEncoding::LegacySnappy | StateEncoding::Delta => {}
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

        let (stripped, is_frame) = match stripped.split_last() {
            Some((b'z', stripped)) => (stripped, true),
            _ => (stripped, false),
        };

        let (hashes, remainder) = stripped.as_chunks::<{ H256::len_bytes().saturating_mul(2) }>();
        ensure!(remainder.is_empty(), "Invalid parents");
        let mut hashes = hashes
            .iter()
            .map(|root| Ok(str::from_utf8(root)?.parse::<H256>()?));

        let Some(block_root) = hashes.next() else {
            bail!("Block root hash is missing");
        };

        let parents = hashes.collect::<Result<Vec<_>>>()?;

        let encoding = match (is_frame, parents.is_empty()) {
            (true, true) => StateEncoding::Frame,
            (false, true) => StateEncoding::LegacySnappy,
            (false, false) => StateEncoding::Delta,
            (true, false) => bail!("invalid state key: state deltas cannot have a suffix"),
        };

        Ok(Self {
            block_root: block_root?,
            parents,
            encoding,
        })
    }
}

impl StateByBlockRoot {
    pub(crate) const fn snapshot(block_root: H256) -> Self {
        Self {
            block_root,
            parents: Vec::new(),
            encoding: StateEncoding::Frame,
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
            encoding: StateEncoding::LegacySnappy,
        }
    }

    /// Create a key for a state, that depends on this value.
    fn extend_chain(mut self, block_root: H256) -> Self {
        self.parents.insert(0, self.block_root);

        Self {
            block_root,
            parents: self.parents,
            encoding: StateEncoding::Delta,
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

pub struct EnvelopeByBlockRoot {
    block_root: H256,
    blinded: bool,
}

impl EnvelopeByBlockRoot {
    // Appended to the key when the envelope is stored blinded, i.e. without its execution payload.
    const BLINDED_SUFFIX: &'static str = "b";
    const BLOCK_ROOT_HEX_LENGTH: usize = H256::len_bytes() * 2;

    #[must_use]
    pub const fn full(block_root: H256) -> Self {
        Self {
            block_root,
            blinded: false,
        }
    }

    #[must_use]
    pub const fn blinded(block_root: H256) -> Self {
        Self {
            block_root,
            blinded: true,
        }
    }
}

impl TryFrom<&[u8]> for EnvelopeByBlockRoot {
    type Error = AnyhowError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let payload =
            bytes
                .strip_prefix(Self::PREFIX.as_bytes())
                .ok_or_else(|| Error::IncorrectPrefix {
                    bytes: bytes.to_vec(),
                })?;

        let string = core::str::from_utf8(payload)?;

        // The suffix cannot be stripped blindly because the block root may end with the same character.
        let (block_root, blinded) = match string.split_at_checked(Self::BLOCK_ROOT_HEX_LENGTH) {
            Some((block_root, Self::BLINDED_SUFFIX)) => (block_root, true),
            _ => (string, false),
        };

        Ok(Self {
            block_root: block_root.parse()?,
            blinded,
        })
    }
}

impl fmt::Display for EnvelopeByBlockRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}{:x}", Self::PREFIX, self.block_root)?;

        if self.blinded {
            formatter.write_str(Self::BLINDED_SUFFIX)?;
        }

        Ok(())
    }
}

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
    #[error(
        "execution payload of block {block_root:?} is pruned; \
         payloads of blocks older than the latest checkpoint are kept only with --store-payloads"
    )]
    PayloadPruned { block_root: H256 },
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

pub fn save(database: &Database, key: impl fmt::Display, value: impl SszWrite) -> Result<()> {
    database.put(serialize_key(key), serialize_value(value)?)
}

pub fn get<V: SszReadDefault>(database: &Database, key: impl fmt::Display) -> Result<Option<V>> {
    database
        .get(serialize_key(key))?
        .map(V::from_ssz_default)
        .transpose()
        .map_err(Into::into)
}

fn serialize_key(key: impl fmt::Display) -> String {
    key.to_string()
}

fn serialize_value(value: impl SszWrite) -> Result<Vec<u8>> {
    value.to_ssz().map_err(Into::into)
}

fn serialize_raw(key: impl fmt::Display, value: impl SszWrite) -> Result<(String, Vec<u8>)> {
    Ok((serialize_key(key), serialize_value(value)?))
}

pub fn serialize(key: impl fmt::Display, value: impl SszWrite) -> Result<(String, Vec<u8>)> {
    let value = serialize_value(value)?;
    let compressed = snap::raw::Encoder::new().compress_vec(&value)?;

    Ok((serialize_key(key), compressed))
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

    use crate::state_field::{
        CommitteeFields, FinalityCheckpoints, StateField as _, StateRandaoMixes,
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

        Storage::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            StorageMode::default(),
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig {
                hierarchy,
                cache_sizes,
            },
        )
    }

    fn load_anchor(storage: &Storage<Mainnet>, state: Arc<BeaconState<Mainnet>>) -> Result<()> {
        futures::executor::block_on(storage.load(
            &Client::new(),
            StateLoadStrategy::Anchor {
                block: Arc::new(block_with_slot(state.slot())),
                state,
            },
        ))
        .map(drop)?;

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
        ))
        .map(drop)?;

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
            serialize(FinalizedBlockByRoot::full(H256::repeat_byte(1)), &block_1)?,
            serialize(SlotByStateRoot(H256::repeat_byte(1)), 1_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(1)),
                1_u64,
            )?,
            // Slot 3
            serialize(BlockRootBySlot(3), H256::repeat_byte(3))?,
            serialize(FinalizedBlockByRoot::full(H256::repeat_byte(3)), &block_3)?,
            // Slot 5
            serialize(BlockRootBySlot(5), H256::repeat_byte(5))?,
            serialize(UnfinalizedBlockByRoot(H256::repeat_byte(5)), &block_5)?,
            //Slot 6
            serialize(BlockRootBySlot(6), H256::repeat_byte(6))?,
            serialize(FinalizedBlockByRoot::full(H256::repeat_byte(6)), &block_6)?,
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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

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
            serialize(FinalizedBlockByRoot::full(H256::repeat_byte(1)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(1)), 1_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(1)),
                1_u64,
            )?,
            // Slot 3
            serialize(BlockRootBySlot(3), H256::repeat_byte(3))?,
            serialize(FinalizedBlockByRoot::full(H256::repeat_byte(3)), &block)?,
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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

        assert_eq!(storage.finalized_block_count()?, 2);
        assert_eq!(storage.unfinalized_block_count()?, 3);
        assert_eq!(storage.block_root_by_slot_count()?, 5);
        assert_eq!(storage.slot_by_state_root_count()?, 3);
        assert_eq!(storage.state_count()?, 3);

        storage.prune_old_blocks_and_states(5)?;

        assert_eq!(storage.finalized_block_count()?, 0);
        assert_eq!(storage.unfinalized_block_count()?, 3);
        assert_eq!(storage.block_root_by_slot_count()?, 3);
        assert_eq!(storage.slot_by_state_root_count()?, 3);
        assert_eq!(storage.state_count()?, 2);

        storage.prune_old_state_roots(5)?;

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
            serialize(BlockRootBySlot(0), H256::repeat_byte(0))?,
            serialize(FinalizedBlockByRoot::full(H256::repeat_byte(0)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(0)), 0_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(0)),
                0_u64,
            )?,
            serialize(BlockRootBySlot(8), H256::repeat_byte(8))?,
            serialize(FinalizedBlockByRoot::full(H256::repeat_byte(8)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(8)), 8_u64)?,
            serialize(
                StateByBlockRoot::legacy_snapshot(H256::repeat_byte(8)),
                8_u64,
            )?,
            serialize(BlockRootBySlot(32), H256::repeat_byte(32))?,
            serialize(FinalizedBlockByRoot::full(H256::repeat_byte(32)), &block)?,
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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

        let retained_slots = storage.retained_prune_slots(33);

        assert!(retained_slots.contains(&0));
        assert!(retained_slots.contains(&32));

        storage.prune_old_blocks_and_states(33)?;
        storage.prune_old_state_roots(33)?;

        assert_eq!(storage.block_root_by_slot(32)?, Some(H256::repeat_byte(32)),);
        assert_eq!(storage.slot_by_state_root(H256::repeat_byte(32))?, Some(32));
        assert_eq!(storage.block_root_by_slot(0)?, Some(H256::zero()));
        assert_eq!(storage.slot_by_state_root(H256::repeat_byte(0))?, Some(0));

        assert_eq!(storage.block_root_by_slot(8)?, None);
        assert_eq!(storage.slot_by_state_root(H256::repeat_byte(8))?, None);

        assert_eq!(storage.finalized_block_count()?, 0);
        assert_eq!(storage.block_root_by_slot_count()?, 2);
        assert_eq!(storage.slot_by_state_root_count()?, 2);
        assert_eq!(storage.state_count()?, 2);

        Ok(())
    }

    #[test]
    fn stored_state_refuses_a_retained_state_below_the_prune_boundary() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let anchor_root = H256::repeat_byte(1);
        let pruned_root = H256::repeat_byte(4);
        let block = SignedBeaconBlock::<Mainnet>::Phase0(Phase0SignedBeaconBlock::default());

        storage.database.put_batch_raw(vec![
            serialize(BlockRootBySlot(0), anchor_root)?,
            serialize(FinalizedBlockByRoot::full(anchor_root), &block)?,
            serialize(BlockRootBySlot(4), pruned_root)?,
            serialize(FinalizedBlockByRoot::full(pruned_root), &block)?,
        ])?;

        storage.append_finalized_states(
            [(0, Some(anchor_root), state_with_slot(0))],
            0,
            finalized_validators,
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

        storage.prune_old_blocks_and_states(33)?;

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
            serialize(
                FinalizedBlockByRoot::full(epoch_start_root),
                block_with_slot(0),
            )?,
            serialize(BlockRootBySlot(8), mid_epoch_root)?,
            serialize(
                FinalizedBlockByRoot::full(mid_epoch_root),
                block_with_slot(8),
            )?,
        ])?;

        storage.append_finalized_states(
            [
                (0, Some(epoch_start_root), state_with_slot(0)),
                (8, Some(mid_epoch_root), state_with_slot(8)),
            ],
            0,
            finalized_validators,
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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

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
    fn test_legacy_execution_payload_envelopes() -> Result<()> {
        let envelope = |slot, block_root| {
            let mut envelope = SignedExecutionPayloadEnvelope::<Mainnet>::default();
            envelope.message.payload.slot_number = slot;
            envelope.message.beacon_block_root = block_root;
            envelope
        };

        let legacy_envelope = envelope(1, H256::repeat_byte(1));
        let new_envelope = envelope(3, H256::repeat_byte(3));
        let kept_envelope = envelope(10, H256::repeat_byte(10));

        let database = Database::persistent(
            "test_db",
            TempDir::new()?,
            ByteSize::mib(10),
            DatabaseMode::ReadWrite,
            None,
        )?;

        database.put_batch_raw(vec![
            serialize(
                EnvelopeByBlockRoot::full(H256::repeat_byte(1)),
                &legacy_envelope,
            )?,
            serialize(
                EnvelopeRootBySlot(1, H256::repeat_byte(1)),
                H256::repeat_byte(1),
            )?,
        ])?;

        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            StorageMode::default(),
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )?;

        storage.append_execution_payload_envelopes([
            Arc::new(new_envelope.clone()),
            Arc::new(kept_envelope.clone()),
        ])?;

        assert!(matches!(
            storage.envelope_by_root(H256::repeat_byte(1))?,
            Some(StoredEnvelope::Full(envelope)) if *envelope == legacy_envelope,
        ));
        assert!(matches!(
            storage.envelope_by_root(H256::repeat_byte(3))?,
            Some(StoredEnvelope::Full(envelope)) if *envelope == new_envelope,
        ));

        storage.prune_old_execution_payload_envelopes(5)?;

        assert!(storage.envelope_by_root(H256::repeat_byte(1))?.is_none());
        assert!(storage.envelope_by_root(H256::repeat_byte(3))?.is_none());
        assert!(matches!(
            storage.envelope_by_root(H256::repeat_byte(10))?,
            Some(StoredEnvelope::Full(envelope)) if *envelope == kept_envelope,
        ));

        Ok(())
    }

    #[test]
    fn test_append_execution_payload_envelopes() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

        let envelope = Arc::new(SignedExecutionPayloadEnvelope::default());
        let block_root = envelope.block_root();

        assert_eq!(
            storage.append_execution_payload_envelopes([envelope.clone_arc()])?,
            [block_root],
        );
        assert!(matches!(
            storage.envelope_by_root(block_root)?,
            Some(StoredEnvelope::Full(stored)) if stored == envelope,
        ));

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
    fn the_checkpoint_state_slot_is_read_without_decoding_the_state() -> Result<()> {
        let database = Database::in_memory();

        database.put_batch_raw(vec![serialize(
            StateCheckpoint::<Mainnet>::KEY,
            StateCheckpoint {
                block_root: H256::repeat_byte(1),
                head_slot: 4096,
                state: Arc::new(BeaconState::<Mainnet>::Phase0(
                    Phase0BeaconState {
                        slot: 4064,
                        ..Phase0BeaconState::default()
                    }
                    .into(),
                )),
            },
        )?])?;

        let value_bytes = database
            .get(StateCheckpoint::<Mainnet>::KEY)?
            .expect("the checkpoint was just written");

        let state_bytes = ssz::subslice(
            &value_bytes,
            StateCheckpoint::<Mainnet>::STATE_START..value_bytes.len(),
        )?;

        assert_eq!(BeaconState::<Mainnet>::slot_from_ssz(state_bytes)?, 4064);

        Ok(())
    }

    #[test]
    fn append_finalized_state_resolves_the_delta_parent_from_the_spine() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

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

        let states = batch
            .iter()
            .filter(|(key, _)| key.starts_with(StateByBlockRoot::PREFIX))
            .collect_vec();

        let [(key, _)] = states.as_slice() else {
            panic!("exactly one state must have been written, got {states:?}");
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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

        let state = state_with_slot(32);
        let validators = state.validators();
        let block_root = H256::repeat_byte(2);

        // Slot 32 is a leaf whose hierarchy parent exists but is not stored, so the state cannot
        // be re-encoded as a delta. A snapshot of it is already on disk, as the unloading of
        // unfinalized states leaves behind.
        assert!(storage.hierarchy.is_leaf::<Mainnet>(&storage.config, 0, 32));

        let snapshot_key = StateByBlockRoot::snapshot(block_root);

        storage.database.put_batch_raw(vec![(
            serialize_key(&snapshot_key),
            BeaconStateFrame::new(
                &state,
                validators.len_usize(),
                storage.zstd_compression_level,
            )
            .to_ssz()?,
        )])?;

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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

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

            (
                slot,
                Some(H256::from_low_u64_be(index)),
                state_with_slot(slot),
            )
        });

        storage.append_finalized_states(states, 0, finalized_validators)?;

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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

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
            1056,
            StateByBlockRoot::snapshot(H256::repeat_byte(3)),
            state_with_slot(1056),
        );

        storage.prune_old_blocks_and_states(1025)?;

        assert!(spine.get(0).is_some());
        assert!(spine.get(512).is_none());
        assert!(spine.get(1056).is_some());

        Ok(())
    }

    /// Writes a snapshot and a delta against it, then reads the delta back
    /// from the database with the spine cleared, so the reconstruction path
    /// runs for real.
    #[test]
    fn storage_appends_and_reads_states() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        // Slot 512 has no ancestor on disk and is not a leaf, so it is written
        // as a snapshot; slot 544 then delta-encodes against it.
        let snapshot_root = H256::repeat_byte(1);
        let delta_root = H256::repeat_byte(2);

        storage.append_finalized_states(
            [
                (512, Some(snapshot_root), state_with_slot(512)),
                (544, Some(delta_root), state_with_slot(544)),
            ],
            0,
            finalized_validators,
        )?;

        storage.forward_spine().clear();

        let (key, state) = storage
            .state_with_key_by_block_root(delta_root, Some(finalized_validators))?
            .expect("the delta-encoded state must be readable");

        assert_eq!(key.parents, vec![snapshot_root]);
        assert_eq!(state.slot(), 544);

        Ok(())
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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let snapshot_root = H256::repeat_byte(1);
        let delta_root = H256::repeat_byte(2);

        storage.append_finalized_states(
            [
                (512, Some(snapshot_root), state_with_slot(512)),
                (544, Some(delta_root), state_with_slot(544)),
            ],
            0,
            finalized_validators,
        )?;

        assert!(storage.forward_spine().get(544).is_some());

        let (warm_key, warm_state) = storage
            .state_with_key_by_block_root(delta_root, Some(finalized_validators))?
            .expect("the delta-encoded state must be readable from the spine");

        // The intermediate frame only: the leaf is resolved from disk, but its
        // parent is still short-circuited.
        let (parent_key, parent_state) = storage
            .forward_spine()
            .get(512)
            .expect("slot 512 was just appended");

        storage.forward_spine().clear();
        storage
            .forward_spine()
            .insert(512, parent_key, parent_state);

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

    fn append_states_with_randao_reveals(
        storage: &Storage<Mainnet>,
        node_slot: Slot,
    ) -> Result<Vec<Arc<BeaconState<Mainnet>>>> {
        let config = Config {
            min_genesis_active_validator_count: Config::minimal()
                .min_genesis_active_validator_count,
            ..Config::mainnet()
        };

        let pubkey_cache = PubkeyCache::default();
        let (genesis_state, _) = factory::min_genesis_state::<Mainnet>(&config, &pubkey_cache)?;
        let genesis_root = H256::repeat_byte(1);

        let mut state = genesis_state.clone_arc();
        let mut states = vec![];
        let mut batch = vec![serialize(
            BlockRootBySlot(0),
            BlockRootBySlotValue::Block(genesis_root),
        )?];
        let mut node_root = genesis_root;

        for slot in [1, 3, node_slot] {
            states.resize(usize::try_from(slot)?, state.clone_arc());

            let (block, post_state) =
                factory::empty_block(&config, &pubkey_cache, state, slot, H256::zero())?;

            node_root = block.message().hash_tree_root();

            batch.push(serialize(
                BlockRootBySlot(slot),
                BlockRootBySlotValue::Block(node_root),
            )?);
            batch.push(serialize(
                FinalizedBlockByRoot::full(node_root),
                block.as_ref(),
            )?);

            state = post_state;
        }

        states.push(state.clone_arc());

        storage.database.put_batch_raw(batch)?;

        storage.append_finalized_states(
            [
                (0, Some(genesis_root), genesis_state.clone_arc()),
                (node_slot, Some(node_root), state),
            ],
            0,
            genesis_state.validators(),
        )?;

        storage.clear_caches();

        Ok(states)
    }

    #[test]
    fn stored_randao_mixes_read_slot_diffs_between_stored_states() -> Result<()> {
        let storage = storage_for_chain_reads();
        let states = append_states_with_randao_reveals(&storage, 32)?;

        for (slot, state) in (0..).zip(&states) {
            let rows = storage
                .state_rows_before_or_at(slot)?
                .expect("the anchor state is stored");

            let StateRandaoMixes { randao_mixes, .. } =
                StateRandaoMixes::reconstruct(slot, rows)?.expect("every slot has a stored mix");

            let epoch = misc::compute_epoch_at_slot::<Mainnet>(slot);

            assert_eq!(
                *randao_mixes.mod_index(epoch),
                accessors::get_randao_mix(state, accessors::get_current_epoch(state)),
                "RANDAO mix in slot {slot}",
            );
        }

        let rows = storage
            .state_rows_before_or_at(32)?
            .expect("the node state is stored");

        let StateRandaoMixes { randao_mixes, .. } =
            StateRandaoMixes::reconstruct(32, rows)?.expect("the node state has mixes");

        assert_eq!(
            *randao_mixes.mod_index(0),
            accessors::get_randao_mix(&states[31], 0),
        );

        Ok(())
    }

    #[test]
    fn slot_diffs_are_not_stored_without_a_state_in_every_epoch() -> Result<()> {
        let directory = TempDir::new()?;
        let storage = storage_with_hierarchy(&directory, [9, 6])?;

        append_states_with_randao_reveals(&storage, 64)?;

        assert!(
            !storage.contains_key(SlotDiffsBySlot(0))?,
            "the diffs between slots 0 and 64 would hold an epoch transition",
        );

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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid")
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

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        let anchor_state = state_with_validators(0, 6, 0);
        let parent_state = state_with_validators(512, 6, 1_000);
        let child_state = state_with_validators(544, 6, 2_000);

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), anchor_state.clone_arc()),
                (512, Some(parent_root), parent_state.clone_arc()),
                (544, Some(child_root), child_state.clone_arc()),
            ],
            0,
            finalized_validators,
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

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        let anchor_state = state_with_validators(0, 6, 0);
        let parent_state = state_with_validators(512, 7, 1_000);
        let child_state = state_with_validators(544, 8, 2_000);

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), anchor_state.clone_arc()),
                (512, Some(parent_root), parent_state.clone_arc()),
                (544, Some(child_root), child_state.clone_arc()),
            ],
            0,
            finalized_validators,
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

    fn state_with_finalized_epoch(slot: Slot, epoch: Epoch) -> Arc<BeaconState<Mainnet>> {
        let mut state = state_with_validators(slot, 6, 0);

        state.make_mut().finalized_checkpoint_mut().epoch = epoch;

        state
    }

    #[test]
    fn finality_checkpoints_are_read_through_a_delta_chain() -> Result<()> {
        let storage = storage_for_chain_reads();

        let validator_source = state_with_validators(0, 6, 0);
        let finalized_validators = validator_source.validators();

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        storage.database.put_batch_raw(
            [(0, anchor_root), (512, parent_root), (544, child_root)]
                .into_iter()
                .map(|(slot, root)| {
                    serialize(BlockRootBySlot(slot), BlockRootBySlotValue::Block(root))
                })
                .collect::<Result<_>>()?,
        )?;

        let justified = |mut state: Arc<BeaconState<Mainnet>>| {
            state.make_mut().previous_justified_checkpoint_mut().epoch = 14;
            state.make_mut().current_justified_checkpoint_mut().epoch = 15;
            state
        };

        let anchor_state = justified(state_with_finalized_epoch(0, 0));
        let parent_state = justified(state_with_finalized_epoch(512, 15));
        let child_state = justified(state_with_finalized_epoch(544, 16));

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), anchor_state.clone_arc()),
                (512, Some(parent_root), parent_state.clone_arc()),
                (544, Some(child_root), child_state.clone_arc()),
            ],
            0,
            finalized_validators,
        )?;

        let read = |slot| -> Result<Option<FinalityCheckpoints>> {
            let Some(rows) = storage.state_rows_before_or_at(slot)? else {
                return Ok(None);
            };

            FinalityCheckpoints::reconstruct(slot, rows)
        };

        for clear_caches in [false, true] {
            if clear_caches {
                storage.clear_caches();
            }

            assert_eq!(
                read(547)?,
                Some(FinalityCheckpoints::from_state(&child_state)),
            );
            assert_eq!(
                read(543)?,
                Some(FinalityCheckpoints::from_state(&parent_state)),
            );
            assert_eq!(
                read(31)?,
                Some(FinalityCheckpoints::from_state(&anchor_state)),
            );
            assert_eq!(read(576)?, None);
        }

        save(&storage.database, PrunedUpToKey, 520_u64)?;

        assert_eq!(read(543)?, None);
        assert_eq!(
            read(547)?,
            Some(FinalityCheckpoints::from_state(&child_state)),
        );

        Ok(())
    }

    #[test]
    fn committee_fields_are_read_through_a_delta_chain() -> Result<()> {
        let storage = storage_for_chain_reads();

        let validator_source = state_with_validators(0, 8, 0);
        let finalized_validators = validator_source.validators();

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        storage.database.put_batch_raw(
            [(0, anchor_root), (512, parent_root), (544, child_root)]
                .into_iter()
                .map(|(slot, root)| {
                    serialize(BlockRootBySlot(slot), BlockRootBySlotValue::Block(root))
                })
                .collect::<Result<_>>()?,
        )?;

        let with_mix = |mut state: Arc<BeaconState<Mainnet>>, epoch, byte| {
            *state.make_mut().randao_mixes_mut().mod_index_mut(epoch) = H256::repeat_byte(byte);
            state
        };

        let anchor_state = state_with_validators(0, 6, 0);
        let parent_state = with_mix(state_with_validators(512, 7, 1), 16, 7);
        let child_state = with_mix(with_mix(state_with_validators(544, 8, 2), 16, 7), 17, 8);

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), anchor_state),
                (512, Some(parent_root), parent_state.clone_arc()),
                (544, Some(child_root), child_state.clone_arc()),
            ],
            0,
            finalized_validators,
        )?;

        let read = |slot| -> Result<_> {
            let Some(rows) = storage.state_rows_before_or_at(slot)? else {
                return Ok(None);
            };

            Ok(CommitteeFields::reconstruct(slot, rows)?.map(|fields| {
                (
                    fields.slot,
                    fields.validators.partial_validators,
                    fields.validators.effective_balances,
                    fields.randao_mixes.hash_tree_root(),
                )
            }))
        };

        let expected = |slot, state: &BeaconState<Mainnet>| {
            Some((
                slot,
                state.validators().partial_validators().copied().collect(),
                state.validators().effective_balances().copied().collect(),
                state.randao_mixes().hash_tree_root(),
            ))
        };

        for clear_caches in [false, true] {
            if clear_caches {
                storage.clear_caches();
            }

            assert_eq!(read(547)?, expected(547, &child_state));
            assert_eq!(read(543)?, expected(543, &parent_state));
            assert_eq!(read(576)?, None);
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

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        let anchor_state = state_with_validators(0, 6, 0);
        let parent_state = state_with_validators(512, 7, 1_000);
        let child_state = state_with_validators(544, 8, 2_000);

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), anchor_state.clone_arc()),
                (512, Some(parent_root), parent_state.clone_arc()),
                (544, Some(child_root), child_state.clone_arc()),
            ],
            0,
            finalized_validators,
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
            assert_eq!(parsed.encoding, key.encoding);
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

        assert_eq!(key.encoding, StateEncoding::LegacySnappy);
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
        ))
        .map(drop)?;

        // The snappy key sorts before the zstd one, so leaving it in place would shadow the
        // snapshot just written and orphan a whole state on disk.
        let key = storage
            .state_key_by_block_root(anchor_block_root)?
            .expect("the anchor state must be stored");

        assert_eq!(key.encoding, StateEncoding::Frame);
        assert!(key.parents.is_empty());

        Ok(())
    }

    #[test]
    fn a_chain_whose_frame_was_pruned_reads_as_absent_rather_than_failing() -> Result<()> {
        let storage = storage_for_chain_reads();

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let anchor_root = H256::repeat_byte(1);
        let child_root = H256::repeat_byte(2);

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), state_with_slot(0)),
                (512, Some(child_root), state_with_slot(512)),
            ],
            0,
            finalized_validators,
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

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        // The anchor is not on disk yet, so 512 is written as a snapshot and
        // 544 delta-encodes against it.
        storage.append_finalized_states(
            [
                (512, Some(parent_root), state_with_slot(512)),
                (544, Some(child_root), state_with_slot(544)),
            ],
            0,
            finalized_validators,
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
                (0, Some(anchor_root), state_with_slot(0)),
                (512, Some(parent_root), state_with_slot(512)),
            ],
            0,
            finalized_validators,
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

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), state_with_slot(0)),
                (512, Some(parent_root), state_with_slot(512)),
                (544, Some(child_root), state_with_slot(544)),
            ],
            0,
            finalized_validators,
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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig {
                cache_sizes: vec![5],
                ..StateStorageConfig::default_for_mode(StorageMode::default())
            },
        )
        .expect("state cache sizes in tests are valid");

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), state_with_slot(0)),
                (512, Some(parent_root), state_with_slot(512)),
            ],
            0,
            finalized_validators,
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
    fn a_cache_size_that_cannot_be_allocated_is_reported_rather_than_panicking() {
        // `StateStorageConfig::validate` only warns about oversized caches, so this is the first
        // place a size the machine cannot hold is refused.
        let result = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig {
                hierarchy: Hierarchy::new([5]).expect("exponents in tests are valid"),
                cache_sizes: vec![usize::MAX],
            },
        );

        let Err(error) = result else {
            panic!("a cache of usize::MAX states cannot be allocated")
        };

        assert!(
            error
                .to_string()
                .starts_with("unable to instantiate a state cache layer of size"),
            "unexpected error: {error}",
        );
    }

    #[test]
    fn an_empty_cache_sizes_list_leaves_every_layer_uncached() -> Result<()> {
        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            Database::in_memory(),
            StorageMode::default(),
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig {
                cache_sizes: vec![],
                ..StateStorageConfig::default_for_mode(StorageMode::default())
            },
        )
        .expect("state cache sizes in tests are valid");

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), state_with_slot(0)),
                (512, Some(parent_root), state_with_slot(512)),
            ],
            0,
            finalized_validators,
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

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), state_with_slot(0)),
                (512, Some(parent_root), state_with_slot(512)),
                (544, Some(child_root), state_with_slot(544)),
            ],
            0,
            finalized_validators,
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

        let anchor_root = H256::repeat_byte(1);
        let parent_root = H256::repeat_byte(2);
        let child_root = H256::repeat_byte(3);

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), state_with_slot(0)),
                (512, Some(parent_root), state_with_slot(512)),
                (544, Some(child_root), state_with_slot(544)),
            ],
            0,
            finalized_validators,
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
            true,
            DEFAULT_ZSTD_COMPRESSION_LEVEL,
            StateStorageConfig::default_for_mode(StorageMode::default()),
        )
        .expect("state cache sizes in tests are valid");

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

    fn state_with_slot_and_marker(
        slot: Slot,
        eth1_deposit_index: u64,
    ) -> Arc<BeaconState<Mainnet>> {
        Arc::new(BeaconState::Phase0(
            Phase0BeaconState {
                slot,
                eth1_deposit_index,
                ..Phase0BeaconState::default()
            }
            .into(),
        ))
    }

    #[test]
    fn block_root_by_slot_values_round_trip_through_their_byte_form() -> Result<()> {
        for root in [H256::repeat_byte(0x11), H256::repeat_byte(b'f')] {
            let block = BlockRootBySlotValue::Block(root);
            let blockless = BlockRootBySlotValue::Blockless(root);

            assert_eq!(block.to_ssz()?, root.to_ssz()?);
            assert_eq!(
                serialize(BlockRootBySlot(7), block)?,
                serialize(BlockRootBySlot(7), root)?,
            );

            let mut blockless_bytes = vec![b'f'];
            blockless_bytes.extend_from_slice(root.as_bytes());

            assert_eq!(blockless.to_ssz()?, blockless_bytes);

            assert_eq!(
                BlockRootBySlotValue::from_ssz_default(root.as_bytes())?,
                block,
            );
            assert_eq!(
                BlockRootBySlotValue::from_ssz_default(&blockless_bytes)?,
                blockless,
            );

            assert_eq!(block.block_root(), Some(root));
            assert_eq!(block.state_key_root(), root);
            assert_eq!(blockless.block_root(), None);
            assert_eq!(blockless.state_key_root(), root);
        }

        Ok(())
    }

    #[test]
    fn a_blockless_root_hashes_the_state_root_followed_by_the_marker() -> Result<()> {
        let expected =
            "8bfb11946ec2ecd2554260c4d4c97b92e99ccd28ae15af271d7060dd6c6f3b83".parse::<H256>()?;

        assert_eq!(
            BlockRootBySlotValue::blockless(H256::repeat_byte(0x11)),
            BlockRootBySlotValue::Blockless(expected),
        );

        Ok(())
    }

    #[test]
    fn malformed_block_root_by_slot_values_are_rejected() {
        let root = H256::repeat_byte(0x11);

        let mut wrong_marker = vec![b'g'];
        wrong_marker.extend_from_slice(root.as_bytes());

        let mut too_long = vec![b'f'];
        too_long.extend_from_slice(root.as_bytes());
        too_long.push(0);

        for bytes in [
            vec![],
            vec![b'f'],
            root.as_bytes()[..31].to_vec(),
            wrong_marker,
            too_long,
        ] {
            assert!(
                BlockRootBySlotValue::from_ssz_default(&bytes).is_err(),
                "{bytes:?} must be rejected",
            );
        }
    }

    #[test]
    fn slot_lookups_see_blockless_rows_only_where_a_state_is_wanted() -> Result<()> {
        let storage = storage_for_chain_reads();

        let block_root = H256::repeat_byte(2);
        let blockless_root = H256::repeat_byte(0xaa);

        storage.database.put_batch_raw(vec![
            serialize(BlockRootBySlot(2), block_root)?,
            serialize(
                BlockRootBySlot(4),
                BlockRootBySlotValue::Blockless(blockless_root),
            )?,
        ])?;

        assert_eq!(storage.block_root_by_slot(2)?, Some(block_root));
        assert_eq!(
            storage.block_root_by_slot_value(2)?,
            Some(BlockRootBySlotValue::Block(block_root)),
        );

        assert_eq!(storage.block_root_by_slot(4)?, None);
        assert_eq!(
            storage.block_root_by_slot_value(4)?,
            Some(BlockRootBySlotValue::Blockless(blockless_root)),
        );

        assert_eq!(storage.block_root_before_or_at_slot(4)?, Some(block_root));
        assert_eq!(storage.block_root_before_or_at_slot(5)?, Some(block_root));
        assert_eq!(storage.block_root_after_slot(2)?, None);

        Ok(())
    }

    #[test]
    fn the_checkpoint_replay_scan_skips_blockless_rows() -> Result<()> {
        let storage = storage_for_chain_reads();

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let anchor_block = Arc::new(block_with_slot(0));
        let root_1 = H256::repeat_byte(1);
        let root_3 = H256::repeat_byte(3);

        storage.database.put_batch_raw(vec![
            serialize(
                StateCheckpoint::<Mainnet>::KEY,
                StateCheckpoint {
                    block_root: anchor_block.message().hash_tree_root(),
                    head_slot: 3,
                    state: state_with_slot(0),
                },
            )?,
            serialize(
                BlockCheckpoint::<Mainnet>::KEY,
                BlockCheckpoint {
                    block: anchor_block,
                },
            )?,
            serialize(BlockRootBySlot(1), BlockRootBySlotValue::Block(root_1))?,
            serialize(FinalizedBlockByRoot::full(root_1), block_with_slot(1))?,
            serialize(
                BlockRootBySlot(2),
                BlockRootBySlotValue::Blockless(H256::repeat_byte(0xaa)),
            )?,
            serialize(BlockRootBySlot(3), BlockRootBySlotValue::Block(root_3))?,
            serialize(FinalizedBlockByRoot::full(root_3), block_with_slot(3))?,
        ])?;

        let (state, _, blocks) = storage
            .load_state_and_blocks_from_checkpoint(Some(finalized_validators))?
            .expect("the checkpoint was written above");

        assert_eq!(state.slot(), 0);

        let slots = blocks
            .map(|block| block.map(|block| block.message().slot()))
            .collect::<Result<Vec<_>>>()?;

        assert_eq!(slots, [1, 3]);

        Ok(())
    }

    fn storage_with_a_blockless_state(
        directory: &TempDir,
    ) -> Result<(Storage<Mainnet>, Arc<BeaconState<Mainnet>>, H256)> {
        let storage = storage_with_hierarchy(directory, [9, 5, 3])?;

        let validator_source = state_with_slot(0);

        let anchor_root = H256::repeat_byte(1);
        let child_root = H256::repeat_byte(40);

        let blockless_state = state_with_slot_and_marker(32, 2);
        let blockless_root =
            BlockRootBySlotValue::blockless(blockless_state.hash_tree_root()).state_key_root();

        storage.database.put_batch_raw(vec![
            serialize(BlockRootBySlot(0), BlockRootBySlotValue::Block(anchor_root))?,
            serialize(FinalizedBlockByRoot::full(anchor_root), block_with_slot(0))?,
            serialize(BlockRootBySlot(40), BlockRootBySlotValue::Block(child_root))?,
            serialize(FinalizedBlockByRoot::full(child_root), block_with_slot(40))?,
        ])?;

        storage.append_finalized_states(
            [
                (0, Some(anchor_root), state_with_slot_and_marker(0, 1)),
                (32, None, blockless_state),
            ],
            0,
            validator_source.validators(),
        )?;

        Ok((storage, validator_source, blockless_root))
    }

    #[test]
    fn a_hierarchy_ancestor_is_found_through_a_blockless_row() -> Result<()> {
        let directory = TempDir::new()?;
        let (storage, validator_source, blockless_root) =
            storage_with_a_blockless_state(&directory)?;
        let finalized_validators = validator_source.validators();

        storage.clear_caches();

        let child_root = H256::repeat_byte(40);
        storage.append_finalized_states(
            [(40, Some(child_root), state_with_slot_and_marker(40, 3))],
            0,
            finalized_validators,
        )?;

        let key = storage
            .state_key_by_block_root(child_root)?
            .expect("the state at slot 40 was appended above");

        assert_eq!(key.parents.first(), Some(&blockless_root));

        storage.clear_caches();

        let state = storage
            .state_by_block_root(child_root, Some(finalized_validators))?
            .expect("the state at slot 40 must be readable");

        assert_eq!(state.slot(), 40);
        assert_eq!(state.eth1_deposit_index(), 3);

        Ok(())
    }

    #[test]
    fn a_blockless_state_is_a_replay_base_but_never_an_anchor() -> Result<()> {
        let directory = TempDir::new()?;
        let (storage, validator_source, _) = storage_with_a_blockless_state(&directory)?;
        let finalized_validators = validator_source.validators();

        let OptionalStateStorage::Blockless(state, blocks) =
            storage.load_state_by_iteration(40, Some(finalized_validators), false)?
        else {
            panic!("the blockless state at slot 32 must be found");
        };

        assert_eq!(state.slot(), 32);
        assert_eq!(state.eth1_deposit_index(), 2);
        assert_eq!(blocks.count(), 1);

        let stored = storage
            .stored_state(32, Some(finalized_validators))?
            .expect("the blockless state at slot 32 must be readable by slot");

        assert_eq!(stored.eth1_deposit_index(), 2);

        let advanced = storage
            .stored_state(33, Some(finalized_validators))?
            .expect("the blockless state at slot 32 must be replayable to slot 33");

        assert_eq!(advanced.slot(), 33);
        assert_eq!(advanced.eth1_deposit_index(), 2);
        assert_eq!(
            *advanced.state_roots().mod_index(32),
            state_with_slot_and_marker(32, 2).hash_tree_root(),
        );

        let OptionalStateStorage::Full((anchor_state, anchor_block, anchor_blocks)) =
            storage.load_state_by_iteration(40, Some(finalized_validators), true)?
        else {
            panic!("the state at slot 0 must be found");
        };

        assert_eq!(anchor_state.slot(), 0);
        assert_eq!(anchor_block.message().slot(), 0);
        assert_eq!(anchor_blocks.count(), 1);

        Ok(())
    }

    #[test]
    fn a_blockless_row_without_a_state_is_scanned_past() -> Result<()> {
        let directory = TempDir::new()?;
        let storage = storage_with_hierarchy(&directory, [9, 3])?;

        let validator_source = state_with_slot(0);
        let finalized_validators = validator_source.validators();

        let anchor_root = H256::repeat_byte(1);
        let child_root = H256::repeat_byte(16);

        storage.database.put_batch_raw(vec![
            serialize(BlockRootBySlot(0), BlockRootBySlotValue::Block(anchor_root))?,
            serialize(FinalizedBlockByRoot::full(anchor_root), block_with_slot(0))?,
            serialize(
                BlockRootBySlot(8),
                BlockRootBySlotValue::Blockless(H256::repeat_byte(0xaa)),
            )?,
            serialize(BlockRootBySlot(16), BlockRootBySlotValue::Block(child_root))?,
            serialize(FinalizedBlockByRoot::full(child_root), block_with_slot(16))?,
        ])?;

        storage.append_finalized_states(
            [(0, Some(anchor_root), state_with_slot(0))],
            0,
            finalized_validators,
        )?;

        let OptionalStateStorage::Full((state, block, blocks)) =
            storage.load_state_by_iteration(16, Some(finalized_validators), false)?
        else {
            panic!("the state at slot 0 must be found");
        };

        assert_eq!(state.slot(), 0);
        assert_eq!(block.message().slot(), 0);

        let slots = blocks
            .map(|block| block.map(|block| block.message().slot()))
            .collect::<Result<Vec<_>>>()?;

        assert_eq!(slots, [16]);

        Ok(())
    }

    #[test]
    fn pruning_deletes_a_blockless_row_with_its_state_and_keeps_a_retained_one() -> Result<()> {
        let directory = TempDir::new()?;
        let (storage, validator_source, blockless_root) =
            storage_with_a_blockless_state(&directory)?;
        let finalized_validators = validator_source.validators();

        storage.prune_old_blocks_and_states(41)?;

        assert_eq!(
            storage.block_root_by_slot_value(32)?,
            Some(BlockRootBySlotValue::Blockless(blockless_root)),
        );
        assert!(storage.state_key_by_block_root(blockless_root)?.is_some());

        storage.prune_old_blocks_and_states(65)?;

        assert_eq!(storage.block_root_by_slot_value(32)?, None);
        assert!(storage.state_key_by_block_root(blockless_root)?.is_none());
        assert_eq!(storage.block_root_by_slot_value(40)?, None);
        assert!(
            storage
                .state_by_block_root(H256::repeat_byte(1), Some(finalized_validators))?
                .is_some()
        );

        Ok(())
    }

    #[test]
    fn pruning_unfinalized_blocks_leaves_a_blockless_row_alone() -> Result<()> {
        let storage = storage_for_chain_reads();

        let unfinalized_root = H256::repeat_byte(8);
        let blockless = BlockRootBySlotValue::Blockless(H256::repeat_byte(0xaa));

        storage.database.put_batch_raw(vec![
            serialize(UnfinalizedBlockByRoot(unfinalized_root), block_with_slot(8))?,
            serialize(BlockRootBySlot(8), blockless)?,
        ])?;

        assert_eq!(storage.prune_unfinalized_blocks(8)?, [8]);
        assert_eq!(storage.block_root_by_slot_value(8)?, Some(blockless));

        Ok(())
    }
}
