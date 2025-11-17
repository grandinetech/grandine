use core::{cell::OnceCell, marker::PhantomData, num::NonZeroU64};
use std::{borrow::Cow, sync::Arc};

use anyhow::{bail, ensure, Context as _, Error as AnyhowError, Result};
use database::{Database, PrefixableKey};
use derive_more::Display;
use fork_choice_store::{ChainLink, Store};
use genesis::AnchorCheckpointProvider;
use helper_functions::{accessors, misc};
use itertools::Itertools as _;
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use nonzero_ext::nonzero;
use pubkey_cache::PubkeyCache;
use reqwest::Client;
use ssz::{Ssz, SszRead, SszReadDefault, SszWrite};
use std_ext::ArcExt as _;
use thiserror::Error;
use transition_functions::combined;
use types::{
    combined::{BeaconState, DataColumnSidecar, SignedBeaconBlock},
    config::Config,
    deneb::{
        containers::{BlobIdentifier, BlobSidecar},
        primitives::BlobIndex,
    },
    fulu::{containers::DataColumnIdentifier, primitives::ColumnIndex},
    gloas::containers::SignedExecutionPayloadEnvelope,
    nonstandard::{BlobSidecarWithId, DataColumnSidecarWithId, FinalizedCheckpoint},
    phase0::{
        consts::GENESIS_SLOT,
        primitives::{Epoch, Slot, H256},
    },
    preset::Preset,
    redacting_url::RedactingUrl,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::{checkpoint_sync, StorageMode};

pub const DEFAULT_ARCHIVAL_EPOCH_INTERVAL: NonZeroU64 = nonzero!(32_u64);

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
pub struct Storage<P> {
    config: Arc<Config>,
    pub(crate) database: Arc<Database>,
    pub(crate) archival_epoch_interval: NonZeroU64,
    storage_mode: StorageMode,
    pub(crate) pubkey_cache: Arc<PubkeyCache>,
    phantom: PhantomData<P>,
}

impl<P: Preset> Storage<P> {
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        pubkey_cache: Arc<PubkeyCache>,
        database: Database,
        archival_epoch_interval: NonZeroU64,
        storage_mode: StorageMode,
    ) -> Self {
        Self {
            config,
            pubkey_cache,
            database: Arc::new(database),
            archival_epoch_interval,
            storage_mode,
            phantom: PhantomData,
        }
    }

    #[must_use]
    pub(crate) const fn config(&self) -> &Arc<Config> {
        &self.config
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
                    Some(slot) => self.load_state_by_iteration(slot)?,
                    None => self.load_latest_state()?,
                };

                if let Some(url) = checkpoint_sync_url {
                    if local_state_storage.is_none() {
                        let result = if let Some(checkpoint) =
                            anchor_checkpoint_provider.checkpoint().checkpoint_synced()
                        {
                            info_with_peers!("anchor checkpoint is already loaded from remote checkpoint sync server");
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

        let anchor_slot = anchor_block.message().slot();
        let anchor_block_root = anchor_block.message().hash_tree_root();
        let anchor_state_root = anchor_block.message().state_root();

        info_with_peers!("loaded state at slot {anchor_slot}");

        self.database.put_batch([
            serialize(FinalizedBlockByRoot(anchor_block_root), &anchor_block)?,
            serialize(BlockRootBySlot(anchor_slot), anchor_block_root)?,
            serialize(SlotByStateRoot(anchor_state_root), anchor_slot)?,
            serialize(StateByBlockRoot(anchor_block_root), &anchor_state)?,
        ])?;

        let state_storage = (anchor_state, anchor_block, unfinalized_blocks);

        Ok((state_storage, loaded_from_remote))
    }

    fn load_latest_state(&self) -> Result<OptionalStateStorage<'_, P>> {
        if let Some((state, block, blocks)) = self.load_state_and_blocks_from_checkpoint()? {
            Ok(OptionalStateStorage::Full((state, block, blocks)))
        } else {
            info_with_peers!(
                "latest state checkpoint was not found; \
                 attempting to find stored state by iteration",
            );

            self.load_state_by_iteration(Slot::MAX)
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
        let mut archival_state_appended = false;
        let mut batch = vec![];

        let unfinalized = unfinalized.zip(core::iter::repeat(false));
        let finalized = finalized.rev().zip(core::iter::repeat(true));

        let mut chain = unfinalized
            .chain(finalized)
            .filter(|(chain_link, is_finalized)| *is_finalized || chain_link.is_valid())
            .peekable();

        if let Some(StateCheckpoint { head_slot, .. }) = self.load_state_checkpoint()? {
            store_head_slot = head_slot;
        }

        if let Some((chain_link, _)) = chain.peek() {
            store_head_slot = chain_link.slot().max(store_head_slot);
        }

        debug_with_peers!("saving store head slot: {store_head_slot}");

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

                let state = OnceCell::new();

                if !checkpoint_state_appended {
                    let append_state = misc::is_epoch_start::<P>(state_slot);

                    if append_state {
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
                                state: state.get_or_init(|| chain_link.state(store)).clone_arc(),
                            },
                        )?);

                        checkpoint_state_appended = true;
                    }
                }

                if !archival_state_appended && !self.prune_storage_enabled() {
                    let state_epoch = Self::epoch_at_slot(state_slot);
                    let append_state = misc::is_epoch_start::<P>(state_slot)
                        && state_epoch.is_multiple_of(self.archival_epoch_interval.into());

                    if append_state {
                        info_with_peers!("saving state in slot {state_slot}");

                        batch.push(serialize(
                            StateByBlockRoot(block_root),
                            state.get_or_init(|| chain_link.state(store)),
                        )?);

                        archival_state_appended = true;
                    }
                }
            }
        }

        self.database.put_batch(batch)?;

        Ok(slots)
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

        self.database.put_batch(batch)?;

        Ok(persisted_blob_ids)
    }

    pub(crate) fn append_states(
        &self,
        states_with_block_roots: impl Iterator<Item = (Arc<BeaconState<P>>, H256)>,
    ) -> Result<Vec<Slot>> {
        let mut slots = vec![];
        let mut batch = vec![];

        for (state, block_root) in states_with_block_roots {
            if !self.contains_key(StateByBlockRoot(block_root))? {
                slots.push(state.slot());
                batch.push(serialize(StateByBlockRoot(block_root), state)?);
            }
        }

        self.database.put_batch(batch)?;

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
        let mut blobs_to_remove: Vec<BlobIdentifier> = vec![];
        let mut keys_to_remove = vec![];

        let results = self
            .database
            .iterator_descending(..=SlotBlobId(up_to_slot, H256::zero(), 0).to_string())?;

        for result in results {
            let (key_bytes, value_bytes) = result?;

            if !SlotBlobId::has_prefix(&key_bytes) {
                break;
            }

            // Deserialize-serialize BlobIdentifier as an additional measure
            // to prevent other types of data getting accidentally deleted.
            blobs_to_remove.push(BlobIdentifier::from_ssz_default(value_bytes)?);
            keys_to_remove.push(key_bytes.into_owned());
        }

        for blob_id in blobs_to_remove {
            let BlobIdentifier { block_root, index } = blob_id;
            let key = BlobSidecarByBlobId(block_root, index).to_string();

            self.database.delete(key)?;
        }

        for key in keys_to_remove {
            self.database.delete(key)?;
        }

        Ok(())
    }

    pub(crate) fn prune_old_blocks_and_states(&self, up_to_slot: Slot) -> Result<()> {
        let mut block_roots_to_remove = vec![];
        let mut keys_to_remove = vec![];

        let results = self
            .database
            .iterator_descending(..=BlockRootBySlot(up_to_slot.saturating_sub(1)).to_string())?;

        for result in results {
            let (key_bytes, value_bytes) = result?;

            if !BlockRootBySlot::has_prefix(&key_bytes) {
                break;
            }

            block_roots_to_remove.push(H256::from_ssz_default(value_bytes)?);
            keys_to_remove.push(key_bytes.into_owned());
        }

        for block_root in block_roots_to_remove {
            let key = FinalizedBlockByRoot(block_root).to_string();
            self.database.delete(key)?;

            let key = StateByBlockRoot(block_root).to_string();
            self.database.delete(key)?;
        }

        for key in keys_to_remove {
            self.database.delete(key)?;
        }

        Ok(())
    }

    pub(crate) fn prune_old_state_roots(&self, up_to_slot: Slot) -> Result<()> {
        let mut keys_to_remove = vec![];

        let results = self
            .database
            .iterator_ascending(SlotByStateRoot(H256::zero()).to_string()..)?;

        for result in results {
            let (key_bytes, value_bytes) = result?;

            if !SlotByStateRoot::has_prefix(&key_bytes) {
                break;
            }

            let slot = Slot::from_ssz_default(value_bytes)?;

            if slot < up_to_slot {
                keys_to_remove.push(key_bytes.into_owned());
            }
        }

        for key in keys_to_remove {
            self.database.delete(key)?;
        }

        Ok(())
    }

    pub(crate) fn prune_unfinalized_blocks(&self, last_finalized_slot: Slot) -> Result<Vec<Slot>> {
        let mut slots = vec![];
        let mut keys_to_remove = vec![];

        let results = self
            .database
            .iterator_ascending(serialize_key(UnfinalizedBlockByRoot(H256::zero()))..)?;

        for result in results {
            let (key_bytes, value_bytes) = result?;

            if !UnfinalizedBlockByRoot::has_prefix(&key_bytes) {
                break;
            }

            let unfinalized_block = SignedBeaconBlock::<P>::from_ssz(&self.config, value_bytes)?;
            let block_slot = unfinalized_block.message().slot();

            if block_slot <= last_finalized_slot {
                slots.push(block_slot);
                keys_to_remove.push(key_bytes.into_owned());
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

        for key in keys_to_remove {
            self.database.delete(key)?;
        }

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

        self.database.put_batch(batch)?;

        Ok(persisted_data_column_ids)
    }

    pub(crate) fn append_execution_payload_envelopes(
        &self,
        envelopes: impl IntoIterator<Item = Arc<SignedExecutionPayloadEnvelope<P>>>,
    ) -> Result<Vec<H256>> {
        let mut batch = vec![];
        let mut persisted_block_roots = vec![];

        for envelope in envelopes {
            let block_root = envelope.message.beacon_block_root;
            let slot = envelope.message.slot;

            batch.push(serialize(EnvelopeByBlockRoot(block_root), envelope)?);
            batch.push(serialize(EnvelopeRootBySlot(slot, block_root), block_root)?);

            persisted_block_roots.push(block_root);
        }

        self.database.put_batch(batch)?;

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
        let mut columns_to_remove: Vec<DataColumnIdentifier> = vec![];
        let mut keys_to_remove = vec![];

        let results = self
            .database
            .iterator_descending(..=SlotColumnId(up_to_slot, H256::zero(), 0).to_string())?;

        for result in results {
            let (key_bytes, value_bytes) = result?;

            if !SlotColumnId::has_prefix(&key_bytes) {
                break;
            }

            // Deserialize-serialize DataColumnIdentifier as an additional measure
            // to prevent other types of data getting accidentally deleted.
            columns_to_remove.push(DataColumnIdentifier::from_ssz_default(value_bytes)?);
            keys_to_remove.push(key_bytes.into_owned());
        }

        for column_id in columns_to_remove {
            let DataColumnIdentifier { block_root, index } = column_id;
            let key = DataColumnSidecarByColumnId(block_root, index).to_string();

            self.database.delete(key)?;
        }

        for key in keys_to_remove {
            self.database.delete(key)?;
        }

        Ok(())
    }

    pub(crate) fn prune_old_execution_payload_envelopes(&self, up_to_slot: Slot) -> Result<()> {
        let mut envelopes_to_remove: Vec<H256> = vec![];
        let mut keys_to_remove = vec![];

        let results = self
            .database
            .iterator_descending(..=EnvelopeRootBySlot(up_to_slot, H256::zero()).to_string())?;

        for result in results {
            let (key_bytes, value_bytes) = result?;

            if !EnvelopeRootBySlot::has_prefix(&key_bytes) {
                break;
            }

            let block_root = H256::from_ssz_default(value_bytes)?;
            envelopes_to_remove.push(block_root);
            keys_to_remove.push(key_bytes.into_owned());
        }

        for block_root in envelopes_to_remove {
            let key = EnvelopeByBlockRoot(block_root).to_string();
            self.database.delete(key)?;
        }

        for key in keys_to_remove {
            self.database.delete(key)?;
        }

        Ok(())
    }

    pub(crate) fn checkpoint_state_slot(&self) -> Result<Option<Slot>> {
        if let Some(StateCheckpoint { head_slot, .. }) = self.load_state_checkpoint()? {
            return Ok(Some(head_slot));
        }

        Ok(None)
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

    fn state_by_block_root(&self, block_root: H256) -> Result<Option<Arc<BeaconState<P>>>> {
        self.get(StateByBlockRoot(block_root))
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

    pub(crate) fn stored_state(&self, slot: Slot) -> Result<Option<Arc<BeaconState<P>>>> {
        let (mut state, state_block, blocks) = match self.load_state_by_iteration(slot)? {
            OptionalStateStorage::None | OptionalStateStorage::UnfinalizedOnly(_) => {
                return Ok(None)
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
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        let mut blocks = vec![];

        let mut state = loop {
            if let Some(state) = self.state_by_block_root(block_root)? {
                let slot = state.slot();

                ensure!(
                    misc::is_epoch_start::<P>(slot),
                    Error::PersistedSlotCannotContainAnchor { slot },
                );

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
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        if let Some(state_slot) = self.slot_by_state_root(state_root)? {
            return self.stored_state(state_slot);
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

    fn load_state_and_blocks_from_checkpoint(&self) -> Result<Option<StateStorage<'_, P>>> {
        if let Some(checkpoint) = self.load_state_checkpoint()? {
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

            let results = self
                .database
                .iterator_ascending(BlockRootBySlot(state.slot() + 1).to_string()..)?;

            let block_roots = itertools::process_results(results, |pairs| {
                pairs
                    .take_while(|(key_bytes, _)| BlockRootBySlot::has_prefix(key_bytes))
                    .map(|(_, value_bytes)| H256::from_ssz_default(value_bytes))
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
    ) -> Result<OptionalStateStorage<'_, P>> {
        let results = self
            .database
            .iterator_descending(..=BlockRootBySlot(start_from_slot).to_string())?;

        let mut block_roots = vec![];

        for result in results {
            let (key_bytes, value_bytes) = result?;

            if !BlockRootBySlot::has_prefix(&key_bytes) {
                break;
            }

            let block_root = H256::from_ssz_default(value_bytes)?;

            if self.contains_key(StateByBlockRoot(block_root))? {
                let Some(block) = self.finalized_block_by_root(block_root)? else {
                    // States are also persisted from unfinalized chain
                    continue;
                };

                if let Some(state) = self.state_by_block_root(block_root)? {
                    let slot = state.slot();

                    ensure!(
                        misc::is_epoch_start::<P>(slot),
                        Error::PersistedSlotCannotContainAnchor { slot },
                    );

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

    fn load_state_checkpoint(&self) -> Result<Option<StateCheckpoint<P>>> {
        self.get(StateCheckpoint::<P>::KEY)
    }

    fn contains_key(&self, key: impl core::fmt::Display) -> Result<bool> {
        let key_string = key.to_string();

        self.database.contains_key(key_string)
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

    pub(crate) fn epoch_at_slot(slot: Slot) -> Epoch {
        misc::compute_epoch_at_slot::<P>(slot)
    }
}

#[cfg(test)]
impl<P: Preset> Storage<P> {
    pub fn block_root_by_slot_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending(BlockRootBySlot(0).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| BlockRootBySlot::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn finalized_block_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending(FinalizedBlockByRoot(H256::zero()).to_string()..)?;

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
            .iterator_ascending(UnfinalizedBlockByRoot(H256::zero()).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| UnfinalizedBlockByRoot::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn slot_by_state_root_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending(SlotByStateRoot(H256::zero()).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| SlotByStateRoot::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn slot_by_blob_id_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending(SlotBlobId(0, H256::zero(), 0).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| SlotBlobId::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn state_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending(StateByBlockRoot(H256::zero()).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| StateByBlockRoot::has_prefix(key_bytes))
                .count()
        })
    }

    pub fn blob_sidecar_by_blob_id_count(&self) -> Result<usize> {
        let results = self
            .database
            .iterator_ascending(BlobSidecarByBlobId(H256::zero(), 0).to_string()..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| BlobSidecarByBlobId::has_prefix(key_bytes))
                .count()
        })
    }
}

impl<P: Preset> fork_choice_store::Storage<P> for Storage<P> {
    fn stored_state_by_block_root(&self, block_root: H256) -> Result<Option<Arc<BeaconState<P>>>> {
        self.state_by_block_root(block_root)
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

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
pub struct StateByBlockRoot(pub H256);

impl PrefixableKey for StateByBlockRoot {
    const PREFIX: &'static str = "s";
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
pub struct SlotByStateRoot(pub H256);

impl PrefixableKey for SlotByStateRoot {
    const PREFIX: &'static str = "t";
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

pub fn serialize(key: impl core::fmt::Display, value: impl SszWrite) -> Result<(String, Vec<u8>)> {
    Ok((serialize_key(key), serialize_value(value)?))
}

#[cfg(test)]
mod tests {
    use bytesize::ByteSize;
    use database::DatabaseMode;
    use tempfile::TempDir;
    use types::{
        phase0::containers::{
            BeaconBlock as Phase0BeaconBlock, SignedBeaconBlock as Phase0SignedBeaconBlock,
        },
        preset::Mainnet,
    };

    use super::*;

    fn block_with_slot(slot: Slot) -> SignedBeaconBlock<Mainnet> {
        SignedBeaconBlock::<Mainnet>::Phase0(Phase0SignedBeaconBlock {
            message: Phase0BeaconBlock {
                slot,
                ..Phase0BeaconBlock::default()
            },
            ..Phase0SignedBeaconBlock::default()
        })
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

        database.put_batch(vec![
            // Slot 1
            serialize(BlockRootBySlot(1), H256::repeat_byte(1))?,
            serialize(FinalizedBlockByRoot(H256::repeat_byte(1)), &block_1)?,
            serialize(SlotByStateRoot(H256::repeat_byte(1)), 1_u64)?,
            serialize(StateByBlockRoot(H256::repeat_byte(1)), 1_u64)?,
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
            serialize(StateByBlockRoot(H256::repeat_byte(6)), 6_u64)?,
            // Slot 10, test case that "10" < "3" is not true
            serialize(BlockRootBySlot(10), H256::repeat_byte(10))?,
            serialize(UnfinalizedBlockByRoot(H256::repeat_byte(10)), &block_10)?,
            serialize(SlotByStateRoot(H256::repeat_byte(10)), 10_u64)?,
            serialize(StateByBlockRoot(H256::repeat_byte(10)), 10_u64)?,
        ])?;

        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            nonzero!(64_u64),
            StorageMode::Standard,
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

        database.put_batch(vec![
            // Slot 1
            serialize(BlockRootBySlot(1), H256::repeat_byte(1))?,
            serialize(FinalizedBlockByRoot(H256::repeat_byte(1)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(1)), 1_u64)?,
            serialize(StateByBlockRoot(H256::repeat_byte(1)), 1_u64)?,
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
            serialize(StateByBlockRoot(H256::repeat_byte(6)), 6_u64)?,
            // Slot 10, test case that "10" < "3" is not true
            serialize(BlockRootBySlot(10), H256::repeat_byte(10))?,
            serialize(UnfinalizedBlockByRoot(H256::repeat_byte(10)), &block)?,
            serialize(SlotByStateRoot(H256::repeat_byte(10)), 10_u64)?,
            serialize(StateByBlockRoot(H256::repeat_byte(10)), 10_u64)?,
        ])?;

        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            nonzero!(64_u64),
            StorageMode::Standard,
        );

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
            nonzero!(64_u64),
            StorageMode::Standard,
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
    fn test_block_root_before_or_at_slot() -> Result<()> {
        let database = Database::in_memory();

        database.put_batch(vec![
            serialize(BlockRootBySlot(2), H256::repeat_byte(2))?,
            serialize(BlockRootBySlot(6), H256::repeat_byte(6))?,
        ])?;

        let storage = Storage::<Mainnet>::new(
            Arc::new(Config::mainnet()),
            Arc::new(PubkeyCache::default()),
            database,
            nonzero!(64_u64),
            StorageMode::Standard,
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
