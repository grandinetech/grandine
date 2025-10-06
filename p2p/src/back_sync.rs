use core::sync::atomic::AtomicBool;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    thread::Builder,
};

use anyhow::{bail, ensure, Result};
use database::{Database, PrefixableKey};
use derive_more::Display;
use eth1_api::RealController;
use fork_choice_store::{
    BlobSidecarAction, BlobSidecarOrigin, DataColumnSidecarAction, DataColumnSidecarOrigin,
};
use futures::channel::mpsc::UnboundedSender;
use genesis::AnchorCheckpointProvider;
use helper_functions::misc;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use ssz::{Ssz, SszReadDefault as _, SszWrite as _};
use std_ext::ArcExt as _;
use thiserror::Error;
use types::{
    combined::SignedBeaconBlock,
    config::Config,
    deneb::{
        containers::{BlobIdentifier, BlobSidecar},
        primitives::BlobIndex,
    },
    fulu::{
        containers::{DataColumnIdentifier, DataColumnSidecar},
        primitives::ColumnIndex,
    },
    nonstandard::{PayloadStatus, WithStatus},
    phase0::{
        consts::GENESIS_SLOT,
        primitives::{Slot, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::messages::ArchiverToSync;

#[derive(Debug)]
pub struct BackSync<P: Preset> {
    batch: Batch<P>,
    data: Data,
    archiving: bool,
    sync_mode: SyncMode,
}

impl<P: Preset> BackSync<P> {
    pub fn load(database: &Database) -> Result<Option<Self>> {
        let data = Data::find(database)?;

        debug!("loaded back-sync: {data:?}");

        let Some(data) = data else {
            return Ok(None);
        };

        let sync_mode = SyncMode::load(database, data.low.slot)?;

        info!(
            "starting {} from {} to {} slot",
            sync_mode.name(),
            data.current.slot,
            data.low.slot
        );

        Ok(Some(Self::new(data, sync_mode)))
    }

    pub fn new(data: Data, sync_mode: SyncMode) -> Self {
        Self {
            data,
            batch: Batch::default(),
            archiving: false,
            sync_mode,
        }
    }

    pub const fn data(&self) -> Data {
        self.data
    }

    pub const fn current_slot(&self) -> Slot {
        self.data.current.slot
    }

    pub const fn high_slot(&self) -> Slot {
        self.data.high.slot
    }

    pub const fn low_slot(&self) -> Slot {
        self.data.low.slot
    }

    pub fn low_slot_with_parent(&self) -> Slot {
        self.data.low.slot.checked_sub(1).unwrap_or(GENESIS_SLOT)
    }

    pub const fn is_finished(&self) -> bool {
        self.data.is_finished()
    }

    pub fn remove(&self, database: &Database) -> Result<()> {
        self.sync_mode.remove(database, self.data.low.slot)?;
        self.data.remove(database)
    }

    pub fn reset_batch(&mut self) {
        self.batch = Batch::default();
    }

    pub fn push_blob_sidecar(&mut self, blob_sidecar: Arc<BlobSidecar<P>>) {
        let slot = blob_sidecar.signed_block_header.message.slot;

        if slot <= self.high_slot() && !self.is_finished() {
            self.batch.push_blob_sidecar(blob_sidecar);
        } else {
            let blob_identifier: BlobIdentifier = blob_sidecar.as_ref().into();
            debug!("ignoring blob sidecar: {blob_identifier:?}, slot: {slot}");
        }
    }

    pub fn push_block(&mut self, block: Arc<SignedBeaconBlock<P>>) {
        let slot = block.message().slot();

        if slot <= self.high_slot() && !self.is_finished() {
            self.batch.push_block(block);
        } else {
            debug!("ignoring block: {slot}");
        }
    }

    pub fn push_data_column_sidecar(&mut self, data_column_sidecar: Arc<DataColumnSidecar<P>>) {
        let slot = data_column_sidecar.signed_block_header.message.slot;

        if slot <= self.high_slot() && !self.is_finished() {
            self.batch.push_data_column_sidecar(data_column_sidecar);
        } else {
            let data_column_id: DataColumnIdentifier = data_column_sidecar.as_ref().into();
            debug!("ignoring data column sidecar: {data_column_id:?}, slot: {slot}");
        }
    }

    pub fn save(&self, database: &Database) -> Result<()> {
        self.sync_mode.save(database, self.data.low.slot)?;
        self.data.save(database)
    }

    pub const fn sync_mode(&self) -> &SyncMode {
        &self.sync_mode
    }

    pub fn try_to_spawn_state_archiver(
        &mut self,
        controller: RealController<P>,
        anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
        is_exiting: Arc<AtomicBool>,
        sync_tx: UnboundedSender<ArchiverToSync>,
    ) -> Result<()> {
        if !self.is_finished() {
            debug!("not spawning state archiver: back-sync not yet finished");
            return Ok(());
        }

        if self.archiving {
            debug!("not spawning state archiver: state archiver already started");
            return Ok(());
        }

        let start_slot = self.low_slot();
        let end_slot = self.high_slot();

        Builder::new()
            .name("state-archiver".to_owned())
            .spawn(move || {
                info!("archiving back-synced states from {start_slot} to {end_slot}");

                match controller.archive_back_sync_states(
                    start_slot,
                    end_slot,
                    &anchor_checkpoint_provider,
                    &is_exiting,
                ) {
                    Ok(()) => info!("back-sync state archiver thread finished successfully"),
                    Err(error) => warn!("unable to archive back back-sync states: {error:?}"),
                }

                ArchiverToSync::BackSyncStatesArchived.send(&sync_tx);
            })?;

        self.archiving = true;

        Ok(())
    }

    pub fn verify_blocks(
        &mut self,
        config: &Config,
        database: &Database,
        controller: &RealController<P>,
    ) -> Result<()> {
        let last_block_checkpoint = self.data.current;

        let (checkpoint, blocks, blob_sidecars, data_column_sidecars) = match &self.sync_mode {
            SyncMode::Default => {
                self.batch
                    .verify_from_checkpoint(config, controller, last_block_checkpoint)?
            }
            SyncMode::DataColumnsOnly { column_indices } => {
                self.batch.verify_extra_data_columns_from_checkpoint(
                    config,
                    controller,
                    last_block_checkpoint,
                    column_indices,
                    self.low_slot(),
                )?
            }
        };

        info!("back-synced to {} slot", checkpoint.slot);

        if self.sync_mode.validate_checkpoint_slot() && checkpoint.slot == self.low_slot() {
            let expected = self.data.low;
            let actual = checkpoint;

            if !expected.block_root.is_zero() {
                ensure!(
                    actual == expected,
                    Error::FinalCheckpointMismatch::<P> { expected, actual },
                );
            }
        }

        // Store back-synced blocks in fork choice db.
        controller.store_back_sync_blocks(blocks)?;
        controller.store_back_sync_blob_sidecars(blob_sidecars)?;
        controller.store_back_sync_data_column_sidecars(data_column_sidecars)?;

        // Update back-sync progress in sync database.
        self.data.current = checkpoint;
        self.save(database)?;

        debug!("back-sync batch saved {checkpoint:?}");

        Ok(())
    }
}

#[derive(Default, Debug)]
struct Batch<P: Preset> {
    blocks: BTreeMap<Slot, Arc<SignedBeaconBlock<P>>>,
    blob_sidecars: HashMap<BlobIdentifier, Arc<BlobSidecar<P>>>,
    data_column_sidecars: HashMap<DataColumnIdentifier, Arc<DataColumnSidecar<P>>>,
}

impl<P: Preset> Batch<P> {
    fn push_blob_sidecar(&mut self, blob_sidecar: Arc<BlobSidecar<P>>) {
        self.blob_sidecars
            .insert(blob_sidecar.as_ref().into(), blob_sidecar);
    }

    fn push_block(&mut self, block: Arc<SignedBeaconBlock<P>>) {
        self.blocks.insert(block.message().slot(), block);
    }

    fn push_data_column_sidecar(&mut self, data_column_sidecar: Arc<DataColumnSidecar<P>>) {
        self.data_column_sidecars
            .insert(data_column_sidecar.as_ref().into(), data_column_sidecar);
    }

    pub fn valid_blob_sidecars_for(
        &self,
        config: &Config,
        controller: &RealController<P>,
        block: &Arc<SignedBeaconBlock<P>>,
        parent: &Arc<SignedBeaconBlock<P>>,
    ) -> Result<Vec<Arc<BlobSidecar<P>>>> {
        let block = block.message();

        let Some(body) = block.body().with_blob_kzg_commitments() else {
            return Ok(vec![]);
        };

        let head_state = controller.head_state().value;
        let block_root = block.hash_tree_root();
        let slot = block.slot();
        let head_slot = head_state.slot();

        if slot < misc::blob_serve_range_slot::<P>(config, head_slot) {
            return Ok(vec![]);
        }

        body.blob_kzg_commitments()
            .into_iter()
            .zip(0..)
            .map(|(_block_commitment, index)| {
                let Some(blob_sidecar) = self
                    .blob_sidecars
                    .get(&BlobIdentifier { block_root, index })
                else {
                    bail!(Error::BlobMissing::<P> {
                        block_root,
                        slot,
                        index,
                    })
                };

                let action = controller.validate_blob_sidecar_with_state(
                    blob_sidecar.clone_arc(),
                    true,
                    &BlobSidecarOrigin::BackSync,
                    || Some((parent.clone_arc(), PayloadStatus::Optimistic)),
                    || Some(head_state.clone_arc()),
                )?;

                if !action.accepted() {
                    bail!(Error::BlobNotAccepted::<P> {
                        action,
                        block_root,
                        slot,
                        index
                    })
                }

                Ok(blob_sidecar.clone_arc())
            })
            .collect()
    }

    fn valid_data_column_sidecars_for(
        &self,
        config: &Config,
        controller: &RealController<P>,
        block: &Arc<SignedBeaconBlock<P>>,
        parent: &Arc<SignedBeaconBlock<P>>,
        validatable_columns: &HashSet<ColumnIndex>,
        validate_block_presence: bool,
    ) -> Result<Vec<Arc<DataColumnSidecar<P>>>> {
        let block = block.message();

        let Some(body) = block.body().post_fulu() else {
            return Ok(vec![]);
        };

        if body.blob_kzg_commitments().is_empty() {
            return Ok(vec![]);
        }

        let head_state = controller.head_state().value;
        let block_root = block.hash_tree_root();
        let slot = block.slot();
        let head_slot = head_state.slot();

        if slot < misc::data_column_serve_range_slot::<P>(config, head_slot) {
            return Ok(vec![]);
        }

        validatable_columns
            .iter()
            .copied()
            .map(|index| {
                let Some(data_column_sidear) = self
                    .data_column_sidecars
                    .get(&DataColumnIdentifier { block_root, index })
                else {
                    bail!(Error::DataColumnMissing::<P> {
                        block_root,
                        slot,
                        index,
                    })
                };

                let action = controller.validate_data_column_sidecar_with_state(
                    data_column_sidear.clone_arc(),
                    true,
                    &DataColumnSidecarOrigin::BackSync,
                    validate_block_presence,
                    || Some((parent.clone_arc(), PayloadStatus::Optimistic)),
                    || Some(head_state.clone_arc()),
                )?;

                if !action.accepted() {
                    bail!(Error::DataColumnNotAccepted::<P> {
                        action,
                        block_root,
                        slot,
                        index
                    })
                }

                Ok(data_column_sidear.clone_arc())
            })
            .collect()
    }

    #[expect(clippy::type_complexity)]
    fn verify_from_checkpoint(
        &self,
        config: &Config,
        controller: &RealController<P>,
        mut checkpoint: SyncCheckpoint,
    ) -> Result<(
        SyncCheckpoint,
        Vec<Arc<SignedBeaconBlock<P>>>,
        Vec<Arc<BlobSidecar<P>>>,
        Vec<Arc<DataColumnSidecar<P>>>,
    )> {
        debug!("verify back-sync batch from: {checkpoint:?}");

        let mut next_parent_root = checkpoint.parent_root;
        let mut verified_blob_sidecars = vec![];
        let mut verified_blocks = vec![];
        let mut verified_data_column_sidecars = vec![];
        let head_state = controller.head_state().value();

        let mut blocks = self
            .blocks
            .values()
            .rev()
            .skip_while(|block| block.message().slot() >= checkpoint.slot)
            .peekable();

        while let Some(block) = blocks.next() {
            let message = block.message();
            let actual = message.hash_tree_root();

            if block.message().slot() == GENESIS_SLOT {
                // if it's a genesis block, return it as is.
                // It will be validated against our own genesis_block during
                // final checkpoint vaildation
                verified_blocks.push(block.clone_arc());
            } else if let Some(parent) = blocks.peek() {
                debug!("back-sync batch block: {} {:?}", message.slot(), actual);

                ensure!(
                    actual == next_parent_root,
                    Error::BlockRootMismatch::<P> {
                        actual,
                        expected: next_parent_root,
                        slot: message.slot(),
                    },
                );

                if config
                    .phase_at_slot::<P>(block.message().slot())
                    .is_peerdas_activated()
                {
                    let mut data_columns = self.valid_data_column_sidecars_for(
                        config,
                        controller,
                        block,
                        parent,
                        &controller.sampling_columns(),
                        true,
                    )?;

                    verified_data_column_sidecars.append(&mut data_columns);
                } else {
                    let mut blobs =
                        self.valid_blob_sidecars_for(config, controller, block, parent)?;

                    verified_blob_sidecars.append(&mut blobs);
                }

                transition_functions::combined::verify_base_signature_with_head_state(
                    config,
                    controller.pubkey_cache(),
                    &head_state,
                    block,
                )?;

                verified_blocks.push(block.clone_arc());

                next_parent_root = message.parent_root();
            }
        }

        if let Some(earliest_block) = verified_blocks.last() {
            checkpoint = earliest_block.as_ref().into();
        }

        debug!("next batch checkpoint: {checkpoint:?}");

        Ok((
            checkpoint,
            verified_blocks,
            verified_blob_sidecars,
            verified_data_column_sidecars,
        ))
    }

    #[expect(clippy::type_complexity)]
    fn verify_extra_data_columns_from_checkpoint(
        &self,
        config: &Config,
        controller: &RealController<P>,
        mut checkpoint: SyncCheckpoint,
        column_indices: &HashSet<ColumnIndex>,
        low_slot: Slot,
    ) -> Result<(
        SyncCheckpoint,
        Vec<Arc<SignedBeaconBlock<P>>>,
        Vec<Arc<BlobSidecar<P>>>,
        Vec<Arc<DataColumnSidecar<P>>>,
    )> {
        debug!("verify back-sync batch from: {checkpoint:?}");

        let mut verified_data_column_sidecars = vec![];

        let block_roots = self
            .data_column_sidecars
            .keys()
            .map(|key| key.block_root)
            .collect::<HashSet<_>>();

        let mut blocks_with_roots = HashMap::new();
        let mut earliest_block: Option<Arc<SignedBeaconBlock<P>>> = None;

        for root in block_roots {
            if let Some(block) = controller.block_by_root(root)?.map(WithStatus::value) {
                blocks_with_roots.insert(root, block);
            }
        }

        for block in blocks_with_roots.values() {
            let parent_root = block.message().parent_root();

            let parent = match blocks_with_roots.get(&parent_root) {
                Some(parent) => parent,
                None => &match controller
                    .block_by_root(parent_root)?
                    .map(WithStatus::value)
                {
                    Some(parent) => parent,
                    None => continue,
                },
            };

            let block_slot = block.message().slot();

            if !config.phase_at_slot::<P>(block_slot).is_peerdas_activated() {
                continue;
            }

            let mut data_columns = self.valid_data_column_sidecars_for(
                config,
                controller,
                block,
                parent,
                column_indices,
                false,
            )?;

            verified_data_column_sidecars.append(&mut data_columns);

            if earliest_block
                .as_ref()
                .map(|block| block_slot < block.message().slot())
                .unwrap_or(true)
            {
                earliest_block = Some(block.clone_arc());
            }
        }

        if let Some(mut earliest_block) = earliest_block {
            // Iterate through ancestor blocks without blobs if any to find the earliest block
            loop {
                let parent_root = earliest_block.message().parent_root();

                if let Some(parent) = controller.block_by_root(parent_root)? {
                    let parent = parent.value;

                    if let Some(body) = parent.message().body().with_blob_kzg_commitments() {
                        if parent.message().slot() >= low_slot
                            && body.blob_kzg_commitments().is_empty()
                        {
                            // Set earliest block without blobs as earliest block
                            earliest_block = parent;
                            continue;
                        }
                    }
                }

                break;
            }

            checkpoint = earliest_block.as_ref().into();
        }

        debug!("next batch checkpoint: {checkpoint:?}");

        Ok((checkpoint, vec![], vec![], verified_data_column_sidecars))
    }
}

#[derive(Clone, Copy, Debug, Ssz)]
#[ssz(derive_hash = false)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Data {
    pub current: SyncCheckpoint,
    pub high: SyncCheckpoint,
    pub low: SyncCheckpoint,
}

impl Data {
    const fn is_finished(&self) -> bool {
        self.current.slot <= self.low.slot
    }

    fn save(&self, database: &Database) -> Result<()> {
        database.put(self.db_key(), self.to_ssz()?)
    }

    fn remove(&self, database: &Database) -> Result<()> {
        database.delete(self.db_key())
    }

    fn find(database: &Database) -> Result<Option<Self>> {
        database
            .prev(BackSyncDataBySlot(Slot::MAX).to_string())?
            .filter(|(key_bytes, _)| key_bytes.starts_with(BackSyncDataBySlot::PREFIX.as_bytes()))
            .map(|(_, value_bytes)| Self::from_ssz_default(value_bytes))
            .transpose()
            .map_err(Into::into)
    }

    fn db_key(&self) -> String {
        BackSyncDataBySlot(self.low.slot).to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SyncMode {
    Default,
    DataColumnsOnly {
        column_indices: HashSet<ColumnIndex>,
    },
}

impl SyncMode {
    fn name(&self) -> String {
        match self {
            Self::Default => "back-sync".into(),
            Self::DataColumnsOnly { column_indices } => {
                format!("data column backfill (columns: {column_indices:?})")
            }
        }
    }

    fn save(&self, database: &Database, low_slot: Slot) -> Result<()> {
        // Due to backwards compatibility and simplicity, back sync without additional sync mode record
        // is treated as default back sync
        if self.is_default() {
            return Ok(());
        }

        database.put(Self::db_key(low_slot), bincode::serialize(&self)?)
    }

    fn remove(&self, database: &Database, low_slot: Slot) -> Result<()> {
        if self.is_default() {
            return Ok(());
        }

        database.delete(Self::db_key(low_slot))
    }

    fn load(database: &Database, low_slot: Slot) -> Result<Self> {
        database
            .get(Self::db_key(low_slot))?
            .as_deref()
            .map(bincode::deserialize)
            .unwrap_or(Ok(Self::Default))
            .map_err(Into::into)
    }

    fn db_key(low_slot: Slot) -> String {
        SyncModeBySlot(low_slot).to_string()
    }

    pub const fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }

    const fn validate_checkpoint_slot(&self) -> bool {
        match self {
            Self::Default => true,
            Self::DataColumnsOnly { .. } => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Ssz)]
#[cfg_attr(test, derive(Default))]
pub struct SyncCheckpoint {
    pub slot: Slot,
    pub block_root: H256,
    pub parent_root: H256,
}

impl<P: Preset> From<&SignedBeaconBlock<P>> for SyncCheckpoint {
    fn from(block: &SignedBeaconBlock<P>) -> Self {
        let message = block.message();

        Self {
            slot: message.slot(),
            block_root: message.hash_tree_root(),
            parent_root: message.parent_root(),
        }
    }
}

#[derive(Display)]
#[display("{}{_0:020}", Self::PREFIX)]
pub struct BackSyncDataBySlot(pub Slot);

impl PrefixableKey for BackSyncDataBySlot {
    const PREFIX: &'static str = "b";
}

#[derive(Display)]
#[display("{}{_0:020}", Self::PREFIX)]
pub struct SyncModeBySlot(pub Slot);

impl PrefixableKey for SyncModeBySlot {
    const PREFIX: &'static str = "m";
}

#[derive(Debug, Error)]
pub enum Error<P: Preset> {
    #[error("blob {index} for block {block_root:?} in slot {slot} not accepted: {action:?}")]
    BlobNotAccepted {
        action: BlobSidecarAction<P>,
        block_root: H256,
        slot: Slot,
        index: BlobIndex,
    },
    #[error("missing blob {index} for block {block_root:?} in slot {slot}")]
    BlobMissing {
        block_root: H256,
        slot: Slot,
        index: BlobIndex,
    },
    #[error(
        "invalid block batch: block root mismatch \
         (slot: {slot}, expected: {expected:?}, actual: {actual:?})"
    )]
    BlockRootMismatch {
        actual: H256,
        expected: H256,
        slot: Slot,
    },
    #[error(
        "data column {index} for block {block_root:?} in slot {slot} not accepted: {action:?}"
    )]
    DataColumnNotAccepted {
        action: DataColumnSidecarAction<P>,
        block_root: H256,
        slot: Slot,
        index: ColumnIndex,
    },
    #[error("missing data column {index} for block {block_root:?} in slot {slot}")]
    DataColumnMissing {
        block_root: H256,
        slot: Slot,
        index: ColumnIndex,
    },
    #[error("final back-sync checkpoint mismatch (expected: {expected:?}, actual: {actual:?})")]
    FinalCheckpointMismatch {
        expected: SyncCheckpoint,
        actual: SyncCheckpoint,
    },
}

#[cfg(test)]
mod tests {
    use database::Database;

    use super::*;

    #[test]
    fn test_back_sync_data_find() -> Result<()> {
        let database = Database::in_memory();

        assert_eq!(None, Data::find(&database)?);

        build_sync_data(120, 0).save(&database)?;
        build_sync_data(30, 2).save(&database)?;
        build_sync_data(140, 0).save(&database)?;
        build_sync_data(200, 160).save(&database)?;

        let selected = Data::find(&database)?;

        assert_eq!(selected, Some(build_sync_data(200, 160)));

        Ok(())
    }

    #[test]
    fn test_back_sync_data_remove() -> Result<()> {
        let database = Database::in_memory();

        build_sync_data(120, 0).save(&database)?;

        let selected = Data::find(&database)?;

        assert_eq!(selected, Some(build_sync_data(120, 0)));

        selected
            .expect("back-sync data is saved earlier in the test")
            .remove(&database)?;

        assert_eq!(Data::find(&database)?, None);

        Ok(())
    }

    fn build_sync_data(high_slot: Slot, low_slot: Slot) -> Data {
        Data {
            current: SyncCheckpoint {
                slot: high_slot,
                ..SyncCheckpoint::default()
            },
            high: SyncCheckpoint {
                slot: high_slot,
                ..SyncCheckpoint::default()
            },
            low: SyncCheckpoint {
                slot: low_slot,
                ..SyncCheckpoint::default()
            },
        }
    }
}
