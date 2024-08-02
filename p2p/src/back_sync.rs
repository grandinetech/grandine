use std::{collections::BTreeMap, sync::Arc, thread::Builder};

use anyhow::{ensure, Result};
use database::Database;
use derive_more::Display;
use eth1_api::RealController;
use futures::channel::mpsc::UnboundedSender;
use genesis::AnchorCheckpointProvider;
use log::{debug, info, warn};
use ssz::{Ssz, SszReadDefault as _, SszWrite as _};
use thiserror::Error;
use types::{
    combined::SignedBeaconBlock,
    phase0::{
        consts::GENESIS_SLOT,
        primitives::{Slot, H256},
    },
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::messages::ArchiverToSync;

pub struct BackSync<P: Preset> {
    batch: Batch<P>,
    data: Data,
    archiving: bool,
}

impl<P: Preset> BackSync<P> {
    pub fn load(database: &Database) -> Result<Option<Self>> {
        let data = Data::find(database)?;

        debug!("loaded back sync: {data:?}");

        Ok(data.map(Self::new))
    }

    pub fn new(data: Data) -> Self {
        Self {
            data,
            batch: Batch::default(),
            archiving: false,
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

    pub fn is_finished(&self) -> bool {
        self.data.is_finished()
    }

    pub fn finish(&self, database: &Database) -> Result<()> {
        self.data.remove(database)
    }

    pub fn push_block(&mut self, block: Arc<SignedBeaconBlock<P>>) {
        let slot = block.message().slot();

        if slot >= self.low_slot() && slot <= self.high_slot() && !self.is_finished() {
            self.batch.push(block);
        } else {
            debug!("ignoring network block during back sync: {slot}");
        }
    }

    pub fn save(&self, database: &Database) -> Result<()> {
        self.data.save(database)
    }

    pub fn try_to_spawn_state_archiver(
        &mut self,
        controller: RealController<P>,
        anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
        sync_tx: UnboundedSender<ArchiverToSync>,
    ) -> Result<()> {
        if !self.is_finished() {
            debug!("not spawning state archiver: back sync not yet finished");

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
                debug!("archiving back sync states from {start_slot} to {end_slot}");

                match controller.archive_back_sync_states(
                    start_slot,
                    end_slot,
                    &anchor_checkpoint_provider,
                ) {
                    Ok(()) => info!("back sync state archiver thread finished successfully"),
                    Err(error) => warn!("back sync state archiver thread failed: {error:?}"),
                };

                ArchiverToSync::BackSyncStatesArchived.send(&sync_tx);
            })?;

        self.archiving = true;

        Ok(())
    }

    pub fn verify_blocks(
        &mut self,
        database: &Database,
        controller: &RealController<P>,
    ) -> Result<()> {
        let last_block_checkpoint = self.data.current;

        match self.batch.verify_from_checkpoint(last_block_checkpoint) {
            Ok((checkpoint, blocks)) => {
                debug!("back sync batch verified: {checkpoint:?}");

                if checkpoint.slot == self.low_slot() {
                    let expected = self.data.low;
                    let actual = checkpoint;

                    ensure!(
                        actual == expected,
                        Error::FinalCheckpointMismatch { expected, actual },
                    );
                }

                // Store back synced blocks in fork choice store.
                controller.store_back_sync_blocks(blocks)?;

                // Update back sync progress in sync database.
                self.data.current = checkpoint;
                self.save(database)?;

                debug!("back sync batch saved {checkpoint:?}");
            }
            Err(error) => debug!("back sync batch verification failed: {error}"),
        }

        Ok(())
    }
}

#[derive(Default)]
struct Batch<P: Preset> {
    blocks: BTreeMap<Slot, Arc<SignedBeaconBlock<P>>>,
}

impl<P: Preset> Batch<P> {
    fn push(&mut self, block: Arc<SignedBeaconBlock<P>>) {
        self.blocks.insert(block.message().slot(), block);
    }

    fn verify_from_checkpoint(
        &mut self,
        mut checkpoint: SyncCheckpoint,
    ) -> Result<(
        SyncCheckpoint,
        impl Iterator<Item = Arc<SignedBeaconBlock<P>>>,
    )> {
        debug!("verify back sync batch from: {checkpoint:?}");

        let mut next_parent_root = checkpoint.parent_root;

        for block in self.blocks.values().rev() {
            let message = block.message();
            let expected = next_parent_root;
            let actual = message.hash_tree_root();

            ensure!(
                actual == expected,
                Error::BlockRootMismatch {
                    slot: message.slot(),
                    expected,
                    actual,
                },
            );

            next_parent_root = message.parent_root();
        }

        if let Some((_, earliest_block)) = self.blocks.first_key_value() {
            checkpoint = earliest_block.as_ref().into();
        }

        debug!("next batch checkpoint: {checkpoint:?}");

        let blocks = core::mem::take(&mut self.blocks).into_values();

        Ok((checkpoint, blocks))
    }
}

#[derive(Clone, Copy, Debug, Ssz)]
#[ssz(derive_hash = false)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Data {
    current: SyncCheckpoint,
    high: SyncCheckpoint,
    low: SyncCheckpoint,
}

impl Data {
    pub const fn new(current: SyncCheckpoint, high: SyncCheckpoint, low: SyncCheckpoint) -> Self {
        Self { current, high, low }
    }

    fn is_finished(&self) -> bool {
        self.current == self.low
    }

    fn save(&self, database: &Database) -> Result<()> {
        database.put(self.db_key(), self.to_ssz()?)
    }

    fn remove(&self, database: &Database) -> Result<()> {
        database.delete(self.db_key())
    }

    fn find(database: &Database) -> Result<Option<Self>> {
        database
            .next(BackSyncDataBySlot(GENESIS_SLOT).to_string())?
            .filter(|(key_bytes, _)| key_bytes.starts_with(BackSyncDataBySlot::PREFIX.as_bytes()))
            .map(|(_, value_bytes)| Self::from_ssz_default(value_bytes))
            .transpose()
            .map_err(Into::into)
    }

    fn db_key(&self) -> String {
        BackSyncDataBySlot(self.low.slot).to_string()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Ssz)]
#[cfg_attr(test, derive(Default))]
pub struct SyncCheckpoint {
    slot: Slot,
    block_root: H256,
    parent_root: H256,
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
#[display(fmt = "{}{_0:020}", Self::PREFIX)]
struct BackSyncDataBySlot(Slot);

impl BackSyncDataBySlot {
    const PREFIX: &'static str = "b";
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(
        "invalid block batch: block root mismatch \
         (slot: {slot}, expected: {expected:?}, actual: {actual:?})"
    )]
    BlockRootMismatch {
        slot: Slot,
        expected: H256,
        actual: H256,
    },
    #[error("final back sync checkpoint mismatch (expected: {expected:?}, actual: {actual:?})")]
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

        assert_eq!(selected, Some(build_sync_data(140, 0)));

        Ok(())
    }

    #[test]
    fn test_back_sync_data_remove() -> Result<()> {
        let database = Database::in_memory();

        build_sync_data(120, 0).save(&database)?;

        let selected = Data::find(&database)?;

        assert_eq!(selected, Some(build_sync_data(120, 0)));

        selected
            .expect("back sync data is saved earlier in the test")
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
