use std::path::PathBuf;

use anyhow::Result;
use bytesize::ByteSize;
use database::{DatabaseMode, PrefixableKey as _};
use fork_choice_control::{
    BlobSidecarByBlobId, BlockCheckpoint, BlockRootBySlot, FinalizedBlockByRoot, SlotBlobId,
    SlotByStateRoot, StateByBlockRoot, StateCheckpoint, UnfinalizedBlockByRoot,
};
use logging::{info_with_peers, warn_with_peers};
use types::preset::Preset;

use crate::StorageConfig;

#[derive(Default, Debug)]
struct EntriesInfo {
    title: &'static str,
    key_size: usize,
    value_size: usize,
    count: usize,
}

impl EntriesInfo {
    fn new(title: &'static str) -> Self {
        Self {
            title,
            ..Default::default()
        }
    }

    const fn total_size(&self) -> usize {
        self.key_size + self.value_size
    }

    const fn track(&mut self, key: &[u8], length: usize) {
        self.key_size += key.len();
        self.value_size += length;
        self.count += 1;
    }

    fn print_report(&self) -> Result<()> {
        let key_size = ByteSize(self.key_size.try_into()?).display().si();
        let value_size = ByteSize(self.value_size.try_into()?).display().si();
        let total_size = ByteSize(self.total_size().try_into()?).display().si();

        info_with_peers!(
            "{}: {} entries, key_size: {key_size}, value_size: {value_size}, total_size: {total_size}",
            self.title, self.count
        );

        Ok(())
    }
}

pub fn print<P: Preset>(
    storage_config: &StorageConfig,
    custom_path: Option<PathBuf>,
) -> Result<()> {
    let storage_database =
        storage_config.beacon_fork_choice_database(custom_path, DatabaseMode::ReadOnly, None)?;

    let mut total_size = 0;
    let mut finalized_block_root_entries = EntriesInfo::new("finalized_block_roots");
    let mut unfinalized_block_root_entries = EntriesInfo::new("unfinalized_block_roots");
    let mut state_by_block_root_entries = EntriesInfo::new("states_by_block_root");
    let mut slot_by_state_root_entries = EntriesInfo::new("slots_by_state_root");
    let mut slot_by_blob_id_entries = EntriesInfo::new("slots_by_blob_id");
    let mut blob_sidecar_by_blob_id_entries = EntriesInfo::new("blob_sidecars_by_blob_id");
    let mut block_root_by_slot_entries = EntriesInfo::new("block_roots_by_slot");
    let mut state_checkpoint_entries = EntriesInfo::new("state_checkpoint");
    let mut block_checkpoint_entries = EntriesInfo::new("block_checkpoint");

    for result in storage_database.iterate_all_keys_with_lengths()? {
        let (key, length) = result?;

        total_size += key.len() + length;

        if UnfinalizedBlockByRoot::has_prefix(&key) {
            unfinalized_block_root_entries.track(&key, length);
        } else if FinalizedBlockByRoot::has_prefix(&key) {
            finalized_block_root_entries.track(&key, length);
        } else if StateByBlockRoot::has_prefix(&key) {
            state_by_block_root_entries.track(&key, length);
        } else if SlotByStateRoot::has_prefix(&key) {
            slot_by_state_root_entries.track(&key, length);
        } else if SlotBlobId::has_prefix(&key) {
            slot_by_blob_id_entries.track(&key, length);
        } else if BlobSidecarByBlobId::has_prefix(&key) {
            blob_sidecar_by_blob_id_entries.track(&key, length);
        } else if BlockRootBySlot::has_prefix(&key) {
            block_root_by_slot_entries.track(&key, length);
        } else if StateCheckpoint::<P>::has_prefix(&key) {
            state_checkpoint_entries.track(&key, length);
        } else if BlockCheckpoint::<P>::has_prefix(&key) {
            block_checkpoint_entries.track(&key, length);
        } else {
            warn_with_peers!("unknown database key: {}", String::from_utf8_lossy(&key));
        }
    }

    if let Some(db_stats) = storage_database.db_stats()? {
        info_with_peers!("{db_stats:?}");
    }

    let mut entries = [
        block_root_by_slot_entries,
        finalized_block_root_entries,
        unfinalized_block_root_entries,
        state_by_block_root_entries,
        slot_by_state_root_entries,
        slot_by_blob_id_entries,
        blob_sidecar_by_blob_id_entries,
        state_checkpoint_entries,
        block_checkpoint_entries,
    ];

    entries.sort_by_key(EntriesInfo::total_size);

    for entry in entries {
        entry.print_report()?;
    }

    info_with_peers!(
        "Total size: {}",
        ByteSize(total_size.try_into()?).display().si()
    );

    Ok(())
}
