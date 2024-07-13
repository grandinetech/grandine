use std::{collections::HashMap, sync::Arc};

use std_ext::ArcExt as _;
use types::{
    combined::BlobSidecar, deneb::containers::BlobIdentifier, nonstandard::BlobSidecarWithId,
    phase0::primitives::Slot, preset::Preset,
};

const BLOB_RETAIN_DURATION_IN_SLOTS: Slot = 2;

#[derive(Clone, Default)]
pub struct BlobCache<P: Preset> {
    blobs: HashMap<BlobIdentifier, (Arc<BlobSidecar<P>>, Slot, bool)>,
}

impl<P: Preset> BlobCache<P> {
    pub fn get(&self, blob_id: BlobIdentifier) -> Option<Arc<BlobSidecar<P>>> {
        Some(self.blobs.get(&blob_id)?.0.clone_arc())
    }

    pub fn has_unpersisted_blob_sidecars(&self) -> bool {
        self.blobs.iter().any(|(_, (_, _, persisted))| !persisted)
    }

    pub fn insert(&mut self, blob_sidecar: Arc<BlobSidecar<P>>) {
        let slot = blob_sidecar.signed_block_header().message.slot;
        let blob_identifier = blob_sidecar.as_ref().into();

        self.blobs
            .insert(blob_identifier, (blob_sidecar, slot, false));
    }

    pub fn mark_persisted_blobs(&mut self, persisted_blob_ids: Vec<BlobIdentifier>) {
        for blob_id in persisted_blob_ids {
            self.blobs.entry(blob_id).and_modify(|entry| entry.2 = true);
        }
    }

    pub fn on_slot(&mut self, slot: Slot) {
        self.blobs
            .retain(|_, (_, blob_slot, _)| *blob_slot + BLOB_RETAIN_DURATION_IN_SLOTS >= slot);
    }

    pub fn size(&self) -> usize {
        self.blobs.values().len()
    }

    pub fn unpersisted_blob_sidecars(&self) -> impl Iterator<Item = BlobSidecarWithId<P>> + '_ {
        self.blobs
            .iter()
            .filter(|(_, (_, _, persisted))| !persisted)
            .map(|(blob_id, (blob_sidecar, _, _))| BlobSidecarWithId {
                blob_sidecar: blob_sidecar.clone_arc(),
                blob_id: *blob_id,
            })
    }
}
