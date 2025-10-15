use std::{collections::HashMap, sync::Arc};

use ssz::H256;
use std_ext::ArcExt as _;
use types::{
    fulu::containers::{DataColumnIdentifier, DataColumnSidecar},
    nonstandard::DataColumnSidecarWithId,
    phase0::primitives::{Slot, ValidatorIndex},
    preset::Preset,
};

#[derive(Clone, Default)]
pub struct DataColumnCache<P: Preset> {
    data_columns: HashMap<DataColumnIdentifier, (Arc<DataColumnSidecar<P>>, Slot, bool)>,
}

impl<P: Preset> DataColumnCache<P> {
    pub fn exhibits_equivocation(
        &self,
        slot: Slot,
        proposer_index: ValidatorIndex,
        block_root: H256,
    ) -> bool {
        self.data_columns.iter().any(
            move |(data_column_identifier, (data_column_sidecar, data_column_slot, _))| {
                let data_column_proposer_index = data_column_sidecar
                    .signed_block_header
                    .message
                    .proposer_index;

                *data_column_slot == slot
                    && data_column_proposer_index == proposer_index
                    && data_column_identifier.block_root != block_root
            },
        )
    }

    pub fn get(&self, data_column_id: DataColumnIdentifier) -> Option<Arc<DataColumnSidecar<P>>> {
        Some(self.data_columns.get(&data_column_id)?.0.clone_arc())
    }

    pub fn insert(&mut self, data_column_sidecar: Arc<DataColumnSidecar<P>>) {
        let slot = data_column_sidecar.signed_block_header.message.slot;
        let identifier = data_column_sidecar.as_ref().into();

        self.data_columns
            .insert(identifier, (data_column_sidecar, slot, false));
    }

    pub fn mark_persisted_data_columns(
        &mut self,
        persisted_data_column_ids: Vec<DataColumnIdentifier>,
    ) {
        for data_column_id in persisted_data_column_ids {
            self.data_columns
                .entry(data_column_id)
                .and_modify(|entry| entry.2 = true);
        }
    }

    pub fn prune(&mut self, prune_slot: Slot) {
        self.data_columns
            .retain(|_, (_, slot, _)| prune_slot <= *slot);
    }

    pub fn prune_persisted(&mut self, prune_slot: Slot) {
        self.data_columns
            .retain(|_, (_, slot, persisted)| !*persisted || prune_slot <= *slot);
    }

    pub fn size(&self) -> usize {
        self.data_columns.values().len()
    }

    pub fn unpersisted_data_column_sidecars(
        &self,
    ) -> impl Iterator<Item = DataColumnSidecarWithId<P>> + '_ {
        self.data_columns
            .iter()
            .filter(|(_, (_, _, persisted))| !persisted)
            .map(
                |(data_column_id, (data_column_sidecar, _, _))| DataColumnSidecarWithId {
                    data_column_sidecar: data_column_sidecar.clone_arc(),
                    data_column_id: *data_column_id,
                },
            )
    }
}
