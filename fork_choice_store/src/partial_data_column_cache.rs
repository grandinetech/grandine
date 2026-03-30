use std::{collections::HashMap, sync::Arc};

use ssz::H256;
use std_ext::ArcExt;
use types::{
    combined::DataColumnSidecar,
    fulu::containers::{
        DataColumnIdentifier, DataColumnSidecar as FuluDataColumnSidecar, PartialDataColumnHeader,
        PartialDataColumnSidecar,
    },
    nonstandard::PartialDataColumn,
    phase0::primitives::Slot,
    preset::Preset,
};

#[derive(Clone, Default)]
pub struct PartialDataColumnCache<P: Preset> {
    headers: HashMap<H256, (Arc<PartialDataColumnHeader<P>>, Slot)>,
    partial_columns: HashMap<DataColumnIdentifier, (PartialDataColumnSidecar<P>, Slot)>,
}

impl<P: Preset> PartialDataColumnCache<P> {
    pub fn header(&self, block_root: H256) -> Option<Arc<PartialDataColumnHeader<P>>> {
        self.headers
            .get(&block_root)
            .map(|(header, _)| header.clone_arc())
    }

    pub fn has_missing(&self, partial_column: &Arc<PartialDataColumn<P>>) -> bool {
        let id: DataColumnIdentifier = partial_column.as_ref().into();
        let Some((sidecar, _)) = self.partial_columns.get(&id) else {
            return true;
        };

        partial_column
            .sidecar
            .cells_present_bitmap
            .any_not_in(&sidecar.cells_present_bitmap)
    }

    pub fn has_conflicting_cells(&self, partial_column: &Arc<PartialDataColumn<P>>) -> bool {
        let id: DataColumnIdentifier = partial_column.as_ref().into();
        let Some((cached_sidecar, _)) = self.partial_columns.get(&id) else {
            return false;
        };

        let mut cached_cell_index = 0;
        let mut incoming_cell_index = 0;
        for (is_cached, is_present) in cached_sidecar
            .cells_present_bitmap
            .iter()
            .zip(partial_column.sidecar.cells_present_bitmap.iter())
        {
            if *is_cached && *is_present {
                let cached_cell = cached_sidecar.partial_column.get(cached_cell_index);
                let cached_proof = cached_sidecar.kzg_proofs.get(cached_cell_index);
                let new_cell = partial_column
                    .sidecar
                    .partial_column
                    .get(incoming_cell_index);
                let new_proof = partial_column.sidecar.kzg_proofs.get(incoming_cell_index);

                if new_cell != cached_cell || new_proof != cached_proof {
                    return true;
                }
            }

            if *is_cached {
                cached_cell_index += 1;
            }

            if *is_present {
                incoming_cell_index += 1;
            }
        }

        false
    }

    pub fn upsert_partial_column(
        &mut self,
        partial_column: &Arc<PartialDataColumn<P>>,
    ) -> Option<Arc<DataColumnSidecar<P>>> {
        let id: DataColumnIdentifier = partial_column.as_ref().into();

        // insert header if contains in partial column
        let header = self.header(id.block_root).or_else(|| {
            let header = Arc::new(partial_column.sidecar.header.first()?.clone());
            self.headers
                .insert(id.block_root, (header.clone_arc(), header.slot()));

            Some(header)
        })?;

        // check if stored partial column is full, return the partial column or merge into column
        let column = &self
            .partial_columns
            .entry(id)
            .and_modify(|(col, _)| col.merge(&partial_column.sidecar))
            .or_insert_with(|| (partial_column.sidecar.clone(), header.slot()))
            .0;

        column.is_full().then(|| {
            Arc::new(
                FuluDataColumnSidecar {
                    index: id.index,
                    column: column.partial_column.clone(),
                    kzg_commitments: header.kzg_commitments.clone(),
                    kzg_proofs: column.kzg_proofs.clone(),
                    signed_block_header: header.signed_block_header,
                    kzg_commitments_inclusion_proof: header.kzg_commitments_inclusion_proof,
                }
                .into(),
            )
        })
    }

    pub fn prune(&mut self, prune_slot: Slot) {
        self.headers.retain(|_, (_, slot)| prune_slot <= *slot);
        self.partial_columns
            .retain(|_, (_, slot)| prune_slot <= *slot);
    }
}
