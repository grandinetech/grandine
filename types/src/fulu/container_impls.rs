use core::fmt;

use ssz::{ContiguousList, Hc, SszHash as _};

use crate::{
    deneb::{
        containers::{ExecutionPayload, ExecutionPayloadHeader},
        primitives::{KzgCommitment, KzgProof},
    },
    electra::containers::ExecutionRequests,
    fulu::containers::{
        BeaconBlock, BeaconBlockBody, BlindedBeaconBlock, BlindedBeaconBlockBody,
        DataColumnIdentifier, DataColumnSidecar, DataColumnsByRootIdentifier, PartialDataColumn,
        PartialDataColumnHeader, PartialDataColumnSidecar,
    },
    phase0::primitives::{H256, Slot},
    preset::Preset,
};

impl<P: Preset> BeaconBlock<P> {
    pub fn with_execution_payload_header_and_kzg_commitments(
        self,
        execution_payload_header: ExecutionPayloadHeader<P>,
        kzg_commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
        execution_requests: Option<ExecutionRequests<P>>,
    ) -> BlindedBeaconBlock<P> {
        let Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = self;

        let BeaconBlockBody {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: _,
            bls_to_execution_changes,
            blob_kzg_commitments,
            execution_requests: beacon_block_execution_requests,
        } = body;

        BlindedBeaconBlock {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body: BlindedBeaconBlockBody {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                execution_payload_header,
                bls_to_execution_changes,
                blob_kzg_commitments: kzg_commitments.unwrap_or(blob_kzg_commitments),
                execution_requests: execution_requests.unwrap_or(beacon_block_execution_requests),
            },
        }
    }
}

impl<P: Preset> BlindedBeaconBlock<P> {
    pub fn with_execution_payload(
        self,
        execution_payload: ExecutionPayload<P>,
    ) -> Hc<BeaconBlock<P>> {
        let Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = self;

        let BlindedBeaconBlockBody {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload_header: _,
            bls_to_execution_changes,
            blob_kzg_commitments,
            execution_requests,
        } = body;

        let body = BeaconBlockBody {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload,
            bls_to_execution_changes,
            blob_kzg_commitments,
            execution_requests,
        };

        BeaconBlock {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        }
        .into()
    }

    #[must_use]
    pub const fn with_state_root(mut self, state_root: H256) -> Self {
        self.state_root = state_root;
        self
    }
}

impl<P: Preset> DataColumnSidecar<P> {
    #[must_use]
    pub const fn slot(&self) -> u64 {
        self.signed_block_header.message.slot
    }

    #[must_use]
    pub fn full() -> Self {
        Self {
            column: ContiguousList::full(Box::default()),
            kzg_commitments: ContiguousList::full(KzgCommitment::repeat_byte(u8::MAX)),
            kzg_proofs: ContiguousList::full(KzgProof::repeat_byte(u8::MAX)),
            ..Default::default()
        }
    }
}

#[expect(clippy::missing_fields_in_debug)]
impl<P: Preset> fmt::Debug for DataColumnSidecar<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataColumnSidecar")
            .field("index", &self.index)
            .field(
                "kzg_commitments_inclusion_proof",
                &self.kzg_commitments_inclusion_proof,
            )
            .field("signed_block_header", &self.signed_block_header)
            .field("kzg_commitments", &self.kzg_commitments)
            .finish()
    }
}

impl<P: Preset> From<&DataColumnSidecar<P>> for DataColumnIdentifier {
    fn from(sidecar: &DataColumnSidecar<P>) -> Self {
        let DataColumnSidecar {
            index,
            signed_block_header,
            ..
        } = *sidecar;

        let block_header = signed_block_header.message;
        let block_root = block_header.hash_tree_root();

        Self { block_root, index }
    }
}

impl<P: Preset> From<DataColumnsByRootIdentifier<P>> for Vec<DataColumnIdentifier> {
    fn from(data_columns_by_root: DataColumnsByRootIdentifier<P>) -> Self {
        let DataColumnsByRootIdentifier {
            block_root,
            columns,
        } = data_columns_by_root;

        columns
            .into_iter()
            .map(|index| DataColumnIdentifier { block_root, index })
            .collect()
    }
}

impl<P: Preset> From<&PartialDataColumn<P>> for DataColumnIdentifier {
    fn from(column: &PartialDataColumn<P>) -> Self {
        Self {
            block_root: column.block_root,
            index: column.index,
        }
    }
}

impl<P: Preset> PartialDataColumnHeader<P> {
    pub const fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }
}

impl<P: Preset> PartialDataColumnSidecar<P> {
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.cells_present_bitmap.iter().all(|bit| *bit)
    }

    pub fn merge(&mut self, other: &Self) {
        let mut cells = Vec::new();
        let mut proofs = Vec::new();

        // iterate over `partial_column` and `kzg_proofs` which has different size from the bitmap
        let mut self_cell_index = 0;
        let mut other_cell_index = 0;

        for (self_present, other_present) in self
            .cells_present_bitmap
            .iter()
            .zip(other.cells_present_bitmap.iter())
        {
            match (*self_present, *other_present) {
                (true, _) => {
                    cells.push(self.partial_column.get(self_cell_index).cloned().expect(
                        "self partial column contains cells less than attached present bitmap",
                    ));
                    proofs.push(*self.kzg_proofs.get(self_cell_index).expect(
                        "self partial kzg proofs contains proofs less than attached present bitmap",
                    ));
                }
                (false, true) => {
                    cells.push(other.partial_column.get(other_cell_index).cloned().expect(
                        "other partial column contains cells less than attached present bitmap",
                    ));
                    proofs.push(*other.kzg_proofs.get(other_cell_index).expect(
                        "other partial kzg proofs contains proofs less than attached present bitmap",
                    ));
                }
                _ => {}
            }

            if *self_present {
                self_cell_index += 1;
            }

            if *other_present {
                other_cell_index += 1;
            }
        }

        // merge cells present bitmap after compare with other
        self.cells_present_bitmap |= &other.cells_present_bitmap;
        self.partial_column = ContiguousList::try_from(cells).expect("should be within bound");
        self.kzg_proofs = ContiguousList::try_from(proofs).expect("should be within bound");

        if self.header.is_empty() && !other.header.is_empty() {
            self.header = other.header.clone();
        }
    }

    pub fn clone_filter<F: Fn(usize) -> bool>(&self, filter: F) -> Option<Self> {
        // create new partial sidecar that only include cells being filter
        let mut cells_present_bitmap = self.cells_present_bitmap.clone();
        let mut cells = Vec::new();
        let mut proofs = Vec::new();

        // iterate over `partial_column` and `kzg_proofs` which has different size from the bitmap
        let mut cell_index = 0;

        for (blob_index, present) in self.cells_present_bitmap.iter().enumerate() {
            if *present {
                let is_included = filter(blob_index);
                cells_present_bitmap.set(blob_index, is_included);

                if is_included {
                    cells.push(self.partial_column.get(cell_index).cloned()?);
                    proofs.push(*self.kzg_proofs.get(cell_index)?);
                }

                cell_index += 1;
            }
        }

        if cells.is_empty() {
            return None;
        }

        Some(Self {
            cells_present_bitmap,
            partial_column: ContiguousList::try_from(cells).expect("should be within bound"),
            kzg_proofs: ContiguousList::try_from(proofs).expect("should be within bound"),
            header: self.header.clone(),
        })
    }
}
