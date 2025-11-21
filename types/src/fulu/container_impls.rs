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
        DataColumnIdentifier, DataColumnSidecar, DataColumnsByRootIdentifier,
    },
    phase0::primitives::H256,
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
