use ssz::{ContiguousList, SszHash as _};
use std_ext::ArcExt as _;

use crate::{
    combined::BlobSidecar,
    deneb::{
        containers::{
            BeaconBlock, BeaconBlockBody, BlindedBeaconBlock, BlindedBeaconBlockBody,
            BlobIdentifier, ExecutionPayload, ExecutionPayloadHeader,
        },
        primitives::KzgCommitment,
    },
    phase0::primitives::H256,
    preset::Preset,
};

impl<P: Preset> BeaconBlock<P> {
    pub fn with_execution_payload_header_and_kzg_commitments(
        self,
        execution_payload_header: ExecutionPayloadHeader<P>,
        kzg_commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
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
            },
        }
    }
}

impl<P: Preset> BlindedBeaconBlock<P> {
    pub fn with_execution_payload(self, execution_payload: ExecutionPayload<P>) -> BeaconBlock<P> {
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
        };

        BeaconBlock {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        }
    }

    #[must_use]
    pub const fn with_state_root(mut self, state_root: H256) -> Self {
        self.state_root = state_root;
        self
    }
}

impl<P: Preset> From<&ExecutionPayload<P>> for ExecutionPayloadHeader<P> {
    fn from(payload: &ExecutionPayload<P>) -> Self {
        let ExecutionPayload {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            ref extra_data,
            base_fee_per_gas,
            block_hash,
            ref transactions,
            ref withdrawals,
            blob_gas_used,
            excess_blob_gas,
        } = *payload;

        let extra_data = extra_data.clone_arc();
        let transactions_root = transactions.hash_tree_root();
        let withdrawals_root = withdrawals.hash_tree_root();

        Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions_root,
            withdrawals_root,
            blob_gas_used,
            excess_blob_gas,
        }
    }
}

impl<P: Preset> From<&BlobSidecar<P>> for BlobIdentifier {
    fn from(blob_sidecar: &BlobSidecar<P>) -> Self {
        Self {
            block_root: blob_sidecar.signed_block_header().message.hash_tree_root(),
            index: blob_sidecar.index(),
        }
    }
}
