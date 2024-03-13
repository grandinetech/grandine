use ssz::SszHash as _;
use std_ext::ArcExt as _;

use crate::{
    capella::containers::{
        BeaconBlock, BeaconBlockBody, BlindedBeaconBlock, BlindedBeaconBlockBody, ExecutionPayload,
        ExecutionPayloadHeader,
    },
    phase0::primitives::H256,
    preset::Preset,
};

impl<P: Preset> BeaconBlock<P> {
    pub fn with_execution_payload_header(
        self,
        execution_payload_header: ExecutionPayloadHeader<P>,
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
        }
    }
}
