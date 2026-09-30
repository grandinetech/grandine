use std::sync::Arc;

use ssz::{ContiguousList, Hc, SszHash as _};
use std_ext::ArcExt as _;

use crate::{
    bellatrix::primitives::Transaction,
    capella::containers::{
        BeaconBlock, BeaconBlockBody, BlindedBeaconBlock, BlindedBeaconBlockBody, ExecutionPayload,
        ExecutionPayloadHeader, Withdrawal,
    },
    nonstandard::ExecutionPayloadBody,
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
        .into()
    }

    pub fn unblind(
        self,
        transactions: Arc<ContiguousList<Transaction<P>, P::MaxTransactionsPerPayload>>,
        withdrawals: ContiguousList<Withdrawal, P::MaxWithdrawalsPerPayload>,
    ) -> Hc<BeaconBlock<P>> {
        let ExecutionPayloadHeader {
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
            transactions_root: _,
            withdrawals_root: _,
        } = self.body.execution_payload_header.clone();

        let execution_payload = ExecutionPayload {
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
            transactions,
            withdrawals,
        };

        self.with_execution_payload(execution_payload)
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

impl<P: Preset> From<ExecutionPayload<P>> for ExecutionPayloadBody<P> {
    fn from(payload: ExecutionPayload<P>) -> Self {
        let transactions = Arc::unwrap_or_clone(payload.transactions)
            .map(Into::into)
            .into();

        Self {
            transactions: Arc::new(transactions),
            withdrawals: Some(payload.withdrawals.into()),
            block_access_list: None,
        }
    }
}
