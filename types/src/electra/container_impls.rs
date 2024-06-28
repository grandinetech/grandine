use hashing::ZERO_HASHES;
use ssz::{ContiguousList, SszHash};
use std_ext::ArcExt as _;
use typenum::U1;

use crate::{
    deneb::primitives::KzgCommitment,
    electra::{
        beacon_state::BeaconState,
        containers::{
            Attestation, BeaconBlock, BeaconBlockBody, BlindedBeaconBlock, BlindedBeaconBlockBody,
            ExecutionPayload, ExecutionPayloadHeader, IndexedAttestation,
        },
    },
    phase0::primitives::H256,
    preset::Preset,
};

impl<P: Preset> SszHash for Attestation<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let Self {
            aggregation_bits,
            data,
            signature,
            committee_bits,
        } = self;

        hashing::hash_256_256(
            hashing::hash_256_256(
                hashing::hash_256_256(aggregation_bits.hash_tree_root(), data.hash_tree_root()),
                hashing::hash_256_256(signature.hash_tree_root(), committee_bits.hash_tree_root()),
            ),
            ZERO_HASHES[2],
        )
    }
}

impl<P: Preset> SszHash for BeaconState<P> {
    type PackingFactor = U1;

    #[allow(clippy::too_many_lines)]
    fn hash_tree_root(&self) -> H256 {
        let Self {
            genesis_time,
            genesis_validators_root,
            slot,
            fork,
            latest_block_header,
            block_roots,
            state_roots,
            historical_roots,
            eth1_data,
            eth1_data_votes,
            eth1_deposit_index,
            validators,
            balances,
            randao_mixes,
            slashings,
            previous_epoch_participation,
            current_epoch_participation,
            justification_bits,
            previous_justified_checkpoint,
            current_justified_checkpoint,
            finalized_checkpoint,
            inactivity_scores,
            current_sync_committee,
            next_sync_committee,
            latest_execution_payload_header,
            next_withdrawal_index,
            next_withdrawal_validator_index,
            historical_summaries,
            deposit_requests_start_index,
            deposit_balance_to_consume,
            exit_balance_to_consume,
            earliest_exit_epoch,
            consolidation_balance_to_consume,
            earliest_consolidation_epoch,
            pending_balance_deposits,
            pending_partial_withdrawals,
            pending_consolidations,
            cache: _,
        } = self;

        hashing::hash_256_256(
            hashing::hash_256_256(
                hashing::hash_256_256(
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                hashing::hash_256_256(
                                    genesis_time.hash_tree_root(),
                                    *genesis_validators_root,
                                ),
                                hashing::hash_256_256(slot.hash_tree_root(), fork.hash_tree_root()),
                            ),
                            hashing::hash_256_256(
                                hashing::hash_256_256(
                                    latest_block_header.hash_tree_root(),
                                    block_roots.hash_tree_root(),
                                ),
                                hashing::hash_256_256(
                                    state_roots.hash_tree_root(),
                                    historical_roots.hash_tree_root(),
                                ),
                            ),
                        ),
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                hashing::hash_256_256(
                                    eth1_data.hash_tree_root(),
                                    eth1_data_votes.hash_tree_root(),
                                ),
                                hashing::hash_256_256(
                                    eth1_deposit_index.hash_tree_root(),
                                    validators.hash_tree_root(),
                                ),
                            ),
                            hashing::hash_256_256(
                                hashing::hash_256_256(
                                    balances.hash_tree_root(),
                                    randao_mixes.hash_tree_root(),
                                ),
                                hashing::hash_256_256(
                                    slashings.hash_tree_root(),
                                    previous_epoch_participation.hash_tree_root(),
                                ),
                            ),
                        ),
                    ),
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                hashing::hash_256_256(
                                    current_epoch_participation.hash_tree_root(),
                                    justification_bits.hash_tree_root(),
                                ),
                                hashing::hash_256_256(
                                    previous_justified_checkpoint.hash_tree_root(),
                                    current_justified_checkpoint.hash_tree_root(),
                                ),
                            ),
                            hashing::hash_256_256(
                                hashing::hash_256_256(
                                    finalized_checkpoint.hash_tree_root(),
                                    inactivity_scores.hash_tree_root(),
                                ),
                                hashing::hash_256_256(
                                    current_sync_committee.hash_tree_root(),
                                    next_sync_committee.hash_tree_root(),
                                ),
                            ),
                        ),
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                hashing::hash_256_256(
                                    latest_execution_payload_header.hash_tree_root(),
                                    next_withdrawal_index.hash_tree_root(),
                                ),
                                hashing::hash_256_256(
                                    next_withdrawal_validator_index.hash_tree_root(),
                                    historical_summaries.hash_tree_root(),
                                ),
                            ),
                            hashing::hash_256_256(
                                hashing::hash_256_256(
                                    deposit_requests_start_index.hash_tree_root(),
                                    deposit_balance_to_consume.hash_tree_root(),
                                ),
                                hashing::hash_256_256(
                                    exit_balance_to_consume.hash_tree_root(),
                                    earliest_exit_epoch.hash_tree_root(),
                                ),
                            ),
                        ),
                    ),
                ),
                hashing::hash_256_256(
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                hashing::hash_256_256(
                                    consolidation_balance_to_consume.hash_tree_root(),
                                    earliest_consolidation_epoch.hash_tree_root(),
                                ),
                                hashing::hash_256_256(
                                    pending_balance_deposits.hash_tree_root(),
                                    pending_partial_withdrawals.hash_tree_root(),
                                ),
                            ),
                            hashing::hash_256_256(
                                hashing::hash_256_256(
                                    pending_consolidations.hash_tree_root(),
                                    ZERO_HASHES[0],
                                ),
                                ZERO_HASHES[1],
                            ),
                        ),
                        ZERO_HASHES[3],
                    ),
                    ZERO_HASHES[4],
                ),
            ),
            ZERO_HASHES[6],
        )
    }
}

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

impl<P: Preset> SszHash for BeaconBlockBody<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let Self {
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
        } = self;

        hashing::hash_256_256(
            hashing::hash_256_256(
                hashing::hash_256_256(
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                randao_reveal.hash_tree_root(),
                                eth1_data.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                graffiti.hash_tree_root(),
                                proposer_slashings.hash_tree_root(),
                            ),
                        ),
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                attester_slashings.hash_tree_root(),
                                attestations.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                deposits.hash_tree_root(),
                                voluntary_exits.hash_tree_root(),
                            ),
                        ),
                    ),
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                sync_aggregate.hash_tree_root(),
                                execution_payload.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                bls_to_execution_changes.hash_tree_root(),
                                blob_kzg_commitments.hash_tree_root(),
                            ),
                        ),
                        ZERO_HASHES[2],
                    ),
                ),
                ZERO_HASHES[4],
            ),
            ZERO_HASHES[5],
        )
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

impl<P: Preset> SszHash for BlindedBeaconBlockBody<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let Self {
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
            blob_kzg_commitments,
        } = self;

        hashing::hash_256_256(
            hashing::hash_256_256(
                hashing::hash_256_256(
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                randao_reveal.hash_tree_root(),
                                eth1_data.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                graffiti.hash_tree_root(),
                                proposer_slashings.hash_tree_root(),
                            ),
                        ),
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                attester_slashings.hash_tree_root(),
                                attestations.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                deposits.hash_tree_root(),
                                voluntary_exits.hash_tree_root(),
                            ),
                        ),
                    ),
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                sync_aggregate.hash_tree_root(),
                                execution_payload_header.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                bls_to_execution_changes.hash_tree_root(),
                                blob_kzg_commitments.hash_tree_root(),
                            ),
                        ),
                        ZERO_HASHES[2],
                    ),
                ),
                ZERO_HASHES[4],
            ),
            ZERO_HASHES[5],
        )
    }
}

impl<P: Preset> SszHash for ExecutionPayload<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let Self {
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
            blob_gas_used,
            excess_blob_gas,
            deposit_requests,
            withdrawal_requests,
            consolidation_requests,
        } = self;

        hashing::hash_256_256(
            hashing::hash_256_256(
                hashing::hash_256_256(
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(*parent_hash, fee_recipient.hash_tree_root()),
                            hashing::hash_256_256(
                                state_root.hash_tree_root(),
                                receipts_root.hash_tree_root(),
                            ),
                        ),
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                logs_bloom.hash_tree_root(),
                                prev_randao.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                block_number.hash_tree_root(),
                                gas_limit.hash_tree_root(),
                            ),
                        ),
                    ),
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                gas_used.hash_tree_root(),
                                timestamp.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                extra_data.hash_tree_root(),
                                base_fee_per_gas.hash_tree_root(),
                            ),
                        ),
                        hashing::hash_256_256(
                            hashing::hash_256_256(*block_hash, transactions.hash_tree_root()),
                            hashing::hash_256_256(
                                withdrawals.hash_tree_root(),
                                blob_gas_used.hash_tree_root(),
                            ),
                        ),
                    ),
                ),
                hashing::hash_256_256(
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                excess_blob_gas.hash_tree_root(),
                                deposit_requests.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                withdrawal_requests.hash_tree_root(),
                                consolidation_requests.hash_tree_root(),
                            ),
                        ),
                        ZERO_HASHES[2],
                    ),
                    ZERO_HASHES[3],
                ),
            ),
            ZERO_HASHES[5],
        )
    }
}

impl<P: Preset> SszHash for ExecutionPayloadHeader<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let Self {
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
            deposit_requests_root,
            withdrawal_requests_root,
            consolidation_requests_root,
        } = self;

        hashing::hash_256_256(
            hashing::hash_256_256(
                hashing::hash_256_256(
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(*parent_hash, fee_recipient.hash_tree_root()),
                            hashing::hash_256_256(
                                state_root.hash_tree_root(),
                                receipts_root.hash_tree_root(),
                            ),
                        ),
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                logs_bloom.hash_tree_root(),
                                prev_randao.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                block_number.hash_tree_root(),
                                gas_limit.hash_tree_root(),
                            ),
                        ),
                    ),
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                gas_used.hash_tree_root(),
                                timestamp.hash_tree_root(),
                            ),
                            hashing::hash_256_256(
                                extra_data.hash_tree_root(),
                                base_fee_per_gas.hash_tree_root(),
                            ),
                        ),
                        hashing::hash_256_256(
                            hashing::hash_256_256(*block_hash, *transactions_root),
                            hashing::hash_256_256(
                                *withdrawals_root,
                                blob_gas_used.hash_tree_root(),
                            ),
                        ),
                    ),
                ),
                hashing::hash_256_256(
                    hashing::hash_256_256(
                        hashing::hash_256_256(
                            hashing::hash_256_256(
                                excess_blob_gas.hash_tree_root(),
                                *deposit_requests_root,
                            ),
                            hashing::hash_256_256(
                                *withdrawal_requests_root,
                                *consolidation_requests_root,
                            ),
                        ),
                        ZERO_HASHES[2],
                    ),
                    ZERO_HASHES[3],
                ),
            ),
            ZERO_HASHES[5],
        )
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
            ref deposit_requests,
            ref withdrawal_requests,
            ref consolidation_requests,
        } = *payload;

        let extra_data = extra_data.clone_arc();
        let transactions_root = transactions.hash_tree_root();
        let withdrawals_root = withdrawals.hash_tree_root();
        let deposit_requests_root = deposit_requests.hash_tree_root();
        let withdrawal_requests_root = withdrawal_requests.hash_tree_root();
        let consolidation_requests_root = consolidation_requests.hash_tree_root();

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
            deposit_requests_root,
            withdrawal_requests_root,
            consolidation_requests_root,
        }
    }
}

impl<P: Preset> SszHash for IndexedAttestation<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let Self {
            attesting_indices,
            data,
            signature,
        } = self;

        hashing::hash_256_256(
            hashing::hash_256_256(
                hashing::hash_256_256(attesting_indices.hash_tree_root(), data.hash_tree_root()),
                hashing::hash_256_256(signature.hash_tree_root(), ZERO_HASHES[0]),
            ),
            ZERO_HASHES[2],
        )
    }
}
