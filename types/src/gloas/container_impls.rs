use core::{fmt, iter, marker::PhantomData};
use std::sync::Arc;

use ssz::{ByteList, ContiguousList, H256, ProgressiveList, SszHash};
use std_ext::ArcExt as _;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned;

use crate::{
    capella::containers::Withdrawal,
    combined::UnblindError,
    deneb::primitives::{KzgCommitment, KzgProof},
    electra::containers::{
        Attestation as ElectraAttestation, AttesterSlashing as ElectraAttesterSlashing,
        ConsolidationRequest, DepositRequest, IndexedAttestation as ElectraIndexedAttestation,
        WithdrawalRequest,
    },
    gloas::{
        containers::{
            Attestation, AttesterSlashing, BlindedExecutionPayloadEnvelope, BuilderDepositRequest,
            BuilderExitRequest, CombinedPayloadAttestation, DataColumnSidecar, ExecutionPayload,
            ExecutionPayloadEnvelope, ExecutionPayloadHeader, ExecutionRequests,
            IndexedAttestation, PayloadAttestationData, PayloadAttestationMessage,
            PayloadEnvelopeIdentifier, SignedBlindedExecutionPayloadEnvelope,
            SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
        },
        primitives::BuilderIndex,
    },
    nonstandard::ExecutionPayloadBody,
    phase0::primitives::Slot,
    preset::Preset,
};

fn repeat_to_limit<T: Clone>(element: T, limit: usize) -> ProgressiveList<T> {
    ProgressiveList::try_from_iter(iter::repeat_n(element, limit))
        .expect("preset limits never exceed the progressive list bound")
}

impl<P: Preset> From<ElectraAttestation<P>> for Attestation<P> {
    fn from(attestation: ElectraAttestation<P>) -> Self {
        let ElectraAttestation {
            aggregation_bits,
            data,
            signature,
            committee_bits,
        } = attestation;

        Self {
            aggregation_bits: aggregation_bits.into(),
            data,
            signature,
            committee_bits,
        }
    }
}

impl<P: Preset> From<Attestation<P>> for ElectraAttestation<P> {
    fn from(attestation: Attestation<P>) -> Self {
        let Attestation {
            aggregation_bits,
            data,
            signature,
            committee_bits,
        } = attestation;

        Self {
            aggregation_bits: aggregation_bits.into(),
            data,
            signature,
            committee_bits,
        }
    }
}

impl<P: Preset> From<ElectraIndexedAttestation<P>> for IndexedAttestation<P> {
    fn from(indexed_attestation: ElectraIndexedAttestation<P>) -> Self {
        let ElectraIndexedAttestation {
            attesting_indices,
            data,
            signature,
        } = indexed_attestation;

        Self {
            attesting_indices: attesting_indices.into(),
            data,
            signature,
            phantom: PhantomData,
        }
    }
}

impl<P: Preset> From<ElectraAttesterSlashing<P>> for AttesterSlashing<P> {
    fn from(attester_slashing: ElectraAttesterSlashing<P>) -> Self {
        let ElectraAttesterSlashing {
            attestation_1,
            attestation_2,
        } = attester_slashing;

        Self {
            attestation_1: attestation_1.into(),
            attestation_2: attestation_2.into(),
        }
    }
}

impl<P: Preset> SignedExecutionPayloadEnvelope<P> {
    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.message.payload.slot_number
    }

    #[must_use]
    pub const fn block_root(&self) -> H256 {
        self.message.beacon_block_root
    }

    #[must_use]
    pub const fn builder_index(&self) -> BuilderIndex {
        self.message.builder_index
    }

    #[must_use]
    pub fn execution_payload_body(&self) -> ExecutionPayloadBody<P> {
        (&self.message.payload).into()
    }

    /// Builds an envelope with every list at its maximum length, except `transactions` and
    /// `block_access_list`, which stay empty: both are bounded by `MaxBytesPerTransaction`, so one
    /// full transaction is a gigabyte and a full list of them is a petabyte. Callers that need
    /// their size add it arithmetically.
    #[must_use]
    pub fn full() -> Self {
        Self {
            message: ExecutionPayloadEnvelope {
                payload: ExecutionPayload {
                    extra_data: Arc::new(ByteList::from(ContiguousList::full(u8::MAX))),
                    withdrawals: repeat_to_limit(
                        Withdrawal::default(),
                        P::MaxWithdrawalsPerPayload::USIZE,
                    ),
                    ..Default::default()
                },
                execution_requests: ExecutionRequests {
                    deposits: repeat_to_limit(
                        DepositRequest::default(),
                        P::GloasDepositRequestsBound::USIZE,
                    ),
                    withdrawals: repeat_to_limit(
                        WithdrawalRequest::default(),
                        P::MaxWithdrawalRequestsPerPayload::USIZE,
                    ),
                    consolidations: repeat_to_limit(
                        ConsolidationRequest::default(),
                        P::MaxConsolidationRequestsPerPayload::USIZE,
                    ),
                    builder_deposits: repeat_to_limit(
                        BuilderDepositRequest::default(),
                        P::MaxBuilderDepositRequestsPerPayload::USIZE,
                    ),
                    builder_exits: repeat_to_limit(
                        BuilderExitRequest::default(),
                        P::MaxBuilderExitRequestsPerPayload::USIZE,
                    ),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

impl<P: Preset> SignedBlindedExecutionPayloadEnvelope<P> {
    pub fn unblind(
        self,
        payload_body: ExecutionPayloadBody<P>,
    ) -> Result<SignedExecutionPayloadEnvelope<P>, UnblindError> {
        let ExecutionPayloadBody {
            transactions,
            withdrawals,
            block_access_list,
        } = payload_body;

        let withdrawals = withdrawals.ok_or(UnblindError::MissingWithdrawals)?;
        let block_access_list = block_access_list.ok_or(UnblindError::MissingBlockAccessList)?;

        Ok(SignedExecutionPayloadEnvelope {
            signature: self.signature,
            message: ExecutionPayloadEnvelope {
                payload: ExecutionPayload {
                    parent_hash: self.message.payload_header.parent_hash,
                    fee_recipient: self.message.payload_header.fee_recipient,
                    state_root: self.message.payload_header.state_root,
                    receipts_root: self.message.payload_header.receipts_root,
                    logs_bloom: self.message.payload_header.logs_bloom,
                    prev_randao: self.message.payload_header.prev_randao,
                    block_number: self.message.payload_header.block_number,
                    gas_limit: self.message.payload_header.gas_limit,
                    gas_used: self.message.payload_header.gas_used,
                    timestamp: self.message.payload_header.timestamp,
                    extra_data: self.message.payload_header.extra_data,
                    base_fee_per_gas: self.message.payload_header.base_fee_per_gas,
                    block_hash: self.message.payload_header.block_hash,
                    transactions,
                    withdrawals,
                    blob_gas_used: self.message.payload_header.blob_gas_used,
                    excess_blob_gas: self.message.payload_header.excess_blob_gas,
                    block_access_list,
                    slot_number: self.message.payload_header.slot_number,
                },
                execution_requests: self.message.execution_requests,
                builder_index: self.message.builder_index,
                beacon_block_root: self.message.beacon_block_root,
                parent_beacon_block_root: self.message.parent_beacon_block_root,
            },
        })
    }
}

impl<P: Preset> DataColumnSidecar<P> {
    #[must_use]
    pub fn with_max_blobs(max_blobs: usize) -> Self {
        Self {
            column: repeat_to_limit(Box::default(), max_blobs),
            kzg_proofs: repeat_to_limit(KzgProof::default(), max_blobs),
            ..Default::default()
        }
    }
}

#[expect(clippy::missing_fields_in_debug)]
impl<P: Preset> fmt::Debug for DataColumnSidecar<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataColumnSidecar")
            .field("index", &self.index)
            .field("beacon_block_root", &self.beacon_block_root)
            .field("slot", &self.slot)
            .finish()
    }
}

impl<P: Preset> CombinedPayloadAttestation<P> {
    pub fn data(&self) -> PayloadAttestationData {
        match self {
            Self::Attestation(payload_attestation) => payload_attestation.data,
            Self::Message(payload_attestation) => payload_attestation.data,
        }
    }

    pub const fn message(&self) -> Option<&Arc<PayloadAttestationMessage>> {
        match self {
            Self::Attestation(_) => None,
            Self::Message(message) => Some(message),
        }
    }
}

impl<P: Preset> SignedExecutionPayloadBid<P> {
    #[must_use]
    pub const fn blob_kzg_commitments(&self) -> &ProgressiveList<KzgCommitment> {
        &self.message.blob_kzg_commitments
    }
}

impl<P: Preset> From<&SignedExecutionPayloadEnvelope<P>> for PayloadEnvelopeIdentifier {
    fn from(payload: &SignedExecutionPayloadEnvelope<P>) -> Self {
        let beacon_block_root = payload.block_root();
        let builder_index = payload.builder_index();

        Self {
            beacon_block_root,
            builder_index,
        }
    }
}

impl<P: Preset> From<&ExecutionPayload<P>> for ExecutionPayloadHeader<P> {
    fn from(value: &ExecutionPayload<P>) -> Self {
        Self {
            parent_hash: value.parent_hash,
            fee_recipient: value.fee_recipient,
            state_root: value.state_root,
            receipts_root: value.receipts_root,
            logs_bloom: value.logs_bloom,
            prev_randao: value.prev_randao,
            block_number: value.block_number,
            gas_limit: value.gas_limit,
            gas_used: value.gas_used,
            timestamp: value.timestamp,
            extra_data: value.extra_data.clone_arc(),
            base_fee_per_gas: value.base_fee_per_gas,
            block_hash: value.block_hash,
            transactions_root: value.transactions.hash_tree_root(),
            withdrawals_root: value.withdrawals.hash_tree_root(),
            blob_gas_used: value.blob_gas_used,
            excess_blob_gas: value.excess_blob_gas,
            block_access_list_root: value.block_access_list.hash_tree_root(),
            slot_number: value.slot_number,
        }
    }
}

impl<P: Preset> From<&ExecutionPayload<P>> for ExecutionPayloadBody<P> {
    fn from(payload: &ExecutionPayload<P>) -> Self {
        Self {
            transactions: payload.transactions.clone_arc(),
            withdrawals: Some(payload.withdrawals.clone()),
            block_access_list: Some(payload.block_access_list.clone_arc()),
        }
    }
}

impl<P: Preset> From<SignedExecutionPayloadEnvelope<P>>
    for SignedBlindedExecutionPayloadEnvelope<P>
{
    fn from(value: SignedExecutionPayloadEnvelope<P>) -> Self {
        Self {
            signature: value.signature,
            message: value.message.into(),
        }
    }
}

impl<P: Preset> From<ExecutionPayloadEnvelope<P>> for BlindedExecutionPayloadEnvelope<P> {
    fn from(value: ExecutionPayloadEnvelope<P>) -> Self {
        Self {
            payload_header: (&value.payload).into(),
            execution_requests: value.execution_requests,
            builder_index: value.builder_index,
            beacon_block_root: value.beacon_block_root,
            parent_beacon_block_root: value.parent_beacon_block_root,
        }
    }
}
