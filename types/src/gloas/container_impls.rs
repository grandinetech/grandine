use core::fmt;
use std::sync::Arc;

use ssz::{ByteList, ContiguousList, H256};

use crate::{
    capella::containers::Withdrawal,
    deneb::primitives::{KzgCommitment, KzgProof},
    electra::containers::{
        ConsolidationRequest, DepositRequest, ExecutionRequests, WithdrawalRequest,
    },
    gloas::{
        containers::{
            CombinedPayloadAttestation, DataColumnSidecar, ExecutionPayload,
            ExecutionPayloadEnvelope, PayloadAttestationData, PayloadAttestationMessage,
            PayloadEnvelopeIdentifier, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
        },
        primitives::BuilderIndex,
    },
    phase0::primitives::Slot,
    preset::Preset,
};

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
    pub fn full() -> Self {
        Self {
            message: ExecutionPayloadEnvelope {
                payload: ExecutionPayload {
                    extra_data: Arc::new(ByteList::from(ContiguousList::full(u8::MAX))),
                    transactions: Arc::new(ContiguousList::full(ByteList::from(
                        ContiguousList::full(u8::MAX),
                    ))),
                    withdrawals: ContiguousList::full(Withdrawal::default()),
                    block_access_list: Arc::new(ByteList::from(ContiguousList::full(u8::MAX))),
                    ..Default::default()
                },
                execution_requests: ExecutionRequests {
                    deposits: ContiguousList::full(DepositRequest::default()),
                    withdrawals: ContiguousList::full(WithdrawalRequest::default()),
                    consolidations: ContiguousList::full(ConsolidationRequest::default()),
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

impl<P: Preset> DataColumnSidecar<P> {
    #[must_use]
    pub fn full() -> Self {
        Self {
            column: ContiguousList::full(Box::default()),
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
    pub const fn blob_kzg_commitments(
        &self,
    ) -> &ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock> {
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
