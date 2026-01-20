use core::fmt;
use std::sync::Arc;

use ssz::{ByteList, ContiguousList, H256};

use crate::{
    capella::containers::Withdrawal,
    deneb::{
        containers::ExecutionPayload,
        primitives::{KzgCommitment, KzgProof},
    },
    electra::containers::{
        ConsolidationRequest, DepositRequest, ExecutionRequests, WithdrawalRequest,
    },
    gloas::containers::{
        CombinedPayloadAttestation, DataColumnSidecar, ExecutionPayloadEnvelope,
        PayloadAttestationData, SignedExecutionPayloadEnvelope,
    },
    phase0::primitives::Slot,
    preset::Preset,
};

impl<P: Preset> SignedExecutionPayloadEnvelope<P> {
    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.message.slot
    }

    #[must_use]
    pub const fn block_root(&self) -> H256 {
        self.message.beacon_block_root
    }

    #[must_use]
    pub const fn blob_kzg_commitments(
        &self,
    ) -> &ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock> {
        &self.message.blob_kzg_commitments
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
                    ..Default::default()
                },
                execution_requests: ExecutionRequests {
                    deposits: ContiguousList::full(DepositRequest::default()),
                    withdrawals: ContiguousList::full(WithdrawalRequest::default()),
                    consolidations: ContiguousList::full(ConsolidationRequest::default()),
                },
                blob_kzg_commitments: ContiguousList::full(KzgCommitment::repeat_byte(u8::MAX)),
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
            .field("beacon_block_root", &self.beacon_block_root)
            .field("kzg_commitments", &self.kzg_commitments)
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
}
