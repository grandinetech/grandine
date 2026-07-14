use core::fmt;
use std::sync::Arc;

use ssz::{ByteList, ContiguousList, H256, ProgressiveByteList, ProgressiveList};

use crate::{
    capella::containers::Withdrawal,
    deneb::primitives::{KzgCommitment, KzgProof},
    electra::containers::{
        Attestation as ElectraAttestation, ConsolidationRequest, DepositRequest, WithdrawalRequest,
    },
    gloas::{
        containers::{
            Attestation, BuilderDepositRequest, BuilderExitRequest, CombinedPayloadAttestation,
            DataColumnSidecar, ExecutionPayload, ExecutionPayloadEnvelope, ExecutionRequests,
            PayloadAttestationData, PayloadAttestationMessage, PayloadEnvelopeIdentifier,
            SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
        },
        primitives::BuilderIndex,
    },
    phase0::primitives::Slot,
    preset::Preset,
};

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
                    transactions: Arc::new(ProgressiveList::full(ProgressiveByteList::from(
                        ByteList::from(ContiguousList::full(u8::MAX)),
                    ))),
                    withdrawals: ProgressiveList::full(Withdrawal::default()),
                    block_access_list: Arc::new(ProgressiveByteList::from(ByteList::from(
                        ContiguousList::full(u8::MAX),
                    ))),
                    ..Default::default()
                },
                execution_requests: ExecutionRequests {
                    deposits: ProgressiveList::full(DepositRequest::default()),
                    withdrawals: ProgressiveList::full(WithdrawalRequest::default()),
                    consolidations: ProgressiveList::full(ConsolidationRequest::default()),
                    builder_deposits: ProgressiveList::full(BuilderDepositRequest::default()),
                    builder_exits: ProgressiveList::full(BuilderExitRequest::default()),
                    ..Default::default()
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
            column: ProgressiveList::full(Box::default()),
            kzg_proofs: ProgressiveList::full(KzgProof::repeat_byte(u8::MAX)),
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
