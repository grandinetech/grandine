use core::time::Duration;
use std::{sync::Arc, time::Instant};

use anyhow::Result;
use clock::Tick;
use derivative::Derivative;
use eth2_libp2p::GossipId;
use execution_engine::PayloadStatusV1;
use fork_choice_store::{
    AggregateAndProofAction, AggregateAndProofOrigin, AttestationAction, AttestationItem,
    AttestationValidationError, BlobSidecarOrigin, BlockItem, BlockOrigin, ChainLink,
    DataColumnSidecarOrigin, ExecutionPayloadEnvelopeOrigin, PayloadAttestationAction,
    PayloadAttestationItem, PayloadAttestationValidationError, ProposerPreferencesOrigin,
};
use scc::HashMap as SccHashMap;
use serde::Serialize;
use ssz::H256;
use strum::IntoStaticStr;
use tokio::sync::broadcast::Sender;
use tracing::Span;
use types::{
    combined::{DataColumnSidecar, SignedAggregateAndProof},
    deneb::{
        containers::{BlobIdentifier, BlobSidecar},
        primitives::BlobIndex,
    },
    fulu::{containers::DataColumnIdentifier, primitives::ColumnIndex},
    gloas::containers::{
        PayloadEnvelopeIdentifier, SignedExecutionPayloadEnvelope, SignedProposerPreferences,
    },
    phase0::primitives::{Slot, ValidatorIndex},
    preset::Preset,
};

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Delayed<P: Preset> {
    // These could be sets rather than `Vec`s now that we have our own SSZ bit collections, but
    // using sets makes logic for handling delayed objects more complicated and seems to worsen
    // performance in benchmarks.
    pub blocks: Vec<PendingBlock<P>>,
    pub unverified_blocks: Vec<PendingBlock<P>>,
    // There can only be one payload status per block
    pub payload_status: Option<(PayloadStatusV1, Slot)>,
    pub aggregates: Vec<PendingAggregateAndProof<P>>,
    pub attestations: Vec<PendingAttestation<P>>,
    pub payload_attestations: Vec<PayloadAttestationItem<P>>,
    pub blob_sidecars: Vec<PendingBlobSidecar<P>>,
    pub data_column_sidecars: Vec<PendingDataColumnSidecar<P>>,
    pub execution_payload_envelopes: Vec<PendingExecutionPayloadEnvelope<P>>,
    pub proposer_preferences: Vec<PendingProposerPreferences>,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessingTimings {
    pub delay_duration: Duration,
    pub delay_time: Option<Instant>,
    pub submission_time: Instant,
}

impl ProcessingTimings {
    pub fn new() -> Self {
        Self {
            delay_duration: Duration::ZERO,
            delay_time: None,
            submission_time: Instant::now(),
        }
    }

    pub fn delayed(self) -> Self {
        self.next(Some(Instant::now()))
    }

    pub fn processing(self) -> Self {
        self.next(None)
    }

    fn next(self, new_delay_time: Option<Instant>) -> Self {
        let Self {
            delay_duration,
            delay_time,
            submission_time,
        } = self;

        let delay_duration = delay_duration.saturating_add(
            delay_time
                .map(|delay_time| Instant::now().duration_since(delay_time))
                .unwrap_or_default(),
        );

        Self {
            delay_duration,
            delay_time: new_delay_time,
            submission_time,
        }
    }
}

impl<P: Preset> Delayed<P> {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        let Self {
            blocks,
            unverified_blocks,
            payload_status,
            aggregates,
            attestations,
            payload_attestations,
            blob_sidecars,
            data_column_sidecars,
            execution_payload_envelopes,
            proposer_preferences,
        } = self;

        blocks.is_empty()
            && unverified_blocks.is_empty()
            && payload_status.is_none()
            && aggregates.is_empty()
            && attestations.is_empty()
            && payload_attestations.is_empty()
            && blob_sidecars.is_empty()
            && data_column_sidecars.is_empty()
            && execution_payload_envelopes.is_empty()
            && proposer_preferences.is_empty()
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct WaitingForCheckpointState<P: Preset> {
    pub ticks: Vec<Tick>,
    pub chain_links: Vec<PendingChainLink<P>>,
    pub aggregates: Vec<PendingAggregateAndProof<P>>,
    pub attestations: Vec<PendingAttestation<P>>,
}

impl<P: Preset> WaitingForCheckpointState<P> {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        let Self {
            ticks,
            chain_links,
            aggregates,
            attestations,
        } = self;

        ticks.is_empty()
            && chain_links.is_empty()
            && aggregates.is_empty()
            && attestations.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct PendingBlock<P: Preset> {
    pub block: BlockItem<P>,
    pub origin: BlockOrigin,
    pub processing_timings: ProcessingTimings,
    pub tracing_span: Span,
}

pub struct PendingChainLink<P: Preset> {
    pub chain_link: ChainLink<P>,
    pub attester_slashing_results: Vec<Result<Vec<ValidatorIndex>>>,
    pub origin: BlockOrigin,
    pub processing_timings: ProcessingTimings,
}

#[derive(Debug)]
pub struct PendingAggregateAndProof<P: Preset> {
    pub aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
    pub origin: AggregateAndProofOrigin<GossipId>,
}

pub type PendingAttestation<P> = AttestationItem<P, GossipId>;

#[derive(Debug)]
pub struct PendingBlobSidecar<P: Preset> {
    pub blob_sidecar: Arc<BlobSidecar<P>>,
    pub block_seen: bool,
    pub origin: BlobSidecarOrigin,
    pub submission_time: Instant,
}

#[derive(Debug)]
pub struct PendingDataColumnSidecar<P: Preset> {
    pub data_column_sidecar: Arc<DataColumnSidecar<P>>,
    pub block_seen: bool,
    pub origin: DataColumnSidecarOrigin,
    pub submission_time: Instant,
}

#[derive(Debug)]
pub struct PendingExecutionPayloadEnvelope<P: Preset> {
    pub execution_payload_envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
    pub origin: ExecutionPayloadEnvelopeOrigin,
    pub processing_timings: ProcessingTimings,
    pub tracing_span: Span,
}

#[derive(Debug)]
pub struct PendingProposerPreferences {
    pub signed_preferences: Arc<SignedProposerPreferences>,
    pub origin: ProposerPreferencesOrigin,
}

pub struct VerifyAggregateAndProofResult<P: Preset> {
    pub result: Result<AggregateAndProofAction<P>>,
    pub origin: AggregateAndProofOrigin<GossipId>,
}

pub type VerifyAttestationResult<P> =
    Result<AttestationAction<P, GossipId>, AttestationValidationError<P, GossipId>>;

pub type VerifyPayloadAttestationResult<P> =
    Result<PayloadAttestationAction<P>, PayloadAttestationValidationError<P>>;

#[expect(clippy::enum_variant_names)]
#[derive(Debug, IntoStaticStr, Serialize)]
#[strum(serialize_all = "snake_case")]
pub enum MutatorIgnoreReason {
    #[strum(serialize = "block_queue_full")]
    BlockQueueFull { block_root: H256 },
    #[strum(serialize = "blob_queue_full")]
    BlobQueueFull { blob_identifier: BlobIdentifier },
    #[strum(serialize = "data_column_queue_full")]
    DataColumnQueueFull {
        data_column_identifier: DataColumnIdentifier,
    },
}

#[expect(clippy::enum_variant_names)]
#[derive(Debug, IntoStaticStr, Serialize)]
#[strum(serialize_all = "snake_case")]
pub enum MutatorRejectionReason {
    InvalidAggregateAndProof,
    InvalidAttestation,
    InvalidBlock,
    #[strum(serialize = "invalid_blob_sidecar")]
    InvalidBlobSidecar {
        blob_identifier: BlobIdentifier,
    },
    #[strum(serialize = "invalid_data_column_sidecar")]
    InvalidDataColumnSidecar {
        data_column_identifier: DataColumnIdentifier,
    },
    #[strum(serialize = "invalid_execution_payload_envelope")]
    InvalidExecutionPayloadEnvelope {
        payload_envelope_identifier: PayloadEnvelopeIdentifier,
    },
    InvalidPayloadBid,
    InvalidPayloadAttestation,
    InvalidProposerPreferences,
}

pub enum BlockBlobAvailability {
    Complete,
    CompleteWithPending,
    Missing(Vec<BlobIndex>),
    Irrelevant,
}

#[derive(Clone, Copy, Debug)]
pub enum ReorgSource {
    AggregateAndProof,
    Attestation,
    AttesterSlashing,
    Block,
    BlockAttestation,
    PayloadAttestation,
    PayloadResponse,
    Tick,
}

#[derive(Debug)]
pub enum BlockDataColumnAvailability {
    Complete,
    CompleteWithReconstruction { import_block: bool },
    AnyPending,
    Missing(Vec<ColumnIndex>),
    Irrelevant,
}

pub type SidecarsPendingReconstruction<P> =
    Arc<SccHashMap<DataColumnIdentifier, (Slot, Sender<Arc<DataColumnSidecar<P>>>)>>;
