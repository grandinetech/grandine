use std::{sync::Arc, time::Instant};

use anyhow::Result;
use clock::Tick;
use derivative::Derivative;
use eth2_libp2p::GossipId;
use fork_choice_store::{
    AggregateAndProofAction, AggregateAndProofOrigin, AttestationAction, AttestationItem,
    AttestationValidationError, BlobSidecarOrigin, BlockOrigin, ChainLink,
};
use serde::Serialize;
use strum::IntoStaticStr;
use types::{
    combined::{SignedAggregateAndProof, SignedBeaconBlock},
    deneb::containers::BlobSidecar,
    phase0::primitives::ValidatorIndex,
    preset::Preset,
};

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Delayed<P: Preset> {
    // These could be sets rather than `Vec`s now that we have our own SSZ bit collections, but
    // using sets makes logic for handling delayed objects more complicated and seems to worsen
    // performance in benchmarks.
    pub blocks: Vec<PendingBlock<P>>,
    pub aggregates: Vec<PendingAggregateAndProof<P>>,
    pub attestations: Vec<PendingAttestation<P>>,
    pub blob_sidecars: Vec<PendingBlobSidecar<P>>,
}

impl<P: Preset> Delayed<P> {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let Self {
            blocks,
            aggregates,
            attestations,
            blob_sidecars,
        } = self;

        blocks.is_empty()
            && aggregates.is_empty()
            && attestations.is_empty()
            && blob_sidecars.is_empty()
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
    pub fn is_empty(&self) -> bool {
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
    pub block: Arc<SignedBeaconBlock<P>>,
    pub origin: BlockOrigin,
    pub submission_time: Instant,
}

pub struct PendingChainLink<P: Preset> {
    pub chain_link: ChainLink<P>,
    pub attester_slashing_results: Vec<Result<Vec<ValidatorIndex>>>,
    pub origin: BlockOrigin,
    pub submission_time: Instant,
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

pub struct VerifyAggregateAndProofResult<P: Preset> {
    pub result: Result<AggregateAndProofAction<P>>,
    pub origin: AggregateAndProofOrigin<GossipId>,
}

pub type VerifyAttestationResult<P> =
    Result<AttestationAction<P, GossipId>, AttestationValidationError<P, GossipId>>;

#[expect(clippy::enum_variant_names)]
#[derive(IntoStaticStr, Serialize)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(test, derive(Debug))]
pub enum MutatorRejectionReason {
    InvalidAggregateAndProof,
    InvalidAttestation,
    InvalidBlock,
    InvalidBlobSidecar,
}

#[derive(Clone, Copy, Debug)]
pub enum StorageMode {
    Prune,
    Standard,
    Archive,
}

impl StorageMode {
    #[must_use]
    pub const fn is_prune(self) -> bool {
        matches!(self, Self::Prune)
    }

    #[must_use]
    pub const fn is_archive(self) -> bool {
        matches!(self, Self::Archive)
    }
}
