//! Deneb containers from [`builder-specs`].
//!
//! [`builder-specs`]: `https://github.com/ethereum/builder-specs/blob/v0.4.0/specs/deneb/builder.md`

use bls::{PublicKeyBytes, SignatureBytes};
use serde::Deserialize;
use ssz::{ContiguousList, Ssz};
use types::{
    deneb::{
        containers::{ExecutionPayload, ExecutionPayloadHeader},
        primitives::{Blob, KzgCommitment, KzgProof},
    },
    phase0::primitives::Uint256,
    preset::Preset,
};

#[derive(Debug, Deserialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BuilderBid<P: Preset> {
    pub header: Box<ExecutionPayloadHeader<P>>,
    pub blob_kzg_commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
    pub value: Uint256,
    pub pubkey: PublicKeyBytes,
}

#[derive(Debug, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedBuilderBid<P: Preset> {
    pub message: BuilderBid<P>,
    pub signature: SignatureBytes,
}

#[derive(Debug, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BlobsBundle<P: Preset> {
    pub commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
    pub proofs: ContiguousList<KzgProof, P::MaxBlobCommitmentsPerBlock>,
    pub blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

#[derive(Debug, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub struct ExecutionPayloadAndBlobsBundle<P: Preset> {
    pub execution_payload: ExecutionPayload<P>,
    pub blobs_bundle: BlobsBundle<P>,
}
