//! Electra containers from [`builder-specs`].
//!
//! [`builder-specs`]: `TODO`

use bls::{PublicKeyBytes, SignatureBytes};
use serde::Deserialize;
use ssz::{ContiguousList, Ssz};
use types::{
    deneb::{containers::ExecutionPayloadHeader, primitives::KzgCommitment},
    electra::containers::ExecutionRequests,
    phase0::primitives::Uint256,
    preset::Preset,
};

#[derive(Debug, Deserialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(derive_unify = false, derive_write = false)]
pub struct BuilderBid<P: Preset> {
    pub header: Box<ExecutionPayloadHeader<P>>,
    pub blob_kzg_commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
    pub execution_requests: ExecutionRequests<P>,
    pub value: Uint256,
    pub pubkey: PublicKeyBytes,
}

#[derive(Debug, Deserialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(derive_unify = false, derive_write = false)]
pub struct SignedBuilderBid<P: Preset> {
    pub message: BuilderBid<P>,
    pub signature: SignatureBytes,
}
