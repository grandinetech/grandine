//! Capella containers from [`builder-specs`].
//!
//! [`builder-specs`]: https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#fork-versioned

use bls::{PublicKeyBytes, SignatureBytes};
use serde::Deserialize;
use ssz::Ssz;
use types::{
    bellatrix::primitives::Wei, capella::containers::ExecutionPayloadHeader, preset::Preset,
};

#[derive(Debug, Deserialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(derive_read = false, derive_size = false, derive_write = false)]
pub struct BuilderBid<P: Preset> {
    pub header: Box<ExecutionPayloadHeader<P>>,
    pub value: Wei,
    pub pubkey: PublicKeyBytes,
}

#[derive(Debug, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedBuilderBid<P: Preset> {
    pub message: BuilderBid<P>,
    pub signature: SignatureBytes,
}
