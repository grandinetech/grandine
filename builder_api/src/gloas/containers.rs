//! Gloas containers from [`builder-specs`].
//!
//! [`builder-specs`]: https://github.com/ethereum/builder-specs/pull/165

use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz::{ByteList, Ssz};
use types::phase0::primitives::Slot;

use crate::consts::MaxDataSize;

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct RequestAuth {
    pub data: ByteList<MaxDataSize>,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SignedRequestAuth {
    pub message: RequestAuth,
    pub signature: SignatureBytes,
}
