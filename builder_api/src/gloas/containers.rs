//! Gloas containers from [`builder-specs`].
//!
//! [`builder-specs`]: https://github.com/ethereum/builder-specs/blob/38f11441c194d150386f567b4d7087ec86d4118c/specs/gloas/validator.md#new-containers

use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz::{ByteList, Ssz};
use types::phase0::primitives::Slot;

use crate::consts::MaxBuilderAuthDataSize;

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct RequestAuth {
    pub data: ByteList<MaxBuilderAuthDataSize>,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SignedRequestAuth {
    pub message: RequestAuth,
    pub signature: SignatureBytes,
}
