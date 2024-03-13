//! Independently versioned containers from [`builder-specs`].
//!
//! [`builder-specs`]: https://github.com/ethereum/builder-specs/blob/d246d57ba2a0c2378c1de4a2bdaff7cd438e99ee/specs/builder.md#independently-versioned

use bls::{PublicKeyBytes, SignatureBytes};
use serde::{Deserialize, Serialize};
use ssz::Ssz;
use types::{
    bellatrix::primitives::Gas,
    phase0::primitives::{ExecutionAddress, UnixSeconds},
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Ssz)]
pub struct ValidatorRegistrationV1 {
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    pub gas_limit: Gas,
    #[serde(with = "serde_utils::string_or_native")]
    pub timestamp: UnixSeconds,
    pub pubkey: PublicKeyBytes,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignedValidatorRegistrationV1 {
    pub message: ValidatorRegistrationV1,
    pub signature: SignatureBytes,
}
