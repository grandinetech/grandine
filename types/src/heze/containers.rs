//! Heze containers from [`consensus-specs`].
//!
//! [`consensus-specs`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/heze/beacon-chain.md#containers

use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz::{ProgressiveList, Ssz};

use crate::{
    gloas::primitives::Transaction,
    phase0::primitives::{H256, Slot, ValidatorIndex},
    preset::Preset,
};

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct InclusionList<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub dependent_root: H256,
    pub transactions: ProgressiveList<Transaction<P>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedInclusionList<P: Preset> {
    pub message: InclusionList<P>,
    pub signature: SignatureBytes,
}
