use crate::{
    bellatrix::primitives::Transaction,
    phase0::primitives::{Slot, ValidatorIndex, H256},
    preset::Preset,
};
use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz::{ContiguousList, Ssz};

pub type InclusionListTransactions<P> =
    ContiguousList<Transaction<P>, <P as Preset>::MaxInclusionListTransactions>;

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct InclusionList<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub inclusion_list_committee_root: H256,
    pub transactions: InclusionListTransactions<P>,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedInclusionList<P: Preset> {
    pub message: InclusionList<P>,
    pub signature: SignatureBytes,
}
