use std::path::PathBuf;

use educe::Educe;
use types::phase0::primitives::{ExecutionAddress, H256};

#[derive(Clone, Debug, Educe)]
#[educe(Default)]
pub struct ValidatorConfig {
    pub graffiti: Vec<H256>,
    #[educe(Default = 32)]
    pub max_empty_slots: u64,
    pub suggested_fee_recipient: ExecutionAddress,
    pub keystore_storage_password_file: Option<PathBuf>,
}
