use std::path::PathBuf;

use derivative::Derivative;
use ssz::Uint256;
use types::{
    bellatrix::primitives::Gas,
    phase0::primitives::{ExecutionAddress, H256},
};

#[derive(Clone, Debug, Derivative)]
#[derivative(Default)]
pub struct ValidatorConfig {
    pub graffiti: Vec<H256>,
    #[derivative(Default(value = "32"))]
    pub max_empty_slots: u64,
    pub suggested_fee_recipient: ExecutionAddress,
    #[derivative(Default(value = "Uint256::from_u64(100)"))]
    pub default_builder_boost_factor: Uint256,
    pub default_gas_limit: Gas,
    pub keystore_storage_password_file: Option<PathBuf>,
    pub withhold_data_columns_publishing: bool,
}
