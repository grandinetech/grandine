use std::{path::PathBuf, sync::Arc};

use derivative::Derivative;
use keymanager::{BuilderSettings, ValidatorDefinitionsWithStorage};
use types::{
    bellatrix::primitives::Gas,
    nonstandard::CustodyMode,
    phase0::primitives::{ExecutionAddress, H256},
};

#[derive(Clone, Debug, Derivative)]
#[derivative(Default)]
pub struct ValidatorConfig {
    pub disable_blockprint_graffiti: bool,
    pub graffiti: Vec<H256>,
    #[derivative(Default(value = "32"))]
    pub max_empty_slots: u64,
    pub suggested_fee_recipient: ExecutionAddress,
    pub default_gas_limit: Option<Gas>,
    pub builder_settings: BuilderSettings,
    pub keystore_storage_password_file: Option<PathBuf>,
    #[derivative(Default(value = "true"))]
    pub backfill_custody_groups: bool,
    pub custody_mode: CustodyMode,
    pub disable_wait_for_late_blocks: bool,
    /// The `validators.yml` definitions, shared with the Keymanager API so runtime settings changes
    /// are reflected in both the running node and the file.
    pub validator_definitions: Arc<ValidatorDefinitionsWithStorage>,
}
