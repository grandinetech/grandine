use std::path::PathBuf;

use derivative::Derivative;
use types::phase0::primitives::Gwei;

#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct BuilderConfig {
    #[derivative(Default(value = "32"))]
    pub max_empty_slots: u64,
    pub keystore_storage_password_file: Option<PathBuf>,

    /// Minimum bid value to submit (in gwei)
    pub min_bid_value: Gwei,
}
