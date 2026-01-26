use std::{path::PathBuf, sync::Arc};

use bls::PublicKeyBytes;
use derivative::Derivative;
use keymanager::{BuilderOptions, ValidatorDefinitionsWithStorage};
use ssz::Uint256;
use types::{
    bellatrix::primitives::Gas,
    nonstandard::CustodyMode,
    phase0::primitives::{ExecutionAddress, H256},
};

#[expect(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Derivative)]
#[derivative(Default)]
pub struct ValidatorConfig {
    pub disable_blockprint_graffiti: bool,
    pub graffiti: Vec<H256>,
    #[derivative(Default(value = "32"))]
    pub max_empty_slots: u64,
    pub suggested_fee_recipient: ExecutionAddress,
    #[derivative(Default(value = "Uint256::from_u64(100)"))]
    pub default_builder_boost_factor: Uint256,
    pub default_gas_limit: Gas,
    pub keystore_storage_password_file: Option<PathBuf>,
    #[derivative(Default(value = "true"))]
    pub backfill_custody_groups: bool,
    pub custody_mode: CustodyMode,
    pub disable_wait_for_late_blocks: bool,
    pub enable_local_payload_building: bool,
    /// The `validators.yml` definitions, shared with the Keymanager API so runtime settings changes
    /// are reflected in both the running node and the file.
    pub validator_definitions: Arc<ValidatorDefinitionsWithStorage>,
}

impl ValidatorConfig {
    /// Resolve the builder boost factor for `pubkey`: per-validator overrides declared in
    /// `validators.yml` take precedence over the process-wide default.
    ///
    /// - `prefer_builder_proposals == Some(true)` → `Uint256::MAX` (always prefer the builder)
    /// - `builder_boost_factor == Some(n)`        → `n` (percentage applied to the builder bid)
    /// - `builder_proposals == Some(false)`       → `Uint256::ZERO` (always prefer local)
    /// - otherwise                                → the process-wide default
    #[must_use]
    pub fn builder_boost_factor(&self, pubkey: PublicKeyBytes) -> Uint256 {
        let validator_definitions = self.validator_definitions.read();

        let Some(definition) = validator_definitions.get(pubkey) else {
            return self.default_builder_boost_factor;
        };

        let BuilderOptions {
            prefer_builder_proposals,
            builder_boost_factor,
            builder_proposals,
        } = definition.builder_options;

        if prefer_builder_proposals == Some(true) {
            Uint256::MAX
        } else if let Some(factor) = builder_boost_factor {
            Uint256::from_u64(factor)
        } else if builder_proposals == Some(false) {
            Uint256::ZERO
        } else {
            self.default_builder_boost_factor
        }
    }
}
