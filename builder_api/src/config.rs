use derive_more::{Debug, Display, FromStr};
use types::redacting_url::RedactingUrl;

pub const DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH: u64 = 8;
pub const DEFAULT_BUILDER_MAX_SKIPPED_SLOTS: u64 = 3;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Display, FromStr)]
pub enum BuilderApiFormat {
    Json,
    #[default]
    Ssz,
}

#[expect(clippy::struct_field_names)]
#[derive(Clone, Debug)]
pub struct Config {
    pub builder_api_format: BuilderApiFormat,
    pub builder_api_url: RedactingUrl,
    pub builder_disable_checks: bool,
    pub builder_max_skipped_slots_per_epoch: u64,
    pub builder_max_skipped_slots: u64,
}
