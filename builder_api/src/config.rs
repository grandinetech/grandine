use derive_more::Debug;
use types::redacting_url::RedactingUrl;

pub const DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH: u64 = 8;
pub const DEFAULT_BUILDER_MAX_SKIPPED_SLOTS: u64 = 3;

#[expect(clippy::struct_field_names)]
#[derive(Clone, Debug)]
pub struct Config {
    pub builder_api_url: RedactingUrl,
    pub builder_disable_checks: bool,
    pub builder_max_skipped_slots_per_epoch: u64,
    pub builder_max_skipped_slots: u64,
}
