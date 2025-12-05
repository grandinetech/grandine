use std::collections::BTreeMap;

use features::Feature;
use tracing::info;

/// `GET /features`
pub fn get_features() -> BTreeMap<Feature, bool> {
    enum_iterator::all::<Feature>()
        .map(|feature| (feature, feature.is_enabled()))
        .collect()
}

/// `PATCH /features`
pub fn patch_features(features: BTreeMap<Feature, bool>) {
    for (feature, enabled) in features {
        feature.set_enabled(enabled);

        let verb = if enabled { "enabled" } else { "disabled" };
        info!("feature {feature} {verb}");
    }
}
