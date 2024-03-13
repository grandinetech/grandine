use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use features::Feature;
use futures::channel::mpsc::UnboundedSender;
use log::info;
use metrics::ApiToMetrics;
use types::nonstandard::SystemStats;

/// `GET /system/stats`
pub async fn get_system_stats(
    api_to_metrics_tx: Option<UnboundedSender<ApiToMetrics>>,
) -> Result<SystemStats> {
    let api_to_metrics_tx =
        api_to_metrics_tx.ok_or_else(|| anyhow!("metrics service is not configured"))?;
    let (sender, receiver) = futures::channel::oneshot::channel();

    ApiToMetrics::SystemStats(sender).send(&api_to_metrics_tx);

    receiver.await?
}

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
