use anyhow::{anyhow, Result};
use futures::channel::mpsc::UnboundedSender;
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
