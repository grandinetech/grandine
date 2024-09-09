use std::time::{Duration, SystemTime};

use anyhow::Result;
use tracing::warn;
use prometheus::{Histogram, HistogramTimer, HistogramVec};
use types::phase0::primitives::UnixSeconds;

pub fn start_timer_vec(histogram_vec: &HistogramVec, label: &str) -> Option<HistogramTimer> {
    match histogram_vec
        .get_metric_with_label_values(&[label])
        .as_ref()
        .map(Histogram::start_timer)
    {
        Ok(timer) => Some(timer),
        Err(error) => {
            warn!(
                "unable to observe {label} metric for histogram_vec ({histogram_vec:?}): \
                    {error}",
            );

            None
        }
    }
}

pub fn stop_and_record(timer: Option<HistogramTimer>) {
    if let Some(timer) = timer {
        timer.stop_and_record();
    }
}

pub fn stop_and_discard(timer: Option<HistogramTimer>) {
    if let Some(timer) = timer {
        timer.stop_and_discard();
    }
}

// TODO: unit tests
pub fn duration_from_now_to(timestamp: UnixSeconds) -> Result<Duration> {
    let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;

    Ok(duration_since_epoch.saturating_sub(Duration::from_secs(timestamp)))
}
