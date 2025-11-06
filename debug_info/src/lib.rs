use core::time::Duration;
use std::time::Instant;

use features::Feature;
use futures::stream::{Fuse, StreamExt as _};
use logging::warn_with_peers;
use tokio_stream::wrappers::IntervalStream;

const HEALTH_CHECK_INTERVAL_DURATION: Duration = Duration::from_millis(10);
const HEALTH_CHECK_ALERT_THRESHOLD: Duration = Duration::from_millis(50);

pub struct HealthCheck {
    pub service_name: String,
    pub last_check: Instant,
    pub interval: Fuse<IntervalStream>,
}

impl HealthCheck {
    pub fn new(service_name: impl Into<String>) -> Self {
        let last_check = Instant::now();
        let interval =
            IntervalStream::new(tokio::time::interval(HEALTH_CHECK_INTERVAL_DURATION)).fuse();

        Self {
            service_name: service_name.into(),
            last_check,
            interval,
        }
    }

    pub fn check(&mut self) {
        if !should_warn() {
            return;
        }

        let now = Instant::now();
        let duration_since_last_check = now.duration_since(self.last_check);

        if duration_since_last_check > HEALTH_CHECK_ALERT_THRESHOLD {
            warn_with_peers!(
                "{} could not handle events for {} ms",
                self.service_name,
                duration_since_last_check.as_millis(),
            );
        }

        self.last_check = now;
    }
}

fn should_warn() -> bool {
    Feature::WarnOnFailedServiceHealthChecks.is_enabled()
}
