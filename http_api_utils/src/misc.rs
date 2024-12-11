use core::time::Duration;
use std::sync::Arc;

use parse_display::Display;
use prometheus_metrics::Metrics;

#[derive(Clone, Copy)]
enum ApiType {
    Http,
    Validator,
}

#[derive(Clone)]
pub struct ApiMetrics {
    api_type: ApiType,
    prometheus_metrics: Arc<Metrics>,
}

impl ApiMetrics {
    #[must_use]
    pub const fn http(prometheus_metrics: Arc<Metrics>) -> Self {
        Self {
            api_type: ApiType::Http,
            prometheus_metrics,
        }
    }

    #[must_use]
    pub const fn validator(prometheus_metrics: Arc<Metrics>) -> Self {
        Self {
            api_type: ApiType::Validator,
            prometheus_metrics,
        }
    }

    pub fn set_response_time(&self, labels: &[&str], response_duration: Duration) {
        match self.api_type {
            ApiType::Http => self
                .prometheus_metrics
                .set_http_api_response_time(labels, response_duration),
            ApiType::Validator => self
                .prometheus_metrics
                .set_validator_api_response_time(labels, response_duration),
        }
    }
}

#[derive(Clone, Copy, Debug, Display)]
#[display(style = "lowercase")]
pub enum Direction {
    Request,
    Response,
}
