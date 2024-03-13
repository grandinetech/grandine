use core::time::Duration;
use std::sync::Arc;

use axum::{error_handling::HandleErrorLayer, http::StatusCode, Router};
use features::Feature;
use prometheus_metrics::Metrics;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::{logging, middleware};

pub fn extend_router_with_middleware(
    mut router: Router,
    timeout: Option<Duration>,
    allowed_origins: AllowOrigin,
    metrics: Option<Arc<Metrics>>,
) -> Router {
    if let Some(timeout) = timeout {
        router = router.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_| async {
                    StatusCode::REQUEST_TIMEOUT
                }))
                .timeout(timeout),
        );
    }

    router = router.layer(CorsLayer::new().allow_origin(allowed_origins).vary([]));

    if Feature::LogHttpRequests.is_enabled() || metrics.is_some() {
        router = router.layer(axum::middleware::from_fn(
            middleware::insert_response_extensions,
        ));
    }

    if Feature::LogHttpRequests.is_enabled()
        || Feature::LogHttpHeaders.is_enabled()
        || Feature::PrometheusMetrics.is_enabled()
    {
        router = router.layer(
            TraceLayer::new_for_http()
                .on_request(logging::log_request)
                .on_response(logging::log_response(metrics)),
        );
    }

    if Feature::LogHttpBodies.is_enabled() {
        router = router.layer(axum::middleware::from_fn(
            middleware::log_request_and_response_bodies,
        ));
    }

    if Feature::PatchHttpContentType.is_enabled() {
        router = router.layer(axum::middleware::map_request(
            middleware::patch_content_type,
        ));
    }

    router
}
