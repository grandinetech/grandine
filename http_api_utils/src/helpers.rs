use core::time::Duration;

use axum::{error_handling::HandleErrorLayer, http::StatusCode, Router};
use features::Feature;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::{logging, middleware, misc::ApiMetrics};

pub fn extend_router_with_middleware(
    mut router: Router,
    timeout: Option<Duration>,
    allowed_origins: AllowOrigin,
    api_metrics: Option<ApiMetrics>,
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

    if Feature::LogHttpRequests.is_enabled() || api_metrics.is_some() {
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
                .on_response(logging::log_response(api_metrics)),
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
