use core::time::Duration;
use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::{ConnectInfo, MatchedPath, OriginalUri},
    http::{Method, Request},
    response::Response,
};
use features::Feature;
use log::{info, warn};
use prometheus_metrics::Metrics;
use tracing::Span;

use crate::error::Error;

// `TraceLayer` already logs most of this out of the box, but we still use `log`.
// We have to duplicate some of the information because `log` does not have spans.
//
// Enabling the `log` feature of the `tracing` crate isn't enough.
// By default, `TraceLayer` emits events at `DEBUG` with the default target.
// Our application filters them out.

pub fn log_request(request: &Request<Body>, _span: &Span) {
    let method = request.method();
    let uri = request.uri();

    if Feature::LogHttpRequests.is_enabled() {
        let version = request.version();

        let ConnectInfo::<SocketAddr>(remote) = request.extensions().get().expect(
            "ConnectInfo<SocketAddr> request extension should be \
             inserted by into_make_service_with_connect_info",
        );

        info!("received request ({method} {uri} {version:?}) from {remote}");
    }

    if Feature::LogHttpHeaders.is_enabled() {
        let headers = request.headers();

        info!("request headers for ({method} {uri}): {headers:?}");
    }
}

pub fn log_response(metrics: Option<Arc<Metrics>>) -> impl Fn(&Response, Duration, &Span) + Clone {
    move |response: &Response, latency: Duration, _span: &Span| {
        if Feature::LogHttpRequests.is_enabled() {
            let version = response.version();
            let status = response.status();

            let method = response.extensions().get::<Method>().expect(
                "Method response extension should be inserted by insert_response_extensions",
            );

            let OriginalUri(original_uri) = response.extensions().get().expect(
                "OriginalUri response extension should be inserted by insert_response_extensions",
            );

            let ConnectInfo::<SocketAddr>(remote) = response.extensions().get().expect(
                "ConnectInfo<SocketAddr> response extension \
                should be inserted by insert_response_extensions",
            );

            match (
                // Use `match` to extend the lifetime of `Arguments` created by `format_args!`. See:
                // <https://stackoverflow.com/questions/48732263/why-is-rusts-assert-eq-implemented-using-a-match/54855986#54855986>
                format_args!(
                    "produced response ({version:?} {status}) \
                    to ({method} {original_uri} {version:?}) \
                    for {remote} in {latency:?}",
                ),
                response.extensions().get::<Error>(),
            ) {
                (shared, Some(error)) => info!("{shared} (error: {})", error.format_sources()),
                (shared, None) => info!("{shared}"),
            }
        }

        if let Some(metrics) = metrics.clone() {
            log_latency_metrics(&metrics, response, latency);
        }
    }
}

pub fn log_latency_metrics(metrics: &Arc<Metrics>, response: &Response, latency: Duration) {
    // Don't observe arbitrary requests
    if response.status().as_u16() == 404 {
        return;
    }

    let method = response
        .extensions()
        .get::<Method>()
        .expect("Method response extension should be inserted by insert_response_extensions");

    if let Some(matched_path) = response
        .extensions()
        .get::<Option<MatchedPath>>()
        .cloned()
        .flatten()
    {
        metrics.set_http_response_time(&[&format!("{method} {}", matched_path.as_str())], latency);
    } else {
        let OriginalUri(original_uri) = response.extensions().get().expect(
            "OriginalUri response extension should be inserted by insert_response_extensions",
        );

        warn!(
            "Unable to observe HTTP API metrics: MatchedPath response extension is missing for: {}",
            original_uri
        );
    }
}
