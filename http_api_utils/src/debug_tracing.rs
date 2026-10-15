use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use binary_utils::TracingHandle;
use serde::Deserialize;
use tracing::instrument;

#[derive(Deserialize)]
pub struct LogLevelRequest {
    target: String,
    level: String,
}

#[derive(Deserialize)]
pub struct TraceLevelRequest {
    target: Option<String>,
    level: String,
}

/// `POST /eth/v2/debug/tracing/log_level`
#[instrument(skip_all, level = "debug", name = "http_api::post_log_level")]
pub async fn post_log_level(
    State(handle): State<Option<TracingHandle>>,
    Json(req): Json<LogLevelRequest>,
) -> impl IntoResponse {
    let directive_str = format!("{}={}", req.target, req.level);

    match directive_str.parse() {
        Ok(directive) => {
            if let Some(handle) = handle {
                if let Err(e) = handle.modify_log(|filter| {
                    let old = core::mem::take(filter);
                    *filter = old.add_directive(directive);
                }) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to reload filter: {e}"),
                    );
                }
                (StatusCode::OK, "log level updated".to_owned())
            } else {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "tracing not available".to_owned(),
                )
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("invalid directive: {e}")),
    }
}

/// `POST /eth/v2/debug/tracing/trace_level`
#[instrument(skip_all, level = "debug", name = "http_api::post_trace_level")]
pub async fn post_trace_level(
    State(handle): State<Option<TracingHandle>>,
    Json(req): Json<TraceLevelRequest>,
) -> impl IntoResponse {
    let TraceLevelRequest { target, level } = req;

    let directive_str = target
        .map(|target| format!("{target}={level}"))
        .unwrap_or(level);

    match directive_str.parse() {
        Ok(directive) => {
            if let Some(handle) = handle {
                match handle.modify_trace(|filter| {
                    let old = core::mem::take(filter);
                    *filter = old.add_directive(directive);
                }) {
                    Ok(Some(())) => (StatusCode::OK, "trace level updated".to_owned()),
                    Ok(None) => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "telemetry not available".to_owned(),
                    ),
                    Err(e) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to reload filter: {e}"),
                    ),
                }
            } else {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "tracing not available".to_owned(),
                )
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("invalid directive: {e}")),
    }
}
