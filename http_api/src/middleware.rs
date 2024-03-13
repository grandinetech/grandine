// This makes `http_api::routing` less messy at the cost of coupling to `axum` even more.
#![allow(clippy::unused_async)]

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
};
use features::Feature;

use crate::{error::Error, misc::SyncedStatus};

#[cfg(test)]
use types::preset::Preset;

#[cfg(test)]
use crate::misc::TestApiController;

pub async fn feature_is_enabled(
    State(feature): State<Feature>,
    request: Request<Body>,
) -> Result<Request<Body>, StatusCode> {
    feature
        .is_enabled()
        .then_some(request)
        .ok_or(StatusCode::FORBIDDEN)
}

pub async fn is_synced(
    State(is_synced): State<Arc<SyncedStatus>>,
    request: Request<Body>,
) -> Result<Request<Body>, Error> {
    is_synced
        .get()
        .then_some(request)
        .ok_or(Error::NodeIsSyncing)
}

#[cfg(test)]
pub async fn wait_for_tasks<P: Preset>(
    State(controller): State<TestApiController<P>>,
    request: Request<Body>,
) -> Result<Request<Body>, Error> {
    tokio::task::spawn_blocking(move || controller.wait_for_tasks()).await?;
    Ok(request)
}
