use core::net::SocketAddr;
use std::error::Error as StdError;

use axum::{
    body::{Body, Bytes, HttpBody},
    extract::{ConnectInfo, MatchedPath, OriginalUri},
    http::{
        header::{HeaderValue, CONTENT_TYPE},
        Request, Uri,
    },
    middleware::Next,
    response::{IntoResponse as _, Response},
    Error as AxumError, Extension,
};
use log::info;
use mime::{APPLICATION_JSON, TEXT_EVENT_STREAM};

use crate::{error::Error, misc::Direction};

// Don't log states when `Feature::LogHttpBodies` is enabled.
const ENDPOINTS_WITH_IGNORED_BODIES: &[&str] = &["/eth/v2/debug/beacon/states/"];

async fn buffer_and_log<B>(direction: Direction, uri: &Uri, body: B) -> Result<Bytes, Error>
where
    B: HttpBody<Data = Bytes> + Send,
    B::Error: StdError + Send + Sync + 'static,
{
    let bytes = hyper::body::to_bytes(body)
        .await
        .map_err(|error| Error::InvalidBody {
            direction,
            uri: uri.clone(),
            source: error.into(),
        })?;

    if let Ok(string) = core::str::from_utf8(&bytes) {
        info!("{direction} body for {uri}: {string:?}");
    }

    Ok(bytes)
}

pub async fn insert_response_extensions(request: Request<Body>, next: Next<Body>) -> Response {
    let remote = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied()
        .expect(
            "ConnectInfo<SocketAddr> request extension should be \
             inserted by into_make_service_with_connect_info",
        );

    let method = request.method().clone();
    let matched_path = request.extensions().get::<MatchedPath>().cloned();

    let original_uri = request
        .extensions()
        .get::<OriginalUri>()
        .cloned()
        .expect("OriginalUri request extension should be inserted by axum");

    (
        Extension(remote),
        Extension(method),
        Extension(original_uri),
        Extension(matched_path),
        next.run(request).await,
    )
        .into_response()
}

pub async fn log_request_and_response_bodies(
    request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, Error> {
    let uri = request.uri().clone();

    let (parts, body) = request.into_parts();
    let bytes = buffer_and_log(Direction::Request, &uri, body).await?;
    let request = Request::from_parts(parts, Body::from(bytes));
    let response = next.run(request).await;

    if response.headers().get(CONTENT_TYPE)
        == Some(&HeaderValue::from_static(TEXT_EVENT_STREAM.as_ref()))
        || ENDPOINTS_WITH_IGNORED_BODIES
            .iter()
            .any(|prefix| uri.path().starts_with(prefix))
    {
        return Ok(response);
    }

    let (parts, body) = response.into_parts();
    let bytes = buffer_and_log(Direction::Response, &uri, body).await?;
    let response = Response::from_parts(
        parts,
        Body::from(bytes).map_err(AxumError::new).boxed_unsync(),
    );

    Ok(response)
}

// Prysm submits requests without `Content-Type`.
// The Eth Beacon Node API [requires `Content-Type` to be present].
// There seem to be no issues about this at <https://github.com/prysmaticlabs/prysm/issues>.
//
// [requires `Content-Type` to be present]: https://github.com/ethereum/beacon-APIs/blob/6ed3820587afce7525528ca1d21abae7647087a3/beacon-node-oapi.yaml#L8-L9
pub async fn patch_content_type(mut request: Request<Body>) -> Request<Body> {
    request
        .headers_mut()
        .entry(CONTENT_TYPE)
        .or_insert(HeaderValue::from_static(APPLICATION_JSON.as_ref()));

    request
}
