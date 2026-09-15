use core::error::Error as StdError;
use std::sync::Arc;

use anyhow::Error as AnyhowError;
use axum::{
    Extension, Json,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;
use tracing::instrument;

use crate::{misc::Direction, traits::ApiError};

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to read {direction} body for {uri}")]
    InvalidBody {
        direction: Direction,
        uri: Uri,
        source: AnyhowError,
    },
    #[error("internal error")]
    Internal(#[from] AnyhowError),
}

impl ApiError for Error {
    fn sources(&self) -> impl Iterator<Item = &dyn StdError> {
        let mut error: Option<&dyn StdError> = Some(self);

        core::iter::from_fn(move || {
            let source = error?.source();
            core::mem::replace(&mut error, source)
        })
    }
}

impl IntoResponse for Error {
    #[instrument(skip_all, level = "debug")]
    fn into_response(self) -> Response {
        let status_code = self.status_code();

        let body = Json(EthErrorResponse {
            code: status_code.as_u16(),
            message: self.format_sources(),
        })
        .into_response();

        let extension = Extension(Arc::new(self));
        (status_code, extension, body).into_response()
    }
}

impl Error {
    const fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidBody { .. } => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Serialize)]
struct EthErrorResponse {
    // The absence of `#[serde(with = "serde_utils::string_or_native")]` is intentional.
    // The `code` field is supposed to contain a number.
    code: u16,
    message: String,
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use http_body_util::BodyExt as _;

    use super::*;

    // The body is what a beacon-API client expects of any error, so a failed response is not
    // left bodiless.
    #[tokio::test]
    async fn an_internal_error_carries_the_standard_error_body() -> Result<(), AnyhowError> {
        let response = Error::Internal(anyhow!("boom")).into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = response.into_body().collect().await?.to_bytes();

        assert_eq!(
            body.as_ref(),
            br#"{"code":500,"message":"internal error: boom"}"#,
        );

        Ok(())
    }
}
