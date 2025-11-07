use core::error::Error as StdError;
use std::sync::Arc;

use anyhow::Error as AnyhowError;
use axum::{
    Extension,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::{misc::Direction, traits::ApiError};

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to read {direction} body for {uri}")]
    InvalidBody {
        direction: Direction,
        uri: Uri,
        source: AnyhowError,
    },
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
    fn into_response(self) -> Response {
        let status_code = self.status_code();
        let extension = Extension(Arc::new(self));
        (status_code, extension).into_response()
    }
}

impl Error {
    const fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidBody { .. } => StatusCode::BAD_REQUEST,
        }
    }
}
