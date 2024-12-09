#![expect(clippy::module_name_repetitions)]

use thiserror::Error;

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum KzgError {
    #[error("kzg error: {0}")]
    KzgError(String),
}
