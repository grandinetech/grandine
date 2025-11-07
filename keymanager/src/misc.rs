use anyhow::Error as AnyhowError;
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("cannot decrypt keystores storage password: {error}")]
    CannotDecryptPassword { error: AnyhowError },
    #[error("cannot load keystores storage password from file: {error}")]
    CannotLoadPassword { error: AnyhowError },
    #[error("key already exists")]
    Duplicate,
    #[error("key not found")]
    NotFound,
    #[error("number of passwords does not match number of keystores")]
    PasswordCountMismatch,
    #[error("key is read-only")]
    ReadOnly,
    #[error(
        "password for decrypting keystores is missing, run Grandine with --keystore-storage-password-file to provide it"
    )]
    StoragePasswordNotProvided,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Deleted,
    Duplicate,
    Error,
    Imported,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct OperationStatus {
    pub status: Status,
    pub message: Option<String>,
}

impl From<AnyhowError> for OperationStatus {
    fn from(error: AnyhowError) -> Self {
        Self {
            status: Status::Error,
            message: Some(format!("{error}")),
        }
    }
}

impl From<Error> for OperationStatus {
    fn from(error: Error) -> Self {
        Self {
            status: Status::Error,
            message: Some(format!("{error}")),
        }
    }
}

impl From<Status> for OperationStatus {
    fn from(status: Status) -> Self {
        Self {
            status,
            message: None,
        }
    }
}
