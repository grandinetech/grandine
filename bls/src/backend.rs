use std::{fmt::{self, Display, Formatter}, sync::OnceLock, str::FromStr};

use thiserror::Error;

static BLS_BACKEND: OnceLock<Backend> = OnceLock::new();

pub fn backend() -> Backend {
    BLS_BACKEND.get().copied().unwrap_or_default()
}

pub fn set_backend(backend: Backend) -> Result<(), Backend> {
    BLS_BACKEND.set(backend)
}

#[derive(Clone, Copy, Debug, Default)]
pub enum Backend {
    #[cfg(feature = "blst")]
    #[default]
    Blst,

    #[cfg(feature = "zkcrypto")]
    #[cfg_attr(not(feature = "blst"), default)]
    Zkcrypto
}

impl Display for Backend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst => f.write_str("blst"),
            #[cfg(feature = "zkcrypto")]
            Self::Zkcrypto => f.write_str("zkcrypto"),
        }
    }
}

#[derive(Debug, Error)]
pub enum KzgBackendParseError {
    #[error("unknown backend {0} - valid values are blst, zkcrypto")]
    InvalidBackend(String),
    #[error("backend is not compiled - please specify feature flag when compiling grandine")]
    BackendNotCompiled,
}

impl FromStr for Backend {
    type Err = KzgBackendParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "blst")]
            "blst" => Ok(Self::Blst),
            #[cfg(not(feature = "blst"))]
            "blst" => Err(KzgBackendParseError::BackendNotCompiled),
            #[cfg(feature = "zkcrypto")]
            "zkcrypto" => Ok(Self::Zkcrypto),
            #[cfg(not(feature = "zkcrypto"))]
            "zkcrypto" => Err(KzgBackendParseError::BackendNotCompiled),
            unknown => Err(KzgBackendParseError::InvalidBackend(unknown.to_owned())),
        }
    }
}
