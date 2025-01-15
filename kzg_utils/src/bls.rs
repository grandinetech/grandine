use core::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy)]
pub enum KzgBackend {
    #[cfg(feature = "arkworks")]
    Arkworks,
    #[cfg(feature = "blst")]
    Blst,
    #[cfg(feature = "constantine")]
    Constantine,
    #[cfg(feature = "mcl")]
    Mcl,
    #[cfg(feature = "zkcrypto")]
    Zkcrypto,
}

impl Display for KzgBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "arkworks")]
            Self::Arkworks => f.write_str("arkworks"),
            #[cfg(feature = "blst")]
            Self::Blst => f.write_str("blst"),
            #[cfg(feature = "constantine")]
            Self::Constantine => f.write_str("constantine"),
            #[cfg(feature = "mcl")]
            Self::Mcl => f.write_str("mcl"),
            #[cfg(feature = "zkcrypto")]
            Self::Zkcrypto => f.write_str("zkcrypto"),
        }
    }
}

#[derive(Debug, Error)]
pub enum KzgBackendParseError {
    #[error("unknown backend {0} - valid values are arkworks, blst, constantine, zkcrypto")]
    InvalidBackend(String),
    #[error("backend is not compiled - please specify feature flag when compiling grandine")]
    BackendNotCompiled,
}

impl FromStr for KzgBackend {
    type Err = KzgBackendParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "arkworks")]
            "arkworks" => Ok(Self::Arkworks),
            #[cfg(not(feature = "arkworks"))]
            "arkworks" => Err(KzgBackendParseError::BackendNotCompiled),
            #[cfg(feature = "blst")]
            "blst" => Ok(Self::Blst),
            #[cfg(not(feature = "blst"))]
            "blst" => Err(KzgBackendParseError::BackendNotCompiled),
            #[cfg(feature = "constantine")]
            "constantine" => Ok(Self::Constantine),
            #[cfg(not(feature = "constantine"))]
            "constantine" => Err(KzgBackendParseError::BackendNotCompiled),
            #[cfg(feature = "mcl")]
            "mcl" => Ok(Self::Mcl),
            #[cfg(not(feature = "mcl"))]
            "mcl" => Err(KzgBackendParseError::BackendNotCompiled),
            #[cfg(feature = "zkcrypto")]
            "zkcrypto" => Ok(Self::Zkcrypto),
            #[cfg(not(feature = "zkcrypto"))]
            "zkcrypto" => Err(KzgBackendParseError::BackendNotCompiled),
            unknown => Err(KzgBackendParseError::InvalidBackend(unknown.to_owned())),
        }
    }
}

#[cfg(feature = "blst")]
pub const DEFAULT_KZG_BACKEND: KzgBackend = KzgBackend::Blst;
#[cfg(all(not(feature = "blst"), feature = "zkcrypto"))]
pub const DEFAULT_KZG_BACKEND: KzgBackend = KzgBackend::Zkcrypto;
#[cfg(all(
    not(feature = "blst"),
    not(feature = "zkcrypto"),
    feature = "constantine"
))]
pub const DEFAULT_KZG_BACKEND: KzgBackend = KzgBackend::Constantine;
#[cfg(all(
    not(feature = "blst"),
    not(feature = "zkcrypto"),
    not(feature = "constantine"),
    feature = "arkworks"
))]
pub const DEFAULT_KZG_BACKEND: KzgBackend = KzgBackend::Arkworks;
#[cfg(all(
    not(feature = "blst"),
    not(feature = "zkcrypto"),
    not(feature = "constantine"),
    not(feature = "arkworks"),
    feature = "mcl"
))]
pub const DEFAULT_KZG_BACKEND: KzgBackend = KzgBackend::Mcl;
