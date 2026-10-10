use core::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    str::{self, FromStr},
};
use std::borrow::Cow;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use ssz::{ByteList, ReadError, Size, SszHash, SszRead, SszSize, SszWrite, WriteError};
use thiserror::Error;
use typenum::{U1, Unsigned as _};
use types::redacting_url::RedactingUrl;

use crate::consts::{MaxBuilderAuthDataSize, MaxBuilderUrlSize};

#[derive(Debug, Error)]
pub enum BuilderUrlError {
    #[error("builder URL is empty")]
    Empty,
    #[error("builder URL is not valid UTF-8")]
    NotUtf8,
    #[error("builder URL is longer than {} bytes", MaxBuilderUrlSize::USIZE)]
    TooLong,
    #[error("builder URL is not a valid URL")]
    Invalid,
    #[error("builder URL scheme is not http or https")]
    NotHttp,
}

/// A string in JSON and `ByteList[MAX_BUILDER_URL_SIZE]` of its UTF-8 bytes in SSZ.
///
/// A zero-length URL is invalid in either encoding.
#[derive(Clone, PartialEq, Eq)]
pub struct BuilderUrl(ByteList<MaxBuilderUrlSize>);

impl BuilderUrl {
    #[must_use]
    pub fn as_str(&self) -> &str {
        str::from_utf8(self.0.as_bytes()).expect("BuilderUrl is validated to be UTF-8")
    }

    // The beacon node must only reach builders over http(s).
    pub fn http_url(&self) -> Result<RedactingUrl, BuilderUrlError> {
        let url = self
            .as_str()
            .parse::<RedactingUrl>()
            .map_err(|_| BuilderUrlError::Invalid)?;

        if !matches!(url.clone().into_url().scheme(), "http" | "https") {
            return Err(BuilderUrlError::NotHttp);
        }

        Ok(url)
    }

    /// The [default auth data] derived from the builder's hostname.
    ///
    /// [default auth data]: https://github.com/ethereum/builder-specs/blob/main/specs/gloas/validator.md#default-auth-data
    pub fn default_auth_data(&self) -> Result<ByteList<MaxBuilderAuthDataSize>, BuilderUrlError> {
        let url = self.http_url()?.into_url();
        let host = url.host_str().ok_or(BuilderUrlError::Invalid)?;

        host.as_bytes()
            .to_vec()
            .try_into()
            .map_err(|_| BuilderUrlError::TooLong)
    }

    pub(crate) fn origin(&self) -> Option<String> {
        let url = self.http_url().ok()?.into_url();

        Some(url.origin().ascii_serialization())
    }
}

impl TryFrom<&str> for BuilderUrl {
    type Error = BuilderUrlError;

    fn try_from(url: &str) -> Result<Self, Self::Error> {
        if url.is_empty() {
            return Err(BuilderUrlError::Empty);
        }

        url.as_bytes()
            .to_vec()
            .try_into()
            .map(Self)
            .map_err(|_| BuilderUrlError::TooLong)
    }
}

impl FromStr for BuilderUrl {
    type Err = BuilderUrlError;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        url.try_into()
    }
}

// Only the origin is shown, since credentials may be anywhere else in the URL.
impl Debug for BuilderUrl {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        match self.origin() {
            Some(origin) => Debug::fmt(&origin, formatter),
            None => formatter.write_str("non-HTTP URL"),
        }
    }
}

impl Display for BuilderUrl {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        match self.origin() {
            Some(origin) => formatter.write_str(&origin),
            None => formatter.write_str("non-HTTP URL"),
        }
    }
}

impl Serialize for BuilderUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BuilderUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Cow::<str>::deserialize(deserializer)?
            .as_ref()
            .try_into()
            .map_err(D::Error::custom)
    }
}

impl SszSize for BuilderUrl {
    const SIZE: Size = <ByteList<MaxBuilderUrlSize> as SszSize>::SIZE;
}

impl<C> SszRead<C> for BuilderUrl {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let byte_list = ByteList::from_ssz_unchecked(context, bytes)?;

        if byte_list.as_bytes().is_empty() {
            return Err(ReadError::Custom {
                message: "builder URL is empty",
            });
        }

        if str::from_utf8(byte_list.as_bytes()).is_err() {
            return Err(ReadError::Custom {
                message: "builder URL is not valid UTF-8",
            });
        }

        Ok(Self(byte_list))
    }
}

impl SszWrite for BuilderUrl {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.0.write_variable(bytes)
    }
}

impl SszHash for BuilderUrl {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> ssz::H256 {
        self.0.hash_tree_root()
    }
}
