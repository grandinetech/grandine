use core::{
    fmt::{Binary, Display, LowerExp, LowerHex, Octal, Pointer, UpperExp, UpperHex},
    ops::Deref,
};
use std::path::PathBuf;

use anyhow::{Context as _, Result, ensure};
use jwt_simple::{
    algorithms::{HS256Key, MACLike},
    claims::Claims,
    prelude::Duration,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use ssz::{SszHash, SszWrite};
use static_assertions::assert_not_impl_any;
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(test)]
use derive_more::Debug;

const JWT_SECRET_SIZE_MIN_BYTES: usize = 32;

#[derive(Debug)]
#[cfg_attr(test, derive(Default))]
pub struct Options {
    pub secrets_path: Option<PathBuf>,
    pub id: Option<String>,
    pub version: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JwtClaims {
    id: Option<String>,
    clv: Option<String>,
}

#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct Auth {
    secret: Option<Secret>,
    id: Option<String>,
    version: Option<String>,
}

// Prevent `Auth` from implementing some traits to avoid leaking secret keys.
// This could also be done by wrapping it in `secrecy::Secret`.
assert_not_impl_any! {
    Auth:

    Clone,
    Copy,
    Deref,
    ToOwned,

    Binary,
    Display,
    LowerExp,
    LowerHex,
    Octal,
    Pointer,
    UpperExp,
    UpperHex,

    Serialize,
    SszHash,
    SszWrite,
}

impl Auth {
    pub fn new(options: Options) -> Result<Self> {
        let Options {
            secrets_path,
            id,
            version,
        } = options;

        let secret = match secrets_path {
            Some(path) => {
                let bytes = fs_err::read(path).map(Zeroizing::new)?;
                let secret = Secret::from_hex(bytes.as_slice())?;
                Some(secret)
            }
            None => None,
        };

        Ok(Self {
            secret,
            id,
            version,
        })
    }

    pub fn headers(&self) -> Result<Option<HeaderMap>> {
        let Some(secret) = &self.secret else {
            return Ok(None);
        };

        let jwt_claims = JwtClaims {
            id: self.id.clone(),
            clv: self.version.clone(),
        };

        let claims = Claims::with_custom_claims(jwt_claims, Duration::from_secs(60));
        let token = Zeroizing::new(secret.key.authenticate(claims)?);
        let token_string = format!("Bearer {}", *token);

        let mut auth_value = HeaderValue::try_from(token_string)?;
        auth_value.set_sensitive(true);

        let headers = HeaderMap::from_iter([(AUTHORIZATION, auth_value)]);

        Ok(Some(headers))
    }
}

#[cfg_attr(test, derive(Debug))]
#[cfg_attr(test, debug("[REDACTED]"))]
struct Secret {
    key: HS256Key,
}

// Prevent `Secret` from implementing some traits to avoid leaking secret keys.
// This could also be done by wrapping it in `secrecy::Secret`.
assert_not_impl_any! {
    Secret:

    Clone,
    Copy,
    Deref,
    ToOwned,

    Binary,
    Display,
    LowerExp,
    LowerHex,
    Octal,
    Pointer,
    UpperExp,
    UpperHex,

    Serialize,
    SszHash,
    SszWrite,
}

impl Secret {
    fn from_hex(mut digits: &[u8]) -> Result<Self> {
        // Trim 0x prefix
        digits = digits.strip_prefix(b"0x").unwrap_or(digits);

        // Trim trailing newline
        digits = digits.strip_suffix(b"\n").unwrap_or(digits);
        digits = digits.strip_suffix(b"\r").unwrap_or(digits);

        let bytes = hex::decode(digits)
            .map(Zeroizing::new)
            .context(JwtSecretError::InvalidSecret)?;

        ensure!(
            bytes.len() >= JWT_SECRET_SIZE_MIN_BYTES,
            JwtSecretError::IncorrectSize,
        );

        let key = HS256Key::from_bytes(bytes.as_slice());

        Ok(Self { key })
    }
}

#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
enum JwtSecretError {
    #[error("JWT secret must be at least {JWT_SECRET_SIZE_MIN_BYTES} bytes")]
    IncorrectSize,
    #[error("failed to parse JWT secret")]
    InvalidSecret,
}

#[cfg(test)]
mod tests {
    use tempfile::{Builder, NamedTempFile};
    use unwrap_none::UnwrapNone as _;

    use super::*;

    #[test]
    fn test_prefixed_secret_decoding() {
        let hex = b"0xa8ecf8012460d00d11a5bd65165c192f705d1ef759afdda5e9db0f2cd29bbf11";
        Secret::from_hex(hex).expect("should decode prefixed secret");
    }

    #[test]
    fn test_secret_ending_with_newline_decoding() {
        let hex = b"a8ecf8012460d00d11a5bd65165c192f705d1ef759afdda5e9db0f2cd29bbf11\n";
        Secret::from_hex(hex).expect("should decode a secret that ends with a newline");
    }

    #[test]
    fn test_short_jwt_secret_decoding() {
        let bytes = b"a8ecf8012460d00d11a5bd65165c192f705d1ef759afdda5e9db0f";
        let error = Secret::from_hex(bytes)
            .expect_err("Secret::from_hex should fail")
            .downcast::<JwtSecretError>()
            .expect("short JWT secret must cause JwtSecretError");
        assert_eq!(error, JwtSecretError::IncorrectSize);
    }

    #[test]
    fn test_auth_with_unset_secrets_path() -> Result<()> {
        let auth = Auth::new(Options::default())?;

        auth.headers()?.unwrap_none();
        auth.id.unwrap_none();
        auth.version.unwrap_none();
        auth.secret.unwrap_none();

        Ok(())
    }

    #[test]
    fn test_auth_with_set_secrets_path() -> Result<()> {
        // ensure specified file is not overwritten with different jwt secret
        let jwt_tempfile = temp_jwt_secrets_file()?;
        let bytes = b"a8ecf8012460d00d11a5bd65165c192f705d1ef759afdda5e9db0f2cd29bbf11";

        fs_err::write(jwt_tempfile.path(), hex::encode(bytes))?;

        let options = Options {
            secrets_path: Some(jwt_tempfile.path().to_path_buf()),
            ..Options::default()
        };

        let auth = Auth::new(options)?;

        assert_eq!(
            auth.secret.map(|secret| secret.key.to_bytes()).as_deref(),
            Some(bytes.as_ref()),
        );

        Ok(())
    }

    #[test]
    fn test_auth_with_invalid_jwt_secret() -> Result<()> {
        let jwt_tempfile = temp_jwt_secrets_file()?;
        let bytes = b"INVALID";

        fs_err::write(jwt_tempfile.path(), bytes)?;

        let options = Options {
            secrets_path: Some(jwt_tempfile.path().to_path_buf()),
            ..Options::default()
        };

        Auth::new(options).expect_err("Secret::from_hex should fail");

        Ok(())
    }

    #[test]
    fn test_auth_headers() -> Result<()> {
        let jwt_tempfile = temp_jwt_secrets_file()?;
        let bytes = b"a8ecf8012460d00d11a5bd65165c192f705d1ef759afdda5e9db0f2cd29bbf11";

        fs_err::write(jwt_tempfile.path(), hex::encode(bytes))?;

        let options = Options {
            secrets_path: Some(jwt_tempfile.path().to_path_buf()),
            id: Some("auth_id".to_owned()),
            version: Some("auth_version".to_owned()),
        };

        let auth = Auth::new(options)?;

        assert_eq!(auth.id.as_deref(), Some("auth_id"));
        assert_eq!(auth.version.as_deref(), Some("auth_version"));

        let headers = auth.headers()?.expect("headers should exist");
        let auth_headers = headers
            .get(AUTHORIZATION)
            .expect("headers must contain authorization header");

        assert!(auth_headers.is_sensitive());

        Ok(())
    }

    fn temp_jwt_secrets_file() -> Result<NamedTempFile> {
        Ok(Builder::new()
            .suffix(".hex")
            .prefix("custom-jwt")
            .rand_bytes(10)
            .tempfile()?)
    }
}
