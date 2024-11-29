#![allow(clippy::disallowed_types)]

use core::fmt::{Debug, Display, Formatter, Result as FmtResult};

use anyhow::{Error, Result};
use derive_more::FromStr;
use url::{ParseError, Url};

const REPLACEMENT_TOKEN: &str = "*";

// Only ad-hoc solutions exist for redacting credentials from URLs:
// <https://github.com/servo/rust-url/issues/714>
#[derive(Clone, PartialEq, Eq, Hash, FromStr)]
pub struct RedactingUrl {
    url: Url,
}

impl Display for RedactingUrl {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        fn sanitize(mut url: Url) -> Result<Url> {
            if url_includes_username(&url) {
                url.set_username(REPLACEMENT_TOKEN)
                    .map_err(|()| Error::msg("failed to sanitize URL username"))?;
            }

            if url_includes_password(&url) {
                url.set_password(Some(REPLACEMENT_TOKEN))
                    .map_err(|()| Error::msg("failed to sanitize URL password"))?;
            }

            Ok(url)
        }

        if !self.includes_credentials() {
            return write!(formatter, "{}", self.url);
        }

        match sanitize(self.url.clone()) {
            Ok(url) => write!(formatter, "{url}"),
            Err(error) => write!(formatter, "unsanitizable URL: {error}"),
        }
    }
}

impl Debug for RedactingUrl {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        if !self.includes_credentials() {
            return Debug::fmt(self.url.as_str(), formatter);
        }

        Debug::fmt(self.to_string().as_str(), formatter)
    }
}

impl RedactingUrl {
    // `RedactingUrl::into_url` could be replaced with an `AsRef<str>` impl if we used `httpclient`.
    #[must_use]
    pub fn into_url(self) -> Url {
        self.url
    }

    pub fn join(&self, input: &str) -> Result<Self, ParseError> {
        let url = self.url.join(input)?;
        Ok(Self { url })
    }

    fn includes_credentials(&self) -> bool {
        url_includes_username(&self.url) || url_includes_password(&self.url)
    }
}

fn url_includes_username(url: &Url) -> bool {
    !url.username().is_empty()
}

fn url_includes_password(url: &Url) -> bool {
    url.password().is_some()
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case(
        "https://example.com", "https://example.com/";
        "username absent, password absent"
    )]
    #[test_case(
        "https://username@example.com", "https://*@example.com/";
        "username present, password absent"
    )]
    #[test_case(
        "https://username:@example.com", "https://*@example.com/";
        "username present, password empty"
    )]
    #[test_case(
        "https://:password@example.com", "https://:*@example.com/";
        "username empty, password present"
    )]
    #[test_case(
        "https://username:password@example.com", "https://*:*@example.com/";
        "username present, password present"
    )]
    #[test_case(
        "https://localhost:3000", "https://localhost:3000/";
        "username absent, hostname is localhost"
    )]
    #[test_case(
        "https://username@localhost:3000", "https://*@localhost:3000/";
        "username present, hostname is localhost"
    )]
    // URLs with schemes other than a few special ones have opaque paths.
    // `url` treats them as having no username or password. See:
    // - <https://docs.rs/url/2.5.2/url/index.html#url-parsing-and-data-structures>
    // - <https://url.spec.whatwg.org/#special-scheme>
    // - <https://url.spec.whatwg.org/#url-opaque-path>
    #[test_case(
        "data:username@example.com", "data:username@example.com";
        "scheme is data"
    )]
    #[test_case(
        "mailto:username@example.com", "mailto:username@example.com";
        "scheme is mailto"
    )]
    fn redacting_url_display_fmt_redacts_credentials(
        raw_url: &str,
        expected_url: &str,
    ) -> Result<(), ParseError> {
        let redacting_url = raw_url.parse::<RedactingUrl>()?;
        assert_eq!(redacting_url.to_string(), expected_url);
        Ok(())
    }
}
