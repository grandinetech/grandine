//! Per-key builder configuration from the keymanager builder config API.
//!
//! <https://github.com/ethereum/keymanager-APIs/blob/master/types/builder_entry.yaml>

use std::collections::HashMap;

use bls::PublicKeyBytes;
use builder_api::{
    consts::{MaxBuilderAuthDataSize, MaxBuilderEntries, MaxBuilderPubkeys},
    gloas::containers::{BuilderEntry, BuilderUrl, BuilderUrlError, SignedBuilderRequestAuth},
};
use serde::{Deserialize, Serialize};
use ssz::{ByteList, ContiguousList, Uint256};
use thiserror::Error;
use typenum::Unsigned as _;
use types::phase0::primitives::Gwei;

#[derive(Debug, Error)]
pub enum BuilderConfigError {
    #[error("at most {} builders are allowed", MaxBuilderEntries::USIZE)]
    TooManyBuilders,
    #[error("builder {index} has an invalid url: {source}")]
    InvalidUrl {
        index: usize,
        #[source]
        source: BuilderUrlError,
    },
    #[error("builder {index} has empty auth_data")]
    EmptyAuthData { index: usize },
    #[error(
        "builder {index} lists more than {} builder pubkeys",
        MaxBuilderPubkeys::USIZE
    )]
    TooManyBuilderPubkeys { index: usize },
    #[error(
        "builder {index} sets max_execution_payment above 0, \
         which requires --allow-trusted-payments"
    )]
    TrustedPaymentsNotAllowed { index: usize },
    #[error("builders {first} and {second} share both url and auth_data")]
    DuplicateBuilder { first: usize, second: usize },
}

#[derive(Clone, Debug)]
pub struct BuilderSettings {
    pub default_builder_boost_factor: Uint256,
    pub default_builder_min_bid: Gwei,
    pub default_builder_max_execution_payment: Gwei,
    pub allow_trusted_payments: bool,
    pub payload_builder_urls: Vec<BuilderUrl>,
}

impl Default for BuilderSettings {
    fn default() -> Self {
        Self {
            default_builder_boost_factor: Uint256::from_u64(100),
            default_builder_min_bid: 0,
            default_builder_max_execution_payment: 0,
            allow_trusted_payments: false,
            payload_builder_urls: vec![],
        }
    }
}

/// A key's builder configuration as submitted, with omitted values left to the defaults.
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderConfigOptions {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::string_or_native_option"
    )]
    pub min_bid: Option<Gwei>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::string_or_native_option"
    )]
    pub builder_boost_factor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builders: Option<Vec<BuilderEntryOptions>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderEntryOptions {
    pub url: BuilderUrl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_data: Option<ByteList<MaxBuilderAuthDataSize>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_pubkeys: Option<Vec<PublicKeyBytes>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::string_or_native_option"
    )]
    pub max_execution_payment: Option<Gwei>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::string_or_native_option"
    )]
    pub min_bid: Option<Gwei>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::string_or_native_option"
    )]
    pub builder_boost_factor: Option<u64>,
}

impl From<BuilderUrl> for BuilderEntryOptions {
    fn from(url: BuilderUrl) -> Self {
        Self {
            url,
            auth_data: None,
            builder_pubkeys: None,
            max_execution_payment: None,
            min_bid: None,
            builder_boost_factor: None,
        }
    }
}

/// The values an omitted field resolves to.
///
/// `min_bid` and `builder_boost_factor` are the key's own, already resolved against the
/// validator client's configuration.
pub struct BuilderConfigDefaults<'urls> {
    pub urls: &'urls [BuilderUrl],
    pub min_bid: Gwei,
    pub builder_boost_factor: u64,
    pub max_execution_payment: Gwei,
    pub allow_trusted_payments: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ResolvedBuilderConfig {
    #[serde(with = "serde_utils::string_or_native")]
    pub min_bid: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_boost_factor: u64,
    pub builders: Vec<ResolvedBuilderEntry>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ResolvedBuilderEntry {
    pub url: BuilderUrl,
    pub auth_data: ByteList<MaxBuilderAuthDataSize>,
    pub builder_pubkeys: ContiguousList<PublicKeyBytes, MaxBuilderPubkeys>,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_execution_payment: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub min_bid: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_boost_factor: u64,
}

impl ResolvedBuilderEntry {
    #[must_use]
    pub fn into_builder_entry(self, auth: SignedBuilderRequestAuth) -> BuilderEntry {
        let Self {
            url,
            builder_pubkeys,
            max_execution_payment,
            min_bid,
            builder_boost_factor,
            ..
        } = self;

        BuilderEntry {
            url,
            auth,
            builder_pubkeys,
            max_execution_payment,
            min_bid,
            builder_boost_factor,
        }
    }
}

/// Resolves `builders` against `defaults`, rejecting a list that breaks the builder config rules.
///
/// Omitted `builders` resolve to the validator client's builders.
pub fn resolve_builder_config(
    builders: Option<&[BuilderEntryOptions]>,
    defaults: &BuilderConfigDefaults,
) -> Result<ResolvedBuilderConfig, BuilderConfigError> {
    let global_builders;

    let builders = match builders {
        Some(builders) => builders,
        None => {
            global_builders = defaults
                .urls
                .iter()
                .cloned()
                .map(BuilderEntryOptions::from)
                .collect::<Vec<_>>();

            &global_builders
        }
    };

    validate_builders(builders)?;

    let builders = builders
        .iter()
        .enumerate()
        .map(|(index, entry)| resolve_builder_entry(index, entry, defaults))
        .collect::<Result<_, _>>()?;

    Ok(ResolvedBuilderConfig {
        min_bid: defaults.min_bid,
        builder_boost_factor: defaults.builder_boost_factor,
        builders,
    })
}

// Check duplicated entries, length limits and other constraints
pub fn validate_builders(builders: &[BuilderEntryOptions]) -> Result<(), BuilderConfigError> {
    if builders.len() > MaxBuilderEntries::USIZE {
        return Err(BuilderConfigError::TooManyBuilders);
    }

    let mut seen = HashMap::new();

    for (index, entry) in builders.iter().enumerate() {
        let auth_data = entry_auth_data(index, entry)?;

        if entry
            .builder_pubkeys
            .as_ref()
            .is_some_and(|builder_pubkeys| builder_pubkeys.len() > MaxBuilderPubkeys::USIZE)
        {
            return Err(BuilderConfigError::TooManyBuilderPubkeys { index });
        }

        let key = (entry.url.as_str(), auth_data.as_bytes().to_vec());

        if let Some(first) = seen.insert(key, index) {
            return Err(BuilderConfigError::DuplicateBuilder {
                first,
                second: index,
            });
        }
    }

    Ok(())
}

fn entry_auth_data(
    index: usize,
    entry: &BuilderEntryOptions,
) -> Result<ByteList<MaxBuilderAuthDataSize>, BuilderConfigError> {
    let BuilderEntryOptions { url, auth_data, .. } = entry;

    url.http_url()
        .map_err(|source| BuilderConfigError::InvalidUrl { index, source })?;

    let auth_data = match auth_data {
        Some(auth_data) => auth_data.clone(),
        None => url
            .default_auth_data()
            .map_err(|source| BuilderConfigError::InvalidUrl { index, source })?,
    };

    if auth_data.as_bytes().is_empty() {
        return Err(BuilderConfigError::EmptyAuthData { index });
    }

    Ok(auth_data)
}

fn resolve_builder_entry(
    index: usize,
    entry: &BuilderEntryOptions,
    defaults: &BuilderConfigDefaults,
) -> Result<ResolvedBuilderEntry, BuilderConfigError> {
    let BuilderEntryOptions {
        url,
        builder_pubkeys,
        max_execution_payment,
        min_bid,
        builder_boost_factor,
        ..
    } = entry;

    let max_execution_payment = max_execution_payment.unwrap_or(defaults.max_execution_payment);

    if max_execution_payment > 0 && !defaults.allow_trusted_payments {
        return Err(BuilderConfigError::TrustedPaymentsNotAllowed { index });
    }

    let builder_pubkeys = builder_pubkeys
        .clone()
        .unwrap_or_default()
        .try_into()
        .map_err(|_| BuilderConfigError::TooManyBuilderPubkeys { index })?;

    Ok(ResolvedBuilderEntry {
        url: url.clone(),
        auth_data: entry_auth_data(index, entry)?,
        builder_pubkeys,
        max_execution_payment,
        min_bid: min_bid.unwrap_or(defaults.min_bid),
        builder_boost_factor: builder_boost_factor.unwrap_or(defaults.builder_boost_factor),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // from <https://github.com/ethereum/keymanager-APIs/blob/master/apis/builder_config.yaml>
    #[test]
    fn builder_config_roundtrips_the_spec_example() {
        let body = json!({
            "min_bid": "10000000",
            "builder_boost_factor": "100",
            "builders": [
                {"url": "https://builder-a.example.com", "max_execution_payment": "0"},
                {
                    "url": "https://builder-b.example.com",
                    "builder_pubkeys": ["0xa057816155ad77931185101128655c0191bd0214c201ca48ed887f6c4c6adf334070efcd75140eada5ac83a92506dd7a"],
                    "max_execution_payment": "0",
                    "builder_boost_factor": "120",
                },
            ],
        });

        let config = serde_json::from_value::<BuilderConfigOptions>(body.clone())
            .expect("spec example should deserialize");

        assert_eq!(config.min_bid, Some(10_000_000));
        assert_eq!(
            serde_json::to_value(&config).expect("config should serialize"),
            body
        );
    }

    const BUILDER_A: &str = "https://builder-a.example.com";
    const BUILDER_B: &str = "https://builder-b.example.com:8080/relay";

    fn url(url: &str) -> BuilderUrl {
        url.try_into().expect("URL should be valid")
    }

    fn defaults(urls: &[BuilderUrl]) -> BuilderConfigDefaults<'_> {
        BuilderConfigDefaults {
            urls,
            min_bid: 10,
            builder_boost_factor: 100,
            max_execution_payment: 0,
            allow_trusted_payments: false,
        }
    }

    fn entries(value: serde_json::Value) -> Vec<BuilderEntryOptions> {
        serde_json::from_value(value).expect("builder entries should deserialize")
    }

    #[test]
    fn omitted_builders_resolve_to_the_validator_client_builders() {
        let urls = [url(BUILDER_A), url(BUILDER_B)];
        let default_config = defaults(&urls);
        let resolved = resolve_builder_config(None, &default_config).expect("config is valid");

        let builders = resolved
            .builders
            .iter()
            .map(|entry| (entry.url.as_str(), entry.auth_data.as_bytes()))
            .collect::<Vec<_>>();

        assert_eq!(
            builders,
            [
                (BUILDER_A, b"builder-a.example.com".as_slice()),
                (BUILDER_B, b"builder-b.example.com".as_slice()),
            ],
        );
        assert!(resolved.builders.iter().all(|entry| {
            entry.builder_pubkeys.is_empty()
                && entry.max_execution_payment == 0
                && entry.min_bid == 10
                && entry.builder_boost_factor == 100
        }));
    }

    #[test]
    fn empty_builders_request_no_bids() {
        let urls = [url(BUILDER_A)];
        let default_config = defaults(&urls);
        let resolved = resolve_builder_config(Some(&[]), &default_config).expect("config is valid");

        assert!(resolved.builders.is_empty());
    }

    #[test]
    fn builders_may_share_a_url_with_distinct_auth_data() {
        let builders = entries(json!([
            {"url": BUILDER_A},
            {"url": BUILDER_A, "auth_data": "0x1234"},
        ]));
        let empty_defaults = defaults(&[]);

        resolve_builder_config(Some(&builders), &empty_defaults).expect("config is valid");
    }

    #[test]
    fn entry_values_take_precedence_over_the_defaults() {
        let builders = entries(json!([{
            "url": BUILDER_A,
            "auth_data": "0x1234",
            "min_bid": "20",
            "builder_boost_factor": "120",
        }]));

        let urls = [url(BUILDER_B)];
        let default_config = defaults(&urls);
        let resolved =
            resolve_builder_config(Some(&builders), &default_config).expect("config is valid");

        assert_eq!(resolved.builders.len(), 1);

        let entry = &resolved.builders[0];
        assert_eq!(entry.url.as_str(), BUILDER_A);
        assert_eq!(entry.auth_data.as_bytes(), [0x12, 0x34]);
        assert_eq!(entry.min_bid, 20);
        assert_eq!(entry.builder_boost_factor, 120);
    }

    // An omitted `auth_data` compares as the value derived from the URL.
    #[test]
    fn builders_sharing_url_and_auth_data_are_rejected() {
        let builders = entries(json!([
            {"url": BUILDER_A},
            {"url": BUILDER_A, "auth_data": "0x6275696c6465722d612e6578616d706c652e636f6d"},
        ]));

        assert!(matches!(
            resolve_builder_config(Some(&builders), &defaults(&[])),
            Err(BuilderConfigError::DuplicateBuilder {
                first: 0,
                second: 1
            }),
        ));
    }

    #[test]
    fn trusted_payments_require_opting_in() {
        let builders = entries(json!([{"url": BUILDER_A, "max_execution_payment": "1"}]));
        let empty_defaults = defaults(&[]);

        assert!(matches!(
            resolve_builder_config(Some(&builders), &empty_defaults),
            Err(BuilderConfigError::TrustedPaymentsNotAllowed { index: 0 }),
        ));

        let allowed = BuilderConfigDefaults {
            allow_trusted_payments: true,
            ..empty_defaults
        };

        resolve_builder_config(Some(&builders), &allowed).expect("config is valid");
    }

    #[test]
    fn invalid_entries_are_rejected() {
        let non_http = entries(json!([{"url": "file:///etc/passwd"}]));
        let empty_auth_data = entries(json!([{"url": BUILDER_A, "auth_data": "0x"}]));
        let too_many = vec![BuilderEntryOptions::from(url(BUILDER_A)); 65];

        assert!(matches!(
            resolve_builder_config(Some(&non_http), &defaults(&[])),
            Err(BuilderConfigError::InvalidUrl { index: 0, .. }),
        ));
        assert!(matches!(
            resolve_builder_config(Some(&empty_auth_data), &defaults(&[])),
            Err(BuilderConfigError::EmptyAuthData { index: 0 }),
        ));
        assert!(matches!(
            resolve_builder_config(Some(&too_many), &defaults(&[])),
            Err(BuilderConfigError::TooManyBuilders),
        ));
    }
}
