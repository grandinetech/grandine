use core::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context as _, Result};
use bls::{PublicKeyBytes, SignatureBytes};
use derive_more::Debug;
use logging::warn_with_peers;
use prometheus_metrics::Metrics;
use reqwest::{Certificate, Client, ClientBuilder, Identity};
use types::{phase0::primitives::H256, preset::Preset, redacting_url::RedactingUrl};

use crate::{ForkInfo, SigningMessage};

use super::types::{SigningRequest, SigningResponse};

pub type FetchedKeys = HashMap<RedactingUrl, Option<HashSet<PublicKeyBytes>>>;

/// Which keys to load from a single Web3Signer URL.
#[derive(Clone, Default, Debug)]
pub struct UrlPolicy {
    /// Load every key the URL serves (narrowed only by the global [`public_keys`](Config::public_keys)
    /// allow-list). Set for a CLI `--web3signer-urls` URL; a `validators.yml` entry never clears it.
    pub load_all: bool,
    /// Keys of `validators.yml` entries naming this URL. Always loaded; an unserved one is warned about.
    pub required: HashSet<PublicKeyBytes>,
}

#[derive(Clone, Default, Debug)]
pub struct Config {
    pub allow_to_reload_keys: bool,
    /// The global `--web3signer-public-keys` allow-list restricting load-all URLs when non-empty.
    pub public_keys: HashSet<PublicKeyBytes>,
    pub urls: HashMap<RedactingUrl, UrlPolicy>,
}

impl Config {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
    }

    /// Declare that `pubkey` is served by `url`. Never clears `load_all`.
    pub fn require_key(&mut self, url: RedactingUrl, pubkey: PublicKeyBytes) {
        self.urls.entry(url).or_default().required.insert(pubkey);
    }
}

#[derive(Default)]
pub struct ClientOptions {
    pub root_certificate_path: Option<PathBuf>,
    pub request_timeout: Option<Duration>,
    pub client_identity_path: Option<PathBuf>,
    pub client_identity_password: Option<String>,
}

/// Build a Web3Signer HTTP client, applying the root certificate, client identity (mutual TLS) and
/// timeout from `options`. Uses reqwest's native-tls backend (PEM root cert, PKCS#12 client identity).
pub fn build_client(mut builder: ClientBuilder, options: &ClientOptions) -> Result<Client> {
    if let Some(timeout) = options.request_timeout {
        builder = builder.timeout(timeout);
    }

    if let Some(path) = &options.root_certificate_path {
        let pem = fs_err::read(path).with_context(|| {
            format!(
                "failed to read Web3Signer root certificate {}",
                path.display()
            )
        })?;

        let certificate =
            Certificate::from_pem(&pem).context("failed to parse Web3Signer root certificate")?;

        builder = builder.add_root_certificate(certificate);
    }

    if let Some(path) = &options.client_identity_path {
        let der = fs_err::read(path).with_context(|| {
            format!(
                "failed to read Web3Signer client identity {}",
                path.display()
            )
        })?;

        let password = options
            .client_identity_password
            .as_deref()
            .unwrap_or_default();

        let identity = Identity::from_pkcs12_der(&der, password)
            .context("failed to load Web3Signer client identity")?;

        builder = builder.identity(identity);
    }

    builder
        .build()
        .context("failed to build Web3Signer HTTP client")
}

#[derive(Clone)]
pub struct Web3Signer {
    client: Client,
    config: Config,
    metrics: Option<Arc<Metrics>>,
    keys_loaded: HashSet<RedactingUrl>,
}

impl Web3Signer {
    #[must_use]
    pub fn new(client: Client, config: Config, metrics: Option<Arc<Metrics>>) -> Self {
        Self {
            client,
            config,
            metrics,
            keys_loaded: HashSet::new(),
        }
    }

    pub async fn fetch_public_keys(&self) -> FetchedKeys {
        let _timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.web3signer_load_keys_times.start_timer());

        let mut keys = HashMap::new();

        for (url, policy) in &self.config.urls {
            if !self.config.allow_to_reload_keys && self.keys_loaded.contains(url) {
                continue;
            }

            match self.fetch_public_keys_from_url(url).await {
                Ok(mut remote_keys) => {
                    if remote_keys.is_empty() {
                        keys.insert(url.clone(), None);
                    } else {
                        // Warn about a declared key this URL does not serve (not for the global list,
                        // whose keys may be served by other URLs).
                        for pubkey in &policy.required {
                            if !remote_keys.contains(pubkey) {
                                warn_with_peers!(
                                    "Web3Signer at {url} does not serve declared validator \
                                     {pubkey:?}; it will not be loaded",
                                );
                            }
                        }

                        // Keep everything only for a load-all URL with no global allow-list.
                        if !policy.load_all || !self.config.public_keys.is_empty() {
                            remote_keys.retain(|pubkey| {
                                self.config.public_keys.contains(pubkey)
                                    || policy.required.contains(pubkey)
                            });
                        }

                        keys.insert(url.clone(), Some(remote_keys));
                    }
                }
                Err(error) => {
                    warn_with_peers!("failed to load Web3Signer keys from {url}: {error:?}")
                }
            }
        }

        keys
    }

    pub fn mark_keys_loaded_from(&mut self, url: RedactingUrl) {
        self.keys_loaded.insert(url);
    }

    pub async fn sign<P: Preset>(
        &self,
        api_url: &RedactingUrl,
        message: SigningMessage<'_, P>,
        signing_root: H256,
        fork_info: Option<ForkInfo<P>>,
        public_key: PublicKeyBytes,
    ) -> Result<SignatureBytes> {
        let _timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.web3signer_sign_times.start_timer());

        let url = api_url.join(&format!("/api/v1/eth2/sign/{public_key:?}"))?;

        let request = SigningRequest::new(message, signing_root, fork_info);

        let response = self
            .client
            .post(url.into_url())
            .json(&request)
            .send()
            .await?
            .json::<SigningResponse>()
            .await?;

        Ok(response.signature)
    }

    async fn fetch_public_keys_from_url(
        &self,
        api_url: &RedactingUrl,
    ) -> Result<HashSet<PublicKeyBytes>> {
        let url = api_url.join("/api/v1/eth2/publicKeys")?;

        self.client
            .get(url.into_url())
            .send()
            .await?
            .json()
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use helper_functions::signing::SignForSingleFork as _;
    use hex_literal::hex;
    use httpmock::{Method, MockServer};
    use serde_json::json;
    use ssz::Hc;
    use types::{
        altair::containers::BeaconBlock as AltairBeaconBlock, config::Config,
        phase0::beacon_state::BeaconState, preset::Minimal,
    };

    use super::{Config as Web3signerConfig, *};

    const SAMPLE_PUBKEY: PublicKeyBytes = PublicKeyBytes(hex!(
        "93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
    ));
    const SAMPLE_PUBKEY_2: PublicKeyBytes = PublicKeyBytes(hex!(
        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
    ));
    const SAMPLE_SIGNATURE: SignatureBytes = SignatureBytes(hex!(
        "b3baa751d0a9132cfe93e4e3d5ff9075111100e3789dca219ade5a24d27e19d16b3353149da1833e9b691bb38634e8dc04469be7032132906c927d7e1a49b414730612877bc6b2810c8f202daf793d1ab0d6b5cb21d52f9e52e883859887a5d9"
    ));

    #[test]
    fn test_require_key_never_narrows_load_all() {
        let url = "https://signer.example/"
            .parse::<RedactingUrl>()
            .expect("url is valid");

        // A URL known only through entries loads exactly the declared keys.
        let mut only = super::Config::default();

        only.require_key(url.clone(), SAMPLE_PUBKEY);
        only.require_key(url.clone(), SAMPLE_PUBKEY_2);

        let policy = &only.urls[&url];

        assert!(!policy.load_all);
        assert_eq!(
            policy.required,
            HashSet::from([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]),
        );

        // A URL already loading everything stays that way — the entry is only recorded as declared.
        let mut load_all = Web3signerConfig {
            allow_to_reload_keys: false,
            public_keys: HashSet::new(),
            urls: HashMap::from([(
                url.clone(),
                UrlPolicy {
                    load_all: true,
                    required: HashSet::new(),
                },
            )]),
        };

        load_all.require_key(url.clone(), SAMPLE_PUBKEY);

        assert!(load_all.urls[&url].load_all);
        assert_eq!(load_all.urls[&url].required, HashSet::from([SAMPLE_PUBKEY]));
    }

    #[tokio::test]
    async fn test_fetch_public_keys() -> Result<()> {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(Method::GET).path("/api/v1/eth2/publicKeys");
            then.status(200)
                .body(json!([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]).to_string());
        });

        let url = server.url("/").parse::<RedactingUrl>()?;
        let config = Web3signerConfig {
            allow_to_reload_keys: false,
            public_keys: HashSet::new(),
            urls: HashMap::from([(
                url.clone(),
                UrlPolicy {
                    load_all: true,
                    required: HashSet::new(),
                },
            )]),
        };

        let mut web3signer = Web3Signer::new(Client::new(), config, None);
        let response = web3signer.fetch_public_keys().await;
        let expected = HashMap::from([(
            url.clone(),
            Some(HashSet::from([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2])),
        )]);

        assert_eq!(response, expected);
        web3signer.mark_keys_loaded_from(url);

        let response = web3signer.fetch_public_keys().await;
        // By default, do not load pubkeys from Web3Signer again if keys were loaded
        assert!(response.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_fetch_public_keys_if_reload_is_allowed() -> Result<()> {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(Method::GET).path("/api/v1/eth2/publicKeys");
            then.status(200)
                .body(json!([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]).to_string());
        });

        let url = server.url("/").parse::<RedactingUrl>()?;
        let config = Web3signerConfig {
            allow_to_reload_keys: true,
            public_keys: HashSet::new(),
            urls: HashMap::from([(
                url.clone(),
                UrlPolicy {
                    load_all: true,
                    required: HashSet::new(),
                },
            )]),
        };

        let mut web3signer = Web3Signer::new(Client::new(), config, None);
        let response = web3signer.fetch_public_keys().await;
        let expected = HashMap::from([(
            url.clone(),
            Some(HashSet::from([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2])),
        )]);

        assert_eq!(response, expected);
        web3signer.mark_keys_loaded_from(url);

        let response = web3signer.fetch_public_keys().await;
        assert_eq!(response, expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_fetch_filtered_public_keys() -> Result<()> {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(Method::GET).path("/api/v1/eth2/publicKeys");
            then.status(200)
                .body(json!([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]).to_string());
        });

        let url = server.url("/").parse::<RedactingUrl>()?;
        let config = super::Config {
            allow_to_reload_keys: false,
            public_keys: HashSet::from([SAMPLE_PUBKEY_2]),
            urls: HashMap::from([(
                url.clone(),
                UrlPolicy {
                    load_all: true,
                    required: HashSet::new(),
                },
            )]),
        };
        let web3signer = Web3Signer::new(Client::new(), config, None);

        let response = web3signer.fetch_public_keys().await;
        let expected = HashMap::from([(url, Some(HashSet::from([SAMPLE_PUBKEY_2])))]);

        assert_eq!(response, expected);

        Ok(())
    }

    /// A URL known only through `validators.yml` entries loads exactly those keys — not everything
    /// the signer serves.
    #[tokio::test]
    async fn test_fetch_loads_only_declared_keys_for_entry_url() -> Result<()> {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(Method::GET).path("/api/v1/eth2/publicKeys");
            then.status(200)
                .body(json!([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]).to_string());
        });

        let url = server.url("/").parse::<RedactingUrl>()?;
        let mut config = Web3signerConfig::default();
        config.require_key(url.clone(), SAMPLE_PUBKEY_2);

        let web3signer = Web3Signer::new(Client::new(), config, None);
        let response = web3signer.fetch_public_keys().await;
        let expected = HashMap::from([(url, Some(HashSet::from([SAMPLE_PUBKEY_2])))]);

        assert_eq!(response, expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_sign() -> Result<()> {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(Method::POST)
                .path(format!("/api/v1/eth2/sign/{SAMPLE_PUBKEY:?}"));
            then.status(200)
                .body(json!({ "signature": SAMPLE_SIGNATURE }).to_string());
        });

        let url = server.url("/").parse::<RedactingUrl>()?;
        let config = Web3signerConfig {
            allow_to_reload_keys: false,
            public_keys: HashSet::new(),
            urls: HashMap::from([(
                url.clone(),
                UrlPolicy {
                    load_all: true,
                    required: HashSet::new(),
                },
            )]),
        };

        let web3signer = Web3Signer::new(Client::new(), config, None);
        let beacon_state = BeaconState::<Minimal>::default();
        let altair_block = Hc::new(AltairBeaconBlock::default());
        let message = SigningMessage::from(&altair_block);
        let signing_root = altair_block.signing_root(&Config::minimal(), &beacon_state);
        let fork_info = ForkInfo::from(&beacon_state);

        let response = web3signer
            .sign(&url, message, signing_root, Some(fork_info), SAMPLE_PUBKEY)
            .await?;

        assert_eq!(response, SAMPLE_SIGNATURE);

        Ok(())
    }
}
