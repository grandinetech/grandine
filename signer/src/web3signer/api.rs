use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use bls::{PublicKeyBytes, SignatureBytes};
use derive_more::Debug;
use log::warn;
use prometheus_metrics::Metrics;
use reqwest::Client;
use types::{phase0::primitives::H256, preset::Preset, redacting_url::RedactingUrl};

use crate::{ForkInfo, SigningMessage};

use super::types::{SigningRequest, SigningResponse};

pub type FetchedKeys = HashMap<RedactingUrl, Option<HashSet<PublicKeyBytes>>>;

#[derive(Clone, Default, Debug)]
pub struct Config {
    pub allow_to_reload_keys: bool,
    pub public_keys: HashSet<PublicKeyBytes>,
    pub urls: Vec<RedactingUrl>,
}

impl Config {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.public_keys.is_empty() || self.urls.is_empty()
    }
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

    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    pub async fn fetch_public_keys(&self) -> FetchedKeys {
        let _timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.web3signer_load_keys_times.start_timer());

        let mut keys = HashMap::new();

        for url in self.config.urls.iter().cloned() {
            if !self.config.allow_to_reload_keys && self.keys_loaded.contains(&url) {
                continue;
            }

            match self.fetch_public_keys_from_url(&url).await {
                Ok(mut remote_keys) => {
                    if remote_keys.is_empty() {
                        keys.insert(url, None);
                    } else {
                        if !self.config.public_keys.is_empty() {
                            remote_keys.retain(|pubkey| self.config.public_keys.contains(pubkey));
                        }

                        keys.insert(url, Some(remote_keys));
                    }
                }
                Err(error) => warn!("failed to load Web3Signer keys from {url}: {error:?}"),
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
    use types::{
        altair::containers::BeaconBlock as AltairBeaconBlock, config::Config,
        phase0::beacon_state::BeaconState, preset::Minimal,
    };

    use super::*;

    const SAMPLE_PUBKEY: PublicKeyBytes = PublicKeyBytes(hex!(
        "93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
    ));
    const SAMPLE_PUBKEY_2: PublicKeyBytes = PublicKeyBytes(hex!(
        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"
    ));
    const SAMPLE_SIGNATURE: SignatureBytes = SignatureBytes(hex!(
        "b3baa751d0a9132cfe93e4e3d5ff9075111100e3789dca219ade5a24d27e19d16b3353149da1833e9b691bb38634e8dc04469be7032132906c927d7e1a49b414730612877bc6b2810c8f202daf793d1ab0d6b5cb21d52f9e52e883859887a5d9"
    ));

    #[tokio::test]
    async fn test_fetch_public_keys() -> Result<()> {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(Method::GET).path("/api/v1/eth2/publicKeys");
            then.status(200)
                .body(json!([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]).to_string());
        });

        let url = server.url("/").parse::<RedactingUrl>()?;
        let config = super::Config {
            allow_to_reload_keys: false,
            public_keys: HashSet::new(),
            urls: vec![url.clone()],
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
        let config = super::Config {
            allow_to_reload_keys: true,
            public_keys: HashSet::new(),
            urls: vec![url.clone()],
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
            public_keys: vec![SAMPLE_PUBKEY_2].into_iter().collect(),
            urls: vec![url.clone()],
        };
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
        let config = super::Config {
            allow_to_reload_keys: false,
            public_keys: HashSet::new(),
            urls: vec![url.clone()],
        };
        let web3signer = Web3Signer::new(Client::new(), config, None);

        let beacon_state = BeaconState::<Minimal>::default();
        let altair_block = AltairBeaconBlock::default();
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
