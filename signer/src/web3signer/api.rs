use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use bls::{PublicKeyBytes, SignatureBytes};
use log::warn;
use prometheus_metrics::Metrics;
use reqwest::{Client, Url};
use types::{phase0::primitives::H256, preset::Preset};

use crate::{ForkInfo, SigningMessage};

use super::types::{SigningRequest, SigningResponse};

#[derive(Clone, Default, Debug)]
pub struct Config {
    pub allow_to_reload_keys: bool,
    pub public_keys: HashSet<PublicKeyBytes>,
    pub urls: Vec<Url>,
}

#[derive(Clone)]
pub struct Web3Signer {
    client: Client,
    config: Config,
    metrics: Option<Arc<Metrics>>,
    keys_loaded: HashSet<Url>,
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

    pub async fn load_public_keys(&mut self) -> HashMap<&Url, HashSet<PublicKeyBytes>> {
        let _timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.web3signer_load_keys_times.start_timer());

        let mut keys = HashMap::new();

        for url in &self.config.urls {
            if !self.config.allow_to_reload_keys && self.keys_loaded.contains(url) {
                continue;
            }

            match self.load_public_keys_from_url(url).await {
                Ok(mut remote_keys) => {
                    if !self.config.public_keys.is_empty() {
                        remote_keys.retain(|pubkey| self.config.public_keys.contains(pubkey));
                    }

                    keys.insert(url, remote_keys);
                    self.keys_loaded.insert(url.clone());
                }
                Err(error) => warn!("failed to load Web3Signer keys from {url}: {error:?}"),
            }
        }

        keys
    }

    pub async fn sign<P: Preset>(
        &self,
        api_url: &Url,
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
            .post(url)
            .json(&request)
            .send()
            .await?
            .json::<SigningResponse>()
            .await?;

        Ok(response.signature)
    }

    async fn load_public_keys_from_url(&self, api_url: &Url) -> Result<HashSet<PublicKeyBytes>> {
        let url = api_url.join("/api/v1/eth2/publicKeys")?;

        self.client
            .get(url)
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
    async fn test_load_public_keys() -> Result<()> {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(Method::GET).path("/api/v1/eth2/publicKeys");
            then.status(200)
                .body(json!([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]).to_string());
        });

        let url = Url::parse(&server.url("/"))?;
        let config = super::Config {
            allow_to_reload_keys: false,
            public_keys: HashSet::new(),
            urls: vec![url.clone()],
        };
        let mut web3signer = Web3Signer::new(Client::new(), config, None);

        let response = web3signer.load_public_keys().await;
        let expected = HashMap::from([(&url, HashSet::from([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]))]);

        assert_eq!(response, expected);

        let response = web3signer.load_public_keys().await;
        // By default, do not load pubkeys from Web3Signer again if keys were loaded
        let expected = HashMap::new();

        assert_eq!(response, expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_load_public_keys_if_reload_is_allowed() -> Result<()> {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(Method::GET).path("/api/v1/eth2/publicKeys");
            then.status(200)
                .body(json!([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]).to_string());
        });

        let url = Url::parse(&server.url("/"))?;
        let config = super::Config {
            allow_to_reload_keys: true,
            public_keys: HashSet::new(),
            urls: vec![url.clone()],
        };
        let mut web3signer = Web3Signer::new(Client::new(), config, None);

        let response = web3signer.load_public_keys().await;
        let expected = HashMap::from([(&url, HashSet::from([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]))]);

        assert_eq!(response, expected);

        let response = web3signer.load_public_keys().await;

        assert_eq!(response, expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_load_filtered_public_keys() -> Result<()> {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(Method::GET).path("/api/v1/eth2/publicKeys");
            then.status(200)
                .body(json!([SAMPLE_PUBKEY, SAMPLE_PUBKEY_2]).to_string());
        });

        let url = Url::parse(&server.url("/"))?;
        let config = super::Config {
            allow_to_reload_keys: false,
            public_keys: vec![SAMPLE_PUBKEY_2].into_iter().collect(),
            urls: vec![url.clone()],
        };
        let mut web3signer = Web3Signer::new(Client::new(), config, None);

        let response = web3signer.load_public_keys().await;
        let expected = HashMap::from([(&url, HashSet::from([SAMPLE_PUBKEY_2]))]);

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

        let url = Url::parse(&server.url("/"))?;
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
