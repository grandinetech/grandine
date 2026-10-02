use std::sync::Arc;

use anyhow::{Result, bail};
use bls::PublicKeyBytes;
use prometheus_metrics::Metrics;
use pubkey_cache::PubkeyCache;
use reqwest::Client;
use thiserror::Error;
use types::{
    combined::SignedBeaconBlock,
    gloas::containers::SignedExecutionPayloadBid,
    phase0::primitives::{ExecutionBlockHash, Gwei, H256, Slot},
    preset::Preset,
    redacting_url::RedactingUrl,
};

use crate::{
    BuilderApiFormat,
    gloas::containers::{BuilderUrl, SignedBuilderRequestAuth},
};

#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum PayloadBuilderApiError {
    #[error("Builder API request to {url} is not implemented")]
    NotImplemented { url: RedactingUrl },
}

#[expect(
    dead_code,
    reason = "fields are used once the endpoints are implemented"
)]
pub struct Api {
    builder_api_format: BuilderApiFormat,
    pubkey_cache: Arc<PubkeyCache>,
    client: Client,
    metrics: Option<Arc<Metrics>>,
}

impl Api {
    #[must_use]
    pub const fn new(
        builder_api_format: BuilderApiFormat,
        pubkey_cache: Arc<PubkeyCache>,
        client: Client,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self {
            builder_api_format,
            pubkey_cache,
            client,
            metrics,
        }
    }

    #[expect(clippy::unused_async)]
    pub async fn get_execution_payload_bid<P: Preset>(
        &self,
        builder_url: &BuilderUrl,
        _auth: &SignedBuilderRequestAuth,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        parent_root: H256,
        pubkey: PublicKeyBytes,
    ) -> Result<Option<SignedExecutionPayloadBid<P>>> {
        let url = join_builder_url(
            builder_url,
            &format!(
                "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
            ),
        )?;

        // TODO: submit the auth with `Date-Milliseconds` and `X-Timeout-Ms`, decode the bid,
        // and check its slot, parent_block_hash and parent_block_root against the request.
        // 204 means the builder is serving no bid, which is `Ok(None)` rather than an error.
        bail!(PayloadBuilderApiError::NotImplemented { url })
    }

    #[expect(clippy::unused_async)]
    pub async fn submit_builder_preferences(
        &self,
        builder_url: &BuilderUrl,
        _auth: &SignedBuilderRequestAuth,
        proposer_pubkey: PublicKeyBytes,
        _max_execution_payment: Gwei,
    ) -> Result<()> {
        let url = join_builder_url(
            builder_url,
            &format!("/eth/v1/builder/builder_preferences/{proposer_pubkey:?}"),
        )?;

        // TODO: submit the auth and `max_execution_payment`. The builder answers 202.
        bail!(PayloadBuilderApiError::NotImplemented { url })
    }

    #[expect(clippy::unused_async)]
    pub async fn submit_signed_beacon_block<P: Preset>(
        &self,
        builder_url: &BuilderUrl,
        _block: &SignedBeaconBlock<P>,
    ) -> Result<()> {
        let url = join_builder_url(builder_url, "/eth/v1/builder/beacon_blocks")?;

        // TODO: submit the block so the builder can reveal its payload envelope.
        // The proposer still has to publish the block over gossip itself.
        bail!(PayloadBuilderApiError::NotImplemented { url })
    }
}

fn join_builder_url(builder_url: &BuilderUrl, path: &str) -> Result<RedactingUrl> {
    builder_url.http_url()?.join(path).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_builder_url_ignore_the_url_path() -> Result<()> {
        let builder_url = BuilderUrl::try_from("https://builder.example.com/relay")?;

        assert_eq!(
            join_builder_url(&builder_url, "/eth/v1/builder/beacon_blocks")?.to_string(),
            "https://builder.example.com/eth/v1/builder/beacon_blocks",
        );

        Ok(())
    }

    // `BuilderUrl` only checks the input is a nonempty UTF-8 string.
    #[test]
    fn join_builder_url_rejects_a_url_without_a_scheme() -> Result<()> {
        let builder_url = BuilderUrl::try_from("builder.example.com")?;

        join_builder_url(&builder_url, "/eth/v1/builder/beacon_blocks")
            .expect_err("a URL without a scheme should be rejected");

        Ok(())
    }

    #[test]
    fn join_builder_url_rejects_non_http_schemes() -> Result<()> {
        for url in [
            "file:///etc/passwd",
            "ftp://builder.example.com",
            "user:secret@host",
        ] {
            let builder_url = BuilderUrl::try_from(url)?;

            join_builder_url(&builder_url, "/eth/v1/builder/beacon_blocks")
                .expect_err("a non-HTTP URL should be rejected");
        }

        Ok(())
    }
}
