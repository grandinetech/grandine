use core::time::Duration;
use std::{collections::HashSet, sync::Arc, time::SystemTime};

use anyhow::{Result, ensure};
use bls::PublicKeyBytes;
use http_api_utils::ETH_CONSENSUS_VERSION;
use logging::{debug_with_peers, warn_with_peers};
use mime::{APPLICATION_JSON, APPLICATION_OCTET_STREAM};
use parking_lot::Mutex;
use prometheus_metrics::Metrics;
use reqwest::{
    Client, RequestBuilder, Response, StatusCode,
    header::{ACCEPT, CONTENT_TYPE, HeaderValue},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use ssz::{SszRead, SszReadDefault as _, SszWrite};
use thiserror::Error;
use types::{
    combined::SignedBeaconBlock,
    config::Config as ChainConfig,
    gloas::containers::SignedExecutionPayloadBid,
    nonstandard::Phase,
    phase0::primitives::{ExecutionBlockHash, Gwei, H256, Slot},
    preset::Preset,
    redacting_url::RedactingUrl,
};

use crate::{
    BuilderApiFormat,
    api::{BuilderApiError, handle_error, validate_phase},
    consts::{BUILDER_BID_REQUEST_TIMEOUT, DATE_MS_HEADER},
    gloas::containers::{
        BuilderPreferences, BuilderPreferencesRequest, BuilderUrl, SignedBuilderRequestAuth,
    },
};

const TIMEOUT_MS_HEADER: &str = "X-Timeout-Ms";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_JSON_ONLY_BUILDERS: usize = 1024;

#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[expect(clippy::enum_variant_names)]
pub enum PayloadBuilderApiError {
    #[error("bid is for slot {received}, requested slot {requested}")]
    SlotMismatch { requested: Slot, received: Slot },
    #[error("bid builds on block hash {received:?}, requested {requested:?}")]
    ParentBlockHashMismatch {
        requested: ExecutionBlockHash,
        received: ExecutionBlockHash,
    },
    #[error("bid builds on block root {received:?}, requested {requested:?}")]
    ParentBlockRootMismatch { requested: H256, received: H256 },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionedResponse<T> {
    version: Phase,
    data: T,
}

pub struct Api {
    chain_config: Arc<ChainConfig>,
    client: Client,
    builder_api_format: BuilderApiFormat,
    metrics: Option<Arc<Metrics>>,
    json_only_builders: Mutex<HashSet<String>>,
}

impl Api {
    #[must_use]
    pub fn new(
        chain_config: Arc<ChainConfig>,
        client: Client,
        builder_api_format: BuilderApiFormat,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self {
            chain_config,
            client,
            builder_api_format,
            metrics,
            json_only_builders: Mutex::default(),
        }
    }

    pub async fn get_execution_payload_bid<P: Preset>(
        &self,
        builder_url: &BuilderUrl,
        auth: &SignedBuilderRequestAuth,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        parent_root: H256,
        pubkey: PublicKeyBytes,
    ) -> Result<Option<SignedExecutionPayloadBid<P>>> {
        let _timer = self.metrics.as_ref().map(|metrics| {
            metrics
                .builder_get_execution_payload_bid_times
                .start_timer()
        });

        let url = join_builder_url(
            builder_url,
            &format!(
                "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
            ),
        )?;

        let phase = self.chain_config.phase_at_slot::<P>(slot);

        debug_with_peers!("getting execution payload bid from {url}");

        let response = self
            .send(builder_url, |format| {
                let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;

                let request = self
                    .client
                    .post(url.clone().into_url())
                    .timeout(BUILDER_BID_REQUEST_TIMEOUT)
                    .header(ETH_CONSENSUS_VERSION, phase.as_ref())
                    .header(DATE_MS_HEADER, timestamp.as_millis().to_string())
                    .header(
                        TIMEOUT_MS_HEADER,
                        BUILDER_BID_REQUEST_TIMEOUT.as_millis().to_string(),
                    );

                let request = match format {
                    BuilderApiFormat::Json => request.header(ACCEPT, APPLICATION_JSON.as_ref()),
                    BuilderApiFormat::Ssz => request.header(
                        ACCEPT,
                        format!("{APPLICATION_OCTET_STREAM};q=1,{APPLICATION_JSON};q=0.9"),
                    ),
                };

                with_body(request, format, auth)
            })
            .await?;

        let response = handle_error(response).await?;

        if response.status() == StatusCode::NO_CONTENT {
            debug_with_peers!("builder has no execution payload bid for slot {slot}");
            return Ok(None);
        }

        let (version, bid) = parse_response::<SignedExecutionPayloadBid<P>>(response).await?;

        validate_phase(phase, version)?;
        validate_bid(&bid, slot, parent_hash, parent_root)?;

        Ok(Some(bid))
    }

    pub async fn submit_builder_preferences<P: Preset>(
        &self,
        builder_url: &BuilderUrl,
        auth: SignedBuilderRequestAuth,
        proposer_pubkey: PublicKeyBytes,
        max_execution_payment: Gwei,
    ) -> Result<()> {
        let _timer = self.metrics.as_ref().map(|metrics| {
            metrics
                .builder_submit_builder_preferences_times
                .start_timer()
        });

        let url = join_builder_url(
            builder_url,
            &format!("/eth/v1/builder/builder_preferences/{proposer_pubkey:?}"),
        )?;

        let phase = self.chain_config.phase_at_slot::<P>(auth.message.slot);

        let body = BuilderPreferencesRequest {
            preferences: BuilderPreferences {
                max_execution_payment,
            },
            auth,
        };

        debug_with_peers!("submitting builder preferences to {url}");

        let response = self
            .send(builder_url, |format| {
                let request = self
                    .client
                    .post(url.clone().into_url())
                    .timeout(REQUEST_TIMEOUT)
                    .header(ETH_CONSENSUS_VERSION, phase.as_ref());

                with_body(request, format, &body)
            })
            .await?;

        let response = handle_error(response).await?;

        ensure!(
            response.status() == StatusCode::ACCEPTED,
            BuilderApiError::UnexpectedStatusCode {
                expected: StatusCode::ACCEPTED,
                received: response.status(),
            },
        );

        Ok(())
    }

    pub async fn submit_signed_beacon_block<P: Preset>(
        &self,
        builder_url: &BuilderUrl,
        block: &SignedBeaconBlock<P>,
    ) -> Result<()> {
        let _timer = self.metrics.as_ref().map(|metrics| {
            metrics
                .builder_submit_signed_beacon_block_times
                .start_timer()
        });

        let url = join_builder_url(builder_url, "/eth/v1/builder/beacon_blocks")?;

        debug_with_peers!("submitting signed beacon block to {url}");

        let response = self
            .send(builder_url, |format| {
                let request = self
                    .client
                    .post(url.clone().into_url())
                    .timeout(REQUEST_TIMEOUT)
                    .header(ETH_CONSENSUS_VERSION, block.phase().as_ref());

                with_body(request, format, block)
            })
            .await?;

        let response = handle_error(response).await?;

        ensure!(
            response.status() == StatusCode::ACCEPTED,
            BuilderApiError::UnexpectedStatusCode {
                expected: StatusCode::ACCEPTED,
                received: response.status(),
            },
        );

        Ok(())
    }

    async fn send(
        &self,
        builder_url: &BuilderUrl,
        request: impl Fn(BuilderApiFormat) -> Result<RequestBuilder>,
    ) -> Result<Response> {
        let origin = builder_url.origin();

        let json_only = origin
            .as_ref()
            .is_some_and(|origin| self.json_only_builders.lock().contains(origin));

        let format = if json_only {
            BuilderApiFormat::Json
        } else {
            self.builder_api_format
        };

        let response = request(format)?.send().await?;

        let ssz_rejected = format == BuilderApiFormat::Ssz
            && matches!(
                response.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE | StatusCode::NOT_ACCEPTABLE,
            );

        if !ssz_rejected {
            return Ok(response);
        }

        if let Some(origin) = origin {
            self.mark_json_only(origin);
        }

        request(BuilderApiFormat::Json)?
            .send()
            .await
            .map_err(Into::into)
    }

    fn mark_json_only(&self, origin: String) {
        let mut json_only_builders = self.json_only_builders.lock();

        if json_only_builders.len() >= MAX_JSON_ONLY_BUILDERS
            || json_only_builders.contains(&origin)
        {
            return;
        }

        warn_with_peers!("builder {origin} rejected an SSZ request, using JSON for it from now on");

        json_only_builders.insert(origin);
    }
}

fn with_body<T: Serialize + SszWrite>(
    request: RequestBuilder,
    format: BuilderApiFormat,
    body: &T,
) -> Result<RequestBuilder> {
    let request = match format {
        BuilderApiFormat::Json => request.json(body),
        BuilderApiFormat::Ssz => request
            .header(CONTENT_TYPE, APPLICATION_OCTET_STREAM.as_ref())
            .body(body.to_ssz()?),
    };

    Ok(request)
}

fn join_builder_url(builder_url: &BuilderUrl, path: &str) -> Result<RedactingUrl> {
    builder_url.http_url()?.join(path).map_err(Into::into)
}

async fn parse_response<T: DeserializeOwned + SszRead<()>>(
    response: Response,
) -> Result<(Phase, T)> {
    let content_type = response.headers().get(CONTENT_TYPE);

    if content_type.is_none()
        || content_type == Some(&HeaderValue::from_static(APPLICATION_JSON.as_ref()))
    {
        let VersionedResponse { version, data } = response.json().await?;
        return Ok((version, data));
    }

    if content_type == Some(&HeaderValue::from_static(APPLICATION_OCTET_STREAM.as_ref())) {
        let phase = http_api_utils::extract_phase_from_headers(response.headers())?;
        let bytes = response.bytes().await?;
        return Ok((phase, T::from_ssz_default(bytes)?));
    }

    Err(BuilderApiError::UnsupportedContentType {
        content_type: content_type.cloned(),
    }
    .into())
}

fn validate_bid<P: Preset>(
    bid: &SignedExecutionPayloadBid<P>,
    slot: Slot,
    parent_hash: ExecutionBlockHash,
    parent_root: H256,
) -> Result<()> {
    let message = &bid.message;

    ensure!(
        message.slot == slot,
        PayloadBuilderApiError::SlotMismatch {
            requested: slot,
            received: message.slot,
        },
    );

    ensure!(
        message.parent_block_hash == parent_hash,
        PayloadBuilderApiError::ParentBlockHashMismatch {
            requested: parent_hash,
            received: message.parent_block_hash,
        },
    );

    ensure!(
        message.parent_block_root == parent_root,
        PayloadBuilderApiError::ParentBlockRootMismatch {
            requested: parent_root,
            received: message.parent_block_root,
        },
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use bls::SignatureBytes;
    use httpmock::{Method, MockServer};
    use serde_json::json;
    use ssz::Hc;
    use types::{gloas::containers::SignedBeaconBlock as GloasSignedBeaconBlock, preset::Minimal};

    use crate::gloas::containers::BuilderRequestAuth;

    use super::*;

    const SLOT: Slot = 9;
    const PARENT_HASH: ExecutionBlockHash = ExecutionBlockHash::repeat_byte(1);
    const PARENT_ROOT: H256 = H256::repeat_byte(2);
    const PUBKEY: PublicKeyBytes = PublicKeyBytes::repeat_byte(3);
    const MAX_EXECUTION_PAYMENT: Gwei = 1_000_000_000;

    fn api(builder_api_format: BuilderApiFormat) -> Api {
        let chain_config = Arc::new(ChainConfig::minimal().start_and_stay_in(Phase::Gloas));

        Api::new(chain_config, Client::new(), builder_api_format, None)
    }

    fn builder_url(server: &MockServer) -> BuilderUrl {
        BuilderUrl::try_from(server.base_url().as_str()).expect("mock server URL should be valid")
    }

    fn auth() -> SignedBuilderRequestAuth {
        SignedBuilderRequestAuth {
            message: BuilderRequestAuth {
                data: b"127.0.0.1"
                    .to_vec()
                    .try_into()
                    .expect("auth data should fit"),
                slot: SLOT,
            },
            signature: SignatureBytes::default(),
        }
    }

    fn bid() -> SignedExecutionPayloadBid<Minimal> {
        let mut bid = SignedExecutionPayloadBid::default();

        bid.message.slot = SLOT;
        bid.message.parent_block_hash = PARENT_HASH;
        bid.message.parent_block_root = PARENT_ROOT;
        bid.message.value = 7;

        bid
    }

    fn block() -> SignedBeaconBlock<Minimal> {
        GloasSignedBeaconBlock {
            message: Hc::default(),
            signature: SignatureBytes::default(),
        }
        .into()
    }

    fn bid_path() -> String {
        format!(
            "/eth/v1/builder/execution_payload_bid/{SLOT}/{PARENT_HASH:?}/{PARENT_ROOT:?}/{PUBKEY:?}"
        )
    }

    async fn get_bid(
        api: &Api,
        server: &MockServer,
    ) -> Result<Option<SignedExecutionPayloadBid<Minimal>>> {
        api.get_execution_payload_bid(
            &builder_url(server),
            &auth(),
            SLOT,
            PARENT_HASH,
            PARENT_ROOT,
            PUBKEY,
        )
        .await
    }

    #[tokio::test]
    async fn submit_signed_beacon_block_post_requests() -> Result<()> {
        for builder_api_format in [BuilderApiFormat::Json, BuilderApiFormat::Ssz] {
            let server = MockServer::start_async().await;
            let json = serde_json::to_value(block())?;
            let ssz = block().to_ssz()?;

            let mock = server.mock(|when, then| {
                let when = when
                    .method(Method::POST)
                    .path("/eth/v1/builder/beacon_blocks")
                    .header(ETH_CONSENSUS_VERSION, "gloas");

                match builder_api_format {
                    BuilderApiFormat::Json => when.json_body(json),
                    BuilderApiFormat::Ssz => when
                        .header(CONTENT_TYPE.as_str(), APPLICATION_OCTET_STREAM.as_ref())
                        .is_true(move |request| request.body().to_vec() == ssz),
                };

                then.status(202);
            });

            api(builder_api_format)
                .submit_signed_beacon_block(&builder_url(&server), &block())
                .await?;

            mock.assert();
        }

        Ok(())
    }

    #[tokio::test]
    async fn submit_signed_beacon_block_reports_a_bad_request() -> Result<()> {
        let server = MockServer::start_async().await;

        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/eth/v1/builder/beacon_blocks");
            then.status(400).body("invalid block");
        });

        let error = api(BuilderApiFormat::Json)
            .submit_signed_beacon_block(&builder_url(&server), &block())
            .await
            .expect_err("a 400 response should be an error");

        assert_eq!(
            error.downcast_ref::<BuilderApiError>(),
            Some(&BuilderApiError::BadRequest {
                message: "invalid block".to_owned(),
            }),
        );

        Ok(())
    }

    #[tokio::test]
    async fn submit_builder_preferences_post_requests() -> Result<()> {
        let request = BuilderPreferencesRequest {
            preferences: BuilderPreferences {
                max_execution_payment: MAX_EXECUTION_PAYMENT,
            },
            auth: auth(),
        };

        for builder_api_format in [BuilderApiFormat::Json, BuilderApiFormat::Ssz] {
            let server = MockServer::start_async().await;
            let json = serde_json::to_value(&request)?;
            let ssz = request.to_ssz()?;

            let mock = server.mock(|when, then| {
                let when = when
                    .method(Method::POST)
                    .path(format!("/eth/v1/builder/builder_preferences/{PUBKEY:?}"))
                    .header(ETH_CONSENSUS_VERSION, "gloas");

                match builder_api_format {
                    BuilderApiFormat::Json => when.json_body(json),
                    BuilderApiFormat::Ssz => when
                        .header(CONTENT_TYPE.as_str(), APPLICATION_OCTET_STREAM.as_ref())
                        .is_true(move |request| request.body().to_vec() == ssz),
                };

                then.status(202);
            });

            api(builder_api_format)
                .submit_builder_preferences::<Minimal>(
                    &builder_url(&server),
                    auth(),
                    PUBKEY,
                    MAX_EXECUTION_PAYMENT,
                )
                .await?;

            mock.assert();
        }

        Ok(())
    }

    #[tokio::test]
    async fn falls_back_to_json_for_a_builder_that_rejects_ssz() -> Result<()> {
        let server = MockServer::start_async().await;

        let ssz_mock = server.mock(|when, then| {
            when.method(Method::POST)
                .header(CONTENT_TYPE.as_str(), APPLICATION_OCTET_STREAM.as_ref());
            then.status(415);
        });

        let json_mock = server.mock(|when, then| {
            when.method(Method::POST)
                .header(CONTENT_TYPE.as_str(), APPLICATION_JSON.as_ref());
            then.status(202);
        });

        let api = api(BuilderApiFormat::Ssz);

        for _ in 0..2 {
            api.submit_builder_preferences::<Minimal>(
                &builder_url(&server),
                auth(),
                PUBKEY,
                MAX_EXECUTION_PAYMENT,
            )
            .await?;
        }

        // first request with ssz body failed, it falls back to json then record the builder
        // support only json format, so the second request is sent with json body directly.
        ssz_mock.assert_calls(1);
        json_mock.assert_calls(2);

        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_decodes_json() -> Result<()> {
        let server = MockServer::start_async().await;

        server.mock(|when, then| {
            when.method(Method::POST).path(bid_path());
            then.status(200)
                .header(CONTENT_TYPE.as_str(), APPLICATION_JSON.as_ref())
                .header(ETH_CONSENSUS_VERSION, "gloas")
                .json_body(json!({"version": "gloas", "data": bid()}));
        });

        assert_eq!(
            get_bid(&api(BuilderApiFormat::Json), &server).await?,
            Some(bid()),
        );

        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_decodes_ssz() -> Result<()> {
        let server = MockServer::start_async().await;
        let ssz = auth().to_ssz()?;

        server.mock(|when, then| {
            when.method(Method::POST)
                .path(bid_path())
                .header(CONTENT_TYPE.as_str(), APPLICATION_OCTET_STREAM.as_ref())
                .is_true(move |request| request.body().to_vec() == ssz);
            then.status(200)
                .header(CONTENT_TYPE.as_str(), APPLICATION_OCTET_STREAM.as_ref())
                .header(ETH_CONSENSUS_VERSION, "gloas")
                .body(bid().to_ssz().expect("bid should be serializable"));
        });

        assert_eq!(
            get_bid(&api(BuilderApiFormat::Ssz), &server).await?,
            Some(bid()),
        );

        Ok(())
    }

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
