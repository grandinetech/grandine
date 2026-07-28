//! Beacon Node API + SSE client used by the standalone builder.
//!
//! All endpoints are defined in the canonical Beacon Node API spec:
//! <https://github.com/ethereum/beacon-APIs/blob/master/beacon-node-oapi.yaml>
//!
//! - Genesis:          `GET  /eth/v1/beacon/genesis`
//! - Spec config:      `GET  /eth/v1/config/spec`
//! - Block (SSZ):      `GET  /eth/v2/beacon/blocks/{block_id}`
//! - Builders query:   `POST /eth/v1/beacon/states/{state_id}/builders`
//! - Finality:         `GET  /eth/v1/beacon/states/{state_id}/finality_checkpoints`
//! - Bid publish:      `POST /eth/v1/beacon/execution_payload_bids`
//! - Envelope publish: `POST /eth/v1/beacon/execution_payload_envelopes`
//! - SSE events:       `GET  /eth/v1/events`

use std::{sync::Arc, time::Duration};

use anyhow::{Context as _, Result, bail};
use beacon_api_types::{
    BuildersQuery, GetGenesisResponse, StateBuilderResponse, StateFinalityCheckpointsResponse,
};
use bytes::Bytes;
use eventsource_stream::Eventsource as _;
use futures::StreamExt as _;
use http_api_utils::{BlockId, ETH_BLOB_DATA_INCLUDED, ETH_CONSENSUS_VERSION, StateId};
use mime::{APPLICATION_JSON, APPLICATION_OCTET_STREAM, TEXT_EVENT_STREAM};
use reqwest::{
    Client, Response,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use sse::{Event, Topic};
use ssz::{ContiguousList, SszRead as _, SszWrite as _};
use tracing::{debug, warn};
use types::{
    combined::SignedBeaconBlock,
    config::Config as ChainConfig,
    deneb::primitives::Blob,
    gloas::containers::{
        SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
        SignedExecutionPayloadEnvelopeContents,
    },
    nonstandard::KzgProofs,
    preset::Preset,
};
use url::Url;

const BN_REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const BN_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Initial delay before retrying a failed SSE connection; doubles up to
/// [`SSE_RECONNECT_MAX_BACKOFF`] on repeated connect failures and resets after a
/// connection that successfully established.
const SSE_RECONNECT_MIN_BACKOFF: Duration = Duration::from_secs(1);
const SSE_RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct BeaconNodeClient {
    base: Arc<Url>,
    auth: Option<Arc<HeaderValue>>,
    client: Client,
}

impl BeaconNodeClient {
    pub fn new(base: Url, auth: Option<String>) -> Result<Self> {
        let auth = auth
            .map(|tok| HeaderValue::from_str(&format!("Bearer {tok}")))
            .transpose()
            .context("invalid beacon node auth header value")?
            .map(Arc::new);

        let client = Client::builder()
            .connect_timeout(BN_CONNECT_TIMEOUT)
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self {
            base: Arc::new(base),
            auth,
            client,
        })
    }

    pub async fn genesis(&self) -> Result<GetGenesisResponse> {
        let resp: DataEnvelope<GetGenesisResponse> = self.get_json("eth/v1/beacon/genesis").await?;
        Ok(resp.data)
    }

    /// Fetch the beacon node's runtime chain configuration via `GET /eth/v1/config/spec`.
    pub async fn config_spec(&self) -> Result<ChainConfig> {
        let resp: DataEnvelope<ChainConfig> = self.get_json("eth/v1/config/spec").await?;
        Ok(resp.data)
    }

    /// Fetch a beacon block via `GET /eth/v2/beacon/blocks/{block_id}` (SSZ) and
    /// deserialize it into the combined `SignedBeaconBlock`.
    pub async fn block_ssz<P: Preset>(
        &self,
        config: &ChainConfig,
        block_id: BlockId,
    ) -> Result<SignedBeaconBlock<P>> {
        let bytes = self
            .get_ssz(&format!("eth/v2/beacon/blocks/{block_id}"))
            .await?;
        SignedBeaconBlock::<P>::from_ssz(config, &bytes)
            .context("failed to deserialize SignedBeaconBlock")
    }

    /// Staked builders in a given state via `POST /eth/v1/beacon/states/{state_id}/builders`.
    /// So this serves both to resolve pubkey to builder_index and to read fresh per-slot balances for the bid coverage check.
    pub async fn builders(
        &self,
        state_id: StateId,
        query: &BuildersQuery,
    ) -> Result<Vec<StateBuilderResponse>> {
        let resp: DataEnvelope<Vec<StateBuilderResponse>> = self
            .post_json(&format!("eth/v1/beacon/states/{state_id}/builders"), query)
            .await?;
        Ok(resp.data)
    }

    /// Fetch a state's finality checkpoints via `GET /eth/v1/beacon/states/{state_id}/finality_checkpoints`.
    /// Used to source the justified (safe) and finalized execution hashes passed to `engine_forkchoiceUpdated`.
    pub async fn finality_checkpoints(
        &self,
        state_id: StateId,
    ) -> Result<StateFinalityCheckpointsResponse> {
        let resp: DataEnvelope<StateFinalityCheckpointsResponse> = self
            .get_json(&format!(
                "eth/v1/beacon/states/{state_id}/finality_checkpoints"
            ))
            .await?;
        Ok(resp.data)
    }

    /// Publish a signed execution payload bid.
    /// Endpoint: `POST /eth/v1/beacon/execution_payload_bids`.
    pub async fn publish_execution_payload_bid<P: Preset>(
        &self,
        bid: &SignedExecutionPayloadBid<P>,
    ) -> Result<()> {
        let url = self.url("eth/v1/beacon/execution_payload_bids")?;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(ETH_CONSENSUS_VERSION),
            HeaderValue::from_static("gloas"),
        );
        self.post_ssz(url, headers, bid.to_ssz()?.into()).await
    }

    /// Publish a signed execution payload envelope to `POST /eth/v1/beacon/execution_payload_envelopes`.
    ///
    /// The standalone builder always operates in the spec's *stateless* flow: it builds
    /// the payload on its own execution engine, so the beacon node it publishes to never
    /// has the blobs and cell proofs cached from block production. We therefore always
    /// send the full `SignedExecutionPayloadEnvelopeContents` (envelope + blobs + cell
    /// proofs) with `Eth-Blob-Data-Included: true`, letting the beacon node derive and
    /// broadcast the data column sidecars.
    pub async fn publish_payload_envelope<P: Preset>(
        &self,
        signed_execution_payload_envelope: SignedExecutionPayloadEnvelope<P>,
        blobs: Option<ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>>,
        proofs: Option<KzgProofs<P>>,
    ) -> Result<()> {
        let mut url = self.url("eth/v1/beacon/execution_payload_envelopes")?;
        url.query_pairs_mut()
            .append_pair("broadcast_validation", "consensus_and_equivocation");

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(ETH_CONSENSUS_VERSION),
            HeaderValue::from_static("gloas"),
        );
        headers.insert(
            HeaderName::from_static(ETH_BLOB_DATA_INCLUDED),
            HeaderValue::from_static("true"),
        );

        let (kzg_proofs, blobs) = match (proofs, blobs) {
            (Some(KzgProofs::Fulu(kzg_proofs)), Some(blobs)) => (kzg_proofs, blobs),
            (None, None) => (ContiguousList::default(), ContiguousList::default()),
            (Some(KzgProofs::Deneb(_)), _) => {
                bail!("execution engine returned pre-Fulu blob proofs")
            }
            (Some(KzgProofs::Fulu(_)), None) | (None, Some(_)) => bail!(
                "execution engine returned blobs and KZG proofs inconsistently: one is present, the other is not"
            ),
        };

        let contents = SignedExecutionPayloadEnvelopeContents {
            signed_execution_payload_envelope,
            kzg_proofs,
            blobs,
        };

        self.post_ssz(url, headers, contents.to_ssz()?.into()).await
    }

    /// Subscribe to BN SSE events. Spawns an internal task that forwards parsed
    /// events over an mpsc channel.
    ///
    /// SSE record framing is handled by `eventsource-stream`, which adapts the
    /// raw `reqwest` byte stream into `event`/`data` records; we only map each
    /// record's topic onto the shared `sse::Event` via `parse_event`.
    pub fn events<P: Preset>(
        &self,
        topics: &[Topic],
    ) -> Result<tokio::sync::mpsc::UnboundedReceiver<Result<Event<P>>>> {
        let topics = topics
            .iter()
            .map(Topic::as_ref)
            .collect::<Vec<_>>()
            .join(",");

        let mut url = self.url("eth/v1/events")?;
        url.query_pairs_mut().append_pair("topics", &topics);

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::try_from(TEXT_EVENT_STREAM.as_ref())?);
        let client = self.client.clone();
        let headers = self.apply_auth(headers);

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut backoff = SSE_RECONNECT_MIN_BACKOFF;
            loop {
                match connect_event_stream::<P>(&client, url.clone(), headers.clone(), &tx).await {
                    StreamOutcome::ReceiverGone => return,
                    StreamOutcome::Disconnected => backoff = SSE_RECONNECT_MIN_BACKOFF,
                    StreamOutcome::ConnectFailed => {}
                }

                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(SSE_RECONNECT_MAX_BACKOFF);
            }
        });
        Ok(rx)
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.base
            .join(path)
            .with_context(|| format!("failed to construct URL for {path}"))
    }

    fn apply_auth(&self, mut headers: HeaderMap) -> HeaderMap {
        if let Some(auth) = self.auth.as_deref() {
            headers.insert(AUTHORIZATION, auth.clone());
        }
        headers
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = self.url(path)?;
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::try_from(APPLICATION_JSON.as_ref())?);
        let req = self
            .client
            .get(url)
            .timeout(BN_REQUEST_TIMEOUT)
            .headers(self.apply_auth(headers));
        let resp = req.send().await?;
        ensure_ok(resp).await?.json().await.map_err(Into::into)
    }

    async fn get_ssz(&self, path: &str) -> Result<Bytes> {
        let url = self.url(path)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::try_from(APPLICATION_OCTET_STREAM.as_ref())?,
        );
        let req = self
            .client
            .get(url)
            .timeout(BN_REQUEST_TIMEOUT)
            .headers(self.apply_auth(headers));
        let resp = req.send().await?;
        ensure_ok(resp).await?.bytes().await.map_err(Into::into)
    }

    async fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = self.url(path)?;
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::try_from(APPLICATION_JSON.as_ref())?);
        let req = self
            .client
            .post(url)
            .timeout(BN_REQUEST_TIMEOUT)
            .headers(self.apply_auth(headers))
            .json(body);
        let resp = req.send().await?;
        ensure_ok(resp).await?.json().await.map_err(Into::into)
    }

    async fn post_ssz(&self, url: Url, mut headers: HeaderMap, body: Bytes) -> Result<()> {
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::try_from(APPLICATION_OCTET_STREAM.as_ref())?,
        );
        let req = self
            .client
            .post(url)
            .timeout(BN_REQUEST_TIMEOUT)
            .headers(self.apply_auth(headers))
            .body(body);
        let resp = req.send().await?;
        ensure_ok(resp).await?;
        Ok(())
    }
}

/// Why a single SSE connection ended, telling [`BeaconNodeClient::events`]
/// whether to stop, reconnect promptly, or back off before retrying.
enum StreamOutcome {
    /// The receiver was dropped, so the task should stop.
    ReceiverGone,
    /// A connection that had established later ended (EOF or stream error).
    /// Reconnect promptly (backoff resets).
    Disconnected,
    /// The connection could not be established (connect error or non-success
    /// status). Retry with a exponential backoff.
    ConnectFailed,
}

/// Generic `{ "data": ... }` envelope wrapping most Beacon Node REST responses.
#[derive(Debug, Deserialize)]
struct DataEnvelope<T> {
    data: T,
}

async fn ensure_ok(resp: Response) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        Ok(resp)
    } else {
        let url = resp.url().clone();
        let body = resp.text().await.unwrap_or_default();
        bail!("HTTP {status} from {url}: {body}")
    }
}

/// Establish one SSE connection to `/eth/v1/events` and forward parsed events to
/// `tx` until the connection ends or the receiver is dropped..
async fn connect_event_stream<P: Preset>(
    client: &Client,
    url: Url,
    headers: HeaderMap,
    tx: &tokio::sync::mpsc::UnboundedSender<Result<Event<P>>>,
) -> StreamOutcome {
    let resp = match client.get(url).headers(headers).send().await {
        Ok(resp) => resp,
        Err(error) => {
            warn!("SSE connect failed: {error}; will retry");
            return StreamOutcome::ConnectFailed;
        }
    };

    if !resp.status().is_success() {
        warn!(
            "SSE status {} from {}; will retry",
            resp.status(),
            resp.url(),
        );
        return StreamOutcome::ConnectFailed;
    }

    let mut stream = resp.bytes_stream().eventsource();
    while let Some(event) = stream.next().await {
        match event {
            // `event.event` is the topic (defaulting to "message"); `event.data`
            // is the JSON payload. `parse_event` maps subscribed topics onto
            // `sse::Event` and returns `None` for anything else (skipped, not an
            // error — see `parse_event`).
            Ok(event) => match parse_event::<P>(&event.event, &event.data) {
                // A per-event decode error is forwarded to the consumer but does
                // not drop the connection; a live stream recovers on the next
                // record.
                Some(parsed) => {
                    if tx.send(parsed).is_err() {
                        return StreamOutcome::ReceiverGone;
                    }
                }
                None => debug!("skipping unsubscribed SSE topic: {}", event.event),
            },
            Err(error) => {
                warn!("SSE stream error: {error}; will reconnect");
                return StreamOutcome::Disconnected;
            }
        }
    }

    // The stream ended cleanly (EOF): the beacon node closed the connection.
    debug!("SSE stream closed by beacon node; will reconnect");
    StreamOutcome::Disconnected
}

fn decode_event_data<T: for<'de> Deserialize<'de>, P: Preset>(
    data: &str,
    wrap: impl FnOnce(T) -> Event<P>,
) -> Result<Event<P>> {
    serde_json::from_str(data).map(wrap).map_err(Into::into)
}

/// Decode an SSE record into the shared `sse::Event` for a subscribed topic.
///
/// The builder subscribes only to `head_v2`, `payload_attributes`, and
/// `proposer_preferences`. Returns `None` for any other topic (unknown or
/// simply unsubscribed).
fn parse_event<P: Preset>(topic: &str, data: &str) -> Option<Result<Event<P>>> {
    let topic: Topic = topic.parse().ok()?;
    Some(match topic {
        Topic::HeadV2 => decode_event_data(data, Event::HeadV2),
        Topic::PayloadAttributes => decode_event_data(data, Event::PayloadAttributes),
        Topic::ProposerPreferences => decode_event_data(data, Event::ProposerPreferences),
        _ => return None,
    })
}
