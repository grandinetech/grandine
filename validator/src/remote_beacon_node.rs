use core::{
    marker::PhantomData,
    num::{NonZeroU32, NonZeroU64},
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
    time::Duration,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, OnceLock},
};

use anyhow::{Error as AnyhowError, Result, bail, ensure};
use bls::PublicKeyBytes;
use derive_more::Display;
use futures::{Stream, StreamExt as _, future};
use helper_functions::{misc, predicates};
use http_api_utils::{
    BlockHeadersResponse, ETH_CONSENSUS_VERSION, EthResponse, ValidatorAttesterDutyResponse,
    ValidatorLivenessResponse, ValidatorPTCDutyResponse, ValidatorSyncDutyResponse,
};
use itertools::Itertools as _;
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use p2p::{BeaconCommitteeSubscription, SyncCommitteeSubscription};
use reqwest::{Body, Client, Response, StatusCode, header::ACCEPT};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sse_stream::SseStream;
use ssz::SszHash as _;
use std_ext::ArcExt as _;
use thiserror::Error;
use types::{
    altair::{
        containers::{SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::{Attestation, SignedAggregateAndProof},
    config::Config as ChainConfig,
    electra::containers::Attestation as ElectraAttestation,
    gloas::containers::{
        Attestation as GloasAttestation, PayloadAttestationData, PayloadAttestationMessage,
    },
    nonstandard::{ForkInfo, OwnAttestation, Phase},
    phase0::containers::Attestation as Phase0Attestation,
    phase0::{
        consts::BASIS_POINTS,
        containers::AttestationData,
        primitives::{CommitteeIndex, Epoch, H256, Slot, ValidatorIndex, Version},
    },
    preset::Preset,
    redacting_url::RedactingUrl,
};

use crate::{
    beacon_node_api::{AttesterDuties, BeaconNodeApi, PtcDuties},
    chain_head::{ChainHead, DependentRoots, HeadUpdate},
    health::Health,
    slot_head::SlotHead,
};

/// The end of the slot as a due point, at 100% of the slot's basis points.
const SLOT_END_BPS: u64 = BASIS_POINTS;
/// No timeout falls below this; short slots must not shrink requests below real network latency.
const MIN_TIMEOUT: Duration = Duration::from_secs(1);
/// A deadline-bound request may use half its window, leaving the rest for another node.
const DEADLINE_ATTEMPTS: NonZeroU64 = NonZeroU64::new(2).expect("the literal is not zero");
/// A lone serving node has no fallback to leave time for; give it a generous fixed wait.
const LONE_NODE_TIMEOUT: Duration = Duration::from_secs(4);

/// Requests off the duty path can afford to wait for a slow node.
const BACKGROUND_TIMEOUT_QUOTIENT: NonZeroU32 =
    NonZeroU32::new(2).expect("the literal is not zero");

const VALIDATOR_IDS_PER_REQUEST: usize = 1024;

#[derive(Debug, Error)]
enum Error {
    #[error(
        "beacon node at {url} is on a different network \
         (expected genesis fork version {expected:?}, received {actual:?})"
    )]
    NetworkMismatch {
        url: String,
        expected: Version,
        actual: Version,
    },
    #[error("beacon node at {url} reported an optimistic head")]
    OptimisticHead { url: String },
    #[error("beacon node at {url} did not report whether its head is optimistic")]
    UnknownOptimisticStatus { url: String },
    #[error(
        "beacon node at {url} returned a sync committee contribution \
         that does not match the request"
    )]
    UnexpectedContribution { url: String },
    #[error(
        "beacon node at {url} returned payload attestation data for slot {actual} \
         where slot {expected} was requested"
    )]
    UnexpectedPayloadAttestationSlot {
        url: String,
        expected: Slot,
        actual: Slot,
    },
    #[error(
        "beacon node returned an aggregate covering committees {actual:?} \
         where only committee {expected} was requested"
    )]
    UnexpectedCommittees {
        expected: CommitteeIndex,
        actual: Vec<CommitteeIndex>,
    },
    #[error("beacon node reported {reported} data where {expected} was expected")]
    UnexpectedVersion { expected: Phase, reported: Phase },
    #[error(
        "beacon node produced attestation data with index {index} \
         for committee {committee_index} in {phase}"
    )]
    UnexpectedAttestationIndex {
        phase: Phase,
        committee_index: CommitteeIndex,
        index: u64,
    },
    #[error("request to beacon node at {url} failed with status {status}: {body}")]
    Response {
        url: String,
        status: StatusCode,
        body: String,
    },
}

#[derive(Deserialize)]
struct Genesis {
    genesis_fork_version: Version,
    genesis_validators_root: H256,
}

/// The request body of `postStateValidators`.
#[derive(Serialize)]
struct ValidatorIds<'keys> {
    ids: &'keys [PublicKeyBytes],
}

/// An entry of the `postStateValidators` response, of which only the key and index are needed.
#[derive(Deserialize)]
struct StateValidator {
    #[serde(with = "serde_utils::string_or_native")]
    index: ValidatorIndex,
    validator: ValidatorPublicKey,
}

#[derive(Deserialize)]
struct ValidatorPublicKey {
    pubkey: PublicKeyBytes,
}

/// The deprecated `head` event, whose dependent roots are named by duty period.
#[derive(Deserialize)]
struct HeadEvent {
    #[serde(with = "serde_utils::string_or_native")]
    slot: Slot,
    block: H256,
    previous_duty_dependent_root: H256,
    current_duty_dependent_root: H256,
    execution_optimistic: bool,
}

/// The `head_v2` event, whose dependent roots are named by the epoch they determine.
#[derive(Deserialize)]
struct HeadV2Event {
    data: HeadV2EventData,
}

#[derive(Deserialize)]
struct HeadV2EventData {
    #[serde(with = "serde_utils::string_or_native")]
    slot: Slot,
    block: H256,
    current_epoch_dependent_root: H256,
    next_epoch_dependent_root: H256,
    execution_optimistic: bool,
}

const HEAD_EVENT: &str = "head";
const HEAD_V2_EVENT: &str = "head_v2";

/// A `head` or `head_v2` event, told apart by shape: only `head_v2` nests under `data`.
#[derive(Deserialize)]
#[serde(untagged)]
enum AnyHeadEvent {
    V2(HeadV2Event),
    V1(HeadEvent),
}

impl AnyHeadEvent {
    fn parse<P: Preset>(data: &str) -> Result<HeadUpdate> {
        serde_json::from_str::<Self>(data)
            .map(Self::into_update::<P>)
            .map_err(Into::into)
    }

    fn into_update<P: Preset>(self) -> HeadUpdate {
        let (slot, block, current, next, execution_optimistic) = match self {
            Self::V2(HeadV2Event { data }) => (
                data.slot,
                data.block,
                data.current_epoch_dependent_root,
                data.next_epoch_dependent_root,
                data.execution_optimistic,
            ),
            // The old names label the duty period rather than the epoch; the values are the same.
            Self::V1(event) => (
                event.slot,
                event.block,
                event.previous_duty_dependent_root,
                event.current_duty_dependent_root,
                event.execution_optimistic,
            ),
        };

        HeadUpdate {
            slot,
            block,
            execution_optimistic,
            dependent_roots: DependentRoots {
                epoch: misc::compute_epoch_at_slot::<P>(slot),
                current,
                next,
            },
        }
    }
}

/// The request body of `getAttesterDuties`, whose indices are quoted in JSON.
#[derive(Serialize)]
#[serde(transparent)]
struct ValidatorIndices(
    #[serde(with = "serde_utils::string_or_native_sequence")] Vec<ValidatorIndex>,
);

// `head_slot` and `sync_distance` are ignored: neither separates a node that has fallen behind
// from a chain with missed slots.
#[derive(Deserialize)]
struct SyncingStatus {
    is_syncing: bool,
    #[serde(default)]
    is_optimistic: bool,
    #[serde(default)]
    el_offline: bool,
}

pub enum NetworkCheck {
    Matches,
    Mismatch(AnyhowError),
    Unreachable(AnyhowError),
}

/// A beacon node reached over <https://ethereum.github.io/beacon-APIs/>.
#[derive(Display)]
#[display("{url}")]
pub struct RemoteBeaconNode {
    chain_config: Arc<ChainConfig>,
    client: Client,
    url: RedactingUrl,
    max_empty_slots: u64,
    /// A [`Health`] discriminant. Atomic because it is read on the duty path.
    health: AtomicU8,
    chain_head: ChainHead,
    /// Learned from the genesis check and unchanging thereafter.
    genesis_validators_root: OnceLock<H256>,
    /// How many nodes of the fleet can serve, shared between them; a lone node is not held to
    /// timeouts that reserve time for a fallback.
    serving_count: Arc<AtomicUsize>,
}

impl RemoteBeaconNode {
    #[must_use]
    pub const fn new(
        chain_config: Arc<ChainConfig>,
        client: Client,
        url: RedactingUrl,
        max_empty_slots: u64,
        serving_count: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            chain_config,
            client,
            url,
            max_empty_slots,
            health: AtomicU8::new(Health::Unknown.as_u8()),
            chain_head: ChainHead::new(),
            genesis_validators_root: OnceLock::new(),
            serving_count,
        }
    }

    #[must_use]
    pub const fn chain_head(&self) -> &ChainHead {
        &self.chain_head
    }

    /// Learned from the genesis check; [`None`] until the node has been reached.
    #[must_use]
    pub fn genesis_validators_root(&self) -> Option<H256> {
        self.genesis_validators_root.get().copied()
    }

    #[must_use]
    pub fn health(&self) -> Health {
        Health::from_u8(self.health.load(Ordering::Relaxed))
    }

    pub async fn head_events<P: Preset>(
        &self,
    ) -> Result<impl Stream<Item = Result<HeadUpdate>> + Send + use<P>> {
        // Older nodes reject an unknown topic outright rather than streaming nothing; a node
        // that cannot be reached at all is no more reachable on the old topic.
        let response = match self.subscribe(HEAD_V2_EVENT).await {
            Ok(response) => response,
            Err(error) if error.downcast_ref::<Error>().is_some() => {
                debug_with_peers!(
                    "{} does not stream {HEAD_V2_EVENT} events, falling back to {HEAD_EVENT}: \
                     {error:?}",
                    self.url,
                );

                self.subscribe(HEAD_EVENT).await?
            }
            Err(error) => return Err(error),
        };

        // An event without data carries no head, as a keep-alive does, and is not a failure.
        let events = SseStream::new(Body::from(response)).filter_map(|event| {
            let head_update = match event {
                Ok(event) => match (event.event.as_deref(), event.data) {
                    (Some(HEAD_V2_EVENT | HEAD_EVENT), Some(data)) => {
                        Some(AnyHeadEvent::parse::<P>(&data))
                    }
                    _ => None,
                },
                Err(error) => Some(Err(error.into())),
            };

            future::ready(head_update)
        });

        Ok(events)
    }

    async fn subscribe(&self, topic: &str) -> Result<Response> {
        let url = self.endpoint(&format!("/eth/v1/events?topics={topic}"))?;

        let response = self
            .client
            .get(url.into_url())
            // Without this some beacon nodes answer with an empty body rather than a stream.
            .header(ACCEPT, "text/event-stream")
            // The client is built with a request timeout, which would end the stream even while
            // events are still arriving.
            .timeout(Duration::MAX)
            .send()
            .await?;

        self.check_status(response).await
    }

    /// Asked for only while the event stream is not keeping the head up to date, so that a
    /// stream that is down costs a request per slot rather than the slot's duties.
    pub async fn refresh_head(&self, slot: Slot) {
        // A node on a different network would otherwise cache a head from another chain,
        // mirroring the filter on the event stream.
        if self.health() == Health::Incompatible {
            return;
        }

        // Polled whenever the head is not from the previous slot, as the stream may be silently
        // dead; a healthy stream keeps this a no-op.
        if self.chain_head.can_serve(slot, 1) {
            return;
        }

        match self.head_header().await {
            // Recorded at the head's own slot, so that a stale head is cached as stale rather
            // than appearing fresh for another `max_empty_slots` slots.
            Ok((head_slot, block_root)) => self.chain_head.overwrite(slot, head_slot, block_root),
            Err(error) => {
                debug_with_peers!("{} did not report its head: {error:?}", self.url);
            }
        }
    }

    /// The current head, polled and bounded like the cached one.
    pub(crate) async fn fresh_head_block_root(&self, slot: Slot) -> Result<H256> {
        let (head_slot, block_root) = self.head_header().await?;

        self.chain_head.overwrite(slot, head_slot, block_root);

        self.chain_head
            .get(slot, self.max_empty_slots)?
            .ok_or_else(|| {
                AnyhowError::msg(format!(
                    "head of beacon node at {} is too old to sign for slot {slot}",
                    self.url,
                ))
            })
    }

    /// The slot and root of the node's head, refused while it is optimistic, like a head event.
    async fn head_header(&self) -> Result<(Slot, H256)> {
        let url = self.endpoint("/eth/v1/beacon/headers/head")?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.head_timeout())
            .send()
            .await?;

        let response = self.check_status(response).await?;

        let (block_header, execution_optimistic) = response
            .json::<EthResponse<BlockHeadersResponse>>()
            .await?
            .into_data_and_execution_optimistic();

        check_not_optimistic(&self.url, execution_optimistic)?;

        Ok((block_header.header.message.slot, block_header.root))
    }

    pub async fn refresh_health(&self, slot: Slot) {
        let previous = self.health();
        let health = self.poll_health(slot).await;

        if health != previous {
            info_with_peers!("beacon node at {} is now {health:?}", self.url);

            match (previous.can_serve(), health.can_serve()) {
                (false, true) => _ = self.serving_count.fetch_add(1, Ordering::Relaxed),
                (true, false) => _ = self.serving_count.fetch_sub(1, Ordering::Relaxed),
                _ => {}
            }
        }

        self.health.store(health.as_u8(), Ordering::Relaxed);
    }

    async fn poll_health(&self, slot: Slot) -> Health {
        match self.check_network().await {
            NetworkCheck::Matches => {}
            NetworkCheck::Mismatch(error) => {
                warn_with_peers!(
                    "beacon node at {} is on a different network: {error:?}",
                    self.url,
                );

                return Health::Incompatible;
            }
            NetworkCheck::Unreachable(error) => {
                debug_with_peers!(
                    "beacon node at {} could not be reached: {error:?}",
                    self.url,
                );

                return Health::Unreachable;
            }
        }

        let health = match self.syncing_status().await {
            Ok(status) => Health::from_syncing_status(
                status.el_offline,
                status.is_syncing,
                status.is_optimistic,
            ),
            Err(error) => {
                debug_with_peers!(
                    "beacon node at {} did not report its sync status: {error:?}",
                    self.url,
                );

                Health::Unreachable
            }
        };

        // A node that has fallen behind keeps serving stale duty data while calling itself
        // synced; its own head, held to the wall clock, shows what its sync status cannot.
        if health == Health::Ready && self.chain_head.is_stale(slot, self.max_empty_slots) {
            debug_with_peers!(
                "beacon node at {} reports itself synced but its head is stale",
                self.url,
            );

            return Health::Unusable;
        }

        health
    }

    async fn syncing_status(&self) -> Result<SyncingStatus> {
        let url = self.endpoint("/eth/v1/node/syncing")?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.background_timeout())
            .send()
            .await?;

        self.parse_data(response).await
    }

    fn attestation_timeout(&self, phase: Phase) -> Duration {
        let config = &self.chain_config;

        self.window_timeout(
            config.attestation_due_bps_at(phase),
            config.aggregate_due_bps_at(phase),
        )
    }

    fn aggregate_timeout(&self, phase: Phase) -> Duration {
        self.window_timeout(self.chain_config.aggregate_due_bps_at(phase), SLOT_END_BPS)
    }

    fn sync_message_timeout(&self, phase: Phase) -> Duration {
        let config = &self.chain_config;

        self.window_timeout(
            config.sync_message_due_bps_at(phase),
            config.contribution_due_bps_at(phase),
        )
    }

    fn contribution_timeout(&self, phase: Phase) -> Duration {
        self.window_timeout(
            self.chain_config.contribution_due_bps_at(phase),
            SLOT_END_BPS,
        )
    }

    /// The vote is cast at the due point, and gossip only accepts it until the slot ends.
    fn payload_attestation_timeout(&self) -> Duration {
        self.window_timeout(self.chain_config.payload_attestation_due_bps, SLOT_END_BPS)
    }

    /// The head is polled without a preset in scope, so the tighter of the two schedules applies.
    fn head_timeout(&self) -> Duration {
        self.sync_message_timeout(Phase::Phase0)
            .min(self.sync_message_timeout(Phase::Gloas))
    }

    fn background_timeout(&self) -> Duration {
        self.slot_fraction_by(BACKGROUND_TIMEOUT_QUOTIENT)
    }

    /// Half the window between the due points, so a failing node leaves the rest for another.
    fn window_timeout(&self, from_bps: u64, until_bps: u64) -> Duration {
        // With no fallback, giving up early buys nothing.
        if self.serving_count.load(Ordering::Relaxed) <= 1 {
            return LONE_NODE_TIMEOUT;
        }

        let window = self
            .chain_config
            .fraction_of_slot(until_bps.saturating_sub(from_bps));

        let nanos = u64::try_from(window.as_nanos())
            .expect("windows are far below u64::MAX nanoseconds")
            / DEADLINE_ATTEMPTS;

        Duration::from_nanos(nanos).max(MIN_TIMEOUT)
    }

    fn slot_fraction_by(&self, quotient: NonZeroU32) -> Duration {
        let nanos = u64::try_from(self.chain_config.slot_duration_ms.as_nanos())
            .expect("slot durations are far below u64::MAX nanoseconds")
            / NonZeroU64::from(quotient);

        Duration::from_nanos(nanos).max(MIN_TIMEOUT)
    }

    pub async fn check_network(&self) -> NetworkCheck {
        match self.ensure_same_network().await {
            Ok(()) => NetworkCheck::Matches,
            Err(error) => {
                if matches!(error.downcast_ref(), Some(Error::NetworkMismatch { .. })) {
                    NetworkCheck::Mismatch(error)
                } else {
                    NetworkCheck::Unreachable(error)
                }
            }
        }
    }

    fn endpoint(&self, path: &str) -> Result<RedactingUrl> {
        self.url.join(path).map_err(Into::into)
    }

    async fn ensure_same_network(&self) -> Result<()> {
        let url = self.endpoint("/eth/v1/beacon/genesis")?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.background_timeout())
            .send()
            .await?;

        let genesis = self.parse_data::<Genesis>(response).await?;
        let expected = self.chain_config.genesis_fork_version;

        // Prevents producing attestations signed under the wrong domain.
        ensure!(
            genesis.genesis_fork_version == expected,
            Error::NetworkMismatch {
                url: self.url.to_string(),
                expected,
                actual: genesis.genesis_fork_version,
            },
        );

        let _ = self
            .genesis_validators_root
            .set(genesis.genesis_validators_root);

        Ok(())
    }

    async fn parse_data<T: DeserializeOwned>(&self, response: Response) -> Result<T> {
        let response = self.check_status(response).await?;
        Ok(response.json::<EthResponse<T>>().await?.into_data())
    }

    async fn parse_versioned_data<T: DeserializeOwned>(
        &self,
        response: Response,
        expected: Phase,
    ) -> Result<T> {
        let response = self.check_status(response).await?;

        let (data, reported) = response
            .json::<EthResponse<T>>()
            .await?
            .into_data_and_version();

        check_version(expected, reported)?;

        Ok(data)
    }

    async fn check_status(&self, response: Response) -> Result<Response> {
        let status = response.status();

        if status.is_success() {
            return Ok(response);
        }

        let body = response.text().await.unwrap_or_default();

        bail!(Error::Response {
            url: self.url.to_string(),
            status,
            body,
        })
    }

    // Epoch-shaped because `getAttesterDuties` is; the built-in node answers per slot instead.
    pub async fn attester_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        let url = self.endpoint(format!("/eth/v1/validator/duties/attester/{epoch}").as_str())?;

        let response = self
            .client
            .post(url.into_url())
            .json(&ValidatorIndices(validator_indices.to_vec()))
            .timeout(self.background_timeout())
            .send()
            .await?;

        let response = self.check_status(response).await?;

        let (duties, dependent_root) = response
            .json::<EthResponse<Vec<ValidatorAttesterDutyResponse>>>()
            .await?
            .into_data_and_dependent_root();

        let dependent_root = dependent_root.ok_or_else(|| {
            AnyhowError::msg(format!(
                "beacon node at {} did not report a dependent root for attester duties",
                self.url,
            ))
        })?;

        debug_with_peers!(
            "{} produced {} attester duties for epoch {epoch}",
            self.url,
            duties.len(),
        );

        Ok(AttesterDuties {
            dependent_root,
            duties,
        })
    }
}

impl<P: Preset> BeaconNodeApi<P> for RemoteBeaconNode {
    async fn liveness(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorLivenessResponse>> {
        let url = self.endpoint(format!("/eth/v1/validator/liveness/{epoch}").as_str())?;

        let response = self
            .client
            .post(url.into_url())
            .json(&ValidatorIndices(validator_indices.to_vec()))
            .timeout(self.background_timeout())
            .send()
            .await?;

        self.parse_data(response).await
    }

    async fn dependent_root(
        &self,
        epoch: Epoch,
        validator_index: Option<ValidatorIndex>,
    ) -> Result<H256> {
        self.attester_duties(epoch, validator_index.as_slice())
            .await
            .map(|duties| duties.dependent_root)
    }

    async fn attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData> {
        let phase = self.chain_config.phase_at_slot::<P>(slot);

        let url = self.endpoint(
            format!(
                "/eth/v1/validator/attestation_data?slot={slot}&committee_index={committee_index}"
            )
            .as_str(),
        )?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.attestation_timeout(phase))
            .send()
            .await?;

        let data = self.parse_data::<AttestationData>(response).await?;

        check_attestation_index(phase, committee_index, data.index)?;

        Ok(data)
    }

    async fn aggregate_attestation(
        &self,
        data: AttestationData,
        committee_index: CommitteeIndex,
    ) -> Result<Attestation<P>> {
        let phase = self.chain_config.phase_at_slot::<P>(data.slot);
        let url = self.endpoint(&aggregate_attestation_path(data, committee_index))?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.aggregate_timeout(phase))
            .send()
            .await?;

        // Electra and Gloas attestations have the same fields, so untagged deserialization would
        // always read a Gloas one as Electra.
        let attestation = if phase < Phase::Electra {
            self.parse_versioned_data::<Phase0Attestation<P>>(response, phase)
                .await
                .map(Attestation::Phase0)?
        } else if phase < Phase::Gloas {
            self.parse_versioned_data::<ElectraAttestation<P>>(response, phase)
                .await
                .map(Attestation::Electra)?
        } else {
            self.parse_versioned_data::<GloasAttestation<P>>(response, phase)
                .await
                .map(Attestation::Gloas)?
        };

        ensure_requested_committee(&attestation, committee_index)?;

        Ok(attestation)
    }

    async fn publish_singular_attestations(
        &self,
        attestations: &[OwnAttestation<P>],
    ) -> Result<()> {
        let Some(first) = attestations.first() else {
            return Ok(());
        };

        let phase = self
            .chain_config
            .phase_at_slot::<P>(first.attestation.data().slot);

        // `combined::Attestation` serializes untagged, so this is a `SingleAttestation` from Electra
        // on and a phase 0 `Attestation` before it, exactly as the endpoint expects.
        let bodies = attestations
            .iter()
            .map(|own_attestation| &own_attestation.attestation)
            .collect::<Vec<_>>();

        let url = self.endpoint("/eth/v2/beacon/pool/attestations")?;

        let response = self
            .client
            .post(url.into_url())
            .header(ETH_CONSENSUS_VERSION, phase.as_ref())
            .json(&bodies)
            .timeout(self.attestation_timeout(phase))
            .send()
            .await?;

        self.check_status(response).await?;

        debug_with_peers!("published {} attestations to {}", bodies.len(), self.url);

        Ok(())
    }

    async fn publish_aggregates_and_proofs(
        &self,
        aggregates_and_proofs: &[Arc<SignedAggregateAndProof<P>>],
    ) -> Result<()> {
        let Some(first) = aggregates_and_proofs.first() else {
            return Ok(());
        };

        let phase = self.chain_config.phase_at_slot::<P>(first.slot());
        let url = self.endpoint("/eth/v2/validator/aggregate_and_proofs")?;

        let response = self
            .client
            .post(url.into_url())
            .header(ETH_CONSENSUS_VERSION, phase.as_ref())
            .json(&aggregates_and_proofs)
            .timeout(self.aggregate_timeout(phase))
            .send()
            .await?;

        self.check_status(response).await?;

        debug_with_peers!(
            "published {} aggregates and proofs to {}",
            aggregates_and_proofs.len(),
            self.url,
        );

        Ok(())
    }

    async fn subscribe_to_beacon_committees(
        &self,
        _current_slot: Slot,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<()> {
        let url = self.endpoint("/eth/v1/validator/beacon_committee_subscriptions")?;

        let response = self
            .client
            .post(url.into_url())
            .json(&subscriptions)
            .timeout(self.background_timeout())
            .send()
            .await?;

        self.check_status(response).await?;

        debug_with_peers!(
            "subscribed to {} beacon committees on {}",
            subscriptions.len(),
            self.url,
        );

        Ok(())
    }

    async fn validator_indices(
        &self,
        public_keys: &[PublicKeyBytes],
    ) -> Result<HashMap<PublicKeyBytes, ValidatorIndex>> {
        let mut indices = HashMap::new();

        // Split up because the whole key set of a large validator client does not belong in a
        // single request body.
        for keys in public_keys.chunks(VALIDATOR_IDS_PER_REQUEST) {
            let url = self.endpoint("/eth/v1/beacon/states/head/validators")?;

            let response = self
                .client
                .post(url.into_url())
                .json(&ValidatorIds { ids: keys })
                .timeout(self.background_timeout())
                .send()
                .await?;

            let validators = self.parse_data::<Vec<StateValidator>>(response).await?;

            indices.extend(
                validators
                    .into_iter()
                    .map(|validator| (validator.validator.pubkey, validator.index)),
            );
        }

        debug_with_peers!(
            "{} resolved {} of {} validator indices",
            self.url,
            indices.len(),
            public_keys.len(),
        );

        Ok(indices)
    }

    async fn slot_head(&self, slot: Slot) -> Result<Option<SlotHead<P>>> {
        let Some(beacon_block_root) = self.chain_head.get(slot, self.max_empty_slots)? else {
            return Ok(None);
        };

        let Some(genesis_validators_root) = self.genesis_validators_root.get().copied() else {
            return Ok(None);
        };

        let epoch = misc::compute_epoch_at_slot::<P>(slot);

        let slot_head = SlotHead {
            config: self.chain_config.clone_arc(),
            slot,
            beacon_block_root,
            fork_info: ForkInfo {
                fork: self.chain_config.fork_at_epoch(epoch),
                genesis_validators_root,
                phantom: PhantomData,
            },
            // Optimistic heads never reach the cache.
            optimistic: false,
        };

        Ok(Some(slot_head))
    }

    async fn sync_committee_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorSyncDutyResponse>> {
        let url = self.endpoint(format!("/eth/v1/validator/duties/sync/{epoch}").as_str())?;

        let response = self
            .client
            .post(url.into_url())
            .json(&ValidatorIndices(validator_indices.to_vec()))
            .timeout(self.background_timeout())
            .send()
            .await?;

        let duties = self
            .parse_data::<Vec<ValidatorSyncDutyResponse>>(response)
            .await?;

        debug_with_peers!(
            "{} produced {} sync committee duties for epoch {epoch}",
            self.url,
            duties.len(),
        );

        Ok(duties)
    }

    async fn publish_sync_committee_messages(
        &self,
        messages: &BTreeMap<SubcommitteeIndex, Vec<SyncCommitteeMessage>>,
    ) -> Result<()> {
        // The endpoint derives the subnets itself, so a validator in several subcommittees is
        // submitted only once.
        let bodies = messages
            .values()
            .flatten()
            .unique_by(|message| message.validator_index)
            .collect::<Vec<_>>();

        let Some(first) = bodies.first() else {
            return Ok(());
        };

        let phase = self.chain_config.phase_at_slot::<P>(first.slot);
        let url = self.endpoint("/eth/v1/beacon/pool/sync_committees")?;

        let response = self
            .client
            .post(url.into_url())
            .json(&bodies)
            .timeout(self.sync_message_timeout(phase))
            .send()
            .await?;

        self.check_status(response).await?;

        debug_with_peers!(
            "published {} sync committee messages to {}",
            bodies.len(),
            self.url,
        );

        Ok(())
    }

    async fn subscribe_to_sync_committees(
        &self,
        _current_epoch: Epoch,
        subscriptions: &[SyncCommitteeSubscription],
    ) -> Result<()> {
        let url = self.endpoint("/eth/v1/validator/sync_committee_subscriptions")?;

        let response = self
            .client
            .post(url.into_url())
            .json(&subscriptions)
            .timeout(self.background_timeout())
            .send()
            .await?;

        self.check_status(response).await?;

        debug_with_peers!(
            "subscribed to {} sync committees on {}",
            subscriptions.len(),
            self.url,
        );

        Ok(())
    }

    async fn sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: SubcommitteeIndex,
        beacon_block_root: H256,
    ) -> Result<SyncCommitteeContribution<P>> {
        let phase = self.chain_config.phase_at_slot::<P>(slot);

        let url = self.endpoint(&sync_committee_contribution_path(
            slot,
            subcommittee_index,
            beacon_block_root,
        ))?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.contribution_timeout(phase))
            .send()
            .await?;

        let contribution = self
            .parse_data::<SyncCommitteeContribution<P>>(response)
            .await?;

        // Signing a mismatched answer would produce a self-inconsistent contribution and proof.
        ensure!(
            contribution.slot == slot
                && contribution.subcommittee_index == subcommittee_index
                && contribution.beacon_block_root == beacon_block_root,
            Error::UnexpectedContribution {
                url: self.url.to_string(),
            },
        );

        Ok(contribution)
    }

    async fn publish_contributions_and_proofs(
        &self,
        contributions_and_proofs: &[SignedContributionAndProof<P>],
    ) -> Result<()> {
        let Some(first) = contributions_and_proofs.first() else {
            return Ok(());
        };

        let phase = self
            .chain_config
            .phase_at_slot::<P>(first.message.contribution.slot);

        let url = self.endpoint("/eth/v1/validator/contribution_and_proofs")?;

        let response = self
            .client
            .post(url.into_url())
            .json(&contributions_and_proofs)
            .timeout(self.contribution_timeout(phase))
            .send()
            .await?;

        self.check_status(response).await?;

        debug_with_peers!(
            "published {} contributions and proofs to {}",
            contributions_and_proofs.len(),
            self.url,
        );

        Ok(())
    }

    async fn ptc_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<PtcDuties> {
        let url = self.endpoint(format!("/eth/v1/validator/duties/ptc/{epoch}").as_str())?;

        let response = self
            .client
            .post(url.into_url())
            .json(&ValidatorIndices(validator_indices.to_vec()))
            .timeout(self.background_timeout())
            .send()
            .await?;

        let response = self.check_status(response).await?;

        let (duties, dependent_root) = response
            .json::<EthResponse<Vec<ValidatorPTCDutyResponse>>>()
            .await?
            .into_data_and_dependent_root();

        let dependent_root = dependent_root.ok_or_else(|| {
            AnyhowError::msg(format!(
                "beacon node at {} did not report a dependent root for PTC duties",
                self.url,
            ))
        })?;

        debug_with_peers!(
            "{} produced {} PTC duties for epoch {epoch}",
            self.url,
            duties.len(),
        );

        Ok(PtcDuties {
            dependent_root,
            duties,
        })
    }

    async fn payload_attestation_data(&self, slot: Slot) -> Result<Option<PayloadAttestationData>> {
        let phase = self.chain_config.phase_at_slot::<P>(slot);
        let url = self.endpoint(&format!(
            "/eth/v1/validator/payload_attestation_data?slot={slot}"
        ))?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.payload_attestation_timeout())
            .send()
            .await?;

        // The endpoint answers with no content when it has seen no block for the slot.
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }

        let data = self
            .parse_versioned_data::<PayloadAttestationData>(response, phase)
            .await?;

        ensure!(
            data.slot == slot,
            Error::UnexpectedPayloadAttestationSlot {
                url: self.url.to_string(),
                expected: slot,
                actual: data.slot,
            },
        );

        Ok(Some(data))
    }

    async fn publish_payload_attestations(
        &self,
        messages: &[Arc<PayloadAttestationMessage>],
    ) -> Result<()> {
        let Some(first) = messages.first() else {
            return Ok(());
        };

        let phase = self.chain_config.phase_at_slot::<P>(first.data.slot);
        let url = self.endpoint("/eth/v1/beacon/pool/payload_attestations")?;

        let response = self
            .client
            .post(url.into_url())
            .header(ETH_CONSENSUS_VERSION, phase.as_ref())
            .json(&messages)
            .timeout(self.payload_attestation_timeout())
            .send()
            .await?;

        self.check_status(response).await?;

        debug_with_peers!(
            "published {} payload attestations to {}",
            messages.len(),
            self.url,
        );

        Ok(())
    }
}

// Before Electra `index` names the committee, so it must be the one requested.
fn check_attestation_index(
    phase: Phase,
    committee_index: CommitteeIndex,
    index: u64,
) -> Result<()> {
    let valid = if phase < Phase::Electra {
        index == committee_index
    } else {
        predicates::is_valid_attestation_data_index(phase, index)
    };

    ensure!(
        valid,
        Error::UnexpectedAttestationIndex {
            phase,
            committee_index,
            index,
        },
    );

    Ok(())
}

fn ensure_requested_committee<P: Preset>(
    attestation: &Attestation<P>,
    committee_index: CommitteeIndex,
) -> Result<()> {
    let Some(committee_bits) = attestation.committee_bits() else {
        return Ok(());
    };

    // Aggregation bits from Electra on span every committee in `committee_bits`, so a position
    // in the requested committee only indexes them when that is the sole committee covered.
    let actual = misc::get_committee_indices::<P>(committee_bits).collect::<Vec<_>>();

    ensure!(
        actual == [committee_index],
        Error::UnexpectedCommittees {
            expected: committee_index,
            actual,
        },
    );

    Ok(())
}

fn check_not_optimistic(url: &RedactingUrl, execution_optimistic: Option<bool>) -> Result<()> {
    match execution_optimistic {
        Some(false) => Ok(()),
        Some(true) => bail!(Error::OptimisticHead {
            url: url.to_string(),
        }),
        // Not saying is not the same as saying no, and an optimistic validator must not sign
        // across the sync committee domains.
        None => bail!(Error::UnknownOptimisticStatus {
            url: url.to_string(),
        }),
    }
}

fn check_version(expected: Phase, reported: Option<Phase>) -> Result<()> {
    if let Some(reported) = reported {
        ensure!(
            reported == expected,
            Error::UnexpectedVersion { expected, reported },
        );
    }

    Ok(())
}

fn aggregate_attestation_path(data: AttestationData, committee_index: CommitteeIndex) -> String {
    format!(
        "/eth/v2/validator/aggregate_attestation?attestation_data_root={:?}\
         &slot={}&committee_index={committee_index}",
        data.hash_tree_root(),
        data.slot,
    )
}

fn sync_committee_contribution_path(
    slot: Slot,
    subcommittee_index: SubcommitteeIndex,
    beacon_block_root: H256,
) -> String {
    format!(
        "/eth/v1/validator/sync_committee_contribution?slot={slot}\
         &subcommittee_index={subcommittee_index}&beacon_block_root={beacon_block_root:?}",
    )
}

#[cfg(test)]
mod tests {
    use bls::{
        AggregateSignatureBytes, PublicKeyBytes, SignatureBytes, traits::SignatureBytes as _,
    };
    use serde_json::json;
    use ssz::BitVector;
    use types::{
        combined::Attestation,
        electra::containers::{
            AggregateAndProof as ElectraAggregateAndProof, Attestation as ElectraAttestation,
            SignedAggregateAndProof as ElectraSignedAggregateAndProof, SingleAttestation,
        },
        phase0::primitives::H256,
        preset::Mainnet,
    };

    use super::*;

    // The endpoint takes a bare array of quoted validator indices.
    #[test]
    fn serializes_attester_duties_request_body() -> Result<()> {
        let body = serde_json::to_value(ValidatorIndices(vec![1, 2]))?;

        assert_eq!(body, json!(["1", "2"]));

        Ok(())
    }

    // The dependent root lives in the response envelope rather than the duties themselves.
    #[test]
    fn parses_attester_duties_response() -> Result<()> {
        let response = json!({
            "dependent_root":
                "0x0404040404040404040404040404040404040404040404040404040404040404",
            "execution_optimistic": false,
            "data": [{
                "pubkey": PublicKeyBytes::zero(),
                "validator_index": "1",
                "committee_index": "2",
                "committee_length": "3",
                "committees_at_slot": "4",
                "validator_committee_index": "5",
                "slot": "6",
            }],
        });

        let (duties, dependent_root) =
            serde_json::from_value::<EthResponse<Vec<ValidatorAttesterDutyResponse>>>(response)?
                .into_data_and_dependent_root();

        assert_eq!(dependent_root, Some(H256::repeat_byte(4)));

        assert_eq!(
            duties,
            [ValidatorAttesterDutyResponse {
                committee_index: 2,
                committee_length: 3,
                committees_at_slot: 4,
                pubkey: PublicKeyBytes::zero(),
                slot: 6,
                validator_committee_index: 5,
                validator_index: 1,
            }],
        );

        Ok(())
    }

    // PTC duties carry a dependent root in the envelope like attester duties do.
    #[test]
    fn parses_ptc_duties_response() -> Result<()> {
        let response = json!({
            "dependent_root":
                "0x0404040404040404040404040404040404040404040404040404040404040404",
            "execution_optimistic": false,
            "data": [{
                "pubkey": PublicKeyBytes::zero(),
                "validator_index": "1",
                "slot": "6",
            }],
        });

        let (duties, dependent_root) =
            serde_json::from_value::<EthResponse<Vec<ValidatorPTCDutyResponse>>>(response)?
                .into_data_and_dependent_root();

        assert_eq!(dependent_root, Some(H256::repeat_byte(4)));

        assert_eq!(
            duties,
            [ValidatorPTCDutyResponse {
                pubkey: PublicKeyBytes::zero(),
                validator_index: 1,
                slot: 6,
            }],
        );

        Ok(())
    }

    #[test]
    fn parses_payload_attestation_data_response() -> Result<()> {
        let response = json!({
            "version": "gloas",
            "data": {
                "beacon_block_root":
                    "0x0101010101010101010101010101010101010101010101010101010101010101",
                "slot": "6",
                "payload_present": true,
                "blob_data_available": false,
            },
        });

        let (data, version) =
            serde_json::from_value::<EthResponse<PayloadAttestationData>>(response)?
                .into_data_and_version();

        assert_eq!(version, Some(Phase::Gloas));

        assert_eq!(
            data,
            PayloadAttestationData {
                beacon_block_root: H256::repeat_byte(1),
                slot: 6,
                payload_present: true,
                blob_data_available: false,
            },
        );

        Ok(())
    }

    // The publication body is a bare array of messages, not `Arc`-wrapped ones.
    #[test]
    fn serializes_payload_attestation_message_body() -> Result<()> {
        let message = Arc::new(PayloadAttestationMessage {
            validator_index: 1,
            data: PayloadAttestationData {
                beacon_block_root: H256::repeat_byte(1),
                slot: 6,
                payload_present: true,
                blob_data_available: true,
            },
            signature: SignatureBytes::empty(),
        });

        let body = serde_json::to_value([message])?;

        assert_eq!(
            body,
            json!([{
                "validator_index": "1",
                "data": {
                    "beacon_block_root":
                        "0x0101010101010101010101010101010101010101010101010101010101010101",
                    "slot": "6",
                    "payload_present": true,
                    "blob_data_available": true,
                },
                "signature": SignatureBytes::empty(),
            }]),
        );

        Ok(())
    }

    #[test]
    fn parses_head_v2_event() -> Result<()> {
        let data = json!({
            "version": "gloas",
            "data": {
                "slot": "70",
                "block": "0x0101010101010101010101010101010101010101010101010101010101010101",
                "state": "0x0202020202020202020202020202020202020202020202020202020202020202",
                "payload_status": "full",
                "epoch_transition": false,
                "current_epoch_dependent_root":
                    "0x0303030303030303030303030303030303030303030303030303030303030303",
                "next_epoch_dependent_root":
                    "0x0404040404040404040404040404040404040404040404040404040404040404",
                "execution_optimistic": false,
            },
        });

        let update = AnyHeadEvent::parse::<Mainnet>(&data.to_string())?;

        assert_eq!(update.slot, 70);
        assert_eq!(update.block, H256::repeat_byte(1));
        assert!(!update.execution_optimistic);
        assert_eq!(
            update.dependent_roots,
            DependentRoots {
                epoch: 2,
                current: H256::repeat_byte(3),
                next: H256::repeat_byte(4),
            },
        );

        Ok(())
    }

    // The deprecated event names the roots by duty period, which reads backwards.
    #[test]
    fn parses_head_event_with_roots_renamed() -> Result<()> {
        let data = json!({
            "slot": "70",
            "block": "0x0101010101010101010101010101010101010101010101010101010101010101",
            "state": "0x0202020202020202020202020202020202020202020202020202020202020202",
            "epoch_transition": false,
            "previous_duty_dependent_root":
                "0x0303030303030303030303030303030303030303030303030303030303030303",
            "current_duty_dependent_root":
                "0x0404040404040404040404040404040404040404040404040404040404040404",
            "execution_optimistic": true,
        });

        let update = AnyHeadEvent::parse::<Mainnet>(&data.to_string())?;

        assert!(update.execution_optimistic);
        assert_eq!(
            update.dependent_roots,
            DependentRoots {
                epoch: 2,
                current: H256::repeat_byte(3),
                next: H256::repeat_byte(4),
            },
        );

        Ok(())
    }

    #[test]
    fn attestation_index_names_the_committee_before_electra() -> Result<()> {
        check_attestation_index(Phase::Deneb, 3, 3)?;
        check_attestation_index(Phase::Deneb, 3, 0).expect_err("index 0 is not committee 3");

        Ok(())
    }

    #[test]
    fn attestation_index_is_checked_against_the_phase_from_electra_on() -> Result<()> {
        check_attestation_index(Phase::Electra, 3, 0)?;
        check_attestation_index(Phase::Gloas, 3, 1)?;
        check_attestation_index(Phase::Fulu, 3, 3).expect_err("index is unused until Gloas");
        check_attestation_index(Phase::Gloas, 3, 2).expect_err("the payload vote is 0 or 1");

        Ok(())
    }

    // The head's true slot lives in the header, so a stale head is cached as stale.
    #[test]
    fn parses_block_header_response() -> Result<()> {
        let response = json!({
            "execution_optimistic": false,
            "finalized": false,
            "data": {
                "root": H256::repeat_byte(1),
                "canonical": true,
                "header": {
                    "message": {
                        "slot": "6",
                        "proposer_index": "2",
                        "parent_root": H256::repeat_byte(3),
                        "state_root": H256::repeat_byte(4),
                        "body_root": H256::repeat_byte(5),
                    },
                    "signature": SignatureBytes::empty(),
                },
            },
        });

        let (block_header, execution_optimistic) =
            serde_json::from_value::<EthResponse<BlockHeadersResponse>>(response)?
                .into_data_and_execution_optimistic();

        assert_eq!(execution_optimistic, Some(false));
        assert_eq!(block_header.root, H256::repeat_byte(1));
        assert_eq!(block_header.header.message.slot, 6);

        Ok(())
    }

    fn test_node(
        chain_config: ChainConfig,
        url: &str,
        serving_count: usize,
    ) -> Result<RemoteBeaconNode> {
        Ok(RemoteBeaconNode::new(
            Arc::new(chain_config),
            Client::new(),
            url.parse()?,
            32,
            Arc::new(AtomicUsize::new(serving_count)),
        ))
    }

    // The node names itself by URL, so logging it must not leak credentials.
    #[test]
    fn display_is_the_redacted_url() -> Result<()> {
        let node = test_node(
            ChainConfig::mainnet(),
            "http://user:password@localhost:5052/",
            1,
        )?;

        assert_eq!(node.to_string(), "http://*:*@localhost:5052/");

        Ok(())
    }

    // A deadline-bound request may use half its window, leaving the rest for another node.
    #[test]
    fn timeouts_follow_the_due_points_of_the_phase() -> Result<()> {
        let node = test_node(ChainConfig::mainnet(), "http://localhost:5052/", 2)?;

        // The pre-Gloas windows of the mainnet configuration are 3334 and 3333 basis points.
        assert_eq!(
            node.attestation_timeout(Phase::Electra),
            Duration::from_micros(2_000_400),
        );
        assert_eq!(
            node.aggregate_timeout(Phase::Electra),
            Duration::from_micros(1_999_800),
        );
        assert_eq!(
            node.attestation_timeout(Phase::Gloas),
            Duration::from_millis(1500),
        );
        assert_eq!(node.aggregate_timeout(Phase::Gloas), Duration::from_secs(3));
        assert_eq!(node.head_timeout(), Duration::from_millis(1500));
        assert_eq!(node.background_timeout(), Duration::from_secs(6));

        Ok(())
    }

    // Short slots must not shrink timeouts below what real networks can answer within.
    #[test]
    fn timeouts_do_not_fall_below_the_minimum() -> Result<()> {
        let config = ChainConfig {
            slot_duration_ms: Duration::from_secs(2),
            ..ChainConfig::mainnet()
        };

        let node = test_node(config, "http://localhost:5052/", 2)?;

        assert_eq!(node.attestation_timeout(Phase::Electra), MIN_TIMEOUT);
        assert_eq!(node.background_timeout(), MIN_TIMEOUT);

        Ok(())
    }

    // With no fallback there is no reason to give up early.
    #[test]
    fn a_lone_serving_node_gets_the_generous_timeout() -> Result<()> {
        let node = test_node(ChainConfig::mainnet(), "http://localhost:5052/", 1)?;

        assert_eq!(node.attestation_timeout(Phase::Electra), LONE_NODE_TIMEOUT);
        assert_eq!(node.aggregate_timeout(Phase::Gloas), LONE_NODE_TIMEOUT);

        Ok(())
    }

    #[test]
    fn parses_genesis_response() -> Result<()> {
        let response = json!({
            "data": {
                "genesis_time": "1590832934",
                "genesis_validators_root":
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                "genesis_fork_version": "0x00000001",
            },
        });

        let data = serde_json::from_value::<EthResponse<Genesis>>(response)?.into_data();

        assert_eq!(data.genesis_fork_version, Version::from([0, 0, 0, 1]));

        Ok(())
    }

    #[test]
    fn parses_attestation_data_response() -> Result<()> {
        let response = json!({
            "data": {
                "slot": "1",
                "index": "1",
                "beacon_block_root":
                    "0x0101010101010101010101010101010101010101010101010101010101010101",
                "source": {
                    "epoch": "2",
                    "root": "0x0202020202020202020202020202020202020202020202020202020202020202",
                },
                "target": {
                    "epoch": "3",
                    "root": "0x0303030303030303030303030303030303030303030303030303030303030303",
                },
            },
        });

        let data = serde_json::from_value::<EthResponse<AttestationData>>(response)?.into_data();

        assert_eq!(data.slot, 1);
        assert_eq!(data.index, 1);
        assert_eq!(data.beacon_block_root, H256::repeat_byte(1));
        assert_eq!(data.source.epoch, 2);
        assert_eq!(data.target.epoch, 3);

        Ok(())
    }

    // The publication body is the bare attestation, not an enveloped or tagged one.
    #[test]
    fn serializes_single_attestation_body() -> Result<()> {
        let attestation = Attestation::<Mainnet>::from(SingleAttestation {
            committee_index: 4,
            attester_index: 5,
            data: AttestationData::default(),
            signature: SignatureBytes::empty(),
        });

        let body = serde_json::to_value([&attestation])?;

        assert_eq!(body[0]["committee_index"], json!("4"));
        assert_eq!(body[0]["attester_index"], json!("5"));
        assert_eq!(body[0]["data"]["slot"], json!("0"));

        Ok(())
    }

    fn electra_aggregate_body() -> serde_json::Value {
        json!({
            "aggregation_bits": "0x07",
            "data": {
                "slot": "6",
                "index": "0",
                "beacon_block_root": H256::zero(),
                "source": { "epoch": "0", "root": H256::zero() },
                "target": { "epoch": "0", "root": H256::zero() },
            },
            "signature": AggregateSignatureBytes::empty(),
            "committee_bits": "0x0100000000000000",
        })
    }

    // Why `aggregate_attestation` parses by phase instead of letting serde choose: Electra and
    // Gloas attestations have the same fields, so an untagged read of either yields Electra.
    #[test]
    fn a_gloas_attestation_is_untagged_as_electra() -> Result<()> {
        let attestation = serde_json::from_value::<Attestation<Mainnet>>(electra_aggregate_body())?;

        assert!(matches!(attestation, Attestation::Electra(_)));

        Ok(())
    }

    // The phases that `deny_unknown_fields` does separate stay separated.
    #[test]
    fn an_electra_aggregate_is_not_a_phase0_one() -> Result<()> {
        let body = electra_aggregate_body();

        serde_json::from_value::<ElectraAttestation<Mainnet>>(body.clone())?;
        serde_json::from_value::<GloasAttestation<Mainnet>>(body.clone())?;

        serde_json::from_value::<Phase0Attestation<Mainnet>>(body)
            .expect_err("committee bits should not fit a phase 0 attestation");

        Ok(())
    }

    // Reading a position in the requested committee against bits covering other committees would
    // silently pick the wrong validator.
    #[test]
    fn rejects_an_aggregate_covering_other_committees() -> Result<()> {
        let aggregate = |indices: &[usize]| {
            let mut committee_bits = BitVector::default();

            for index in indices {
                committee_bits.set(*index, true);
            }

            Attestation::<Mainnet>::Electra(ElectraAttestation {
                committee_bits,
                ..ElectraAttestation::default()
            })
        };

        ensure_requested_committee(&aggregate(&[3]), 3)?;

        ensure_requested_committee(&aggregate(&[2]), 3)
            .expect_err("an aggregate for another committee should be rejected");

        ensure_requested_committee(&aggregate(&[2, 3]), 3)
            .expect_err("an aggregate covering several committees should be rejected");

        ensure_requested_committee(&aggregate(&[]), 3)
            .expect_err("an aggregate covering no committee should be rejected");

        Ok(())
    }

    // A phase 0 aggregate has no committee bits; its committee is fixed by the data root.
    #[test]
    fn accepts_a_phase0_aggregate() -> Result<()> {
        let aggregate = Attestation::<Mainnet>::Phase0(Phase0Attestation::default());

        ensure_requested_committee(&aggregate, 3)
    }

    // A node that reports no version is taken at its word; one that disagrees is not.
    #[test]
    fn check_version_rejects_only_a_disagreeing_node() -> Result<()> {
        check_version(Phase::Electra, None)?;
        check_version(Phase::Electra, Some(Phase::Electra))?;

        check_version(Phase::Electra, Some(Phase::Gloas))
            .expect_err("a node reporting another phase should be rejected");

        Ok(())
    }

    // Signing across the sync committee domains requires a head the node has verified.
    #[test]
    fn check_not_optimistic_accepts_only_a_verified_head() -> Result<()> {
        let url = "http://localhost:5052/".parse()?;

        check_not_optimistic(&url, Some(false))?;
        check_not_optimistic(&url, Some(true)).expect_err("an optimistic head is not verified");
        check_not_optimistic(&url, None).expect_err("an unreported head is not verified");

        Ok(())
    }

    // The root goes into the query in full; `Display` would abbreviate it.
    #[test]
    fn aggregate_attestation_path_spells_out_the_root() {
        let data = AttestationData {
            slot: 6,
            ..AttestationData::default()
        };

        let path = aggregate_attestation_path(data, 3);

        let root = path
            .split("attestation_data_root=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .expect("path contains the attestation data root");

        assert!(root.starts_with("0x"));
        assert_eq!(root.len(), 66);
        assert!(path.ends_with("&slot=6&committee_index=3"));
    }

    // The root goes into the query in full, for the same reason.
    #[test]
    fn sync_committee_contribution_path_spells_out_the_root() {
        let path = sync_committee_contribution_path(6, 3, H256::repeat_byte(1));

        assert_eq!(
            path,
            "/eth/v1/validator/sync_committee_contribution?slot=6&subcommittee_index=3\
             &beacon_block_root=0x0101010101010101010101010101010101010101010101010101010101010101",
        );
    }

    // The publication body is the bare aggregate and proof, not an `Arc`-wrapped one.
    #[test]
    fn serializes_aggregate_and_proof_body() -> Result<()> {
        let aggregate_and_proof = Arc::new(SignedAggregateAndProof::<Mainnet>::from(
            ElectraSignedAggregateAndProof {
                message: ElectraAggregateAndProof {
                    aggregator_index: 6,
                    aggregate: ElectraAttestation::default(),
                    selection_proof: SignatureBytes::empty(),
                },
                signature: SignatureBytes::empty(),
            },
        ));

        let body = serde_json::to_value([&aggregate_and_proof])?;

        assert_eq!(body[0]["message"]["aggregator_index"], json!("6"));
        assert_eq!(body[0]["message"]["aggregate"]["data"]["slot"], json!("0"));

        Ok(())
    }

    // The endpoint takes a bare array of subscriptions with quoted numbers.
    #[test]
    fn serializes_beacon_committee_subscription_body() -> Result<()> {
        let body = serde_json::to_value([BeaconCommitteeSubscription {
            validator_index: 1,
            committee_index: 2,
            committees_at_slot: 3,
            slot: 4,
            is_aggregator: true,
        }])?;

        assert_eq!(body[0]["validator_index"], json!("1"));
        assert_eq!(body[0]["committee_index"], json!("2"));
        assert_eq!(body[0]["committees_at_slot"], json!("3"));
        assert_eq!(body[0]["slot"], json!("4"));
        assert_eq!(body[0]["is_aggregator"], json!(true));

        Ok(())
    }
}
