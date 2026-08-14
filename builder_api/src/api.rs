use core::time::Duration;
use std::{sync::Arc, time::SystemTime};

use anyhow::{Result, bail, ensure};
use arc_swap::ArcSwap;
use bls::PublicKeyBytes;
use helper_functions::{misc, signing::SignForAllForks};
use http_api_utils::ETH_CONSENSUS_VERSION;
use itertools::Itertools as _;
use logging::{debug_with_peers, info_with_peers};
use mime::{APPLICATION_JSON, APPLICATION_OCTET_STREAM};
use prometheus_metrics::Metrics;
use pubkey_cache::PubkeyCache;
use reqwest::{
    Client, Response, StatusCode,
    header::{ACCEPT, CONTENT_TYPE, HeaderValue},
};
use serde::de::DeserializeOwned;
use ssz::{ContiguousList, SszHash as _, SszRead, SszWrite as _};
use thiserror::Error;
use typenum::Unsigned as _;
use types::{
    combined::{ExecutionPayload, SignedBeaconBlock, SignedBlindedBeaconBlock},
    config::Config as ChainConfig,
    gloas::containers::SignedExecutionPayloadBid,
    nonstandard::{Phase, WithBlobsAndMev},
    phase0::{
        consts::GENESIS_SLOT,
        primitives::{ExecutionBlockHash, H256, Slot, UnixSeconds},
    },
    preset::Preset,
    redacting_url::RedactingUrl,
    traits::SignedBeaconBlock as _,
};

use crate::{
    BuilderApiFormat, BuilderConfig,
    combined::{ExecutionPayloadAndBlobsBundle, GetExecutionPayloadBidResponse, SignedBuilderBid},
    consts::BUILDER_PROPOSAL_DELAY_TOLERANCE,
    gloas::containers::{BuilderPreferencesRequest, SignedRequestAuth},
    unphased::containers::SignedValidatorRegistrationV1,
};

const DATE_MS_HEADER: &str = "Date-Milliseconds";
const X_TIMEOUT_MS_HEADER: &str = "X-Timeout-Ms";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(BUILDER_PROPOSAL_DELAY_TOLERANCE);

#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum BuilderApiError {
    #[error("request auth slot ({auth_slot}) has already passed (current slot: {current_slot})")]
    AuthSlotAlreadyPassed { auth_slot: Slot, current_slot: Slot },
    #[error(
        "request auth slot ({auth_slot}) does not match execution payload bid path slot ({path_slot})"
    )]
    AuthSlotMismatch { auth_slot: Slot, path_slot: Slot },
    #[error("bad request to Builder API (builder node response: {message})")]
    BadRequest { message: String },
    #[error(
        "execution payload bid parent_block_hash ({bid_parent_hash:?}) does not match request parent_hash ({request_parent_hash:?})"
    )]
    BidParentHashMismatch {
        bid_parent_hash: ExecutionBlockHash,
        request_parent_hash: ExecutionBlockHash,
    },
    #[error(
        "execution payload bid parent_block_root ({bid_parent_root:?}) does not match request parent_root ({request_parent_root:?})"
    )]
    BidParentRootMismatch {
        bid_parent_root: H256,
        request_parent_root: H256,
    },
    #[error("execution payload bid slot ({bid_slot}) does not match request slot ({request_slot})")]
    BidSlotMismatch { bid_slot: Slot, request_slot: Slot },
    #[error("builder node internal error (builder node response: {message})")]
    BuilderNodeInternalError { message: String },
    #[error("{missing_blocks} consecutive missing blocks since head")]
    ConsecutiveMissingBlocks { missing_blocks: u64 },
    #[error("{missing_blocks} missing blocks in the last rolling epoch")]
    RollingEpochMissingBlocks { missing_blocks: u64 },
    #[error("Builder API is applicable from Gloas onwards (phase: {phase})")]
    PhaseBeforeGloas { phase: Phase },
    #[error(
        "execution payload root ({payload_root:?}) does not match header root ({header_root:?})"
    )]
    RootMismatch {
        header_root: H256,
        payload_root: H256,
    },
    #[error("received unexpected status code: {received}, expected: {expected}")]
    UnexpectedStatusCode {
        expected: StatusCode,
        received: StatusCode,
    },
    #[error("received response with unsupported content-type: {content_type:?}")]
    UnsupportedContentType { content_type: Option<HeaderValue> },
    #[error(
        "Builder API responded with incorrect version \
         (computed: {computed}, response: {in_response})"
    )]
    VersionMismatch { computed: Phase, in_response: Phase },
}

pub struct Api {
    config: BuilderConfig,
    pubkey_cache: Arc<PubkeyCache>,
    client: Client,
    metrics: Option<Arc<Metrics>>,
    supports_block_ssz: ArcSwap<Option<bool>>,
    supports_validators_ssz: ArcSwap<Option<bool>>,
}

impl Api {
    #[must_use]
    pub fn new(
        config: BuilderConfig,
        pubkey_cache: Arc<PubkeyCache>,
        client: Client,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self {
            config,
            pubkey_cache,
            client,
            metrics,
            supports_block_ssz: ArcSwap::from_pointee(None),
            supports_validators_ssz: ArcSwap::from_pointee(None),
        }
    }

    #[expect(
        clippy::unnecessary_min_or_max,
        reason = "GENESIS_SLOT const might be adjusted independently."
    )]
    pub fn can_use_builder_api<P: Preset>(
        &self,
        slot: Slot,
        nonempty_slots: impl IntoIterator<Item = Slot>,
    ) -> Result<(), BuilderApiError> {
        if self.config.builder_disable_checks {
            return Ok(());
        }

        let mut nonempty_slots = nonempty_slots.into_iter().peekable();

        let end_slot = misc::previous_slot(slot);
        let head_slot = nonempty_slots.peek().copied().unwrap_or(GENESIS_SLOT);

        // check for missed blocks from head
        let mut missing_blocks = end_slot.saturating_sub(head_slot);

        if missing_blocks > self.config.builder_max_skipped_slots {
            return Err(BuilderApiError::ConsecutiveMissingBlocks { missing_blocks });
        }

        // check last rolling epoch for missed blocks
        let start_slot = end_slot
            .saturating_sub(P::SlotsPerEpoch::U64)
            .max(GENESIS_SLOT);

        missing_blocks = missing_blocks.saturating_add(
            nonempty_slots
                .take_while(|slot| *slot > start_slot)
                .chain(core::iter::once(start_slot))
                .tuple_windows()
                .map(|(slot, parent_slot)| {
                    slot.abs_diff(parent_slot.max(start_slot)).saturating_sub(1)
                })
                .sum::<u64>(),
        );

        if missing_blocks > self.config.builder_max_skipped_slots_per_epoch {
            return Err(BuilderApiError::RollingEpochMissingBlocks { missing_blocks });
        }

        Ok(())
    }

    pub async fn register_validators<P: Preset>(
        &self,
        validator_registrations: ContiguousList<
            SignedValidatorRegistrationV1,
            P::ValidatorRegistryLimit,
        >,
    ) -> Result<()> {
        let _timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.builder_register_validator_times.start_timer());

        let use_json = self.config.builder_api_format == BuilderApiFormat::Json
            || self
                .supports_validators_ssz
                .load()
                .is_some_and(|supported| !supported);

        let response = self
            .post_validators::<P>(&validator_registrations, use_json)
            .await;

        // See <https://github.com/ethereum/builder-specs/pull/110>
        if use_json {
            response
        } else {
            match response {
                Ok(()) => {
                    self.supports_validators_ssz.store(Arc::new(Some(true)));
                    Ok(())
                }
                Err(error) => {
                    debug_with_peers!(
                        "received error in non-JSON register validators request: {error:?}, \
                         retrying in JSON"
                    );

                    self.supports_validators_ssz.store(Arc::new(Some(false)));
                    self.post_validators::<P>(&validator_registrations, true)
                        .await
                }
            }
        }
    }

    async fn post_validators<P: Preset>(
        &self,
        validator_registrations: &ContiguousList<
            SignedValidatorRegistrationV1,
            P::ValidatorRegistryLimit,
        >,
        use_json: bool,
    ) -> Result<()> {
        debug_with_peers!(
            "registering validators: {validator_registrations:?}, use_json: {use_json}"
        );

        let url = self.url("/eth/v1/builder/validators")?;
        let request = self.client.post(url.into_url());

        let request = if use_json {
            request.json(validator_registrations)
        } else {
            request
                .header(ACCEPT, APPLICATION_OCTET_STREAM.as_ref())
                .header(CONTENT_TYPE, APPLICATION_OCTET_STREAM.as_ref())
                .body(validator_registrations.to_ssz()?)
        };

        let response = request.send().await?;
        let response = handle_error(response).await?;

        debug_with_peers!("register_validators response: {response:?}");

        Ok(())
    }

    pub async fn get_execution_payload_header<P: Preset>(
        &self,
        chain_config: &ChainConfig,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        pubkey: PublicKeyBytes,
    ) -> Result<Option<SignedBuilderBid<P>>> {
        let _timer = self.metrics.as_ref().map(|metrics| {
            metrics
                .builder_get_execution_payload_header_times
                .start_timer()
        });

        let url = self.url(&format!(
            "/eth/v1/builder/header/{slot}/{parent_hash:?}/{pubkey:?}"
        ))?;

        let use_json = self.config.builder_api_format == BuilderApiFormat::Json;

        debug_with_peers!("getting execution payload header from {url}, use_json: {use_json}");

        let request = self.client.get(url.into_url()).timeout(REQUEST_TIMEOUT);

        // See <https://github.com/ethereum/builder-specs/pull/104>
        let request = if use_json {
            request.header(ACCEPT, APPLICATION_JSON.as_ref())
        } else {
            request.header(
                ACCEPT,
                format!("{APPLICATION_OCTET_STREAM};q=1,{APPLICATION_JSON};q=0.9"),
            )
        };

        let request = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(timestamp) => request.header(DATE_MS_HEADER, format!("{}", timestamp.as_millis())),
            Err(error) => {
                debug_with_peers!("unable to calculate timestamp: {error:?}");
                request
            }
        };

        let response = request.send().await?;
        let response = handle_error(response).await?;

        if response.status() == StatusCode::NO_CONTENT {
            info_with_peers!("builder has no execution payload header available for slot {slot}");
            return Ok(None);
        }

        let builder_bid = self.parse_response::<SignedBuilderBid<P>>(response).await?;

        debug_with_peers!("get_execution_payload_header response: {builder_bid:?}");

        validate_phase(chain_config.phase_at_slot::<P>(slot), builder_bid.phase())?;

        let signature = builder_bid.signature();
        let public_key = self.pubkey_cache.get_or_insert(builder_bid.pubkey())?;

        match &builder_bid {
            SignedBuilderBid::Bellatrix(builder_bid) => {
                builder_bid
                    .message
                    .verify(chain_config, signature, public_key)?
            }
            SignedBuilderBid::Capella(builder_bid) => {
                builder_bid
                    .message
                    .verify(chain_config, signature, public_key)?
            }
            SignedBuilderBid::Deneb(builder_bid) => {
                builder_bid
                    .message
                    .verify(chain_config, signature, public_key)?
            }
            SignedBuilderBid::Electra(builder_bid) => {
                builder_bid
                    .message
                    .verify(chain_config, signature, public_key)?
            }
            SignedBuilderBid::Fulu(builder_bid) => {
                builder_bid
                    .message
                    .verify(chain_config, signature, public_key)?
            }
        }

        info_with_peers!("received execution payload header from builder for slot {slot}");

        Ok(Some(builder_bid))
    }

    pub async fn post_blinded_block<P: Preset>(
        &self,
        chain_config: &ChainConfig,
        genesis_time: UnixSeconds,
        block: &SignedBlindedBeaconBlock<P>,
    ) -> Result<WithBlobsAndMev<ExecutionPayload<P>, P>> {
        let _timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.builder_post_blinded_block_times.start_timer());

        let url = self.url("/eth/v1/builder/blinded_blocks")?;

        let (next_interval, remaining_time) =
            clock::next_interval_with_remaining_time::<P>(chain_config, genesis_time)?;

        let use_json = self.config.builder_api_format == BuilderApiFormat::Json
            || self
                .supports_block_ssz
                .load()
                .is_some_and(|supported| !supported);

        debug_with_peers!(
            "posting blinded block to {url} with timeout of {remaining_time:?} \
             before next interval {next_interval:?}, use_json: {use_json}",
        );

        let block_root = block.message().hash_tree_root();
        let slot = block.message().slot();

        let request = self
            .client
            .post(url.into_url())
            .timeout(remaining_time)
            .header(ETH_CONSENSUS_VERSION, block.phase().as_ref());

        let request = if use_json {
            request.json(block)
        } else {
            request
                .header(ACCEPT, APPLICATION_OCTET_STREAM.as_ref())
                .header(CONTENT_TYPE, APPLICATION_OCTET_STREAM.as_ref())
                .body(block.to_ssz()?)
        };

        let response = request.send().await?;
        let response = handle_error(response).await?;

        let response: WithBlobsAndMev<ExecutionPayload<P>, P> = self
            .parse_response::<ExecutionPayloadAndBlobsBundle<P>>(response)
            .await?
            .into();

        let execution_payload = &response.value;

        debug_with_peers!("post_blinded_block response: {execution_payload:?}");

        ensure!(
            execution_payload.is_valid_with(block.phase()),
            BuilderApiError::VersionMismatch {
                computed: block.phase(),
                in_response: execution_payload.phase(),
            },
        );

        let header_root = block.execution_payload_header().hash_tree_root();
        let payload_root = execution_payload.hash_tree_root();

        ensure!(
            payload_root == header_root,
            BuilderApiError::RootMismatch {
                header_root,
                payload_root,
            },
        );

        info_with_peers!(
            "received execution payload from builder for block {block_root:?} at slot {slot}"
        );

        Ok(response)
    }

    pub async fn post_blinded_block_post_fulu<P: Preset>(
        &self,
        chain_config: &ChainConfig,
        genesis_time: UnixSeconds,
        block: &SignedBlindedBeaconBlock<P>,
    ) -> Result<()> {
        let _timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.builder_post_blinded_block_times.start_timer());

        let url = self.url("/eth/v2/builder/blinded_blocks")?;

        let (next_interval, remaining_time) =
            clock::next_interval_with_remaining_time::<P>(chain_config, genesis_time)?;

        let use_json = self.config.builder_api_format == BuilderApiFormat::Json
            || self
                .supports_block_ssz
                .load()
                .is_some_and(|supported| !supported);

        debug_with_peers!(
            "posting blinded block to {url} with timeout of {remaining_time:?} \
             before next interval {next_interval:?}, use_json: {use_json}",
        );

        let block_root = block.message().hash_tree_root();
        let slot = block.message().slot();

        let request = self
            .client
            .post(url.into_url())
            .timeout(remaining_time)
            .header(ETH_CONSENSUS_VERSION, block.phase().as_ref());

        let request = if use_json {
            request.json(block)
        } else {
            request
                .header(ACCEPT, APPLICATION_OCTET_STREAM.as_ref())
                .header(CONTENT_TYPE, APPLICATION_OCTET_STREAM.as_ref())
                .body(block.to_ssz()?)
        };

        let response = request.send().await?;
        let response = handle_error(response).await?;

        if response.status() == StatusCode::ACCEPTED {
            info_with_peers!(
                "received successful response from builder for block {block_root:?} at slot {slot}"
            );

            return Ok(());
        }

        bail!(BuilderApiError::UnexpectedStatusCode {
            expected: StatusCode::ACCEPTED,
            received: response.status()
        })
    }

    // Full bid validation (signature, builder eligibility, etc.) is deferred to the caller; it
    // needs beacon state. See
    // <https://github.com/ethereum/builder-specs/blob/main/specs/gloas/validator.md#validating-a-signedexecutionpayloadbid>.
    // Request slot / parent_hash / parent_root consistency is checked below.
    pub async fn get_execution_payload_bid<P: Preset>(
        &self,
        chain_config: &ChainConfig,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        parent_root: H256,
        pubkey: PublicKeyBytes,
        signed_request_auth: &SignedRequestAuth,
    ) -> Result<Option<SignedExecutionPayloadBid<P>>> {
        let _timer = self.metrics.as_ref().map(|metrics| {
            metrics
                .builder_get_execution_payload_bid_times
                .start_timer()
        });

        // See <https://github.com/ethereum/builder-specs/blob/main/apis/builder/execution_payload_bid.yaml>
        // (applicable from Gloas onwards).
        let phase = chain_config.phase_at_slot::<P>(slot);
        ensure_gloas_phase(phase)?;

        ensure!(
            signed_request_auth.message.slot == slot,
            BuilderApiError::AuthSlotMismatch {
                auth_slot: signed_request_auth.message.slot,
                path_slot: slot,
            },
        );

        let url = self.url(&format!(
            "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
        ))?;

        let use_json = self.config.builder_api_format == BuilderApiFormat::Json;

        debug_with_peers!("getting execution payload bid from {url}, use_json: {use_json}");

        let date_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|timestamp| timestamp.as_millis())
            .map_err(|error| anyhow::anyhow!("unable to calculate Date-Milliseconds: {error:?}"))?;

        let request = self
            .client
            .post(url.into_url())
            .timeout(REQUEST_TIMEOUT)
            .header(DATE_MS_HEADER, format!("{date_ms}"))
            .header(
                X_TIMEOUT_MS_HEADER,
                format!("{}", REQUEST_TIMEOUT.as_millis()),
            )
            .header(ETH_CONSENSUS_VERSION, phase.as_ref());

        let request = if use_json {
            request
                .header(ACCEPT, APPLICATION_JSON.as_ref())
                .json(signed_request_auth)
        } else {
            request
                .header(
                    ACCEPT,
                    format!("{APPLICATION_OCTET_STREAM};q=1,{APPLICATION_JSON};q=0.9"),
                )
                .header(CONTENT_TYPE, APPLICATION_OCTET_STREAM.as_ref())
                .body(signed_request_auth.to_ssz()?)
        };

        let response = request.send().await?;
        let response = handle_error(response).await?;

        if response.status() == StatusCode::NO_CONTENT {
            info_with_peers!("builder has no execution payload bid available for slot {slot}");
            return Ok(None);
        }

        if response.status() != StatusCode::OK {
            bail!(BuilderApiError::UnexpectedStatusCode {
                expected: StatusCode::OK,
                received: response.status()
            });
        }

        let bid_response = self
            .parse_gloas_response::<GetExecutionPayloadBidResponse<P>>(response)
            .await?;

        let bid = bid_response.into_bid();

        debug_with_peers!("get_execution_payload_bid response: {bid:?}");

        ensure!(
            bid.message.slot == slot,
            BuilderApiError::BidSlotMismatch {
                bid_slot: bid.message.slot,
                request_slot: slot,
            },
        );
        ensure!(
            bid.message.parent_block_hash == parent_hash,
            BuilderApiError::BidParentHashMismatch {
                bid_parent_hash: bid.message.parent_block_hash,
                request_parent_hash: parent_hash,
            },
        );
        ensure!(
            bid.message.parent_block_root == parent_root,
            BuilderApiError::BidParentRootMismatch {
                bid_parent_root: bid.message.parent_block_root,
                request_parent_root: parent_root,
            },
        );

        info_with_peers!("received execution payload bid from builder for slot {slot}");

        Ok(Some(bid))
    }

    pub async fn submit_builder_preferences<P: Preset>(
        &self,
        chain_config: &ChainConfig,
        genesis_time: UnixSeconds,
        pubkey: PublicKeyBytes,
        request_body: &BuilderPreferencesRequest,
    ) -> Result<()> {
        let _timer = self.metrics.as_ref().map(|metrics| {
            metrics
                .builder_submit_builder_preferences_times
                .start_timer()
        });

        // ethereum/builder-specs#165: auth.message.slot is the proposal slot preferences
        // apply to; the builder MUST reject if it has already passed. Client preflight
        // is best-effort (clock may skew). See
        // <https://github.com/ethereum/builder-specs/pull/165>.
        let current_slot = clock::Tick::current::<P>(chain_config, genesis_time)?.slot;
        let auth_slot = request_body.auth.message.slot;
        debug_with_peers!(
            "submit_builder_preferences auth_slot={auth_slot} current_slot={current_slot}"
        );
        ensure!(
            auth_slot >= current_slot,
            BuilderApiError::AuthSlotAlreadyPassed {
                auth_slot,
                current_slot,
            },
        );

        // Eth-Consensus-Version is required and must match the fork of the proposal slot.
        let phase = chain_config.phase_at_slot::<P>(auth_slot);
        ensure_gloas_phase(phase)?;

        let url = self.url(&format!("/eth/v1/builder/builder_preferences/{pubkey:?}"))?;

        let use_json = self.config.builder_api_format == BuilderApiFormat::Json;

        debug_with_peers!("submitting builder preferences to {url}, use_json: {use_json}");

        let request = self
            .client
            .post(url.into_url())
            .header(ETH_CONSENSUS_VERSION, phase.as_ref());

        let request = if use_json {
            request.json(request_body)
        } else {
            request
                .header(CONTENT_TYPE, APPLICATION_OCTET_STREAM.as_ref())
                .body(request_body.to_ssz()?)
        };

        let response = request.send().await?;
        let response = handle_error(response).await?;

        if response.status() == StatusCode::ACCEPTED {
            info_with_peers!("submitted builder preferences for validator {pubkey:?}");
            return Ok(());
        }

        bail!(BuilderApiError::UnexpectedStatusCode {
            expected: StatusCode::ACCEPTED,
            received: response.status()
        })
    }

    // Notifies the builder so it can publish the corresponding
    // `SignedExecutionPayloadEnvelope`. The proposer must still gossip the beacon block.
    // See <https://github.com/ethereum/builder-specs/blob/main/apis/builder/beacon_blocks.yaml>.
    pub async fn submit_signed_beacon_block<P: Preset>(
        &self,
        chain_config: &ChainConfig,
        genesis_time: UnixSeconds,
        block: &SignedBeaconBlock<P>,
    ) -> Result<()> {
        let _timer = self.metrics.as_ref().map(|metrics| {
            metrics
                .builder_submit_signed_beacon_block_times
                .start_timer()
        });

        // Applicable from Gloas onwards. See
        // <https://github.com/ethereum/builder-specs/pull/165>.
        let phase = block.phase();
        ensure_gloas_phase(phase)?;

        let url = self.url("/eth/v1/builder/beacon_blocks")?;

        let (next_interval, remaining_time) =
            clock::next_interval_with_remaining_time::<P>(chain_config, genesis_time)?;

        let use_json = self.config.builder_api_format == BuilderApiFormat::Json;

        debug_with_peers!(
            "submitting signed beacon block to {url} with timeout of {remaining_time:?} \
             before next interval {next_interval:?}, use_json: {use_json}",
        );

        let block_root = block.message().hash_tree_root();
        let slot = block.message().slot();

        let request = self
            .client
            .post(url.into_url())
            .timeout(remaining_time)
            .header(ETH_CONSENSUS_VERSION, phase.as_ref());

        let request = if use_json {
            request.json(block)
        } else {
            request
                .header(ACCEPT, APPLICATION_OCTET_STREAM.as_ref())
                .header(CONTENT_TYPE, APPLICATION_OCTET_STREAM.as_ref())
                .body(block.to_ssz()?)
        };

        let response = request.send().await?;
        let response = handle_error(response).await?;

        if response.status() == StatusCode::ACCEPTED {
            info_with_peers!(
                "notified builder of signed beacon block {block_root:?} at slot {slot}"
            );
            return Ok(());
        }

        bail!(BuilderApiError::UnexpectedStatusCode {
            expected: StatusCode::ACCEPTED,
            received: response.status()
        })
    }

    async fn parse_gloas_response<T: DeserializeOwned + SszRead<Phase>>(
        &self,
        response: Response,
    ) -> Result<T> {
        let content_type = response.headers().get(CONTENT_TYPE);

        debug_with_peers!("received Gloas response with content_type: {content_type:?}");

        if content_type.is_none()
            || content_type == Some(&HeaderValue::from_static(APPLICATION_JSON.as_ref()))
        {
            return response.json().await.map_err(Into::into);
        }

        if content_type == Some(&HeaderValue::from_static(APPLICATION_OCTET_STREAM.as_ref())) {
            let phase = http_api_utils::extract_phase_from_headers(response.headers())?;
            let bytes = response.bytes().await?;

            return T::from_ssz(&phase, &bytes).map_err(Into::into);
        }

        bail!(BuilderApiError::UnsupportedContentType {
            content_type: content_type.cloned(),
        })
    }

    async fn parse_response<T: DeserializeOwned + SszRead<Phase>>(
        &self,
        response: Response,
    ) -> Result<T> {
        let content_type = response.headers().get(CONTENT_TYPE);

        debug_with_peers!("received response with content_type: {content_type:?}");

        if content_type.is_none()
            || content_type == Some(&HeaderValue::from_static(APPLICATION_JSON.as_ref()))
        {
            return response
                .json()
                .await
                .inspect(|_| self.supports_block_ssz.store(Arc::new(Some(false))))
                .map_err(Into::into);
        }

        if content_type == Some(&HeaderValue::from_static(APPLICATION_OCTET_STREAM.as_ref())) {
            let phase = http_api_utils::extract_phase_from_headers(response.headers())?;
            let bytes = response.bytes().await?;

            return T::from_ssz(&phase, &bytes)
                .inspect(|_| self.supports_block_ssz.store(Arc::new(Some(true))))
                .map_err(Into::into);
        }

        bail!(BuilderApiError::UnsupportedContentType {
            content_type: content_type.cloned(),
        })
    }

    fn url(&self, path: &str) -> Result<RedactingUrl> {
        self.config.builder_api_url.join(path).map_err(Into::into)
    }
}

async fn handle_error(response: Response) -> Result<Response> {
    if response.status().is_client_error() {
        let message = response.text().await?;
        bail!(BuilderApiError::BadRequest { message });
    }

    if response.status().is_server_error() {
        let message = response.text().await?;
        bail!(BuilderApiError::BuilderNodeInternalError { message });
    }

    Ok(response)
}

fn validate_phase(computed: Phase, in_response: Phase) -> Result<()> {
    ensure!(
        computed == in_response,
        BuilderApiError::VersionMismatch {
            computed,
            in_response,
        },
    );

    Ok(())
}

fn ensure_gloas_phase(phase: Phase) -> Result<()> {
    ensure!(
        phase >= Phase::Gloas,
        BuilderApiError::PhaseBeforeGloas { phase },
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use helper_functions::signing::SignForAllForks as _;
    use httpmock::{Method, MockServer};
    use reqwest::Client;
    use serde_json::json;
    use ssz::{ByteList, Hc};
    use test_case::test_case;
    use types::{
        config::Config,
        gloas::containers::{
            BeaconBlock as GloasBeaconBlock, SignedBeaconBlock as GloasSignedBeaconBlock,
            SignedExecutionPayloadBid,
        },
        nonstandard::{
            DEFAULT_BUILDER_MAX_SKIPPED_SLOTS, DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH,
        },
        phase0::primitives::H256,
        preset::Mainnet,
    };

    use crate::{
        BuilderApi, BuilderConfig,
        consts::{DOMAIN_REQUEST_AUTH, MaxDataSize},
        gloas::containers::{
            BuilderPreferences, BuilderPreferencesRequest, RequestAuth, SignedRequestAuth,
        },
    };

    use super::*;

    use bls::SignatureBytes;

    const NON_EMPTY_SLOTS: [Slot; 27] = [
        128, 127, 126, 125, 124, 122, 121, 120, 119, 118, 117, 116, 115, 114, 112, 111, 110, 109,
        108, 104, 102, 101, 100, 99, 98, 97, 96,
    ];

    fn test_api(builder_url: &str) -> BuilderApi {
        BuilderApi::new(
            BuilderConfig {
                builder_api_format: BuilderApiFormat::Json,
                builder_api_url: builder_url
                    .parse()
                    .expect("test builder URL should be valid"),
                builder_disable_checks: false,
                builder_max_skipped_slots_per_epoch: DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH,
                builder_max_skipped_slots: DEFAULT_BUILDER_MAX_SKIPPED_SLOTS,
            },
            PubkeyCache::default().into(),
            Client::new(),
            None,
        )
    }

    fn gloas_chain_config() -> Config {
        Config::mainnet().upgrade_once(Phase::Gloas, 0)
    }

    fn sample_auth() -> SignedRequestAuth {
        sample_auth_for_slot(1)
    }

    fn sample_auth_for_slot(slot: Slot) -> SignedRequestAuth {
        SignedRequestAuth {
            message: RequestAuth {
                data: ByteList::<MaxDataSize>::try_from(b"http://builder.example.com".to_vec())
                    .expect("builder URL fits MAX_DATA_SIZE"),
                slot,
            },
            signature: SignatureBytes::default(),
        }
    }

    fn sample_bid(
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        parent_root: H256,
    ) -> SignedExecutionPayloadBid<Mainnet> {
        let mut bid = SignedExecutionPayloadBid::<Mainnet>::default();
        bid.message.slot = slot;
        bid.message.parent_block_hash = parent_hash;
        bid.message.parent_block_root = parent_root;
        bid
    }

    fn sample_gloas_block() -> SignedBeaconBlock<Mainnet> {
        SignedBeaconBlock::Gloas(GloasSignedBeaconBlock {
            message: Hc::from(GloasBeaconBlock::default()),
            signature: SignatureBytes::default(),
        })
    }

    fn genesis_time_now() -> UnixSeconds {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_secs()
            .saturating_sub(12)
    }

    #[test_case(
        129, NON_EMPTY_SLOTS => Ok(());
        "missing blocks: 123, 113, 107, 106, 105, 103 (not enough for short circuit)"
    )]
    #[test_case(
        132, NON_EMPTY_SLOTS => Err(BuilderApiError::RollingEpochMissingBlocks { missing_blocks: 9 });
        "missing blocks: 131, 130, 129, 123, 113, 107, 106, 105, 103"
    )]
    #[test_case(
        133, NON_EMPTY_SLOTS => Err(BuilderApiError::ConsecutiveMissingBlocks { missing_blocks: 4 });
        "missing blocks: 132, 131, 130, 129, 123, 113, 107, 106, 105, 103"
    )]
    #[test_case(
        34, [0] => Err(BuilderApiError::ConsecutiveMissingBlocks { missing_blocks: 33 });
        "more consecutive missing blocks than slots in an epoch"
    )]
    #[test_case(
        17, [16, 0] => Err(BuilderApiError::RollingEpochMissingBlocks { missing_blocks: 15 });
        "many missing blocks in less than an epoch since genesis"
    )]
    #[test_case(
        43, [42, 21, 0] => Err(BuilderApiError::RollingEpochMissingBlocks { missing_blocks: 30 });
        "more missing blocks than allowed in first gap alone"
    )]
    fn circuit_breaker_conditions(
        slot: Slot,
        nonempty_slots: impl IntoIterator<Item = Slot>,
    ) -> Result<(), BuilderApiError> {
        test_api("http://localhost").can_use_builder_api::<Mainnet>(slot, nonempty_slots)
    }

    #[test]
    fn request_auth_signing_root_uses_domain_request_auth() {
        let config = Config::mainnet();
        let auth = RequestAuth {
            data: ByteList::<MaxDataSize>::try_from(b"http://builder.example.com".to_vec())
                .expect("builder URL fits MAX_DATA_SIZE"),
            slot: 42,
        };

        let root = auth.signing_root(&config);
        assert_ne!(root, H256::zero());

        let other_data = RequestAuth {
            data: ByteList::<MaxDataSize>::try_from(b"http://other.example.com".to_vec())
                .expect("builder URL fits MAX_DATA_SIZE"),
            slot: 42,
        };
        let other_slot = RequestAuth {
            data: auth.data,
            slot: 43,
        };

        assert_ne!(root, other_data.signing_root(&config));
        assert_ne!(root, other_slot.signing_root(&config));
        assert_eq!(DOMAIN_REQUEST_AUTH.0, [0x0b, 0x00, 0x00, 0x01]);
    }

    #[tokio::test]
    async fn get_execution_payload_bid_returns_bid_on_200() -> Result<()> {
        let server = MockServer::start();
        let slot = 1_u64;
        let parent_hash = ExecutionBlockHash::zero();
        let parent_root = H256::zero();
        let pubkey = PublicKeyBytes::default();
        let auth = sample_auth();

        let path = format!(
            "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
        );

        let bid = sample_bid(slot, parent_hash, parent_root);
        let mock = server.mock(|when, then| {
            when.method(Method::POST)
                .path(&path)
                .header("Eth-Consensus-Version", "gloas")
                .header("X-Timeout-Ms", "1000")
                .header_exists("Date-Milliseconds");
            then.status(200).json_body(json!({
                "version": "gloas",
                "data": bid,
            }));
        });

        let api = test_api(&server.url("/"));
        let result = api
            .get_execution_payload_bid::<Mainnet>(
                &gloas_chain_config(),
                slot,
                parent_hash,
                parent_root,
                pubkey,
                &auth,
            )
            .await?;

        mock.assert();
        assert!(result.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_returns_none_on_204() -> Result<()> {
        let server = MockServer::start();
        let slot = 1_u64;
        let parent_hash = ExecutionBlockHash::zero();
        let parent_root = H256::zero();
        let pubkey = PublicKeyBytes::default();
        let auth = sample_auth();

        let path = format!(
            "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
        );

        let mock = server.mock(|when, then| {
            when.method(Method::POST)
                .path(&path)
                .header("Eth-Consensus-Version", "gloas")
                .header("X-Timeout-Ms", "1000")
                .header_exists("Date-Milliseconds");
            then.status(204);
        });

        let api = test_api(&server.url("/"));
        let result = api
            .get_execution_payload_bid::<Mainnet>(
                &gloas_chain_config(),
                slot,
                parent_hash,
                parent_root,
                pubkey,
                &auth,
            )
            .await?;

        mock.assert();
        assert!(result.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_rejects_non_200_success() -> Result<()> {
        let server = MockServer::start();
        let slot = 1_u64;
        let parent_hash = ExecutionBlockHash::zero();
        let parent_root = H256::zero();
        let pubkey = PublicKeyBytes::default();
        let auth = sample_auth();
        let path = format!(
            "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
        );

        let mock = server.mock(|when, then| {
            when.method(Method::POST).path(&path);
            then.status(202);
        });

        let api = test_api(&server.url("/"));
        let err = api
            .get_execution_payload_bid::<Mainnet>(
                &gloas_chain_config(),
                slot,
                parent_hash,
                parent_root,
                pubkey,
                &auth,
            )
            .await
            .expect_err("202 should not be accepted as a bid");
        mock.assert();
        assert!(err.downcast_ref::<BuilderApiError>().is_some_and(|e| {
            matches!(
                e,
                BuilderApiError::UnexpectedStatusCode {
                    expected: StatusCode::OK,
                    received: StatusCode::ACCEPTED,
                }
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_rejects_pre_gloas_slot() -> Result<()> {
        let server = MockServer::start();
        let chain_config = Config::mainnet();
        let api = test_api(&server.url("/"));
        let auth = sample_auth();

        let err = api
            .get_execution_payload_bid::<Mainnet>(
                &chain_config,
                1,
                ExecutionBlockHash::zero(),
                H256::zero(),
                PublicKeyBytes::default(),
                &auth,
            )
            .await
            .expect_err("pre-Gloas slot should fail before HTTP");

        assert!(err.downcast_ref::<BuilderApiError>().is_some_and(|e| {
            matches!(
                e,
                BuilderApiError::PhaseBeforeGloas {
                    phase: Phase::Phase0,
                }
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_rejects_auth_slot_mismatch() -> Result<()> {
        let server = MockServer::start();
        let api = test_api(&server.url("/"));
        let auth = sample_auth();

        let err = api
            .get_execution_payload_bid::<Mainnet>(
                &gloas_chain_config(),
                2,
                ExecutionBlockHash::zero(),
                H256::zero(),
                PublicKeyBytes::default(),
                &auth,
            )
            .await
            .expect_err("auth.slot != path slot should fail before HTTP");

        assert!(err.downcast_ref::<BuilderApiError>().is_some_and(|e| {
            matches!(
                e,
                BuilderApiError::AuthSlotMismatch {
                    auth_slot: 1,
                    path_slot: 2,
                }
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_maps_400() -> Result<()> {
        let server = MockServer::start();
        let slot = 1_u64;
        let parent_hash = ExecutionBlockHash::zero();
        let parent_root = H256::zero();
        let pubkey = PublicKeyBytes::default();
        let auth = sample_auth();
        let path = format!(
            "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
        );

        let mock = server.mock(|when, then| {
            when.method(Method::POST).path(&path);
            then.status(400).body("bad request");
        });

        let api = test_api(&server.url("/"));
        let err = api
            .get_execution_payload_bid::<Mainnet>(
                &gloas_chain_config(),
                slot,
                parent_hash,
                parent_root,
                pubkey,
                &auth,
            )
            .await
            .expect_err("400 should fail");
        mock.assert();
        assert!(
            err.downcast_ref::<BuilderApiError>()
                .is_some_and(|e| { matches!(e, BuilderApiError::BadRequest { .. }) })
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_maps_500() -> Result<()> {
        let server = MockServer::start();
        let slot = 1_u64;
        let parent_hash = ExecutionBlockHash::zero();
        let parent_root = H256::zero();
        let pubkey = PublicKeyBytes::default();
        let auth = sample_auth();
        let path = format!(
            "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
        );

        let mock = server.mock(|when, then| {
            when.method(Method::POST).path(&path);
            then.status(500).body("internal");
        });

        let api = test_api(&server.url("/"));
        let err = api
            .get_execution_payload_bid::<Mainnet>(
                &gloas_chain_config(),
                slot,
                parent_hash,
                parent_root,
                pubkey,
                &auth,
            )
            .await
            .expect_err("500 should fail");
        mock.assert();
        assert!(
            err.downcast_ref::<BuilderApiError>()
                .is_some_and(|e| { matches!(e, BuilderApiError::BuilderNodeInternalError { .. }) })
        );
        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_sends_auth_body() -> Result<()> {
        let server = MockServer::start();
        let slot = 1_u64;
        let parent_hash = ExecutionBlockHash::zero();
        let parent_root = H256::zero();
        let pubkey = PublicKeyBytes::default();
        let auth = sample_auth();

        let path = format!(
            "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
        );

        let bid = sample_bid(slot, parent_hash, parent_root);
        let mock = server.mock(|when, then| {
            when.method(Method::POST)
                .path(&path)
                .header("Eth-Consensus-Version", "gloas")
                .header("X-Timeout-Ms", "1000")
                .header_exists("Date-Milliseconds")
                .json_body_obj(&auth);
            then.status(200).json_body(json!({
                "version": "gloas",
                "data": bid,
            }));
        });

        let api = test_api(&server.url("/"));
        let result = api
            .get_execution_payload_bid::<Mainnet>(
                &gloas_chain_config(),
                slot,
                parent_hash,
                parent_root,
                pubkey,
                &auth,
            )
            .await?;

        mock.assert();
        assert!(result.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_rejects_bid_slot_mismatch() -> Result<()> {
        let server = MockServer::start();
        let slot = 1_u64;
        let parent_hash = ExecutionBlockHash::zero();
        let parent_root = H256::zero();
        let pubkey = PublicKeyBytes::default();
        let auth = sample_auth();

        let path = format!(
            "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
        );

        let bid = sample_bid(2, parent_hash, parent_root);
        let mock = server.mock(|when, then| {
            when.method(Method::POST).path(&path);
            then.status(200).json_body(json!({
                "version": "gloas",
                "data": bid,
            }));
        });

        let api = test_api(&server.url("/"));
        let err = api
            .get_execution_payload_bid::<Mainnet>(
                &gloas_chain_config(),
                slot,
                parent_hash,
                parent_root,
                pubkey,
                &auth,
            )
            .await
            .expect_err("bid.slot != request slot should fail");

        mock.assert();
        assert!(err.downcast_ref::<BuilderApiError>().is_some_and(|e| {
            matches!(
                e,
                BuilderApiError::BidSlotMismatch {
                    bid_slot: 2,
                    request_slot: 1,
                }
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_rejects_bid_parent_hash_mismatch() -> Result<()> {
        let server = MockServer::start();
        let slot = 1_u64;
        let parent_hash = ExecutionBlockHash::zero();
        let other_parent_hash = ExecutionBlockHash::repeat_byte(1);
        let parent_root = H256::zero();
        let pubkey = PublicKeyBytes::default();
        let auth = sample_auth();

        let path = format!(
            "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
        );

        let bid = sample_bid(slot, other_parent_hash, parent_root);
        let mock = server.mock(|when, then| {
            when.method(Method::POST).path(&path);
            then.status(200).json_body(json!({
                "version": "gloas",
                "data": bid,
            }));
        });

        let api = test_api(&server.url("/"));
        let err = api
            .get_execution_payload_bid::<Mainnet>(
                &gloas_chain_config(),
                slot,
                parent_hash,
                parent_root,
                pubkey,
                &auth,
            )
            .await
            .expect_err("bid.parent_block_hash != request parent_hash should fail");

        mock.assert();
        assert!(err.downcast_ref::<BuilderApiError>().is_some_and(|e| {
            matches!(
                e,
                BuilderApiError::BidParentHashMismatch {
                    bid_parent_hash,
                    request_parent_hash,
                } if *bid_parent_hash == other_parent_hash && *request_parent_hash == parent_hash
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn get_execution_payload_bid_rejects_bid_parent_root_mismatch() -> Result<()> {
        let server = MockServer::start();
        let slot = 1_u64;
        let parent_hash = ExecutionBlockHash::zero();
        let parent_root = H256::zero();
        let other_parent_root = H256::repeat_byte(1);
        let pubkey = PublicKeyBytes::default();
        let auth = sample_auth();

        let path = format!(
            "/eth/v1/builder/execution_payload_bid/{slot}/{parent_hash:?}/{parent_root:?}/{pubkey:?}"
        );

        let bid = sample_bid(slot, parent_hash, other_parent_root);
        let mock = server.mock(|when, then| {
            when.method(Method::POST).path(&path);
            then.status(200).json_body(json!({
                "version": "gloas",
                "data": bid,
            }));
        });

        let api = test_api(&server.url("/"));
        let err = api
            .get_execution_payload_bid::<Mainnet>(
                &gloas_chain_config(),
                slot,
                parent_hash,
                parent_root,
                pubkey,
                &auth,
            )
            .await
            .expect_err("bid.parent_block_root != request parent_root should fail");

        mock.assert();
        assert!(err.downcast_ref::<BuilderApiError>().is_some_and(|e| {
            matches!(
                e,
                BuilderApiError::BidParentRootMismatch {
                    bid_parent_root,
                    request_parent_root,
                } if *bid_parent_root == other_parent_root && *request_parent_root == parent_root
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn submit_builder_preferences_succeeds_on_202() -> Result<()> {
        let server = MockServer::start();
        let pubkey = PublicKeyBytes::default();
        let path = format!("/eth/v1/builder/builder_preferences/{pubkey:?}");
        let chain_config = gloas_chain_config();
        let genesis_time = genesis_time_now();
        let current_slot = clock::Tick::current::<Mainnet>(&chain_config, genesis_time)?.slot;
        let request_body = BuilderPreferencesRequest {
            auth: sample_auth_for_slot(current_slot.saturating_add(32)),
            preferences: BuilderPreferences {
                max_execution_payment: 0,
            },
        };

        let mock = server.mock(|when, then| {
            when.method(Method::POST)
                .path(&path)
                .header("Eth-Consensus-Version", "gloas");
            then.status(202);
        });

        let api = test_api(&server.url("/"));
        api.submit_builder_preferences::<Mainnet>(
            &chain_config,
            genesis_time,
            pubkey,
            &request_body,
        )
        .await?;
        mock.assert();
        Ok(())
    }

    #[tokio::test]
    async fn submit_builder_preferences_allows_auth_slot_equal_to_current() -> Result<()> {
        let server = MockServer::start();
        let pubkey = PublicKeyBytes::default();
        let path = format!("/eth/v1/builder/builder_preferences/{pubkey:?}");
        let chain_config = gloas_chain_config();
        let genesis_time = genesis_time_now();
        let current_slot = clock::Tick::current::<Mainnet>(&chain_config, genesis_time)?.slot;
        let request_body = BuilderPreferencesRequest {
            auth: sample_auth_for_slot(current_slot),
            preferences: BuilderPreferences {
                max_execution_payment: 0,
            },
        };

        let mock = server.mock(|when, then| {
            when.method(Method::POST)
                .path(&path)
                .header("Eth-Consensus-Version", "gloas");
            then.status(202);
        });

        let api = test_api(&server.url("/"));
        api.submit_builder_preferences::<Mainnet>(
            &chain_config,
            genesis_time,
            pubkey,
            &request_body,
        )
        .await?;
        mock.assert();
        Ok(())
    }

    #[tokio::test]
    async fn submit_builder_preferences_rejects_auth_slot_already_passed() -> Result<()> {
        let server = MockServer::start();
        let pubkey = PublicKeyBytes::default();
        let chain_config = gloas_chain_config();
        // Genesis far enough in the past that the current slot is well above 0.
        let genesis_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_secs()
            .saturating_sub(12 * 1_000);
        let current_slot = clock::Tick::current::<Mainnet>(&chain_config, genesis_time)?.slot;
        let auth_slot = current_slot.saturating_sub(1);
        assert!(
            auth_slot < current_slot,
            "test requires a past auth slot (current_slot={current_slot})"
        );

        let request_body = BuilderPreferencesRequest {
            auth: sample_auth_for_slot(auth_slot),
            preferences: BuilderPreferences {
                max_execution_payment: 0,
            },
        };

        let api = test_api(&server.url("/"));
        let err = api
            .submit_builder_preferences::<Mainnet>(
                &chain_config,
                genesis_time,
                pubkey,
                &request_body,
            )
            .await
            .expect_err("past auth.slot should fail before HTTP");

        assert!(err.downcast_ref::<BuilderApiError>().is_some_and(|e| {
            matches!(
                e,
                BuilderApiError::AuthSlotAlreadyPassed {
                    auth_slot: past,
                    current_slot: now,
                } if *past == auth_slot && *now == current_slot
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn submit_builder_preferences_rejects_pre_gloas_proposal_slot() -> Result<()> {
        let server = MockServer::start();
        let pubkey = PublicKeyBytes::default();
        // Mainnet config has no Gloas fork; phase_at_slot stays Phase0.
        let chain_config = Config::mainnet();
        let genesis_time = genesis_time_now();
        let current_slot = clock::Tick::current::<Mainnet>(&chain_config, genesis_time)?.slot;
        let request_body = BuilderPreferencesRequest {
            auth: sample_auth_for_slot(current_slot.saturating_add(32)),
            preferences: BuilderPreferences {
                max_execution_payment: 0,
            },
        };

        let api = test_api(&server.url("/"));
        let err = api
            .submit_builder_preferences::<Mainnet>(
                &chain_config,
                genesis_time,
                pubkey,
                &request_body,
            )
            .await
            .expect_err("pre-Gloas proposal slot should fail before HTTP");

        assert!(err.downcast_ref::<BuilderApiError>().is_some_and(|e| {
            matches!(
                e,
                BuilderApiError::PhaseBeforeGloas {
                    phase: Phase::Phase0,
                }
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn submit_builder_preferences_maps_400() -> Result<()> {
        let server = MockServer::start();
        let pubkey = PublicKeyBytes::default();
        let path = format!("/eth/v1/builder/builder_preferences/{pubkey:?}");
        let chain_config = gloas_chain_config();
        let genesis_time = genesis_time_now();
        let current_slot = clock::Tick::current::<Mainnet>(&chain_config, genesis_time)?.slot;
        let request_body = BuilderPreferencesRequest {
            auth: sample_auth_for_slot(current_slot.saturating_add(32)),
            preferences: BuilderPreferences {
                max_execution_payment: 0,
            },
        };

        let mock = server.mock(|when, then| {
            when.method(Method::POST).path(&path);
            then.status(400).body("invalid preferences");
        });

        let api = test_api(&server.url("/"));
        let err = api
            .submit_builder_preferences::<Mainnet>(
                &chain_config,
                genesis_time,
                pubkey,
                &request_body,
            )
            .await
            .expect_err("400 should fail");
        mock.assert();
        assert!(
            err.downcast_ref::<BuilderApiError>()
                .is_some_and(|e| { matches!(e, BuilderApiError::BadRequest { .. }) })
        );
        Ok(())
    }

    #[tokio::test]
    async fn submit_signed_beacon_block_succeeds_on_202() -> Result<()> {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(Method::POST)
                .path("/eth/v1/builder/beacon_blocks")
                .header("Eth-Consensus-Version", "gloas");
            then.status(202);
        });

        let api = test_api(&server.url("/"));
        api.submit_signed_beacon_block::<Mainnet>(
            &gloas_chain_config(),
            genesis_time_now(),
            &sample_gloas_block(),
        )
        .await?;
        mock.assert();
        Ok(())
    }

    #[tokio::test]
    async fn submit_signed_beacon_block_rejects_pre_gloas_block() -> Result<()> {
        let server = MockServer::start();
        let api = test_api(&server.url("/"));
        let err = api
            .submit_signed_beacon_block::<Mainnet>(
                &gloas_chain_config(),
                genesis_time_now(),
                &SignedBeaconBlock::Phase0(Default::default()),
            )
            .await
            .expect_err("pre-Gloas block should fail before HTTP");

        assert!(err.downcast_ref::<BuilderApiError>().is_some_and(|e| {
            matches!(
                e,
                BuilderApiError::PhaseBeforeGloas {
                    phase: Phase::Phase0,
                }
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn submit_signed_beacon_block_rejects_non_202_success() -> Result<()> {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(Method::POST)
                .path("/eth/v1/builder/beacon_blocks");
            then.status(200);
        });

        let api = test_api(&server.url("/"));
        let err = api
            .submit_signed_beacon_block::<Mainnet>(
                &gloas_chain_config(),
                genesis_time_now(),
                &sample_gloas_block(),
            )
            .await
            .expect_err("200 should not be accepted");
        mock.assert();
        assert!(err.downcast_ref::<BuilderApiError>().is_some_and(|e| {
            matches!(
                e,
                BuilderApiError::UnexpectedStatusCode {
                    expected: StatusCode::ACCEPTED,
                    received: StatusCode::OK,
                }
            )
        }));
        Ok(())
    }
}
