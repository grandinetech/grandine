use core::time::Duration;
use std::sync::Arc;

use anyhow::{bail, ensure, Result};
use bls::PublicKeyBytes;
use derive_more::Constructor;
use helper_functions::signing::SignForAllForks;
use itertools::Itertools as _;
use tracing::{debug, info};
use prometheus_metrics::Metrics;
use reqwest::{Client, Response, StatusCode, Url};
use ssz::SszHash as _;
use thiserror::Error;
use typenum::Unsigned as _;
use types::{
    combined::{ExecutionPayload, SignedBlindedBeaconBlock},
    config::Config as ChainConfig,
    nonstandard::{Phase, WithBlobsAndMev},
    phase0::{
        consts::GENESIS_SLOT,
        primitives::{ExecutionBlockHash, Slot, UnixSeconds, H256},
    },
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::{
    combined::{ExecutionPayloadAndBlobsBundle, SignedBuilderBid},
    consts::BUILDER_PROPOSAL_DELAY_TOLERANCE,
    unphased::containers::SignedValidatorRegistrationV1,
    BuilderConfig,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(BUILDER_PROPOSAL_DELAY_TOLERANCE);

#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum BuilderApiError {
    #[error("bad request to Builder API (builder node response: {message})")]
    BadRequest { message: String },
    #[error("builder node internal error (builder node response: {message})")]
    BuilderNodeInternalError { message: String },
    #[error("{missing_blocks} consecutive missing blocks since head")]
    ConsecutiveMissingBlocks { missing_blocks: u64 },
    #[error("{missing_blocks} missing blocks in the last rolling epoch")]
    RollingEpochMissingBlocks { missing_blocks: u64 },
    #[error(
        "execution payload root ({payload_root:?}) does not match header root ({header_root:?})"
    )]
    RootMismatch {
        header_root: H256,
        payload_root: H256,
    },
    #[error(
        "Builder API responded with incorrect version \
         (computed: {computed}, response: {in_response})"
    )]
    VersionMismatch { computed: Phase, in_response: Phase },
}

#[derive(Constructor)]
pub struct Api {
    config: BuilderConfig,
    client: Client,
    metrics: Option<Arc<Metrics>>,
}

impl Api {
    pub fn can_use_builder_api<P: Preset>(
        &self,
        slot: Slot,
        nonempty_slots: impl IntoIterator<Item = Slot>,
    ) -> Result<(), BuilderApiError> {
        if self.config.builder_disable_checks {
            return Ok(());
        }

        let mut nonempty_slots = nonempty_slots.into_iter().peekable();

        let end_slot = slot.saturating_sub(1).max(GENESIS_SLOT);
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

        missing_blocks += nonempty_slots
            .take_while(|slot| *slot > start_slot)
            .chain(core::iter::once(start_slot))
            .tuple_windows()
            .map(|(slot, parent_slot)| slot.abs_diff(parent_slot.max(start_slot)).saturating_sub(1))
            .sum::<u64>();

        if missing_blocks > self.config.builder_max_skipped_slots_per_epoch {
            return Err(BuilderApiError::RollingEpochMissingBlocks { missing_blocks });
        }

        Ok(())
    }

    pub async fn register_validators(
        &self,
        validator_registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<()> {
        let _timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.builder_register_validator_times.start_timer());

        debug!("registering validators: {validator_registrations:?}");

        let url = self.url("/eth/v1/builder/validators")?;
        let response = self
            .client
            .post(url)
            .json(validator_registrations)
            .send()
            .await?;

        let response = handle_error(response).await?;

        debug!("register_validators response: {response:?}");

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

        debug!("getting execution payload header from {url}");

        let response = self.client.get(url).timeout(REQUEST_TIMEOUT).send().await?;
        let response = handle_error(response).await?;

        if response.status() == StatusCode::NO_CONTENT {
            info!("builder has no execution payload header available for slot {slot}");
            return Ok(None);
        }

        let builder_bid = response.json::<SignedBuilderBid<P>>().await?;

        debug!("get_execution_payload_header response: {builder_bid:?}");

        validate_phase(chain_config.phase_at_slot::<P>(slot), builder_bid.phase())?;

        let signature = builder_bid.signature();
        let public_key = builder_bid.pubkey().into();

        match &builder_bid {
            SignedBuilderBid::Bellatrix(builder_bid) => {
                builder_bid
                    .message
                    .verify(chain_config, signature, &public_key)?
            }
            SignedBuilderBid::Capella(builder_bid) => {
                builder_bid
                    .message
                    .verify(chain_config, signature, &public_key)?
            }
            SignedBuilderBid::Deneb(builder_bid) => {
                builder_bid
                    .message
                    .verify(chain_config, signature, &public_key)?
            }
        }

        info!("received execution payload header from builder for slot {slot}");

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
            clock::next_interval_with_remaining_time(chain_config, genesis_time)?;

        debug!(
            "posting blinded block to {url} with timeout of {remaining_time:?} \
             before next interval {next_interval:?}",
        );

        let block_root = block.message().hash_tree_root();
        let slot = block.message().slot();

        let response = self
            .client
            .post(url)
            .json(block)
            .timeout(remaining_time)
            .send()
            .await?;

        let response = handle_error(response).await?;
        let response: WithBlobsAndMev<ExecutionPayload<P>, P> = response
            .json::<ExecutionPayloadAndBlobsBundle<P>>()
            .await?
            .into();

        let execution_payload = &response.value;

        debug!("post_blinded_block response: {execution_payload:?}");

        validate_phase(block.phase(), execution_payload.phase())?;

        let header_root = block.execution_payload_header().hash_tree_root();
        let payload_root = execution_payload.hash_tree_root();

        ensure!(
            payload_root == header_root,
            BuilderApiError::RootMismatch {
                header_root,
                payload_root,
            },
        );

        info!("received execution payload from builder for block {block_root:?} at slot {slot}");

        Ok(response)
    }

    fn url(&self, path: &str) -> Result<Url> {
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

#[cfg(test)]
mod tests {
    use reqwest::{Client, Url};
    use test_case::test_case;
    use types::preset::Mainnet;

    use crate::{
        config::{DEFAULT_BUILDER_MAX_SKIPPED_SLOTS, DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH},
        BuilderApi, BuilderConfig,
    };

    use super::*;

    const NON_EMPTY_SLOTS: [Slot; 27] = [
        128, 127, 126, 125, 124, 122, 121, 120, 119, 118, 117, 116, 115, 114, 112, 111, 110, 109,
        108, 104, 102, 101, 100, 99, 98, 97, 96,
    ];

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
        let api = BuilderApi::new(
            BuilderConfig {
                builder_api_url: Url::parse("http://localhost")
                    .expect("http://localhost should be a valid URL"),
                builder_disable_checks: false,
                builder_max_skipped_slots_per_epoch: DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH,
                builder_max_skipped_slots: DEFAULT_BUILDER_MAX_SKIPPED_SLOTS,
            },
            Client::new(),
            None,
        );

        api.can_use_builder_api::<Mainnet>(slot, nonempty_slots)
    }
}
