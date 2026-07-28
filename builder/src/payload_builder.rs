//! Engine-API-driven execution payload assembly for the standalone builder.
//!
//! The builder owns its own execution engine connection. The flow per slot is:
//!
//! 1. On the BN `payload_attributes` SSE event (or at the latest the slot's start),
//!    call `engine_forkchoiceUpdated` on our EL with the attributes derived from
//!    the parent block's `block_hash` + the proposer's fee recipient. The EL
//!    begins assembling a payload.
//! 2. At slot start (or just before bid deadline) call `engine_getPayloadV6`
//!    (Gloas) with the `payloadId` returned in step 1. The EL returns the
//!    finalized payload + blob commitments + blob proofs.
//! 3. Build an `ExecutionPayloadBid` referencing the payload's `block_hash`,
//!    `parent_hash`, etc. and a bid `value`.
//! 4. If our bid is accepted, the same payload + blobs are wrapped in an
//!    `ExecutionPayloadEnvelope` and published via the BN REST API.

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context as _, Result};
use either::Either;
use eth1_api::{Auth, AuthOptions, Eth1Api};
use execution_engine::{
    ForkChoiceUpdatedResponse, PayloadAttributes, PayloadAttributesV4, PayloadId,
};
use parking_lot::Mutex;
use reqwest::ClientBuilder;
use sse::{PayloadAttributesEvent, PayloadAttributesEventDataV4};
use ssz::ContiguousList;
use try_from_iterator::TryFromIterator as _;
use types::{
    combined::ExecutionPayload,
    config::Config as ChainConfig,
    gloas::containers::ProposerPreferences,
    nonstandard::{Phase, WithBlobsAndMev},
    phase0::primitives::{ExecutionAddress, ExecutionBlockHash, H256, Slot},
    preset::Preset,
    redacting_url::RedactingUrl,
};

const EL_REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const EL_USER_AGENT: &str = concat!("grandine-builder/", env!("CARGO_PKG_VERSION"));

pub struct PayloadBuilder {
    pub eth1: Arc<Eth1Api>,
    pending_builds: Mutex<HashMap<Slot, PendingBuild>>,
}

#[derive(Clone, Debug)]
pub struct PendingBuild {
    pub payload_id: PayloadId,
    pub parent_block_root: H256,
}

impl PayloadBuilder {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        endpoint: RedactingUrl,
        jwt_secret_path: PathBuf,
        jwt_id: Option<String>,
        jwt_version: Option<String>,
    ) -> Result<Self> {
        let auth = Arc::new(Auth::new(AuthOptions {
            secrets_path: Some(jwt_secret_path),
            id: jwt_id,
            version: jwt_version,
        })?);

        let client = ClientBuilder::new()
            .timeout(EL_REQUEST_TIMEOUT)
            .user_agent(EL_USER_AGENT)
            .connection_verbose(true)
            .build()
            .context("failed to build reqwest client for EL")?;

        let eth1 = Arc::new(Eth1Api::new(
            chain_config,
            client,
            auth,
            vec![endpoint],
            None,
            None,
        ));

        Ok(Self {
            eth1,
            pending_builds: Mutex::new(HashMap::new()),
        })
    }

    /// Handle an SSE `payload_attributes` event from the beacon node and call `engine_forkchoiceUpdated` against the EL,
    /// and remember the resulting `PayloadId` for retrieval at slot start.
    pub async fn prepare_payload_for_attributes<P: Preset>(
        &self,
        event: PayloadAttributesEvent,
        safe_block_hash: ExecutionBlockHash,
        finalized_block_hash: ExecutionBlockHash,
        builder_fee_recipient: ExecutionAddress,
        preferences: Option<ProposerPreferences>,
    ) -> Result<Option<PayloadId>> {
        let proposal_slot = event.proposal_slot();
        let parent_block_root = event.parent_block_root();
        let parent_block_hash = event.parent_block_hash();

        let attrs = match event {
            PayloadAttributesEvent::Bellatrix(_)
            | PayloadAttributesEvent::Capella(_)
            | PayloadAttributesEvent::Deneb(_)
            | PayloadAttributesEvent::Electra(_)
            | PayloadAttributesEvent::Fulu(_) => return Ok(None),
            PayloadAttributesEvent::Gloas(data) => {
                let PayloadAttributesEventDataV4 {
                    timestamp,
                    prev_randao,
                    withdrawals,
                    parent_beacon_block_root,
                    slot_number,
                    target_gas_limit,
                    ..
                } = data.payload_attributes;

                let withdrawals =
                    ContiguousList::try_from_iter(withdrawals.into_iter().map(Into::into))
                        .context("withdrawals list exceeds MaxWithdrawalsPerPayload")?;

                PayloadAttributes::Gloas(PayloadAttributesV4 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient: builder_fee_recipient,
                    withdrawals,
                    parent_beacon_block_root,
                    slot_number,
                    target_gas_limit: preferences.map_or(target_gas_limit, |p| p.target_gas_limit),
                })
            }
        };

        let response = self
            .forkchoice_updated::<P>(
                parent_block_hash,
                safe_block_hash,
                finalized_block_hash,
                Either::Right(attrs),
            )
            .await
            .context("engine_forkchoiceUpdated failed for builder attributes")?;

        Ok(response.payload_id.inspect(|&payload_id| {
            self.pending_builds.lock().insert(
                proposal_slot,
                PendingBuild {
                    payload_id,
                    parent_block_root,
                },
            );
        }))
    }

    /// Take the pending build for `slot`, prune any builds prepared for older slots.
    /// Keep the builds state only for the current and future slots.
    pub fn take_pending(&self, slot: Slot) -> Option<PendingBuild> {
        let mut pending_builds = self.pending_builds.lock();
        pending_builds.retain(|pending_slot, _| *pending_slot >= slot);
        pending_builds.remove(&slot)
    }

    pub async fn forkchoice_updated<P: Preset>(
        &self,
        head_block_hash: ExecutionBlockHash,
        safe_block_hash: ExecutionBlockHash,
        finalized_block_hash: ExecutionBlockHash,
        payload_attributes: Either<Phase, PayloadAttributes<P>>,
    ) -> Result<ForkChoiceUpdatedResponse> {
        self.eth1
            .forkchoice_updated::<P>(
                head_block_hash,
                safe_block_hash,
                finalized_block_hash,
                payload_attributes,
            )
            .await
    }

    pub async fn get_payload<P: Preset>(
        &self,
        payload_id: PayloadId,
    ) -> Result<WithBlobsAndMev<ExecutionPayload<P>, P>> {
        Ok(self.eth1.get_payload::<P>(payload_id).await?.result)
    }
}
