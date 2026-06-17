//! Standalone builder main loop.
//!
//! Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/builder.md>

use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context as _, Result, bail};
use beacon_api_types::{BuilderId, BuilderStatus, BuildersQuery};
use bls::{PublicKeyBytes, SignatureBytes};
use clock::Tick;
use futures::{
    StreamExt as _,
    future::{join, join_all},
};
use helper_functions::{predicates, signing::SignForSingleFork};
use http_api_utils::{BlockId, StateId};
use parking_lot::Mutex;
use signer::{Keystores, Signer, SigningMessage, SigningTriple};
use sse::{Event, HeadV2EventData, Topic};
use ssz::{ProgressiveList, SszHash as _};
use tokio::select;
use tracing::{debug, info, warn};
use types::{
    bellatrix::primitives::Gas,
    combined::{ExecutionPayload, ExecutionRequests, SignedBeaconBlock},
    config::Config as ChainConfig,
    gloas::{
        containers::{
            ExecutionPayloadBid, ExecutionPayloadEnvelope, ProposerPreferences,
            SignedBeaconBlock as GloasSignedBeaconBlock, SignedExecutionPayloadBid,
            SignedExecutionPayloadEnvelope,
        },
        primitives::BuilderIndex,
    },
    nonstandard::{WEI_IN_GWEI, WithBlobsAndMev},
    phase0::primitives::{ExecutionAddress, ExecutionBlockHash, Gwei, H256, Slot, UnixSeconds},
    preset::{Mainnet, Minimal, Preset, PresetName},
    traits::SignedBeaconBlock as _,
};

use crate::{
    args::BuilderArgs,
    bn_client::BeaconNodeClient,
    config::BuilderConfig,
    error::{BidError, BuilderError},
    payload_builder::{PayloadBuilder, PendingBuild},
};

pub fn run(args: BuilderArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    runtime.block_on(run_async(args.into()))
}

async fn run_async(config: BuilderConfig) -> Result<()> {
    info!(
        "starting grandine-builder against beacon node {} and execution engine {}",
        config.beacon_node, config.execution_engine,
    );

    let beacon_client = BeaconNodeClient::new(
        config.beacon_node.clone().into_url(),
        config.beacon_node_auth.clone(),
    )?;

    let chain_config = Arc::new(
        beacon_client
            .config_spec()
            .await
            .context("failed to fetch chain config from beacon node")?,
    );

    match chain_config.preset_base {
        PresetName::Mainnet => {
            run_with_config::<Mainnet>(config, beacon_client, chain_config).await
        }
        PresetName::Minimal => {
            run_with_config::<Minimal>(config, beacon_client, chain_config).await
        }
        preset_name => bail!("unsupported preset {preset_name} reported by beacon node"),
    }
}

async fn run_with_config<P: Preset>(
    config: BuilderConfig,
    beacon_client: BeaconNodeClient,
    chain_config: Arc<ChainConfig>,
) -> Result<()> {
    let genesis = beacon_client
        .genesis()
        .await
        .context("failed to fetch genesis from beacon node")?;

    let signer = load_signer(&config).await?;

    let signer_snapshot = signer.load();
    if signer_snapshot.is_empty() {
        warn!("no builder keys loaded, exiting...");
        return Ok(());
    }

    info!("loaded {} builder key(s)", signer_snapshot.keys().len());

    let payload_builder = PayloadBuilder::new(
        chain_config.clone(),
        config.execution_engine.clone(),
        config.jwt_secret_path.clone(),
        config.jwt_id.clone(),
        config.jwt_version.clone(),
    )?;

    let builder = Builder::<P> {
        config,
        beacon_client,
        chain_config,
        genesis_validators_root: genesis.genesis_validators_root,
        genesis_time: genesis.genesis_time,
        signer,
        payload_builder,
        built_payloads: Mutex::new(HashMap::new()),
        proposer_preferences: Mutex::new(HashMap::new()),
        latest_head: Mutex::new(LatestHead::default()),
        forkchoice_hashes: Mutex::new(ForkchoiceHashes::default()),
        owned_builders: Mutex::new(None),
        pending_payments: Mutex::new(HashMap::new()),
        reported_not_active: AtomicBool::new(false),
    };

    builder.run_loop().await
}

pub struct Builder<P: Preset> {
    pub config: BuilderConfig,
    pub chain_config: Arc<ChainConfig>,
    pub genesis_validators_root: H256,
    pub genesis_time: UnixSeconds,
    pub signer: Arc<Signer>,
    pub beacon_client: BeaconNodeClient,
    pub payload_builder: PayloadBuilder,
    latest_head: Mutex<LatestHead>,
    /// Safe/finalized execution hashes threaded into `engine_forkchoiceUpdated`,
    /// refreshed from the beacon node's finality checkpoints on the epoch tick.
    forkchoice_hashes: Mutex<ForkchoiceHashes>,
    /// Payloads we bid on, popped by the head handler to build the envelope when one of our bids wins.
    built_payloads: Mutex<HashMap<(Slot, ExecutionBlockHash), BuiltBid<P>>>,
    /// Latest proposer preferences received over SSE, keyed by `proposal_slot`.
    proposer_preferences: Mutex<HashMap<Slot, ProposerPreferences>>,
    /// Owned active builder indices with balances, keyed by the head root.
    /// The balance is pre-charge for a bid at the head slot and post-charge for earlier ones.
    owned_builders: Mutex<Option<(H256, Vec<OwnedBuilder>)>>,
    /// Keep track of builder pending payments which isn't deducted from the builder balance.
    pending_payments: Mutex<HashMap<(Slot, BuilderIndex), Gwei>>,
    /// Whether we already reported that none of our keys are active.
    reported_not_active: AtomicBool,
}

pub struct BuiltBid<P: Preset> {
    payload: WithBlobsAndMev<ExecutionPayload<P>, P>,
    builders: HashMap<BuilderIndex, PublicKeyBytes>,
}

type OwnedBuilder = (PublicKeyBytes, BuilderIndex, Gwei);

#[derive(Default, Clone, Copy)]
struct LatestHead {
    slot: Slot,
    root: H256,
    /// The head block's committed bid `gas_limit`, read by `parent_gas_limit`.
    gas_limit: Option<Gas>,
}

#[derive(Default, Clone, Copy)]
struct ForkchoiceHashes {
    safe: ExecutionBlockHash,
    finalized: ExecutionBlockHash,
}

impl<P: Preset> Builder<P> {
    pub async fn run_loop(self) -> Result<()> {
        let mut events = self
            .beacon_client
            .events::<P>(&[
                Topic::HeadV2,
                Topic::PayloadAttributes,
                Topic::ProposerPreferences,
            ])
            .context("failed to subscribe to beacon node SSE")?;

        let genesis_time_ms = self.genesis_time.saturating_mul(1000);
        let mut ticks = clock::ticks::<P>(&self.chain_config, genesis_time_ms)
            .context("failed to start clock tick stream")?;

        loop {
            let outcome = select! {
                event = events.recv() => match event {
                    Some(event) => self.handle_event(event).await,
                    None => {
                        warn!("SSE channel closed; exiting builder loop");
                        break;
                    }
                },
                tick = ticks.next() => match tick {
                    Some(tick) => self.handle_tick(tick).await,
                    None => {
                        warn!("clock tick stream ended; exiting builder loop");
                        break;
                    }
                },
            };

            if let Err(error) = outcome {
                error.log();
            }
        }

        Ok(())
    }

    async fn handle_event(&self, event: Result<Event<P>>) -> Result<(), BuilderError> {
        match event.map_err(BuilderError::SseDecode)? {
            Event::HeadV2(head) => self.handle_head(head.data).await,
            Event::PayloadAttributes(payload_attributes) => {
                let slot = payload_attributes.proposal_slot();
                let parent_block_hash = payload_attributes.parent_block_hash();
                let preferences = self.proposer_preferences.lock().get(&slot).copied();
                let ForkchoiceHashes { safe, finalized } = *self.forkchoice_hashes.lock();

                let payload_id = self
                    .payload_builder
                    .prepare_payload_for_attributes::<P>(
                        payload_attributes,
                        safe,
                        finalized,
                        self.config.builder_fee_recipient,
                        preferences,
                    )
                    .await
                    .map_err(|error| BuilderError::ForkchoiceUpdated { slot, error })?;

                match payload_id {
                    Some(payload_id) => debug!(
                        "EL accepted payload attributes for slot {slot} parent {parent_block_hash:?}: payload_id {payload_id:?}"
                    ),
                    None => debug!(
                        "no payload build for slot {slot}: pre-Gloas event, or the EL returned no payload_id"
                    ),
                }

                Ok(())
            }
            Event::ProposerPreferences(event) => {
                let preferences = event.data.message;

                debug!(
                    "proposer preferences for slot {} (validator_index {}): \
                     fee_recipient {:?} target_gas_limit {}",
                    preferences.proposal_slot,
                    preferences.validator_index,
                    preferences.fee_recipient,
                    preferences.target_gas_limit,
                );

                self.proposer_preferences
                    .lock()
                    .insert(preferences.proposal_slot, preferences);

                Ok(())
            }
            event => {
                debug!("unhandled SSE topic: {}", event.topic().as_ref());
                Ok(())
            }
        }
    }

    async fn handle_head(&self, head: HeadV2EventData) -> Result<(), BuilderError> {
        // Ignore the second `head` event
        if head.payload_status.is_full() {
            debug!("head {} payload status transition to full", head.block);
            return Ok(());
        }

        debug!(
            "new head {} at slot {} (payload_status {:?})",
            head.block, head.slot, head.payload_status,
        );

        *self.latest_head.lock() = LatestHead {
            slot: head.slot,
            root: head.block,
            gas_limit: None,
        };

        let envelope_outcome = match self.block(head.block).await {
            Some(SignedBeaconBlock::Gloas(block)) => {
                // Cache head slot's gas limit for the next slot's bid path, which
                // checks the parent block's gas limit for target compatibility.
                self.latest_head.lock().gas_limit = Some(
                    block
                        .message
                        .body
                        .signed_execution_payload_bid
                        .message
                        .gas_limit,
                );

                self.maybe_publish_payload_envelope(&block, head.block)
                    .await
                    .map_err(|error| BuilderError::EnvelopeHandling {
                        head: head.block,
                        error,
                    })
            }
            Some(
                SignedBeaconBlock::Phase0(_)
                | SignedBeaconBlock::Altair(_)
                | SignedBeaconBlock::Bellatrix(_)
                | SignedBeaconBlock::Capella(_)
                | SignedBeaconBlock::Deneb(_)
                | SignedBeaconBlock::Electra(_)
                | SignedBeaconBlock::Fulu(_),
            )
            | None => Ok(()),
        };

        self.built_payloads
            .lock()
            .retain(|(bid_slot, _), _| *bid_slot + 2 >= head.slot);

        if let Err(error) = self.refresh_owned_builders(head.block).await {
            BuilderError::BuilderSetRefresh {
                head: head.block,
                error,
            }
            .log();
        }

        envelope_outcome
    }

    async fn handle_tick(&self, tick: Result<Tick>) -> Result<(), BuilderError> {
        let tick = tick.map_err(BuilderError::ClockTick)?;

        if tick.is_start_of_epoch::<P>()
            || (tick.is_start_of_slot() && self.forkchoice_hashes_unresolved())
        {
            self.refresh_forkchoice_hashes().await;
        }

        // TODO: user should be able to configure which point in slot to bid at
        if tick.is_end_of_slot::<P>(&self.chain_config) {
            // Bid for the next slot: its proposer includes the bid in the block it publishes
            // at the start of that slot, so the bid must be out before this slot ends.
            let bid_slot = tick.slot.saturating_add(1);

            self.maybe_publish_payload_bids(bid_slot)
                .await
                .map_err(|source| BuilderError::BidHandling {
                    slot: bid_slot,
                    source,
                })?;
        }

        Ok(())
    }

    /// Pull the EL-built payload prepared for `slot`, build an `ExecutionPayloadBid` for each builder pubkey we control
    /// that can cover it, then sign and publish so the bids reach the proposer of `slot` before it assembles its block.
    async fn maybe_publish_payload_bids(&self, slot: Slot) -> Result<(), BidError> {
        let (pending_build, preferences) = self.prepare_pending_build(slot)?;
        let PendingBuild {
            payload_id,
            parent_block_root,
        } = pending_build;

        let head_root = self.latest_head.lock().root;

        let owned_builders = self
            .owned_builders(head_root)
            .await
            .map_err(BidError::BuilderSetUnavailable)?;

        if owned_builders.is_empty() {
            return Err(BidError::NotAnActiveBuilder {
                first_occurrence: !self.reported_not_active.swap(true, Ordering::Relaxed),
            });
        }

        if self.reported_not_active.swap(false, Ordering::Relaxed) {
            info!("our pubkeys are in the active builder set again; resuming bids");
        }

        let with_blobs = self
            .payload_builder
            .get_payload::<P>(payload_id)
            .await
            .map_err(|error| BidError::GetPayloadFailed { payload_id, error })?;

        // Naive strategy: bid the built payload's full MEV (in gwei) to the proposer.
        // TODO: allow user to configue their bidding strategy
        let value: Gwei = with_blobs
            .mev
            .map(|wei| u64::try_from(wei / WEI_IN_GWEI).unwrap_or(u64::MAX))
            .unwrap_or_default();

        let gas_limit = with_blobs.value.gas_limit();
        if let Some(parent_gas_limit) = self.parent_gas_limit(parent_block_root).await
            && !predicates::is_gas_limit_target_compatible(
                parent_gas_limit,
                gas_limit,
                preferences.target_gas_limit,
            )
        {
            return Err(BidError::GasLimitIncompatible {
                gas_limit,
                parent_gas_limit,
                target_gas_limit: preferences.target_gas_limit,
            });
        }

        let coverable_builders = self.filter_coverable_builders(slot, value, owned_builders);
        if coverable_builders.is_empty() {
            return Err(BidError::NoCoverableBuilder { value });
        }

        self.sign_and_publish_bids(
            slot,
            parent_block_root,
            value,
            preferences.fee_recipient,
            with_blobs,
            coverable_builders,
        )
        .await
    }

    fn prepare_pending_build(
        &self,
        slot: Slot,
    ) -> Result<(PendingBuild, ProposerPreferences), BidError> {
        let latest_head = *self.latest_head.lock();
        if slot.saturating_sub(latest_head.slot) > self.config.max_empty_slots {
            return Err(BidError::HeadLagging {
                head_slot: latest_head.slot,
                max_empty_slots: self.config.max_empty_slots,
            });
        }

        let preferences = {
            let mut preferences = self.proposer_preferences.lock();
            preferences.retain(|preference_slot, _| *preference_slot >= slot);
            preferences.get(&slot).copied()
        };
        let preferences = preferences.ok_or(BidError::NoProposerPreferences)?;

        let pending_build = self
            .payload_builder
            .take_pending(slot)
            .ok_or(BidError::NoPendingBuild)?;

        if !latest_head.root.is_zero() && pending_build.parent_block_root != latest_head.root {
            return Err(BidError::OrphanedParent {
                parent: pending_build.parent_block_root,
                head: latest_head.root,
            });
        }

        Ok((pending_build, preferences))
    }

    fn filter_coverable_builders(
        &self,
        slot: Slot,
        value: Gwei,
        owned_builders: Vec<OwnedBuilder>,
    ) -> Vec<(PublicKeyBytes, BuilderIndex)> {
        // Prune old pending payments up to the current head slot,
        // since those are already reflected in the builder balance,
        // the builder balance is updated in `refresh_owned_builders` during head events.
        let head_slot = self.latest_head.lock().slot;
        let mut pending_payments = self.pending_payments.lock();
        pending_payments.retain(|(payment_slot, _), _| *payment_slot >= head_slot);

        owned_builders
            .into_iter()
            .filter_map(|(pubkey, builder_index, balance)| {
                let in_flight = pending_payments
                    .iter()
                    .filter(|((_, index), _)| *index == builder_index)
                    .fold(Gwei::default(), |total, (_, amount)| {
                        total.saturating_add(*amount)
                    });
                let min_balance = P::MIN_DEPOSIT_AMOUNT.saturating_add(in_flight);

                if balance >= min_balance && balance - min_balance >= value {
                    Some((pubkey, builder_index))
                } else {
                    debug!(
                        "skipping bid for slot {slot}: builder_index {builder_index} cannot cover bid value \
                         {value} gwei (balance: {balance}, pending payments: {in_flight})"
                    );
                    None
                }
            })
            .collect()
    }

    async fn sign_and_publish_bids(
        &self,
        slot: Slot,
        parent_block_root: H256,
        value: Gwei,
        fee_recipient: ExecutionAddress,
        with_blobs: WithBlobsAndMev<ExecutionPayload<P>, P>,
        coverable_builders: Vec<(PublicKeyBytes, BuilderIndex)>,
    ) -> Result<(), BidError> {
        let payload = &with_blobs.value;
        let parent_block_hash = payload.parent_hash();
        let block_hash = payload.block_hash();
        let prev_randao = payload.prev_randao();
        let gas_limit = payload.gas_limit();

        let blob_kzg_commitments: ProgressiveList<_> =
            with_blobs.commitments.clone().unwrap_or_default().into();
        let execution_requests_root = with_blobs
            .execution_requests
            .as_ref()
            .map(|r| r.hash_tree_root())
            .unwrap_or_default();

        let bids: Vec<(PublicKeyBytes, BuilderIndex, ExecutionPayloadBid<P>)> = coverable_builders
            .into_iter()
            .map(|(pubkey, builder_index)| {
                let bid = ExecutionPayloadBid::<P> {
                    parent_block_hash,
                    parent_block_root,
                    block_hash,
                    prev_randao,
                    fee_recipient,
                    gas_limit,
                    builder_index,
                    slot,
                    value,
                    execution_payment: 0,
                    blob_kzg_commitments: blob_kzg_commitments.clone(),
                    execution_requests_root,
                    phantom: PhantomData,
                };

                (pubkey, builder_index, bid)
            })
            .collect();

        let signer = self.signer.load();
        let triples = bids.iter().map(|(pubkey, _, bid)| SigningTriple {
            message: SigningMessage::ExecutionPayloadBid(bid.clone()),
            signing_root: bid
                .signing_root_without_state(&self.chain_config, self.genesis_validators_root),
            public_key: *pubkey,
        });

        // TODO: pass `fork_info` once Web3Signer support builder signing
        let signatures: Vec<_> = signer
            .sign_triples_without_slashing_protection::<P>(triples, None)
            .await
            .map_err(BidError::SigningFailed)?
            .collect();

        let published: HashMap<_, _> = join_all(bids.into_iter().zip(signatures).map(
            |((pubkey, builder_index, bid), signature)| async move {
                let signed = SignedExecutionPayloadBid {
                    message: bid,
                    signature: SignatureBytes::from(signature),
                };
                let result = self
                    .beacon_client
                    .publish_execution_payload_bid::<P>(&signed)
                    .await;
                (pubkey, builder_index, result)
            },
        ))
        .await
        .into_iter()
        .filter_map(|(pubkey, builder_index, result)| match result {
            Ok(()) => {
                info!(
                    "published bid at slot {slot} for builder_index {builder_index} \
                     block_hash {block_hash:?} value {value} gwei"
                );
                Some((builder_index, pubkey))
            }
            Err(error) => {
                warn!(
                    "publish bid failed at slot {slot} for builder_index {builder_index}: \
                     {error:?}"
                );
                None
            }
        })
        .collect();

        if !published.is_empty() {
            self.built_payloads.lock().insert(
                (slot, block_hash),
                BuiltBid {
                    payload: with_blobs,
                    builders: published,
                },
            );
        }

        Ok(())
    }

    async fn maybe_publish_payload_envelope(
        &self,
        block: &GloasSignedBeaconBlock<P>,
        beacon_block_root: H256,
    ) -> Result<()> {
        let parent_beacon_block_root = block.message.parent_root;
        let bid = &block.message.body.signed_execution_payload_bid.message;
        let slot = bid.slot;
        let block_hash = bid.block_hash;
        let builder_index = bid.builder_index;
        let value = bid.value;

        let Some(built) = self.built_payloads.lock().remove(&(slot, block_hash)) else {
            return Ok(());
        };
        let Some(pubkey) = built.builders.get(&builder_index).copied() else {
            return Ok(());
        };

        let current_tick = Tick::current::<P>(&self.chain_config, self.genesis_time)?;

        if current_tick.slot != slot
            || !current_tick.is_before_due_bps_deadline::<P>(
                &self.chain_config,
                self.chain_config.payload_due_bps,
            )
        {
            warn!(
                "not revealing payload for slot {slot}: head arrived at {:?} of slot {}, \
                 past the payload reveal deadline",
                current_tick.kind, current_tick.slot,
            );

            return Ok(());
        }

        *self
            .pending_payments
            .lock()
            .entry((slot, builder_index))
            .or_default() += value;

        let payload = match built.payload.value {
            ExecutionPayload::Gloas(payload) => payload,
            other @ (ExecutionPayload::Bellatrix(_)
            | ExecutionPayload::Capella(_)
            | ExecutionPayload::Deneb(_)) => bail!(
                "cannot build envelope: cached payload is not a Gloas payload (got phase {:?})",
                other.phase(),
            ),
        };

        let execution_requests = match built.payload.execution_requests {
            Some(ExecutionRequests::Gloas(requests)) => requests,
            Some(ExecutionRequests::Electra(_)) => {
                bail!("cached execution requests are Electra, not Gloas; cannot build envelope")
            }
            None => Default::default(),
        };

        let envelope = ExecutionPayloadEnvelope::<P> {
            payload,
            execution_requests,
            builder_index,
            beacon_block_root,
            parent_beacon_block_root,
        };

        let signature = self
            .signer
            .load()
            .sign_without_slashing_protection::<P>(
                SigningMessage::ExecutionPayloadEnvelope(&envelope),
                envelope
                    .signing_root_without_state(&self.chain_config, self.genesis_validators_root),
                None,
                pubkey,
            )
            .await
            .context("failed to sign envelope")?;

        let signed_envelope = SignedExecutionPayloadEnvelope {
            message: envelope,
            signature: signature.into(),
        };

        self.beacon_client
            .publish_payload_envelope::<P>(
                signed_envelope,
                built.payload.blobs,
                built.payload.proofs,
            )
            .await
            .context("failed to publish envelope")?;

        info!(
            "published envelope at slot {slot} for builder_index {builder_index} \
             block_hash {block_hash:?}"
        );

        Ok(())
    }

    async fn parent_gas_limit(&self, parent_block_root: H256) -> Option<Gas> {
        let latest_head = *self.latest_head.lock();

        if let Some(gas_limit) = latest_head.gas_limit
            && latest_head.root == parent_block_root
        {
            debug!("gas limit cache hit for block {parent_block_root:?}");
            return Some(gas_limit);
        }

        debug!("gas limit cache miss for block {parent_block_root:?}; fetching block");

        let block = self.block(parent_block_root).await?;
        Some(block.payload_bid()?.gas_limit)
    }

    async fn block(&self, block_root: H256) -> Option<SignedBeaconBlock<P>> {
        self.beacon_client
            .block_ssz::<P>(&self.chain_config, BlockId::Root(block_root))
            .await
            .map_err(|error| debug!("failed to fetch block {block_root:?}: {error:?}"))
            .ok()
    }

    fn forkchoice_hashes_unresolved(&self) -> bool {
        let hashes = self.forkchoice_hashes.lock();
        hashes.safe.is_zero() || hashes.finalized.is_zero()
    }

    async fn refresh_forkchoice_hashes(&self) {
        let checkpoints = match self.beacon_client.finality_checkpoints(StateId::Head).await {
            Ok(checkpoints) => checkpoints,
            Err(error) => {
                debug!("failed to fetch finality checkpoints: {error:?}");
                return;
            }
        };

        let (safe, finalized) = join(
            self.checkpoint_execution_hash(checkpoints.current_justified.root),
            self.checkpoint_execution_hash(checkpoints.finalized.root),
        )
        .await;

        let mut hashes = self.forkchoice_hashes.lock();

        if let Some(safe) = safe {
            hashes.safe = safe;
        }

        if let Some(finalized) = finalized {
            hashes.finalized = finalized;
        }
    }

    async fn checkpoint_execution_hash(&self, checkpoint_root: H256) -> Option<ExecutionBlockHash> {
        if checkpoint_root.is_zero() {
            return None;
        }

        let block = self.block(checkpoint_root).await?;

        if let Some(bid) = block.payload_bid() {
            return Some(bid.parent_block_hash);
        }

        block
            .message()
            .body()
            .with_execution_payload()
            .map(|body| body.execution_payload().block_hash())
    }

    async fn owned_builders(&self, head_root: H256) -> Result<Vec<OwnedBuilder>> {
        let cached = self.owned_builders.lock().clone();
        if let Some((root, owned)) = cached
            && root == head_root
            && !head_root.is_zero()
        {
            debug!(
                "builder set cache hit for head {head_root:?}: {} builder(s)",
                owned.len(),
            );
            return Ok(owned);
        }

        debug!("builder set cache miss for head {head_root:?}; fetching builder set");

        self.refresh_owned_builders(head_root).await
    }

    /// Fetch the active builders we control at `head_root` and cache them under it.
    async fn refresh_owned_builders(&self, head_root: H256) -> Result<Vec<OwnedBuilder>> {
        let signer = self.signer.load();
        let query = BuildersQuery {
            ids: signer.keys().copied().map(BuilderId::PublicKey).collect(),
            statuses: vec![BuilderStatus::Active],
        };

        let state_id = if head_root.is_zero() {
            StateId::Head
        } else {
            StateId::Root(head_root)
        };

        let builders = self
            .beacon_client
            .builders(state_id, &query)
            .await
            .context("failed to fetch builder set from beacon node")?;

        let owned = builders
            .into_iter()
            .map(|info| (info.builder.pubkey, info.index, info.builder.balance))
            .collect::<Vec<_>>();

        *self.owned_builders.lock() = Some((head_root, owned.clone()));

        Ok(owned)
    }
}

async fn load_signer(config: &BuilderConfig) -> Result<Arc<Signer>> {
    let keystore_password_file = config
        .builder_keystore_password_file
        .clone()
        .or_else(|| config.builder_keystore_password_dir.clone())
        .context(
            "--builder-keystore-password-file or --builder-keystore-password-dir is required",
        )?;

    let keystores = Keystores {
        keystore_dir: config.builder_keystore_dir.clone(),
        keystore_password_file,
    };

    let keys = tokio::task::spawn_blocking(move || keystores.normalize(None))
        .await
        .context("keystore decryption task panicked")??;

    let client = reqwest::Client::new();
    Ok(Arc::new(Signer::new(
        keys,
        client,
        signer::Web3SignerConfig::default(),
        None,
    )))
}
