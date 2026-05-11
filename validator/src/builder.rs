//! <https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/builder.md>

use core::time::Duration;
use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use block_producer::{BlockBuildOptions, BlockProducer};
use bls::PublicKeyBytes;
use clock::{Tick, TickKind};
use debug_info::HealthCheck;
use derive_more::Display;
use eth1_api::ApiController;
use features::Feature;
use fork_choice_control::{BuilderMessage, Event, EventChannels, Topic, Wait};
use fork_choice_store::ChainLink;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    select,
    stream::StreamExt as _,
};
use helper_functions::{accessors, signing::SignForSingleFork as _};
use itertools::Itertools as _;
use logging::{debug_with_peers, error_with_peers, info_with_peers, warn_with_peers};
use once_cell::sync::OnceCell;
use p2p::BuilderToP2p;
use prometheus_metrics::Metrics;
use signer::{Signer, SigningMessage, SigningTriple};
use ssz::H256;
use std_ext::ArcExt as _;
use tokio::time::timeout;
use tracing::instrument;
use types::{
    config::Config as ChainConfig,
    gloas::{
        consts::BUILDER_INDEX_SELF_BUILD,
        containers::{
            ExecutionPayloadBid, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
        },
    },
    nonstandard::WithStatus,
    phase0::primitives::{ExecutionBlockHash, Slot},
    preset::Preset,
    traits::{BeaconState as _, BlockBodyWithPayloadBid, SignedBeaconBlock},
};

use crate::{builder_config::BuilderConfig, slot_head::SlotHead};

#[derive(Display)]
#[display("too many empty slots after head: {head_slot} + {max_empty_slots} < {slot}")]
struct HeadFarBehind {
    head_slot: Slot,
    max_empty_slots: u64,
    slot: Slot,
}

pub struct Channels<P: Preset, W> {
    // TODO(gloas): handle GET/POST request via beacon API
    // pub api_to_builder_rx: UnboundedReceiver<ApiToBuilder<P>>,
    pub fork_choice_rx: UnboundedReceiver<BuilderMessage<P, W>>,
    pub p2p_tx: UnboundedSender<BuilderToP2p<P>>,
}

/// Builder struct for handling non-validating staked builder duties
///
/// Builders can optionally submit payload bids via P2P to produce execution payloads.
/// If a block proposer accepts their bid, they are expected to publish the payload envelope.
///
/// Honest builder duties:
/// - Construct and broadcast `SignedExecutionPayloadBid` for current or next slot
/// - When bid is accepted, construct and broadcast `DataColumnSidecar`s and `SignedExecutionPayloadEnvelope` if block is timely
#[expect(clippy::struct_field_names)]
pub struct Builder<P: Preset, W: Wait> {
    chain_config: Arc<ChainConfig>,
    builder_config: Arc<BuilderConfig>,
    block_producer: Arc<BlockProducer<P, W>>,
    controller: ApiController<P, W>,
    // api_to_builder_rx: UnboundedReceiver<ApiToBuilder<P>>,
    fork_choice_rx: UnboundedReceiver<BuilderMessage<P, W>>,
    p2p_tx: UnboundedSender<BuilderToP2p<P>>,
    signer: Arc<Signer>,
    event_channels: Arc<EventChannels<P>>,
    last_tick: Option<Tick>,
    last_block_root: Option<H256>,
    own_signed_payload_bids: OnceCell<Vec<Arc<SignedExecutionPayloadBid<P>>>>,
    metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> Builder<P, W> {
    #[must_use]
    pub fn new(
        channels: Channels<P, W>,
        builder_config: Arc<BuilderConfig>,
        block_producer: Arc<BlockProducer<P, W>>,
        controller: ApiController<P, W>,
        signer: Arc<Signer>,
        event_channels: Arc<EventChannels<P>>,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let Channels {
            // api_to_builder_rx,
            fork_choice_rx,
            p2p_tx,
        } = channels;

        Self {
            chain_config: controller.chain_config().clone_arc(),
            builder_config,
            block_producer,
            controller,
            // api_to_builder_rx,
            fork_choice_rx,
            p2p_tx,
            signer,
            event_channels,
            last_tick: None,
            last_block_root: None,
            own_signed_payload_bids: OnceCell::new(),
            metrics,
        }
    }

    pub async fn run(self) -> Result<()> {
        self.run_internal().await;

        Ok(())
    }

    async fn run_internal(mut self) {
        let mut health_check = HealthCheck::new("builder");

        loop {
            select! {
                _ = health_check.interval.select_next_some() => {
                    health_check.check();
                },

                // api_message = self.api_to_builder_rx.select_next_some() => {
                //     self.handle_api_message(api_message).await;
                // },

                builder_message = self.fork_choice_rx.select_next_some() => {
                    match builder_message {
                        BuilderMessage::Tick(wait_group, tick) => {
                            if let Err(error) = self.handle_tick(wait_group, tick).await {
                                panic!("error while handling tick: {error:?}");
                            }
                        },
                        BuilderMessage::Head(wait_group, head) => {
                            let span = tracing::debug_span!("BuilderMessage::Head", service = "builder");
                            let _enter = span.enter();

                            if let Err(error) = self.maybe_publish_execution_payload_envelope(wait_group, head).await {
                                panic!("error while handling head: {error:?}");
                            }
                        },
                        BuilderMessage::PrepareExecutionPayload(slot, safe_execution_payload_hash, finalized_execution_payload_hash) => {
                            let span = tracing::debug_span!("BuilderMessage::PrepareExecutionPayload", service = "builder");
                            let _enter = span.enter();

                            self.prepare_execution_payload(slot, safe_execution_payload_hash, finalized_execution_payload_hash).await;
                        },
                        BuilderMessage::ProposerPreferences(signed_preferences) => {
                            self.block_producer
                                .update_proposer_preferences(signed_preferences.message)
                                .await;
                        },
                        BuilderMessage::Stop => {
                            break;
                        }
                    }
                },

                complete => break,
            }
        }
    }

    #[instrument(
        parent = None,
        level = "debug",
        fields(
            service = "builder",
            tick = ?tick,
        ),
        skip_all
    )]
    async fn handle_tick(&mut self, _wait_group: W, tick: Tick) -> Result<()> {
        if self.signer.load().no_builder_keys() {
            return Ok(());
        }

        if let Some(metrics) = self.metrics.as_ref()
            && tick.is_start_of_interval()
        {
            let tick_delay = tick.delay::<P>(&self.chain_config, self.controller.genesis_time())?;
            debug_with_peers!("tick_delay: {tick_delay:?} for {tick:?}");
            metrics.set_tick_delay(tick.kind.as_ref(), tick_delay);
        }

        let Tick { slot, kind } = tick;

        debug_with_peers!("{kind:?} tick in slot {slot}");

        let Some(slot_head) = self
            .slot_head(slot)
            .await?
            .map_err(|head_far_behind| warn_with_peers!("{head_far_behind}"))
            .ok()
        else {
            return Ok(());
        };

        if !slot_head.beacon_state.is_post_gloas() {
            return Ok(());
        }

        if self
            .wait_for_fully_validated_head(&slot_head)
            .await
            .is_err()
        {
            warn_with_peers!(
                "builder cannot place a bid because \
                 chain head has not been fully verified by an execution engine",
            );
            return Ok(());
        }

        if kind == TickKind::PayloadAttestFourth {
            // Discard old payload bids at the end of slot
            self.own_signed_payload_bids.take();
        }

        if tick.is_start_of_slot() && self.builder_config.always_bid {
            let proposer_index = tokio::task::block_in_place(|| slot_head.proposer_index())?;
            let block_build_context = self.block_producer.new_build_context(
                slot_head.beacon_state.clone_arc(),
                slot_head.beacon_block_root,
                proposer_index,
                BlockBuildOptions::default(),
            );

            let Some(payload_bid) = block_build_context
                .produce_builder_default_payload_bid()
                .await?
            else {
                return Ok(());
            };

            let own_signed_payload_bids = self
                .own_signed_payload_bids(&slot_head, payload_bid)
                .await?;

            if own_signed_payload_bids.is_empty() {
                return Ok(());
            }

            debug_with_peers!(
                "builders [{}] publish execution payload bids for slot {}",
                own_signed_payload_bids
                    .iter()
                    .map(|b| b.message.builder_index)
                    .format(", "),
                slot_head.slot(),
            );

            for signed_payload_bid in own_signed_payload_bids {
                self.controller
                    .on_own_execution_payload_bid(signed_payload_bid.clone_arc());

                BuilderToP2p::PublishPayloadBid(signed_payload_bid.clone_arc()).send(&self.p2p_tx);
            }

            self.last_block_root = Some(slot_head.beacon_block_root);
        }

        self.last_tick = Some(tick);

        Ok(())
    }

    async fn maybe_publish_execution_payload_envelope(
        &self,
        wait_group: W,
        head: ChainLink<P>,
    ) -> Result<()> {
        let beacon_block_root = head.block_root;
        let parent_root = head.parent_root();

        let Some(last_tick) = self.last_tick else {
            return Ok(());
        };

        // Check if block is timely, otherwise builder withhold the payload
        if !(last_tick.slot == head.slot() && last_tick.is_before_attesting_interval()) {
            return Ok(());
        }

        // Get the block_root which used to create the block build context when placing bid
        let Some(last_block_root) = self.last_block_root else {
            return Ok(());
        };

        // Get beacon state at `last_block_root` to retrieve the proposer index
        let Some(beacon_state) = self
            .controller
            .state_before_or_at_slot(last_block_root, head.slot())
        else {
            return Ok(());
        };

        let Some(state) = beacon_state.post_gloas() else {
            return Ok(());
        };

        let Some(signed_payload_bid) = head
            .block
            .message()
            .body()
            .with_payload_bid()
            .map(BlockBodyWithPayloadBid::signed_execution_payload_bid)
        else {
            warn_with_peers!(
                "builder cannot publish payload envelope because \
                 head block has not been transited to post-Gloas block"
            );
            return Ok(());
        };

        let builder_index = signed_payload_bid.message.builder_index;

        // Block with self-build payload bid, proposer responsible to publish the payload envelope
        if builder_index == BUILDER_INDEX_SELF_BUILD {
            info_with_peers!("proposer of block {beacon_block_root:?} build their own payload",);
            return Ok(());
        }

        let public_key = accessors::builder_public_key(state, builder_index)?;
        let signer_snapshot = self.signer.load();

        if !signer_snapshot.has_key(*public_key) {
            return Ok(());
        }

        let proposer_index = tokio::task::block_in_place(|| {
            accessors::get_beacon_proposer_index(&self.chain_config, &beacon_state)
        })?;
        let block_build_context = self.block_producer.new_build_context(
            beacon_state.clone_arc(),
            last_block_root,
            proposer_index,
            BlockBuildOptions::default(),
        );

        let Some(envelope) = block_build_context
            .compute_execution_payload_envelope(beacon_block_root, parent_root, builder_index)
            .await?
        else {
            warn_with_peers!(
                "builder {} has been selected to publish payload envelope, \
                but block producer has no execution payload to construct",
                builder_index,
            );
            return Ok(());
        };

        let signature = match signer_snapshot
            .sign_without_slashing_protection(
                SigningMessage::ExecutionPayloadEnvelope(&envelope),
                envelope.signing_root(&self.chain_config, &beacon_state),
                Some(beacon_state.as_ref().into()),
                *public_key,
            )
            .await
        {
            Ok(signature) => signature.into(),
            Err(error) => {
                warn_with_peers!(
                    "failed to sign execution payload envelope (block: {:?}, builder_index: {}): \
                    {error:?}",
                    beacon_block_root,
                    builder_index,
                );

                return Ok(());
            }
        };

        let signed_envelope = Arc::new(SignedExecutionPayloadEnvelope {
            message: envelope,
            signature,
        });

        debug_with_peers!(
            "builder {} publishing execution payload envelope for (block {:?}, slot: {})",
            builder_index,
            beacon_block_root,
            head.slot(),
        );

        self.controller
            .on_own_execution_payload_envelope(wait_group, signed_envelope.clone_arc());

        BuilderToP2p::PublishExecutionPayloadEnvelope(signed_envelope).send(&self.p2p_tx);

        Ok(())
    }

    async fn prepare_execution_payload(
        &self,
        slot: Slot,
        safe_execution_payload_hash: ExecutionBlockHash,
        finalized_execution_payload_hash: ExecutionBlockHash,
    ) {
        let slot_head = self.safe_slot_head(slot).await;

        if let Some(slot_head) = slot_head {
            let proposer_index = match slot_head.proposer_index() {
                Ok(proposer_index) => proposer_index,
                Err(error) => {
                    error_with_peers!(
                        "failed to compute proposer index while preparing execution payload: {error:?}"
                    );
                    return;
                }
            };

            let should_prepare_execution_payload = Feature::AlwaysPrepareExecutionPayload
                .is_enabled()
                || self.signer.load().has_builder_keys();

            if !should_prepare_execution_payload {
                return;
            }

            let block_build_context = self.block_producer.new_build_context(
                slot_head.beacon_state.clone_arc(),
                slot_head.beacon_block_root,
                proposer_index,
                BlockBuildOptions::default(),
            );

            let payload_attributes = match block_build_context
                .prepare_execution_payload_attributes()
                .await
            {
                Ok(Some(attributes)) => attributes,
                Ok(None) => {
                    debug_with_peers!("no payload attributes prepared");
                    return;
                }
                Err(error) => {
                    warn_with_peers!("failed to prepare execution payload attributes: {error:?}");
                    return;
                }
            };

            if let Some(state) = slot_head.beacon_state.post_bellatrix() {
                let payload = state.latest_execution_payload_header();

                self.event_channels.send_payload_attributes_event(
                    slot_head.beacon_state.phase(),
                    proposer_index,
                    slot,
                    slot_head.beacon_block_root,
                    &payload_attributes,
                    payload.block_number(),
                    payload.block_hash(),
                );
            }

            block_build_context
                .prepare_execution_payload_for_slot(
                    slot,
                    safe_execution_payload_hash,
                    finalized_execution_payload_hash,
                    payload_attributes,
                )
                .await;
        }
    }

    fn own_public_keys(&self) -> HashSet<PublicKeyBytes> {
        self.signer.load().builder_keys().copied().collect()
    }

    async fn own_signed_payload_bids(
        &self,
        slot_head: &SlotHead<P>,
        payload_bid: ExecutionPayloadBid<P>,
    ) -> Result<&[Arc<SignedExecutionPayloadBid<P>>]> {
        if let Some(own_signed_payload_bids) = self.own_signed_payload_bids.get() {
            return Ok(own_signed_payload_bids);
        }

        let Some(state) = slot_head.beacon_state.post_gloas() else {
            return Ok(&[]);
        };

        let (triples, data): (Vec<_>, Vec<_>) = self
            .own_public_keys()
            .iter()
            .filter_map(|pubkey| {
                let builder_index = accessors::builder_index_of_public_key(state, pubkey)?;
                let data = ExecutionPayloadBid {
                    builder_index,
                    // TODO(gloas): set `value` (in gwei) that the builder will pay the proposer if the bid is accepted.
                    value: 0,
                    ..payload_bid.clone()
                };

                let signing_root = data.signing_root(&self.chain_config, &slot_head.beacon_state);
                let triple = SigningTriple {
                    message: SigningMessage::<P>::ExecutionPayloadBid(data.clone()),
                    signing_root,
                    public_key: *pubkey,
                };

                Some((triple, data))
            })
            .unzip();

        let snapshot = self.signer.load();

        let result = snapshot
            .sign_triples_without_slashing_protection(
                triples,
                Some(slot_head.beacon_state.as_ref().into()),
            )
            .await;

        let signatures = match result {
            Ok(signatures) => signatures,
            Err(error) => {
                warn_with_peers!("failed to sign payload bid: {error:?}");
                return Ok(&[]);
            }
        };

        self.own_signed_payload_bids
            .get_or_try_init(|| {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    metrics
                        .builder_own_signed_payload_bids_init_times
                        .start_timer()
                });

                let own_signed_payload_bids = signatures
                    .zip(data)
                    .map(|(signature, data)| {
                        Arc::new(SignedExecutionPayloadBid {
                            message: data,
                            signature: signature.into(),
                        })
                    })
                    .collect();

                Ok(own_signed_payload_bids)
            })
            .map(Vec::as_slice)
    }

    #[instrument(level = "debug", skip_all)]
    async fn safe_slot_head(&self, slot: Slot) -> Option<SlotHead<P>> {
        self.slot_head(slot)
            .await
            .map(Result::ok)
            .map_err(|error| error_with_peers!("state transition to slot {slot} failed: {error:?}"))
            .unwrap_or_default()
    }

    // The nested `Result` is inspired by `sled`:
    // <https://sled.rs/errors.html#making-unhandled-errors-unrepresentable>
    #[instrument(level = "debug", skip_all)]
    async fn slot_head(&self, slot: Slot) -> Result<Result<SlotHead<P>, HeadFarBehind>> {
        let WithStatus {
            value: head,
            status,
            ..
        } = self.controller.head();

        let block_root = head.block_root;
        let state = self.controller.state_by_chain_link(&head);
        let head_slot = head.slot();
        let max_empty_slots = self.builder_config.max_empty_slots;

        if head_slot + max_empty_slots < slot {
            return Ok(Err(HeadFarBehind {
                head_slot,
                max_empty_slots,
                slot,
            }));
        }

        let beacon_state = if state.slot() < slot {
            let controller = self.controller.clone_arc();

            tokio::task::spawn_blocking(move || {
                controller.preprocessed_state_post_block_blocking(block_root, slot)
            })
            .await??
        } else {
            state
        };

        Ok(Ok(SlotHead {
            config: self.chain_config.clone_arc(),
            beacon_block_root: block_root,
            beacon_state,
            optimistic: status.is_optimistic(),
        }))
    }

    async fn wait_for_fully_validated_head(&self, slot_head: &SlotHead<P>) -> Result<()> {
        const BLOCK_EVENT_WAIT_TIMEOUT: Duration = Duration::from_secs(1);

        if !slot_head.is_optimistic(&self.controller)? {
            return Ok(());
        }

        timeout(BLOCK_EVENT_WAIT_TIMEOUT, async {
            loop {
                let block_event = match self.event_channels.receiver_for(Topic::Block).recv().await
                {
                    Ok(Event::Block(block_event)) => block_event,
                    Ok(_) => continue,
                    Err(error) => {
                        warn_with_peers!("error receiving block event: {error:?}");
                        continue;
                    }
                };

                if block_event.block == slot_head.beacon_block_root
                    && !block_event.execution_optimistic
                {
                    break;
                }
            }
        })
        .await
        .map_err(Into::into)
    }
}
