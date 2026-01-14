//! <https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/builder.md>

use std::sync::Arc;

use anyhow::Result;
use block_producer::{BlockBuildOptions, BlockProducer};
use clock::Tick;
use debug_info::HealthCheck;
use derive_more::Display;
use eth1_api::ApiController;
use features::Feature;
use fork_choice_control::{BuilderMessage, EventChannels, Wait};
use fork_choice_store::ChainLink;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    select,
    stream::StreamExt as _,
};
use logging::{debug_with_peers, error_with_peers, info_with_peers, warn_with_peers};
use once_cell::sync::OnceCell;
use p2p::{BuilderToP2p, P2pToBuilder};
use prometheus_metrics::Metrics;
use signer::Signer;
use std_ext::ArcExt as _;
use tracing::instrument;
use types::{
    config::Config as ChainConfig,
    gloas::containers::{
        ExecutionPayloadBid, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
    },
    nonstandard::WithStatus,
    phase0::primitives::{ExecutionBlockHash, Slot},
    preset::Preset,
    traits::BeaconState as _,
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
    pub p2p_to_builder_rx: UnboundedReceiver<P2pToBuilder>,
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
    p2p_to_builder_rx: UnboundedReceiver<P2pToBuilder>,
    signer: Arc<Signer>,
    event_channels: Arc<EventChannels<P>>,
    last_tick: Option<Tick>,
    own_payload_bids: OnceCell<Vec<ExecutionPayloadBid>>,
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
            p2p_to_builder_rx,
        } = channels;

        Self {
            chain_config: controller.chain_config().clone_arc(),
            builder_config,
            block_producer,
            controller,
            // api_to_builder_rx,
            fork_choice_rx,
            p2p_tx,
            p2p_to_builder_rx,
            signer,
            event_channels,
            last_tick: None,
            own_payload_bids: OnceCell::new(),
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

                            self.maybe_publish_execution_payload_envelope(wait_group, head)
                                .await;
                        },
                        BuilderMessage::PrepareExecutionPayload(slot, safe_execution_payload_hash, finalized_execution_payload_hash) => {
                            let span = tracing::debug_span!("BuilderMessage::PrepareExecutionPayload", service = "builder");
                            let _enter = span.enter();

                            self.prepare_execution_payload(slot, safe_execution_payload_hash, finalized_execution_payload_hash).await;
                        },
                        BuilderMessage::Stop => {
                            break;
                        }
                    }
                },

                p2p_message = self.p2p_to_builder_rx.select_next_some() => {
                    match p2p_message {
                        P2pToBuilder::ProposerPreferences(proposer_preferences, gossip_id) => {

                        }
                    }
                },

                complete => break,
            }
        }
    }

    async fn handle_tick(&mut self, wait_group: W, tick: Tick) -> Result<()> {
        // TODO(gloas): Implement payload bids submission at slot start
        // - Consider to bid for building payload for the slot
        // - Call `BlockProducer::construct_payload_bid` to construct the payload bid
        // - Sign bid and broadcast to `execution_payload_bid` gossipsub topic
        Ok(())
    }

    async fn maybe_publish_execution_payload_envelope(
        &mut self,
        wait_group: W,
        head: ChainLink<P>,
    ) {
        // TODO(gloas): Implement payload envelope publishing
        // - Check the `signed_execution_payload_bid` in head block, and the block is timely
        // - Call `BlockProducer::construct_payload_envelope` to construct the payload envelope
        // - Sign the envelope with the builder key, then broadcast to `execution_payload`
        // gossipsub topic
    }

    async fn prepare_execution_payload(
        &mut self,
        slot: Slot,
        safe_execution_payload_hash: ExecutionBlockHash,
        finalized_execution_payload_hash: ExecutionBlockHash,
    ) {
        let slot_head = self.safe_slot_head(slot).await;

        if let Some(slot_head) = slot_head {
            let proposer_index = match slot_head.proposer_index() {
                Ok(proposer_index) => proposer_index,
                Err(error) => {
                    error_with_peers!("failed to compute proposer index while preparing execution payload: {error:?}");
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

    fn publish_payload_bid(&self, signed_bid: Arc<SignedExecutionPayloadBid>) {
        info_with_peers!(
            "Publishing execution payload bid (slot: {}, value: {} gwei)",
            signed_bid.message.slot,
            signed_bid.message.value
        );

        BuilderToP2p::PublishPayloadBid(signed_bid).send(&self.p2p_tx);
    }

    fn publish_execution_payload(
        &mut self,
        signed_envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
    ) {
        info_with_peers!(
            "Publishing execution payload envelope (block root: {:?}, slot: {})",
            signed_envelope.block_root(),
            signed_envelope.slot()
        );

        BuilderToP2p::PublishExecutionPayloadEnvelope(signed_envelope).send(&self.p2p_tx);
    }
}
