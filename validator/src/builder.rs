//! <https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/builder.md>

use std::{collections::HashSet, sync::Arc, time::Duration};

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
use p2p::{BuilderToP2p, P2pToBuilder};
use prometheus_metrics::Metrics;
use signer::{Signer, SigningMessage, SigningTriple};
use std_ext::ArcExt as _;
use tokio::time::timeout;
use tracing::instrument;
use types::{
    config::Config as ChainConfig,
    gloas::containers::{ExecutionPayloadBid, SignedExecutionPayloadBid},
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
    own_signed_payload_bids: OnceCell<Vec<SignedExecutionPayloadBid>>,
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

    #[expect(clippy::too_many_lines)]
    #[instrument(
        parent = None,
        level = "debug",
        fields(
            service = "builder",
            tick = ?tick,
        ),
        skip_all
    )]
    async fn handle_tick(&mut self, wait_group: W, tick: Tick) -> Result<()> {
        if self.signer.load().no_builder_keys() {
            return Ok(());
        }

        if let Some(metrics) = self.metrics.as_ref() {
            if tick.is_start_of_interval() {
                let tick_delay =
                    tick.delay::<P>(&self.chain_config, self.controller.genesis_time())?;
                debug_with_peers!("tick_delay: {tick_delay:?} for {tick:?}");
                metrics.set_tick_delay(tick.kind.as_ref(), tick_delay);
            }
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
            warn_with_peers!(
                "builder cannot place a bid because \
                 head state has not been transited to Gloas state"
            );
            return Ok(());
        };

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

            let Some(payload_bid) = block_build_context.produce_default_payload_bid().await? else {
                return Ok(());
            };

            let own_signed_payload_bids = self
                .own_signed_payload_bids(&slot_head, payload_bid)
                .await?;

            if own_signed_payload_bids.is_empty() {
                return Ok(());
            }

            info_with_peers!(
                "builders [{}] publish execution payload bids for slot {}",
                own_signed_payload_bids
                    .iter()
                    .map(|b| b.message.builder_index)
                    .format(", "),
                slot_head.slot(),
            );

            for own_signed_payload_bid in own_signed_payload_bids {
                BuilderToP2p::PublishPayloadBid(Arc::new(*own_signed_payload_bid))
                    .send(&self.p2p_tx);
            }
        }

        self.last_tick = Some(tick);

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
        payload_bid: ExecutionPayloadBid,
    ) -> Result<&[SignedExecutionPayloadBid]> {
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
                    ..payload_bid
                };

                let triple = SigningTriple {
                    message: SigningMessage::<P>::ExecutionPayloadBid(data),
                    signing_root: data.signing_root(&self.chain_config, &slot_head.beacon_state),
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
                    .map(|(signature, data)| SignedExecutionPayloadBid {
                        message: data,
                        signature: signature.into(),
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
