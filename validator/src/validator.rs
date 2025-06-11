//! <https://github.com/ethereum/consensus-specs/blob/b2f42bf4d79432ee21e2f2b3912ff4bbf7898ada/specs/phase0/validator.md>

use core::{error::Error as StdError, time::Duration};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::SystemTime,
};

use anyhow::{Error as AnyhowError, Result};
use block_producer::{BlockBuildOptions, BlockProducer, ValidatorBlindedBlock};
use bls::{PublicKeyBytes, Signature, SignatureBytes};
use builder_api::{
    consts::EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION,
    unphased::containers::{SignedValidatorRegistrationV1, ValidatorRegistrationV1},
    BuilderApi,
};
use clock::{Tick, TickKind};
use derive_more::Display;
use doppelganger_protection::DoppelgangerProtection;
use eth1_api::ApiController;
use eth2_libp2p::GossipId;
use features::Feature;
use fork_choice_control::{Event, EventChannels, Topic, ValidatorMessage, Wait};
use fork_choice_store::{AttestationItem, AttestationOrigin, ChainLink, StateCacheError};
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    future::{Either as EitherFuture, OptionFuture},
    lock::Mutex,
    select,
    stream::{FuturesOrdered, StreamExt as _},
};
use helper_functions::{
    accessors, misc,
    signing::{RandaoEpoch, SignForAllForks, SignForSingleFork},
};
use itertools::Itertools as _;
use keymanager::ProposerConfigs;
use liveness_tracker::ValidatorToLiveness;
use log::{debug, error, info, warn};
use once_cell::sync::OnceCell;
use operation_pools::{AttestationAggPool, Origin, PoolAdditionOutcome, SyncCommitteeAggPool};
use p2p::{P2pToValidator, ToSubnetService, ValidatorToP2p};
use prometheus_metrics::Metrics;
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use signer::{Signer, SigningMessage, SigningTriple};
use slasher::{SlasherToValidator, ValidatorToSlasher};
use slashing_protection::SlashingProtector;
use ssz::{BitList, BitVector, ContiguousList, ReadError};
use static_assertions::assert_not_impl_any;
use std_ext::ArcExt as _;
use tap::{Conv as _, Pipe as _};
use tokio::time::timeout;
use try_from_iterator::TryFromIterator as _;
use types::{
    altair::{
        containers::{ContributionAndProof, SignedContributionAndProof, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::{
        AggregateAndProof, Attestation, AttesterSlashing, BeaconState, SignedAggregateAndProof,
    },
    config::Config as ChainConfig,
    electra::containers::{
        AggregateAndProof as ElectraAggregateAndProof, Attestation as ElectraAttestation,
        SignedAggregateAndProof as ElectraSignedAggregateAndProof,
    },
    nonstandard::{OwnAttestation, Phase, SyncCommitteeEpoch, WithBlobsAndMev, WithStatus},
    phase0::{
        consts::GENESIS_SLOT,
        containers::{
            AggregateAndProof as Phase0AggregateAndProof, Attestation as Phase0Attestation,
            AttestationData, Checkpoint, SignedAggregateAndProof as Phase0SignedAggregateAndProof,
        },
        primitives::{Epoch, Slot, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, PostAltairBeaconState, SignedBeaconBlock as _},
};
use validator_statistics::ValidatorStatistics;

use crate::{
    messages::{ApiToValidator, InternalMessage},
    misc::{Aggregator, SyncCommitteeMember},
    own_beacon_committee_members::{BeaconCommitteeMember, OwnBeaconCommitteeMembers},
    own_sync_committee_subscriptions::OwnSyncCommitteeSubscriptions,
    slot_head::SlotHead,
    validator_config::ValidatorConfig,
};

const EPOCHS_TO_KEEP_REGISTERED_VALIDATORS: u64 = 2;

// Some relays reject requests whose bodies are too long.
// We have 50000 validators in Holesky. Their registrations add up to over 20 MiB.
//
// We originally set `MAX_VALIDATORS_PER_REGISTRATION` to 1000.
// That didn't work because processing registrations for 1000 validators takes around 3 seconds,
// which happens to be the default timeout for validator registration requests in `mev-boost`.
const MAX_VALIDATORS_PER_REGISTRATION: usize = 500;

#[derive(Display)]
#[display("too many empty slots after head: {head_slot} + {max_empty_slots} < {slot}")]
struct HeadFarBehind {
    head_slot: Slot,
    max_empty_slots: u64,
    slot: Slot,
}

// Prevent `HeadFarBehind` from being converted into an `AnyhowError`.
// See <https://sled.rs/errors.html>.
assert_not_impl_any!(HeadFarBehind: StdError);

pub struct Channels<P: Preset, W> {
    pub api_to_validator_rx: UnboundedReceiver<ApiToValidator<P>>,
    pub fork_choice_rx: UnboundedReceiver<ValidatorMessage<P, W>>,
    pub p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
    pub p2p_to_validator_rx: UnboundedReceiver<P2pToValidator<P>>,
    pub slasher_to_validator_rx: Option<UnboundedReceiver<SlasherToValidator<P>>>,
    pub subnet_service_tx: UnboundedSender<ToSubnetService>,
    pub validator_to_liveness_tx: Option<UnboundedSender<ValidatorToLiveness<P>>>,
    pub validator_to_slasher_tx: Option<UnboundedSender<ValidatorToSlasher>>,
}

#[expect(clippy::struct_field_names)]
pub struct Validator<P: Preset, W: Wait> {
    chain_config: Arc<ChainConfig>,
    validator_config: Arc<ValidatorConfig>,
    block_producer: Arc<BlockProducer<P, W>>,
    controller: ApiController<P, W>,
    api_to_validator_rx: UnboundedReceiver<ApiToValidator<P>>,
    fork_choice_rx: UnboundedReceiver<ValidatorMessage<P, W>>,
    p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
    p2p_to_validator_rx: UnboundedReceiver<P2pToValidator<P>>,
    last_tick: Option<Tick>,
    next_graffiti_index: usize,
    attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    own_beacon_committee_members: Arc<OwnBeaconCommitteeMembers>,
    own_singular_attestations: OnceCell<Vec<OwnAttestation<P>>>,
    own_sync_committee_members: OnceCell<Vec<SyncCommitteeMember>>,
    own_sync_committee_subscriptions: OwnSyncCommitteeSubscriptions<P>,
    published_own_sync_committee_messages_for: Option<SlotHead<P>>,
    own_aggregators: BTreeMap<AttestationData, Vec<Aggregator>>,
    builder_api: Option<Arc<BuilderApi>>,
    doppelganger_protection: Option<Arc<DoppelgangerProtection>>,
    event_channels: Arc<EventChannels<P>>,
    last_registration_epoch: Option<Epoch>,
    proposer_configs: Arc<ProposerConfigs>,
    signer: Arc<Signer>,
    slashing_protector: Arc<Mutex<SlashingProtector>>,
    slasher_to_validator_rx: Option<UnboundedReceiver<SlasherToValidator<P>>>,
    subnet_service_tx: UnboundedSender<ToSubnetService>,
    registered_validators:
        BTreeMap<Epoch, BTreeMap<PublicKeyBytes, (ValidatorRegistrationV1, Signature)>>,
    sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    metrics: Option<Arc<Metrics>>,
    validator_statistics: Option<Arc<ValidatorStatistics>>,
    internal_tx: UnboundedSender<InternalMessage>,
    internal_rx: UnboundedReceiver<InternalMessage>,
    validator_to_liveness_tx: Option<UnboundedSender<ValidatorToLiveness<P>>>,
    validator_to_slasher_tx: Option<UnboundedSender<ValidatorToSlasher>>,
}

impl<P: Preset, W: Wait + Sync> Validator<P, W> {
    #[expect(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        validator_config: Arc<ValidatorConfig>,
        block_producer: Arc<BlockProducer<P, W>>,
        controller: ApiController<P, W>,
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        builder_api: Option<Arc<BuilderApi>>,
        doppelganger_protection: Option<Arc<DoppelgangerProtection>>,
        event_channels: Arc<EventChannels<P>>,
        proposer_configs: Arc<ProposerConfigs>,
        signer: Arc<Signer>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
        metrics: Option<Arc<Metrics>>,
        validator_statistics: Option<Arc<ValidatorStatistics>>,
        channels: Channels<P, W>,
    ) -> Self {
        let Channels {
            api_to_validator_rx,
            fork_choice_rx,
            p2p_tx,
            p2p_to_validator_rx,
            slasher_to_validator_rx,
            subnet_service_tx,
            validator_to_liveness_tx,
            validator_to_slasher_tx,
        } = channels;

        let (internal_tx, internal_rx) = futures::channel::mpsc::unbounded();

        let own_beacon_committee_members = Arc::new(OwnBeaconCommitteeMembers::new(
            controller.chain_config().clone_arc(),
            signer.clone_arc(),
        ));

        Self {
            chain_config: controller.chain_config().clone_arc(),
            validator_config,
            block_producer,
            controller,
            api_to_validator_rx,
            fork_choice_rx,
            p2p_tx,
            p2p_to_validator_rx,
            last_tick: None,
            next_graffiti_index: 0,
            attestation_agg_pool,
            own_beacon_committee_members,
            own_singular_attestations: OnceCell::new(),
            own_sync_committee_members: OnceCell::new(),
            own_sync_committee_subscriptions: OwnSyncCommitteeSubscriptions::default(),
            published_own_sync_committee_messages_for: None,
            own_aggregators: BTreeMap::new(),
            builder_api,
            doppelganger_protection,
            event_channels,
            last_registration_epoch: None,
            proposer_configs,
            signer,
            slashing_protector,
            sync_committee_agg_pool,
            slasher_to_validator_rx,
            subnet_service_tx,
            registered_validators: BTreeMap::new(),
            metrics,
            validator_statistics,
            internal_rx,
            internal_tx,
            validator_to_liveness_tx,
            validator_to_slasher_tx,
        }
    }

    pub async fn run(self) -> Result<()> {
        self.run_internal().await;

        Ok(())
    }

    #[expect(clippy::cognitive_complexity)]
    #[expect(clippy::too_many_lines)]
    async fn run_internal(mut self) {
        loop {
            let mut slasher_to_validator_rx = self
                .slasher_to_validator_rx
                .as_mut()
                .map(EitherFuture::Left)
                .unwrap_or_else(|| EitherFuture::Right(futures::stream::pending()));

            select! {
                message = self.internal_rx.select_next_some() => match message {
                    InternalMessage::DoppelgangerProtectionResult(result) => {
                        if let Err(error) = result {
                            panic!("Doppelganger protection error: {error}");
                        }
                    }
                },

                message = self.fork_choice_rx.select_next_some() => match message {
                    ValidatorMessage::Tick(wait_group, tick) => {
                        if let Err(error) = self.handle_tick(wait_group, tick).await {
                            panic!("error while handling tick: {error:?}");
                        }
                    }
                    ValidatorMessage::Head(wait_group, head) => {
                        if let Some(validator_to_liveness_tx) = &self.validator_to_liveness_tx {
                            let state = self.controller.state_by_chain_link(&head);
                            ValidatorToLiveness::Head(head.block.clone_arc(), state).send(validator_to_liveness_tx);
                        }

                        self.attest_gossip_block(&wait_group, head).await;
                    }
                    ValidatorMessage::ValidAttestation(wait_group, attestation) => {
                        self.attestation_agg_pool
                            .insert_attestation(wait_group, &attestation, None);

                        if let Some(validator_to_liveness_tx) = &self.validator_to_liveness_tx {
                            ValidatorToLiveness::ValidAttestation(attestation)
                                .send(validator_to_liveness_tx);
                        }
                    },
                    ValidatorMessage::PrepareExecutionPayload(slot, safe_execution_payload_hash, finalized_execution_payload_hash) => {
                        let slot_head = self.safe_slot_head(slot).await;

                        if let Some(slot_head) = slot_head {
                            let proposer_index = match slot_head.proposer_index() {
                                Ok(proposer_index) => proposer_index,
                                Err(error) => {
                                    error!("failed to compute proposer index while preparing execution payload: {error:?}");
                                    continue;
                                }
                            };

                            let should_prepare_execution_payload = Feature::AlwaysPrepareExecutionPayload.is_enabled()
                                || self.attestation_agg_pool.is_registered_validator(proposer_index).await;

                            if !should_prepare_execution_payload {
                                continue;
                            }

                            let block_build_context = self.block_producer.new_build_context(
                                slot_head.beacon_state.clone_arc(),
                                slot_head.beacon_block_root,
                                proposer_index,
                                BlockBuildOptions::default(),
                            );

                            let payload_attributes = match block_build_context.prepare_execution_payload_attributes().await {
                                Ok(Some(attributes)) => attributes,
                                Ok(None) => {
                                    debug!("no payload attributes prepared");
                                    continue;
                                },
                                Err(error) => {
                                    warn!("failed to prepare execution payload attributes: {error:?}");
                                    continue
                                },
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

                            block_build_context.prepare_execution_payload_for_slot(
                                slot,
                                safe_execution_payload_hash,
                                finalized_execution_payload_hash,
                                payload_attributes,
                            ).await;
                        }
                    }
                    ValidatorMessage::Stop => {
                        if let Some(validator_to_liveness_tx) = &self.validator_to_liveness_tx {
                            ValidatorToLiveness::Stop.send(validator_to_liveness_tx);
                        }

                        break;
                    }
                },

                slashing = slasher_to_validator_rx.select_next_some() => match slashing {
                    SlasherToValidator::AttesterSlashing(attester_slashing) => {
                        self.block_producer.add_new_attester_slashing(AttesterSlashing::Phase0(attester_slashing)).await;
                    }
                    SlasherToValidator::ProposerSlashing(proposer_slashing) => {
                        self.block_producer.add_new_proposer_slashing(proposer_slashing).await;
                    }
                },

                gossip_message = self.p2p_to_validator_rx.select_next_some() => match gossip_message {
                    P2pToValidator::AttesterSlashing(slashing, gossip_id) => {
                        let outcome = match self
                            .block_producer
                            .handle_external_attester_slashing(*slashing.clone())
                            .await {
                                Ok(outcome) => outcome,
                                Err(error) => {
                                    warn!("failed to handle attester slashing: {error}");
                                    continue;
                                }
                            };

                        if matches!(outcome, PoolAdditionOutcome::Accept) {
                            self.event_channels.send_attester_slashing_event(slashing);
                        }

                        self.handle_pool_addition_outcome_for_p2p(outcome, gossip_id);
                    }
                    P2pToValidator::ProposerSlashing(slashing, gossip_id) => {
                        let outcome = match self
                            .block_producer
                            .handle_external_proposer_slashing(*slashing)
                            .await {
                                Ok(outcome) => outcome,
                                Err(error) => {
                                    warn!("failed to handle proposer slashing: {error}");
                                    continue;
                                }
                            };

                        if matches!(outcome, PoolAdditionOutcome::Accept) {
                            self.event_channels.send_proposer_slashing_event(*slashing);
                        }

                        self.handle_pool_addition_outcome_for_p2p(outcome, gossip_id);
                    }
                    P2pToValidator::VoluntaryExit(voluntary_exit, gossip_id) => {
                        let outcome = match self
                            .block_producer
                            .handle_external_voluntary_exit(*voluntary_exit)
                            .await {
                                Ok(outcome) => outcome,
                                Err(error) => {
                                    warn!("failed to handle voluntary exit: {error}");
                                    continue;
                                }
                            };

                        if matches!(outcome, PoolAdditionOutcome::Accept) {
                            self.event_channels.send_voluntary_exit_event(*voluntary_exit);
                        }

                        self.handle_pool_addition_outcome_for_p2p(outcome, gossip_id);
                    }
                },

                api_message = self.api_to_validator_rx.select_next_some() => {
                    let success = match api_message {
                        ApiToValidator::RegisteredValidators(sender) => {
                            let registered_pubkeys = self
                                .registered_validators
                                .values()
                                .flat_map(BTreeMap::keys)
                                .copied()
                                .collect();

                            sender.send(registered_pubkeys).is_ok()
                        },
                        ApiToValidator::SignedValidatorRegistrations(sender, registrations) => {
                            let (registered_validators, errors): (Vec<_>, Vec<_>) = registrations
                                .into_iter()
                                .enumerate()
                                .map(|(index, registration)| {
                                    let SignedValidatorRegistrationV1 {
                                        message,
                                        signature,
                                    } = registration;

                                    match signature.try_into() {
                                        Ok(signature) => Ok((message, signature)),
                                        Err(error) => Err((index, AnyhowError::new(error))),
                                    }
                                })
                                .partition_result();


                            if errors.is_empty() {
                                let current_slot = self.controller.slot();
                                let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);

                                let registrations = registered_validators
                                    .into_iter()
                                    .map(|registration| (registration.0.pubkey, registration))
                                    .collect();

                                self.registered_validators
                                    .entry(current_epoch)
                                    .and_modify(|map| map.extend(&registrations))
                                    .or_insert(registrations);
                            }

                            sender.send(errors).is_ok()
                        },
                        ApiToValidator::SignedContributionsAndProofs(sender, contributions_and_proofs) => {
                            let current_slot = self.controller.slot();

                            let slot_head = self.safe_slot_head(current_slot).await;

                            let failures = slot_head
                                .map(|slot_head| {
                                    self.handle_external_contributions_and_proofs(
                                        slot_head,
                                        contributions_and_proofs,
                                    )
                                })
                                .conv::<OptionFuture<_>>()
                                .await;

                            sender.send(failures).is_ok()
                        }
                    };

                    if !success {
                        debug!("send to HTTP API failed because the receiver was dropped");
                    }
                }

                complete => break,
            }
        }
    }

    fn handle_pool_addition_outcome_for_p2p(
        &self,
        outcome: PoolAdditionOutcome,
        gossip_id: GossipId,
    ) {
        let message = match outcome {
            PoolAdditionOutcome::Accept => ValidatorToP2p::Accept(gossip_id),
            PoolAdditionOutcome::Ignore => ValidatorToP2p::Ignore(gossip_id),
            PoolAdditionOutcome::Reject(rejection_error, _) => {
                ValidatorToP2p::Reject(gossip_id, rejection_error)
            }
        };

        message.send(&self.p2p_tx);
    }

    #[expect(clippy::cognitive_complexity)]
    #[expect(clippy::too_many_lines)]
    async fn handle_tick(&mut self, wait_group: W, tick: Tick) -> Result<()> {
        if let Some(metrics) = self.metrics.as_ref() {
            if tick.is_start_of_interval() {
                let tick_delay = tick.delay(&self.chain_config, self.controller.genesis_time())?;
                debug!("tick_delay: {tick_delay:?} for {tick:?}");
                metrics.set_tick_delay(tick.kind.as_ref(), tick_delay);
            }
        }

        let Tick { slot, kind } = tick;

        let no_validators = self.signer.load().no_keys()
            && self.registered_validators.is_empty()
            && self.block_producer.no_prepared_proposers().await;

        debug!("{kind:?} tick in slot {slot}");

        let current_epoch = misc::compute_epoch_at_slot::<P>(slot);

        if tick.is_start_of_epoch::<P>() {
            let _timer = self
                .metrics
                .as_ref()
                .map(|metrics| metrics.validator_epoch_processing_times.start_timer());

            self.register_validators(current_epoch).await;

            if let Some(validator_to_slasher_tx) = &self.validator_to_slasher_tx {
                ValidatorToSlasher::Epoch(current_epoch).send(validator_to_slasher_tx);
            }

            if let Some(validator_to_liveness_tx) = &self.validator_to_liveness_tx {
                ValidatorToLiveness::Epoch(current_epoch).send(validator_to_liveness_tx);
            }

            self.discard_old_registered_validators(current_epoch);
            self.block_producer.discard_old_data(current_epoch).await;
            self.own_sync_committee_subscriptions
                .discard_old_subscriptions(current_epoch);

            if let Some(validator_statistics) = self.validator_statistics.as_ref() {
                let validator_statistics = validator_statistics.clone_arc();
                let controller = self.controller.clone_arc();

                tokio::spawn(async move {
                    if controller.is_forward_synced() {
                        validator_statistics
                            .report_validator_performance(&controller, current_epoch)
                            .await;
                    }

                    validator_statistics.prune(current_epoch).await;
                });
            }
        }

        if self.last_registration_epoch.is_none() {
            self.register_validators(current_epoch).await;
        }

        self.track_collection_metrics().await;

        let slot_head = if no_validators {
            None
        } else {
            self.slot_head(slot)
                .await?
                .map_err(|head_far_behind| warn!("{head_far_behind}"))
                .ok()
        };

        self.update_subnet_subscriptions(&wait_group, slot_head.as_ref());

        if misc::is_epoch_start::<P>(slot) && kind == TickKind::AggregateFourth {
            self.refresh_signer_keys();
        }

        let Some(slot_head) = slot_head else {
            return Ok(());
        };

        if tick.is_start_of_slot() {
            if let Some(doppelganger_protection) = &self.doppelganger_protection {
                let doppelganger_protection = doppelganger_protection.clone_arc();
                let internal_tx = self.internal_tx.clone();

                tokio::spawn(async move {
                    let result = doppelganger_protection
                        .detect_doppelgangers::<P>(slot)
                        .await;

                    InternalMessage::DoppelgangerProtectionResult(result).send(&internal_tx);
                });
            }
        }

        self.attestation_agg_pool
            .compute_proposer_indices(slot_head.beacon_state.clone_arc());

        if let Some(state) = slot_head.beacon_state.post_altair() {
            if misc::is_epoch_start::<P>(state.slot() + 1) {
                self.own_sync_committee_members.take();

                self.own_sync_committee_members.get_or_try_init(|| {
                    self.own_sync_committee_members_for_epoch(SyncCommitteeEpoch::Next, state)
                })?;
            }

            self.own_sync_committee_members.get_or_try_init(|| {
                self.own_sync_committee_members_for_epoch(SyncCommitteeEpoch::Current, state)
            })?;
        }

        match kind {
            TickKind::Propose => {
                let _timer = self
                    .metrics
                    .as_ref()
                    .map(|metrics| metrics.validator_propose_tick_times.start_timer());

                self.discard_previous_slot_attestations();
                self.propose(wait_group, &slot_head).await?;
                self.published_own_sync_committee_messages_for = None;
            }
            TickKind::Attest => {
                let _timer = self
                    .metrics
                    .as_ref()
                    .map(|metrics| metrics.validator_attest_tick_times.start_timer());

                if let Err(error) = self
                    .attest_and_start_aggregating(&wait_group, &slot_head)
                    .await
                {
                    error!("failed to produce and publish own attestations: {error:?}");
                }

                if let Err(error) = self
                    .publish_sync_committee_messages(&wait_group, slot_head)
                    .await
                {
                    error!("failed to produce and publish own sync_committee messages: {error:?}");
                }
            }
            TickKind::Aggregate => {
                let _timer = self
                    .metrics
                    .as_ref()
                    .map(|metrics| metrics.validator_aggregate_tick_times.start_timer());

                self.publish_aggregates_and_proofs(&wait_group, &slot_head)
                    .await;

                self.publish_contributions_and_proofs(
                    self.published_own_sync_committee_messages_for
                        .as_ref()
                        .unwrap_or(&slot_head),
                )
                .await;

                if misc::is_epoch_start::<P>(slot) {
                    let current_epoch = misc::compute_epoch_at_slot::<P>(slot);
                    self.spawn_slashing_protection_pruning(current_epoch);
                }
            }
            _ => {}
        }

        self.last_tick = Some(tick);

        Ok(())
    }

    async fn safe_slot_head(&self, slot: Slot) -> Option<SlotHead<P>> {
        self.slot_head(slot)
            .await
            .map(Result::ok)
            .map_err(|error| error!("state transition to slot {slot} failed: {error:?}"))
            .unwrap_or_default()
    }

    // The nested `Result` is inspired by `sled`:
    // <https://sled.rs/errors.html#making-unhandled-errors-unrepresentable>
    async fn slot_head(&self, slot: Slot) -> Result<Result<SlotHead<P>, HeadFarBehind>> {
        let WithStatus {
            value: head,
            status,
            ..
        } = self.controller.head();

        let block_root = head.block_root;
        let state = self.controller.state_by_chain_link(&head);
        let head_slot = head.slot();
        let max_empty_slots = self.validator_config.max_empty_slots;

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
                controller.preprocessed_state_post_block(block_root, slot)
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

    /// <https://github.com/ethereum/consensus-specs/blob/b2f42bf4d79432ee21e2f2b3912ff4bbf7898ada/specs/phase0/validator.md#block-proposal>
    #[expect(clippy::too_many_lines)]
    async fn propose(&mut self, wait_group: W, slot_head: &SlotHead<P>) -> Result<()> {
        if slot_head.slot() == GENESIS_SLOT {
            // All peers should already have the genesis block.
            // It would fail multiple validations if it were published like non-genesis blocks.
            return Ok(());
        }

        if self.wait_for_fully_validated_head(slot_head).await.is_err() {
            warn!(
                "validator cannot produce a block because \
                 chain head has not been fully verified by an execution engine",
            );
            return Ok(());
        }

        let proposer_index = tokio::task::block_in_place(|| slot_head.proposer_index())?;
        let public_key = slot_head.public_key(proposer_index);
        let signer_snapshot = self.signer.load();

        if !signer_snapshot.has_key(*public_key) {
            return Ok(());
        }

        let doppelganger_protection = self
            .doppelganger_protection
            .as_deref()
            .map(DoppelgangerProtection::load);

        if let Some(doppelganger_protection) = &doppelganger_protection {
            if !doppelganger_protection.is_validator_active(*public_key) {
                info!(
                    "Validator {public_key:?} skipping proposer duty in slot {} \
                     since not enough time has passed to ensure there are \
                     no doppelganger validators participating on network. \
                     Validator will start performing duties on slot {}.",
                    slot_head.slot(),
                    doppelganger_protection.tracking_end_slot::<P>(*public_key),
                );
                return Ok(());
            }
        }

        let _propose_timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.validator_propose_times.start_timer());

        let graffiti = self
            .proposer_configs
            .graffiti_bytes(*public_key)?
            .or_else(|| self.next_graffiti());

        let block_build_context = self.block_producer.new_build_context(
            slot_head.beacon_state.clone_arc(),
            slot_head.beacon_block_root,
            proposer_index,
            BlockBuildOptions {
                graffiti,
                disable_blockprint_graffiti: self.validator_config.disable_blockprint_graffiti,
                builder_boost_factor: self.validator_config.default_builder_boost_factor,
                ..BlockBuildOptions::default()
            },
        );

        let execution_payload_header_handle =
            block_build_context.get_execution_payload_header(*public_key);

        let local_execution_payload_handle = block_build_context.get_local_execution_payload();

        let epoch = slot_head.current_epoch();

        let result = signer_snapshot
            .sign_without_slashing_protection(
                SigningMessage::RandaoReveal { epoch },
                RandaoEpoch::from(epoch).signing_root(&self.chain_config, &slot_head.beacon_state),
                Some(slot_head.beacon_state.as_ref().into()),
                *public_key,
            )
            .await;

        let randao_reveal = match result {
            Ok(signature) => signature.into(),
            Err(error) => {
                warn!(
                    "failed to sign RANDAO reveal (epoch: {epoch}, public_key: {public_key}): \
                    {error:?}",
                );

                return Ok(());
            }
        };

        let beacon_block_option = match block_build_context
            .build_blinded_beacon_block(
                randao_reveal,
                execution_payload_header_handle,
                local_execution_payload_handle,
            )
            .await
        {
            Ok(block_opt) => block_opt,
            Err(error) => {
                warn!("failed to produce beacon block: {error}");
                return Ok(());
            }
        };

        let Some((
            WithBlobsAndMev {
                value: validator_blinded_block,
                proofs: mut block_proofs,
                blobs: mut block_blobs,
                ..
            },
            _block_rewards,
        )) = beacon_block_option
        else {
            warn!(
                "validator {} skipping beacon block proposal in slot {}",
                proposer_index,
                slot_head.slot(),
            );
            return Ok(());
        };

        let beacon_block = match validator_blinded_block {
            ValidatorBlindedBlock::BlindedBeaconBlock { blinded_block, .. } => {
                let Some(signature) = slot_head
                    .sign_beacon_block(
                        &self.signer,
                        &blinded_block,
                        (&blinded_block).into(),
                        *public_key,
                        self.slashing_protector.clone_arc(),
                    )
                    .await
                else {
                    return Ok(());
                };

                let signed_blinded_block = blinded_block.with_signature(signature);

                let builder_api = self.builder_api.as_ref().expect(
                    "Builder API should be present as it was used to query ExecutionPayloadHeader",
                );

                let WithBlobsAndMev {
                    value: execution_payload,
                    proofs,
                    blobs,
                    ..
                } = match builder_api
                    .post_blinded_block(
                        &self.chain_config,
                        self.controller.genesis_time(),
                        &signed_blinded_block,
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        warn!("failed to post blinded block to the builder node: {error:?}");
                        return Ok(());
                    }
                };

                block_proofs = proofs;
                block_blobs = blobs;

                debug!("received execution payload from the builder node: {execution_payload:?}");

                let (message, signature) = signed_blinded_block.split();

                message
                    .with_execution_payload(execution_payload)?
                    .with_signature(signature)
            }
            ValidatorBlindedBlock::BeaconBlock(block) => {
                match slot_head
                    .sign_beacon_block(
                        &self.signer,
                        &block,
                        (&block).into(),
                        *public_key,
                        self.slashing_protector.clone_arc(),
                    )
                    .await
                {
                    Some(signature) => block.with_signature(signature),
                    None => return Ok(()),
                }
            }
        };

        info!(
            "validator {} proposing beacon block with root {:?} in slot {}",
            proposer_index,
            beacon_block.message().hash_tree_root(),
            slot_head.slot(),
        );

        debug!("beacon block: {beacon_block:?}");

        let block = Arc::new(beacon_block);

        if let Some(blobs) = block_blobs {
            if !blobs.is_empty() {
                if self
                    .chain_config
                    .phase_at_slot::<P>(slot_head.slot())
                    .is_peerdas_activated()
                {
                    let cells_and_kzg_proofs = eip_7594::try_convert_to_cells_and_kzg_proofs::<P>(
                        blobs.as_ref(),
                        block_proofs.unwrap_or_default().as_ref(),
                        self.controller.store_config().kzg_backend,
                    )?;
                    for data_column_sidecar in eip_7594::construct_data_column_sidecars(
                        &block,
                        &cells_and_kzg_proofs,
                        &self.chain_config,
                    )? {
                        let data_column_sidecar = Arc::new(data_column_sidecar);

                        if self
                            .controller
                            .sampling_columns()
                            .into_iter()
                            .contains(&data_column_sidecar.index)
                        {
                            self.controller.on_own_data_column_sidecar(
                                wait_group.clone(),
                                data_column_sidecar.clone_arc(),
                            );
                        }

                        if !self.validator_config.withhold_data_columns_publishing {
                            ValidatorToP2p::PublishDataColumnSidecar(data_column_sidecar)
                                .send(&self.p2p_tx);
                        }
                    }
                } else {
                    for blob_sidecar in misc::construct_blob_sidecars(
                        &block,
                        blobs.into_iter(),
                        block_proofs.unwrap_or_default().into_iter(),
                    )? {
                        let blob_sidecar = Arc::new(blob_sidecar);

                        self.controller
                            .on_own_blob_sidecar(wait_group.clone(), blob_sidecar.clone_arc());

                        ValidatorToP2p::PublishBlobSidecar(blob_sidecar).send(&self.p2p_tx);
                    }
                }
            }
        }

        self.controller
            .on_own_block(wait_group.clone(), block.clone_arc());

        ValidatorToP2p::PublishBeaconBlock(block).send(&self.p2p_tx);

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.validator_propose_successes.inc();
        }

        Ok(())
    }

    /// See:
    /// - <https://github.com/ethereum/consensus-specs/blob/b2f42bf4d79432ee21e2f2b3912ff4bbf7898ada/specs/phase0/validator.md#attesting>
    /// - <https://github.com/ethereum/consensus-specs/blob/b2f42bf4d79432ee21e2f2b3912ff4bbf7898ada/specs/phase0/validator.md#attestation-aggregation>
    #[expect(clippy::too_many_lines)]
    async fn attest_and_start_aggregating(
        &mut self,
        wait_group: &W,
        slot_head: &SlotHead<P>,
    ) -> Result<()> {
        if self.wait_for_fully_validated_head(slot_head).await.is_err() {
            warn!(
                "validator cannot participate in attestation because \
                 chain head has not been fully verified by an execution engine",
            );

            return Ok(());
        }

        // Skip attesting if validators already attested at slot
        if self.attested_in_current_slot() {
            return Ok(());
        }

        let timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.validator_attest_times.start_timer());

        let needs_to_update_subscriptions = self
            .own_beacon_committee_members
            .needs_to_compute_members_at_slot(slot_head.slot())
            .await;

        let Some(own_members) = self
            .own_beacon_committee_members
            .get_or_init_at_slot(&slot_head.beacon_state, slot_head.slot())
            .await
        else {
            return Ok(());
        };

        if needs_to_update_subscriptions {
            update_beacon_committee_subscriptions(
                slot_head.slot(),
                &own_members,
                &self.subnet_service_tx,
            )
            .await;
        }

        let own_singular_attestations = self
            .own_singular_attestations(slot_head, &own_members)
            .await?;

        if own_singular_attestations.is_empty() {
            prometheus_metrics::stop_and_discard(timer);
            return Ok(());
        }

        info!(
            "validators [{}] attesting in slot {}",
            own_singular_attestations
                .iter()
                .map(|a| a.validator_index)
                .format(", "),
            slot_head.slot(),
        );

        for own_attestation in own_singular_attestations {
            let OwnAttestation {
                validator_index,
                attestation,
                ..
            } = own_attestation;

            let committee_index = misc::committee_index(attestation);

            debug!(
                "validator {} of committee {} ({:?}) attesting in slot {}: {:?}",
                validator_index,
                committee_index,
                slot_head
                    .beacon_committee(committee_index)
                    .expect("committee was already used to construct attestation"),
                slot_head.slot(),
                attestation,
            );

            let attestation = Arc::new(attestation.clone());
            let subnet_id = slot_head.subnet_id(attestation.data().slot, committee_index)?;

            self.controller
                .on_singular_attestation(AttestationItem::unverified(
                    attestation.clone_arc(),
                    AttestationOrigin::Own(subnet_id),
                ));

            ValidatorToP2p::PublishSingularAttestation(attestation.clone_arc(), subnet_id)
                .send(&self.p2p_tx);

            self.attestation_agg_pool.insert_attestation(
                wait_group.clone(),
                &attestation,
                Some(*validator_index),
            );
        }

        prometheus_metrics::stop_and_record(timer);

        let own_members = own_members
            .iter()
            .map(|member| ((member.committee_index, member.validator_index), member))
            .collect::<HashMap<_, _>>();

        self.own_aggregators = own_singular_attestations
            .iter()
            .filter_map(|own_attestation| {
                let committee_index = misc::committee_index(&own_attestation.attestation);

                let member =
                    own_members.get(&(committee_index, own_attestation.validator_index))?;

                let BeaconCommitteeMember {
                    public_key,
                    validator_index,
                    position_in_committee,
                    is_aggregator,
                    selection_proof,
                    ..
                } = **member;

                if !is_aggregator {
                    return None;
                }

                let aggregator = selection_proof.map(|selection_proof| Aggregator {
                    aggregator_index: validator_index,
                    position_in_committee,
                    public_key,
                    selection_proof,
                })?;

                let data = AttestationData {
                    index: committee_index,
                    ..own_attestation.attestation.data()
                };

                Some((data, aggregator))
            })
            .pipe(group_into_btreemap);

        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    async fn publish_aggregates_and_proofs(&self, wait_group: &W, slot_head: &SlotHead<P>) {
        if self.wait_for_fully_validated_head(slot_head).await.is_err() {
            warn!(
                "validators cannot participate in aggregation because \
                 chain head has not been fully verified by an execution engine",
            );
            return;
        }

        let config = &self.chain_config;
        let phase = slot_head.phase();

        let (triples, proofs): (Vec<_>, Vec<_>) = self
            .own_aggregators
            .iter()
            .map(|(data, aggregators)| async {
                self.attestation_agg_pool
                    .best_aggregate_attestation(*data)
                    .await
                    .into_iter()
                    .flat_map(|aggregate| {
                        aggregators.iter().filter_map(move |aggregator| {
                            let Aggregator {
                                aggregator_index,
                                position_in_committee,
                                public_key,
                                selection_proof,
                            } = *aggregator;

                            if !*aggregate.aggregation_bits.get(position_in_committee)? {
                                return None;
                            }

                            let aggregate_and_proof = if phase < Phase::Electra {
                                AggregateAndProof::from(Phase0AggregateAndProof {
                                    aggregator_index,
                                    aggregate: aggregate.clone(),
                                    selection_proof,
                                })
                            } else {
                                let aggregate = operation_pools::convert_to_electra_attestation(
                                    aggregate.clone(),
                                )
                                .ok()?;

                                AggregateAndProof::from(ElectraAggregateAndProof {
                                    aggregator_index,
                                    aggregate,
                                    selection_proof,
                                })
                            };

                            let triple = SigningTriple {
                                message: SigningMessage::AggregateAndProof(Box::new(
                                    aggregate_and_proof.clone(),
                                )),
                                signing_root: aggregate_and_proof
                                    .signing_root(config, &slot_head.beacon_state),
                                public_key,
                            };

                            Some((triple, aggregate_and_proof))
                        })
                    })
                    .collect_vec()
            })
            .collect::<FuturesOrdered<_>>()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .unzip();

        let sign_result = self
            .signer
            .load()
            .sign_triples_without_slashing_protection(
                triples,
                Some(slot_head.beacon_state.as_ref().into()),
            )
            .await;

        let signatures = match sign_result {
            Ok(signature) => signature,
            Err(error) => {
                warn!("failed to sign aggregates and proofs: {error:?}");
                return;
            }
        };

        let aggregates_and_proofs = signatures
            .zip(proofs)
            .map(|(signature, message)| {
                let aggregate_and_proof = match message {
                    AggregateAndProof::Phase0(message) => {
                        SignedAggregateAndProof::from(Phase0SignedAggregateAndProof {
                            message,
                            signature: signature.into(),
                        })
                    }
                    AggregateAndProof::Electra(message) => {
                        SignedAggregateAndProof::from(ElectraSignedAggregateAndProof {
                            message,
                            signature: signature.into(),
                        })
                    }
                };

                debug!("constructed aggregate and proof: {aggregate_and_proof:?}");

                aggregate_and_proof
            })
            .collect_vec();

        let Some(aggregate_and_proof) = aggregates_and_proofs.first() else {
            return;
        };

        info!(
            "validators [{}] aggregating in slot {}",
            aggregates_and_proofs
                .iter()
                .map(SignedAggregateAndProof::aggregator_index)
                .format(", "),
            aggregate_and_proof.slot(),
        );

        for aggregate_and_proof in aggregates_and_proofs {
            let attestation = Arc::new(aggregate_and_proof.aggregate());
            let aggregate_and_proof = Arc::new(aggregate_and_proof);

            self.attestation_agg_pool
                .insert_attestation(wait_group.clone(), &attestation, None);

            ValidatorToP2p::PublishAggregateAndProof(aggregate_and_proof).send(&self.p2p_tx);
        }
    }

    /// <https://github.com/ethereum/consensus-specs/blob/v1.1.1/specs/altair/validator.md#broadcast-sync-committee-message>
    async fn publish_sync_committee_messages(
        &mut self,
        wait_group: &W,
        slot_head: SlotHead<P>,
    ) -> Result<()> {
        // > To reduce complexity during the Altair fork, sync committees are not expected to
        // > produce signatures for `compute_epoch_at_slot(ALTAIR_FORK_EPOCH) - 1`.
        if !slot_head.has_sync_committee() {
            return Ok(());
        }

        if self
            .published_own_sync_committee_messages_for
            .as_ref()
            .is_some_and(|published| published.slot() == slot_head.slot())
        {
            return Ok(());
        }

        if self
            .wait_for_fully_validated_head(&slot_head)
            .await
            .is_err()
        {
            warn!(
                "validator cannot participate in sync committees because \
                 chain head has not been fully verified by an execution engine",
            );
            return Ok(());
        }

        let own_messages = self.own_sync_committee_messages(&slot_head).await?;

        for (subcommittee_index, messages) in &own_messages {
            if !messages.is_empty() {
                info!(
                    "validators [{}] participating in sync subcommittee {subcommittee_index} in slot {}",
                    messages.iter().map(|m| m.validator_index).format(", "),
                    slot_head.slot(),
                );
            }
        }

        for (sync_subnet_id, messages) in own_messages {
            for sync_committee_message in &messages {
                debug!(
                    "validator {} publishing sync committee message (subnet_id: {}): {:?}",
                    sync_committee_message.validator_index, sync_subnet_id, sync_committee_message,
                );

                ValidatorToP2p::PublishSyncCommitteeMessage(Box::new((
                    sync_subnet_id,
                    *sync_committee_message,
                )))
                .send(&self.p2p_tx);
            }

            self.sync_committee_agg_pool.aggregate_own_messages(
                wait_group.clone(),
                messages,
                sync_subnet_id,
                slot_head.beacon_state.clone_arc(),
            );
        }

        self.published_own_sync_committee_messages_for = Some(slot_head);

        Ok(())
    }

    /// <https://github.com/ethereum/consensus-specs/blob/v1.1.1/specs/altair/validator.md#broadcast-sync-committee-contribution>
    async fn publish_contributions_and_proofs(&self, slot_head: &SlotHead<P>) {
        if !self.controller.is_forward_synced() {
            return;
        }

        if !slot_head.has_sync_committee() {
            return;
        }

        if self.wait_for_fully_validated_head(slot_head).await.is_err() {
            warn!(
                "validator cannot participate in sync committees because \
                 chain head has not been fully verified by an execution engine",
            );
            return;
        }

        let contributions = match self.own_contributions_and_proofs(slot_head).await {
            Ok(contributions) => contributions,
            Err(error) => {
                error!("error while producing own contributions and proofs: {error:?}");
                return;
            }
        };

        if contributions.is_empty() {
            return;
        }

        info!(
            "validators [{}] aggregating in sync committee in slot {}",
            contributions
                .iter()
                .map(|c| c.message.aggregator_index)
                .format(", "),
            slot_head.slot(),
        );

        for contribution_and_proof in contributions {
            debug!(
                "validator {} publishing sync committee contribution and proof: {:?}",
                contribution_and_proof.message.aggregator_index, contribution_and_proof,
            );

            ValidatorToP2p::PublishContributionAndProof(Box::new(contribution_and_proof))
                .send(&self.p2p_tx);

            self.sync_committee_agg_pool.add_own_contribution(
                contribution_and_proof.message.aggregator_index,
                contribution_and_proof.message.contribution,
                slot_head.beacon_state.clone_arc(),
            );
        }
    }

    async fn attest_gossip_block(&mut self, wait_group: &W, head: ChainLink<P>) {
        let Some(last_tick) = self.last_tick else {
            return;
        };

        if !(last_tick.slot == head.slot() && last_tick.is_before_attesting_interval()) {
            return;
        }

        let slot_head = SlotHead {
            config: self.chain_config.clone_arc(),
            beacon_block_root: head.block_root,
            beacon_state: self.controller.state_by_chain_link(&head),
            // Validator is only notified about new fully validated chain heads
            // (ValidatorMessage::Head event does not inform validator about optimistic heads)
            optimistic: false,
        };

        // Publish attestations late by default.
        // This noticeably improves rewards in Goerli.
        // This is a deviation from the Honest Validator specification.
        if Feature::PublishAttestationsEarly.is_enabled() {
            if let Err(error) = self
                .attest_and_start_aggregating(wait_group, &slot_head)
                .await
            {
                error!("failed to produce and publish own attestations: {error:?}");
            }
        }

        // Publish sync committee messages late by default.
        // This noticeably improves rewards in Goerli.
        // This is a deviation from the Honest Validator specification.
        if Feature::PublishSyncCommitteeMessagesEarly.is_enabled() {
            if let Err(error) = self
                .publish_sync_committee_messages(wait_group, slot_head)
                .await
            {
                error!("failed to produce and publish own sync_committee messages: {error:?}");
            }
        }
    }

    fn next_graffiti(&mut self) -> Option<H256> {
        if self.validator_config.graffiti.is_empty() {
            return None;
        }

        let index = self.next_graffiti_index;

        self.next_graffiti_index = (index + 1) % self.validator_config.graffiti.len();

        Some(self.validator_config.graffiti[index])
    }

    fn own_public_keys(&self) -> HashSet<PublicKeyBytes> {
        self.signer.load().keys().copied().collect::<HashSet<_>>()
    }

    #[expect(clippy::too_many_lines)]
    async fn own_singular_attestations(
        &self,
        slot_head: &SlotHead<P>,
        own_members: &[BeaconCommitteeMember],
    ) -> Result<&[OwnAttestation<P>]> {
        if let Some(own_attestations) = self.own_singular_attestations.get() {
            return Ok(own_attestations);
        }

        let phase = slot_head.phase();

        let (triples, other_data): (Vec<_>, Vec<_>) = tokio::task::block_in_place(|| {
            let target = Checkpoint {
                epoch: slot_head.current_epoch(),
                root: accessors::epoch_boundary_block_root(
                    &slot_head.beacon_state,
                    slot_head.beacon_block_root,
                ),
            };

            let doppelganger_protection = self
                .doppelganger_protection
                .as_deref()
                .map(DoppelgangerProtection::load);

            own_members
                .iter()
                .filter_map(|member| {
                    if let Some(doppelganger_protection) = &doppelganger_protection {
                        if !doppelganger_protection.is_validator_active(member.public_key) {
                            info!(
                                "Validator {:?} skipping attesting duty in slot {} \
                                 since not enough time has passed to ensure there are \
                                 no doppelganger validators participating on network. \
                                 Validator will start performing duties on slot {}.",
                                member.public_key,
                                slot_head.slot(),
                                doppelganger_protection.tracking_end_slot::<P>(member.public_key),
                            );
                            return None;
                        }
                    }

                    let mut data = AttestationData {
                        slot: slot_head.slot(),
                        index: member.committee_index,
                        beacon_block_root: slot_head.beacon_block_root,
                        source: slot_head.beacon_state.current_justified_checkpoint(),
                        target,
                    };

                    if phase >= Phase::Electra {
                        data.index = 0;
                    }

                    let triple = SigningTriple {
                        message: SigningMessage::<P>::Attestation(data),
                        signing_root: data
                            .signing_root(&self.chain_config, &slot_head.beacon_state),
                        public_key: member.public_key,
                    };

                    Some((triple, (data, member)))
                })
                .unzip()
        });

        let snapshot = self.signer.load();

        let result = snapshot
            .sign_triples(
                triples,
                slot_head.beacon_state.as_ref(),
                self.slashing_protector.clone_arc(),
            )
            .await;

        let signatures = match result {
            Ok(signatures) => signatures,
            Err(error) => {
                warn!("failed to sign attestations: {error:?}");
                return Ok(&[]);
            }
        };

        self.own_singular_attestations
            .get_or_try_init(|| {
                let _timer = self
                    .metrics
                    .as_ref()
                    .map(|metrics| metrics.validator_own_attestations_init_times.start_timer());

                let own_attestations = signatures
                    .zip(other_data)
                    .filter_map(|(signature, (data, member))| {
                        signature.and_then(|signature| {
                            let attestation = if phase < Phase::Electra {
                                let mut aggregation_bits =
                                    BitList::with_length(member.committee_size);

                                aggregation_bits.set(member.position_in_committee, true);

                                Some(Attestation::from(Phase0Attestation {
                                    aggregation_bits,
                                    data,
                                    signature: signature.into(),
                                }))
                            } else {
                                let mut aggregation_bits =
                                    BitList::with_length(member.committee_size);

                                aggregation_bits.set(member.position_in_committee, true);

                                // TODO(feature/electra: don't hide error?)
                                let mut committee_bits = BitVector::default();

                                committee_bits.set(member.committee_index.try_into().ok()?, true);

                                Some(Attestation::from(ElectraAttestation {
                                    aggregation_bits,
                                    data,
                                    committee_bits,
                                    signature: signature.into(),
                                }))
                            };

                            attestation.map(|attestation| OwnAttestation {
                                validator_index: member.validator_index,
                                attestation,
                                signature,
                            })
                        })
                    })
                    .collect();

                Ok(own_attestations)
            })
            .map(Vec::as_slice)
    }

    fn own_sync_committee_members_for_epoch(
        &self,
        relative_epoch: SyncCommitteeEpoch,
        state: &(impl PostAltairBeaconState<P> + ?Sized),
    ) -> Result<Vec<SyncCommitteeMember>> {
        let own_public_keys = self.own_public_keys();

        tokio::task::block_in_place(|| {
            let sync_committee = match relative_epoch {
                SyncCommitteeEpoch::Current => state.current_sync_committee(),
                SyncCommitteeEpoch::Next => {
                    if misc::sync_committee_period::<P>(accessors::get_current_epoch(state))
                        == misc::sync_committee_period::<P>(accessors::get_next_epoch(state))
                    {
                        state.current_sync_committee()
                    } else {
                        state.next_sync_committee()
                    }
                }
            };

            sync_committee
                .pubkeys
                .iter()
                .filter_map(|public_key| {
                    if !own_public_keys.contains(public_key) {
                        return None;
                    }

                    let validator_index = accessors::index_of_public_key(state, public_key)?;
                    Some((validator_index, public_key))
                })
                .sorted_by_key(|(validator_index, _)| *validator_index)
                .collect_vec()
                .into_par_iter()
                .map(|(validator_index, public_key)| {
                    let subnets = misc::compute_subnets_for_sync_committee(state, validator_index)?;

                    Ok(SyncCommitteeMember {
                        validator_index,
                        public_key: *public_key,
                        subnets,
                    })
                })
                .collect()
        })
    }

    async fn own_sync_committee_messages(
        &self,
        slot_head: &SlotHead<P>,
    ) -> Result<BTreeMap<SubcommitteeIndex, Vec<SyncCommitteeMessage>>> {
        let indices_with_pubkeys = self
            .own_sync_committee_members()
            .map(|member| (member.validator_index, member.public_key));

        let messages = match slot_head
            .sync_committee_messages(slot_head.slot(), indices_with_pubkeys, &self.signer)
            .await
        {
            Ok(messages) => messages,
            Err(error) => {
                warn!(
                    "failed to sign sync committee messages (slot: {}): {:?}",
                    slot_head.slot(),
                    error,
                );
                return Ok(BTreeMap::new());
            }
        };

        Ok(messages
            .zip(self.own_sync_committee_members())
            .flat_map(|(message, member)| {
                core::iter::zip(member.subnets, 0..)
                    .filter(|(in_subnet, _)| *in_subnet)
                    .map(move |(_, subcommittee_index)| (subcommittee_index, message))
            })
            .pipe(group_into_btreemap))
    }

    async fn own_contributions_and_proofs(
        &self,
        slot_head: &SlotHead<P>,
    ) -> Result<Vec<SignedContributionAndProof<P>>> {
        let subcommittee_aggregators = self.own_subcommittee_aggregators(slot_head).await?;

        // TODO(Grandine Team): Parallelize.
        //                      This used `into_par_iter` before, however, `build_sync_committee_contribution`
        //                      uses blocking calls from `tokio`, and mixing `tokio` with `rayon` is tricky
        //                      and invites all kinds of trouble.
        let (triples, proofs): (Vec<_>, Vec<_>) = futures::stream::iter(subcommittee_aggregators)
            .then(|(subcommittee_index, aggregators)| async move {
                let contribution = self
                    .sync_committee_agg_pool
                    .best_subcommittee_contribution(
                        slot_head.slot(),
                        slot_head.beacon_block_root,
                        subcommittee_index,
                    )
                    .await;

                (contribution, aggregators)
            })
            .flat_map(|(contribution, aggregators)| {
                aggregators
                    .into_iter()
                    .map(move |(aggregator, selection_proof)| {
                        let contribution_and_proof = ContributionAndProof {
                            aggregator_index: aggregator.validator_index,
                            contribution,
                            selection_proof,
                        };

                        let triple = SigningTriple {
                            message: SigningMessage::ContributionAndProof(contribution_and_proof),
                            signing_root: contribution_and_proof
                                .signing_root(&self.chain_config, &slot_head.beacon_state),
                            public_key: aggregator.public_key,
                        };

                        (triple, contribution_and_proof)
                    })
                    .pipe(futures::stream::iter)
            })
            .unzip()
            .await;

        let result = self
            .signer
            .load()
            .sign_triples_without_slashing_protection(
                triples,
                Some(slot_head.beacon_state.as_ref().into()),
            )
            .await;

        let signatures = match result {
            Ok(signatures) => signatures,
            Err(error) => {
                warn!("failed to sign contributions and proofs: {error:?}");
                return Ok(vec![]);
            }
        };

        Ok(signatures
            .zip(proofs)
            .map(|(signature, message)| SignedContributionAndProof {
                message,
                signature: signature.into(),
            })
            .collect())
    }

    fn own_sync_committee_members(&self) -> impl Iterator<Item = &SyncCommitteeMember> {
        self.own_sync_committee_members.get().into_iter().flatten()
    }

    async fn own_subcommittee_aggregators(
        &self,
        slot_head: &SlotHead<P>,
    ) -> Result<BTreeMap<SubcommitteeIndex, Vec<(&SyncCommitteeMember, SignatureBytes)>>> {
        let subcommittee_members = self
            .own_sync_committee_members()
            .flat_map(|member| {
                core::iter::zip(member.subnets, 0..)
                    .filter(|(in_subnet, _)| *in_subnet)
                    .map(move |(_, subcommittee_index)| (subcommittee_index, member))
            })
            .collect_vec();

        let indices_with_pubkeys = subcommittee_members
            .iter()
            .copied()
            .map(|(subcommittee_index, member)| (subcommittee_index, member.public_key));

        let proofs = match slot_head
            .sync_committee_selection_proofs(indices_with_pubkeys, &self.signer)
            .await
        {
            Ok(proofs) => proofs,
            Err(error) => {
                warn!(
                    "failed to sign sync aggregator selection data for sync committee selection proofs (slot: {}): {:?}",
                    slot_head.slot(),
                    error,
                );
                return Ok(BTreeMap::new());
            }
        };

        Ok(proofs
            .into_iter()
            .zip(subcommittee_members)
            .filter_map(|(selection_proof, (subcommittee_index, member))| {
                let selection_proof = selection_proof?;
                Some((subcommittee_index, (member, selection_proof)))
            })
            .pipe(group_into_btreemap))
    }

    fn attested_in_current_slot(&self) -> bool {
        self.own_singular_attestations.get().is_some()
    }

    fn discard_previous_slot_attestations(&mut self) {
        self.own_singular_attestations.take();
    }

    fn discard_old_registered_validators(&mut self, current_epoch: Epoch) {
        if let Some(epoch_boundary) =
            current_epoch.checked_sub(EPOCHS_TO_KEEP_REGISTERED_VALIDATORS)
        {
            self.registered_validators = self.registered_validators.split_off(&epoch_boundary);
        }
    }

    fn spawn_slashing_protection_pruning(&self, current_epoch: Epoch) {
        let slashing_protector = self.slashing_protector.clone_arc();
        tokio::spawn(async move { slashing_protector.lock().await.prune::<P>(current_epoch) });
    }

    fn update_beacon_committee_subscriptions(
        &self,
        wait_group: W,
        mut beacon_state: Arc<BeaconState<P>>,
    ) {
        let chain_config = self.chain_config.clone_arc();
        let controller = self.controller.clone_arc();
        let current_slot = beacon_state.slot();
        let own_members = self.own_beacon_committee_members.clone_arc();
        let subnet_service_tx = self.subnet_service_tx.clone();

        tokio::task::spawn(async move {
            for slot in OwnBeaconCommitteeMembers::slots_to_compute_in_advance(current_slot) {
                let phase_at_slot = chain_config.phase_at_slot::<P>(slot);

                if chain_config.phase_at_slot::<P>(current_slot) != phase_at_slot {
                    beacon_state = match controller
                        .preprocessed_state_at_epoch(chain_config.fork_epoch(phase_at_slot))
                    {
                        Ok(with_status) => with_status.value,
                        Err(error) => {
                            warn!("failed to preprocess next fork beacon state for beacon committee subscriptions: {error:?}");
                            break;
                        }
                    }
                }

                if own_members.needs_to_compute_members_at_slot(slot).await {
                    if let Some(members) =
                        own_members.get_or_init_at_slot(&beacon_state, slot).await
                    {
                        update_beacon_committee_subscriptions(
                            current_slot,
                            &members,
                            &subnet_service_tx,
                        )
                        .await;
                    }
                }
            }

            drop(wait_group);
        });
    }

    fn update_sync_committee_subscriptions(&mut self, beacon_state: &BeaconState<P>) {
        if let Some(post_altair_state) = beacon_state.post_altair() {
            let own_public_keys = self.own_public_keys();

            self.own_sync_committee_subscriptions
                .build(post_altair_state, &own_public_keys);

            let current_epoch = accessors::get_current_epoch(beacon_state);

            if let Some(subscriptions) = self
                .own_sync_committee_subscriptions
                .take_epoch_subscriptions(current_epoch)
            {
                ToSubnetService::UpdateSyncCommitteeSubscriptions(current_epoch, subscriptions)
                    .send(&self.subnet_service_tx);
            }
        }
    }

    fn update_subnet_subscriptions(&mut self, wait_group: &W, slot_head: Option<&SlotHead<P>>) {
        if !self.controller.is_forward_synced() {
            return;
        }

        let beacon_state = match slot_head.map(|sh| sh.beacon_state.clone_arc()) {
            Some(state) => state,
            None => match self.controller.preprocessed_state_at_current_slot() {
                Ok(state) => state,
                Err(error) => {
                    let is_too_many_empty_slots = matches!(
                        error.downcast_ref(),
                        Some(StateCacheError::StateFarBehind { .. })
                    );

                    if !is_too_many_empty_slots {
                        warn!("failed to obtain beacon state for current slot: {error}");
                    }

                    return;
                }
            },
        };

        self.update_beacon_committee_subscriptions(wait_group.clone(), beacon_state.clone_arc());
        self.update_sync_committee_subscriptions(&beacon_state);
    }

    async fn handle_external_contributions_and_proofs(
        &self,
        slot_head: SlotHead<P>,
        contributions_and_proofs: Vec<SignedContributionAndProof<P>>,
    ) -> Vec<(usize, AnyhowError)> {
        contributions_and_proofs
            .into_iter()
            .enumerate()
            .filter(|(_, contribution_and_proof)| {
                contribution_and_proof.message.contribution.slot == slot_head.slot()
            })
            .map(|(index, contribution_and_proof)| async move {
                let result = self
                    .sync_committee_agg_pool
                    .handle_external_contribution_and_proof(contribution_and_proof, Origin::Api)
                    .await;

                (index, contribution_and_proof, result)
            })
            .collect::<FuturesOrdered<_>>()
            .filter_map(|(index, contribution_and_proof, result)| async move {
                match result {
                    Ok(_) => {
                        self.event_channels
                            .send_contribution_and_proof_event(contribution_and_proof);

                        ValidatorToP2p::PublishContributionAndProof(Box::new(
                            contribution_and_proof,
                        ))
                        .send(&self.p2p_tx);

                        None
                    }
                    Err(error) => Some((index, error)),
                }
            })
            .collect()
            .await
    }

    fn refresh_signer_keys(&self) {
        let signer = self.signer.clone_arc();
        let head_state = self.controller.head_state().value;
        let current_slot = self.controller.slot();

        tokio::spawn(async move {
            signer.load_keys_from_web3signer().await;

            signer.update_doppelganger_protection_pubkeys(&head_state, current_slot);
        });
    }

    async fn register_validators(&mut self, current_epoch: Epoch) {
        if let Some(last_registration_epoch) = self.last_registration_epoch {
            let next_registration_epoch =
                last_registration_epoch + EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION;

            if next_registration_epoch < current_epoch {
                return;
            }
        }

        let builder_api = self.builder_api.clone();
        let chain_config = self.chain_config.clone_arc();
        let proposer_configs = self.proposer_configs.clone_arc();
        let signer = self.signer.clone_arc();
        let prepared_proposer_indices = self.block_producer.get_prepared_proposer_indices().await;
        let registered_validators = self.registered_validators.clone();
        let subnet_service_tx = self.subnet_service_tx.clone();

        tokio::spawn(async move {
            let signer_snapshot = signer.load();
            let pubkeys = signer_snapshot.keys().copied().collect_vec();

            ToSubnetService::SetRegisteredValidators(
                registered_validators
                    .values()
                    .flat_map(BTreeMap::keys)
                    .copied()
                    .chain(pubkeys.iter().copied())
                    .collect(),
                prepared_proposer_indices,
            )
            .send(&subnet_service_tx);

            let Some(builder_api) = builder_api.clone() else {
                return Ok(());
            };

            let registrations = pubkeys
                .into_iter()
                .map(|pubkey| {
                    Ok(ValidatorRegistrationV1 {
                        fee_recipient: proposer_configs.fee_recipient(pubkey)?,
                        gas_limit: proposer_configs.gas_limit(pubkey)?,
                        timestamp: SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)?
                            .as_secs(),
                        pubkey,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            let triples = registrations
                .iter()
                .map(|registration| SigningTriple {
                    message: SigningMessage::ValidatorRegistration::<P>(*registration),
                    signing_root: registration.signing_root(&chain_config),
                    public_key: registration.pubkey,
                })
                .collect_vec();

            let signatures = signer_snapshot
                .sign_triples_without_slashing_protection(triples, None)
                .await?;

            let signed_registrations = registrations
                .into_iter()
                .zip(signatures)
                .chain(
                    registered_validators
                        .into_values()
                        .flat_map(BTreeMap::into_values),
                )
                .map(|(message, signature)| SignedValidatorRegistrationV1 {
                    message,
                    signature: signature.into(),
                })
                .chunks(MAX_VALIDATORS_PER_REGISTRATION)
                .into_iter()
                .map(ContiguousList::<_, P::ValidatorRegistryLimit>::try_from_iter)
                .collect::<Result<Vec<_>, ReadError>>()
                .inspect_err(|error| {
                    warn!("failed to collect validator registrations: {error:?}")
                })?;

            // Do not submit requests in parallel. Doing so causes all of them to be timed out.
            for registrations in signed_registrations {
                if let Err(error) = builder_api.register_validators::<P>(registrations).await {
                    warn!("failed to register validator batch: {error}");
                }
            }

            Ok::<_, AnyhowError>(())
        });

        self.last_registration_epoch = Some(current_epoch);
    }

    async fn track_collection_metrics(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            let type_name = tynm::type_name::<Self>();

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "own_singular_attestations",
                self.own_singular_attestations
                    .get()
                    .map(Vec::len)
                    .unwrap_or(0),
            );

            self.block_producer.track_collection_metrics().await;
        }

        if let Some(validator_statistics) = self.validator_statistics.as_ref() {
            validator_statistics.track_collection_metrics().await;
        }
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
                        warn!("error receiving block event: {error:?}");
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

// Use `BTreeMap` to make grouping deterministic for snapshot testing.
// There is no equivalent of `Itertools::into_group_map` that collects into a `BTreeMap`.
// See <https://github.com/rust-itertools/itertools/issues/520>.
fn group_into_btreemap<K: Ord, V>(pairs: impl IntoIterator<Item = (K, V)>) -> BTreeMap<K, Vec<V>> {
    let mut groups = BTreeMap::<_, Vec<_>>::new();

    for (key, value) in pairs {
        groups.entry(key).or_default().push(value);
    }

    groups
}

async fn update_beacon_committee_subscriptions(
    current_slot: Slot,
    members: &[BeaconCommitteeMember],
    subnet_service_tx: &UnboundedSender<ToSubnetService>,
) {
    if members.is_empty() {
        return;
    }

    let subscriptions = members.iter().copied().map(Into::into).collect();

    let (sender, receiver) = futures::channel::oneshot::channel();

    ToSubnetService::UpdateBeaconCommitteeSubscriptions(current_slot, subscriptions, sender)
        .send(subnet_service_tx);

    if let Err(error) = receiver.await {
        warn!("failed to update beacon committee subscriptions: {error:?}");
    }
}
