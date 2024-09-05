//! <https://github.com/ethereum/consensus-specs/blob/b2f42bf4d79432ee21e2f2b3912ff4bbf7898ada/specs/phase0/validator.md>

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    error::Error as StdError,
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
use eth1_api::ApiController;
use eth2_libp2p::GossipId;
use features::Feature;
use fork_choice_control::{ValidatorMessage, Wait};
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
use log::{debug, error, info, log, warn, Level};
use once_cell::sync::OnceCell;
use operation_pools::{AttestationAggPool, Origin, PoolAdditionOutcome, SyncCommitteeAggPool};
use p2p::{P2pToValidator, ToSubnetService, ValidatorToP2p};
use prometheus_metrics::Metrics;
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use signer::{Signer, SigningMessage, SigningTriple};
use slasher::{SlasherToValidator, ValidatorToSlasher};
use slashing_protection::SlashingProtector;
use ssz::BitList;
use static_assertions::assert_not_impl_any;
use std_ext::ArcExt as _;
use tap::{Conv as _, Pipe as _};
use types::{
    altair::{
        containers::{ContributionAndProof, SignedContributionAndProof, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::BeaconState,
    config::Config as ChainConfig,
    nonstandard::{OwnAttestation, SyncCommitteeEpoch, WithBlobsAndMev, WithStatus},
    phase0::{
        consts::{GENESIS_EPOCH, GENESIS_SLOT},
        containers::{
            AggregateAndProof, Attestation, AttestationData, Checkpoint, SignedAggregateAndProof,
        },
        primitives::{Epoch, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, PostAltairBeaconState, SignedBeaconBlock as _},
};

use crate::{
    messages::{ApiToValidator, ValidatorToApi, ValidatorToLiveness},
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
#[display(fmt = "too many empty slots after head: {head_slot} + {max_empty_slots} < {slot}")]
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
    pub validator_to_api_tx: UnboundedSender<ValidatorToApi<P>>,
    pub validator_to_liveness_tx: Option<UnboundedSender<ValidatorToLiveness<P>>>,
    pub validator_to_slasher_tx: Option<UnboundedSender<ValidatorToSlasher>>,
}

#[allow(clippy::struct_field_names)]
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
    published_own_sync_committee_messages: bool,
    own_aggregators: BTreeMap<AttestationData, Vec<Aggregator>>,
    validator_votes: HashMap<Epoch, Vec<ValidatorVote>>,
    builder_api: Option<Arc<BuilderApi>>,
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
    validator_to_api_tx: UnboundedSender<ValidatorToApi<P>>,
    validator_to_liveness_tx: Option<UnboundedSender<ValidatorToLiveness<P>>>,
    validator_to_slasher_tx: Option<UnboundedSender<ValidatorToSlasher>>,
}

impl<P: Preset, W: Wait + Sync> Validator<P, W> {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        validator_config: Arc<ValidatorConfig>,
        block_producer: Arc<BlockProducer<P, W>>,
        controller: ApiController<P, W>,
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        builder_api: Option<Arc<BuilderApi>>,
        proposer_configs: Arc<ProposerConfigs>,
        signer: Arc<Signer>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
        metrics: Option<Arc<Metrics>>,
        channels: Channels<P, W>,
    ) -> Self {
        let Channels {
            api_to_validator_rx,
            fork_choice_rx,
            p2p_tx,
            p2p_to_validator_rx,
            slasher_to_validator_rx,
            subnet_service_tx,
            validator_to_api_tx,
            validator_to_liveness_tx,
            validator_to_slasher_tx,
        } = channels;

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
            published_own_sync_committee_messages: false,
            own_aggregators: BTreeMap::new(),
            validator_votes: HashMap::new(),
            builder_api,
            last_registration_epoch: None,
            proposer_configs,
            signer,
            slashing_protector,
            sync_committee_agg_pool,
            slasher_to_validator_rx,
            subnet_service_tx,
            registered_validators: BTreeMap::new(),
            metrics,
            validator_to_api_tx,
            validator_to_liveness_tx,
            validator_to_slasher_tx,
        }
    }

    #[allow(clippy::too_many_lines)]
    pub async fn run(mut self) -> Result<()> {
        loop {
            let mut slasher_to_validator_rx = self
                .slasher_to_validator_rx
                .as_mut()
                .map(EitherFuture::Left)
                .unwrap_or_else(|| EitherFuture::Right(futures::stream::pending()));

            select! {
                message = self.fork_choice_rx.select_next_some() => match message {
                    ValidatorMessage::Tick(wait_group, tick) => {
                        self.handle_tick(wait_group, tick).await?;
                    }
                    ValidatorMessage::FinalizedEth1Data(finalized_eth1_deposit_index) => {
                        self.block_producer.finalize_deposits(finalized_eth1_deposit_index)?;
                    },
                    ValidatorMessage::Head(wait_group, head) => {
                        if let Some(validator_to_liveness_tx) = &self.validator_to_liveness_tx {
                            let state = self.controller.state_by_chain_link(&head);
                            ValidatorToLiveness::Head(head.block.clone_arc(), state).send(validator_to_liveness_tx);
                        }

                        self.attest_gossip_block(&wait_group, head).await?;
                    }
                    ValidatorMessage::ValidAttestation(wait_group, attestation) => {
                        self.attestation_agg_pool
                            .insert_attestation(wait_group, attestation.clone_arc());

                        if let Some(validator_to_liveness_tx) = &self.validator_to_liveness_tx {
                            ValidatorToLiveness::ValidAttestation(attestation)
                                .send(validator_to_liveness_tx);
                        }
                    },
                    ValidatorMessage::PrepareExecutionPayload(slot, safe_execution_payload_hash, finalized_execution_payload_hash) => {
                        let should_prepare_execution_payload = Feature::AlwaysPrepareExecutionPayload.is_enabled()
                            || self.attestation_agg_pool.has_registered_validators_proposing_in_slots(slot..=slot).await;

                        if !should_prepare_execution_payload {
                            continue;
                        }

                        let slot_head = self.safe_slot_head(slot).await;

                        if let Some(slot_head) = slot_head {
                            let block_build_context = self.block_producer.new_build_context(
                                slot_head.beacon_state.clone_arc(),
                                slot_head.beacon_block_root,
                                slot_head.proposer_index()?,
                                BlockBuildOptions::default(),
                            );

                            block_build_context.prepare_execution_payload_for_slot(
                                slot,
                                safe_execution_payload_hash,
                                finalized_execution_payload_hash,
                            ).await;
                        }
                    }
                },

                slashing = slasher_to_validator_rx.select_next_some() => match slashing {
                    SlasherToValidator::AttesterSlashing(attester_slashing) => {
                        self.block_producer.add_new_attester_slashing(attester_slashing).await;
                    }
                    SlasherToValidator::ProposerSlashing(proposer_slashing) => {
                        self.block_producer.add_new_proposer_slashing(proposer_slashing).await;
                    }
                },

                gossip_message = self.p2p_to_validator_rx.select_next_some() => match gossip_message {
                    P2pToValidator::AttesterSlashing(slashing, gossip_id) => {
                        let outcome = self
                            .block_producer
                            .handle_external_attester_slashing(*slashing)
                            .await?;
                        self.handle_pool_addition_outcome_for_p2p(outcome, gossip_id);
                    }
                    P2pToValidator::ProposerSlashing(slashing, gossip_id) => {
                        let outcome = self
                            .block_producer
                            .handle_external_proposer_slashing(*slashing)
                            .await?;
                        self.handle_pool_addition_outcome_for_p2p(outcome, gossip_id);
                    }
                    P2pToValidator::VoluntaryExit(voluntary_exit, gossip_id) => {
                        let outcome = self
                            .block_producer
                            .handle_external_voluntary_exit(*voluntary_exit)
                            .await?;

                        if matches!(outcome, PoolAdditionOutcome::Accept) {
                            ValidatorToApi::VoluntaryExit(voluntary_exit).send(&self.validator_to_api_tx);
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

                complete => break Ok(()),
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

    #[allow(clippy::too_many_lines)]
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

        log!(
            if no_validators {
                Level::Debug
            } else {
                Level::Info
            },
            "{kind:?} tick in slot {slot}",
        );

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

            self.process_validator_votes(current_epoch)?;
            self.discard_old_registered_validators(current_epoch);
            self.block_producer.discard_old_data(current_epoch).await;
            self.own_sync_committee_subscriptions
                .discard_old_subscriptions(current_epoch);
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
                self.published_own_sync_committee_messages = false;
            }
            TickKind::Attest => {
                let _timer = self
                    .metrics
                    .as_ref()
                    .map(|metrics| metrics.validator_attest_tick_times.start_timer());

                self.attest_and_start_aggregating(&wait_group, &slot_head)
                    .await?;

                self.publish_sync_committee_messages(&wait_group, &slot_head)
                    .await?;
            }
            TickKind::Aggregate => {
                let _timer = self
                    .metrics
                    .as_ref()
                    .map(|metrics| metrics.validator_aggregate_tick_times.start_timer());

                self.publish_aggregates_and_proofs(&wait_group, &slot_head)
                    .await;

                self.publish_contributions_and_proofs(&slot_head).await;

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
            optimistic,
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
            optimistic,
        }))
    }

    /// <https://github.com/ethereum/consensus-specs/blob/b2f42bf4d79432ee21e2f2b3912ff4bbf7898ada/specs/phase0/validator.md#block-proposal>
    #[allow(clippy::too_many_lines)]
    async fn propose(&mut self, wait_group: W, slot_head: &SlotHead<P>) -> Result<()> {
        if slot_head.slot() == GENESIS_SLOT {
            // All peers should already have the genesis block.
            // It would fail multiple validations if it were published like non-genesis blocks.
            return Ok(());
        }

        if slot_head.optimistic {
            warn!(
                "validator cannot produce a block because \
                 chain head has not been fully verified by an execution engine",
            );
            return Ok(());
        }

        let proposer_index = tokio::task::block_in_place(|| slot_head.proposer_index())?;
        let public_key = slot_head.public_key(proposer_index);
        let signer_snapshot = self.signer.load();

        if !signer_snapshot.has_key(public_key.to_bytes()) {
            return Ok(());
        }

        let _propose_timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.validator_propose_times.start_timer());

        let graffiti = self
            .proposer_configs
            .graffiti_bytes(public_key.to_bytes())?
            .unwrap_or_else(|| self.next_graffiti());

        let block_build_context = self.block_producer.new_build_context(
            slot_head.beacon_state.clone_arc(),
            slot_head.beacon_block_root,
            proposer_index,
            BlockBuildOptions {
                graffiti,
                ..BlockBuildOptions::default()
            },
        );

        let execution_payload_header_handle =
            block_build_context.get_execution_payload_header(public_key.to_bytes());

        let local_execution_payload_handle = block_build_context.get_local_execution_payload();

        let epoch = slot_head.current_epoch();

        let result = signer_snapshot
            .sign_without_slashing_protection(
                SigningMessage::RandaoReveal { epoch },
                RandaoEpoch::from(epoch).signing_root(&self.chain_config, &slot_head.beacon_state),
                Some(slot_head.beacon_state.as_ref().into()),
                public_key.to_bytes(),
            )
            .await;

        let randao_reveal = match result {
            Ok(signature) => signature.into(),
            Err(error) => {
                warn!(
                    "failed to sign RANDAO reveal (epoch: {}, public_key: {}): {:?}",
                    epoch,
                    public_key.to_bytes(),
                    error,
                );
                return Ok(());
            }
        };

        let beacon_block_option = block_build_context
            .build_blinded_beacon_block(
                randao_reveal,
                execution_payload_header_handle,
                local_execution_payload_handle,
            )
            .await?;

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
                        public_key,
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
                        public_key,
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

        for blob_sidecar in misc::construct_blob_sidecars(
            &block,
            block_blobs.unwrap_or_default().into_iter(),
            block_proofs.unwrap_or_default().into_iter(),
        )? {
            let blob_sidecar = Arc::new(blob_sidecar);

            self.controller
                .on_own_blob_sidecar(wait_group.clone(), blob_sidecar.clone_arc());

            ValidatorToP2p::PublishBlobSidecar(blob_sidecar).send(&self.p2p_tx);
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
    #[allow(clippy::too_many_lines)]
    async fn attest_and_start_aggregating(
        &mut self,
        wait_group: &W,
        slot_head: &SlotHead<P>,
    ) -> Result<()> {
        // Skip attesting if validators already attested at slot
        if self.attested_in_current_slot() {
            return Ok(());
        }

        if slot_head.optimistic {
            warn!(
                "validator cannot participate in attestation because \
                 chain head has not been fully verified by an execution engine",
            );
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

            let committee_index = attestation.data.index;

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

            let subnet_id = slot_head.subnet_id(attestation.data.slot, attestation.data.index)?;

            self.controller
                .on_singular_attestation(AttestationItem::unverified(
                    attestation.clone_arc(),
                    AttestationOrigin::Own(subnet_id),
                ));

            ValidatorToP2p::PublishSingularAttestation(attestation.clone_arc(), subnet_id)
                .send(&self.p2p_tx);

            self.attestation_agg_pool
                .insert_attestation(wait_group.clone(), attestation);
        }

        prometheus_metrics::stop_and_record(timer);

        let own_members = own_members
            .iter()
            .map(|member| ((member.committee_index, member.validator_index), member))
            .collect::<HashMap<_, _>>();

        self.own_aggregators = own_singular_attestations
            .iter()
            .filter_map(|own_attestation| {
                let member = own_members.get(&(
                    own_attestation.attestation.data.index,
                    own_attestation.validator_index,
                ))?;

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

                Some((own_attestation.attestation.data, aggregator))
            })
            .pipe(group_into_btreemap);

        Ok(())
    }

    async fn publish_aggregates_and_proofs(&self, wait_group: &W, slot_head: &SlotHead<P>) {
        let config = &self.chain_config;

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

                            let aggregate_and_proof = AggregateAndProof {
                                aggregator_index,
                                aggregate: aggregate.clone(),
                                selection_proof,
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
                let aggregate_and_proof = SignedAggregateAndProof {
                    message,
                    signature: signature.into(),
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
                .map(|a| a.message.aggregator_index)
                .format(", "),
            aggregate_and_proof.message.aggregate.data.slot,
        );

        for aggregate_and_proof in aggregates_and_proofs {
            let attestation = Arc::new(aggregate_and_proof.message.aggregate.clone());
            let aggregate_and_proof = Arc::new(aggregate_and_proof);

            self.attestation_agg_pool
                .insert_attestation(wait_group.clone(), attestation);

            ValidatorToP2p::PublishAggregateAndProof(aggregate_and_proof).send(&self.p2p_tx);
        }
    }

    /// <https://github.com/ethereum/consensus-specs/blob/v1.1.1/specs/altair/validator.md#broadcast-sync-committee-message>
    async fn publish_sync_committee_messages(
        &mut self,
        wait_group: &W,
        slot_head: &SlotHead<P>,
    ) -> Result<()> {
        // > To reduce complexity during the Altair fork, sync committees are not expected to
        // > produce signatures for `compute_epoch_at_slot(ALTAIR_FORK_EPOCH) - 1`.
        if !slot_head.has_sync_committee() {
            return Ok(());
        }

        if self.published_own_sync_committee_messages {
            return Ok(());
        }

        if slot_head.optimistic {
            warn!(
                "validator cannot participate in sync committees because \
                 chain head has not been fully verified by an execution engine",
            );
            return Ok(());
        }

        self.published_own_sync_committee_messages = true;

        let own_messages = self.own_sync_committee_messages(slot_head).await?;

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

        Ok(())
    }

    /// <https://github.com/ethereum/consensus-specs/blob/v1.1.1/specs/altair/validator.md#broadcast-sync-committee-contribution>
    async fn publish_contributions_and_proofs(&self, slot_head: &SlotHead<P>) {
        if !slot_head.has_sync_committee() {
            return;
        }

        if slot_head.optimistic {
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

    async fn attest_gossip_block(&mut self, wait_group: &W, head: ChainLink<P>) -> Result<()> {
        let Some(last_tick) = self.last_tick else {
            return Ok(());
        };

        if !(last_tick.slot == head.slot() && last_tick.is_before_attesting_interval()) {
            return Ok(());
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
            self.attest_and_start_aggregating(wait_group, &slot_head)
                .await?;
        }

        // Publish sync committee messages late by default.
        // This noticeably improves rewards in Goerli.
        // This is a deviation from the Honest Validator specification.
        if Feature::PublishSyncCommitteeMessagesEarly.is_enabled() {
            self.publish_sync_committee_messages(wait_group, &slot_head)
                .await?;
        }

        Ok(())
    }

    fn next_graffiti(&mut self) -> H256 {
        if self.validator_config.graffiti.is_empty() {
            return H256::default();
        }

        let index = self.next_graffiti_index;

        self.next_graffiti_index = (index + 1) % self.validator_config.graffiti.len();

        self.validator_config.graffiti[index]
    }

    fn own_public_keys(&self) -> HashSet<PublicKeyBytes> {
        self.signer.load().keys().copied().collect::<HashSet<_>>()
    }

    async fn own_singular_attestations(
        &self,
        slot_head: &SlotHead<P>,
        own_members: &[BeaconCommitteeMember],
    ) -> Result<&[OwnAttestation<P>]> {
        if let Some(own_attestations) = self.own_singular_attestations.get() {
            return Ok(own_attestations);
        }

        let (triples, other_data): (Vec<_>, Vec<_>) = tokio::task::block_in_place(|| {
            let target = Checkpoint {
                epoch: slot_head.current_epoch(),
                root: accessors::epoch_boundary_block_root(
                    &slot_head.beacon_state,
                    slot_head.beacon_block_root,
                ),
            };

            own_members
                .iter()
                .map(|member| {
                    let data = AttestationData {
                        slot: slot_head.slot(),
                        index: member.committee_index,
                        beacon_block_root: slot_head.beacon_block_root,
                        source: slot_head.beacon_state.current_justified_checkpoint(),
                        target,
                    };

                    let triple = SigningTriple {
                        message: SigningMessage::<P>::Attestation(data),
                        signing_root: data
                            .signing_root(&self.chain_config, &slot_head.beacon_state),
                        public_key: member.public_key,
                    };

                    (triple, (data, member))
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
                        let mut aggregation_bits = BitList::with_length(member.committee_size);

                        aggregation_bits.set(member.position_in_committee, true);

                        signature.map(|signature| OwnAttestation {
                            validator_index: member.validator_index,
                            attestation: Attestation {
                                aggregation_bits,
                                data,
                                signature: signature.into(),
                            },
                            signature,
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
                    let public_key = public_key.to_bytes();

                    if !own_public_keys.contains(&public_key) {
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
                        public_key,
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
        if let Some(own_attestations) = self.own_singular_attestations.take() {
            for own_attestation in own_attestations {
                let AttestationData {
                    beacon_block_root,
                    slot,
                    ..
                } = own_attestation.attestation.data;

                let vote = ValidatorVote {
                    validator_index: own_attestation.validator_index,
                    beacon_block_root,
                    slot,
                };

                self.validator_votes
                    .entry(misc::compute_epoch_at_slot::<P>(slot))
                    .or_default()
                    .push(vote);
            }
        }
    }

    fn discard_old_registered_validators(&mut self, current_epoch: Epoch) {
        if let Some(epoch_boundary) =
            current_epoch.checked_sub(EPOCHS_TO_KEEP_REGISTERED_VALIDATORS)
        {
            self.registered_validators = self.registered_validators.split_off(&epoch_boundary);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn process_validator_votes(&mut self, current_epoch: Epoch) -> Result<()> {
        let Some(epoch_to_check) = current_epoch
            .saturating_sub(1)
            .max(GENESIS_EPOCH)
            .checked_sub(1)
        else {
            return Ok(());
        };

        // Take beacon blocks from `epoch_to_check` and the epoch before it in case the first
        // slot(s) of `epoch_to_check` are empty.
        let start_slot = Self::start_of_epoch(epoch_to_check.saturating_sub(1).max(GENESIS_EPOCH));
        let end_slot = Self::start_of_epoch(current_epoch.saturating_sub(1).max(GENESIS_EPOCH));

        // We assume that stored blocks from epoch before previous do reflect canonical chain
        let canonical_blocks_with_roots = self.controller.blocks_by_range(start_slot..end_slot)?;

        let root_to_block_map = canonical_blocks_with_roots
            .iter()
            .map(|block_with_root| (block_with_root.root, block_with_root))
            .collect::<HashMap<_, _>>();

        let slot_to_block_map = canonical_blocks_with_roots
            .iter()
            .map(|block_with_root| (block_with_root.block.message().slot(), block_with_root))
            .collect::<HashMap<_, _>>();

        let Some(validator_votes) = self.validator_votes.remove(&epoch_to_check) else {
            debug!("no own validators voted in epoch {epoch_to_check}");
            return Ok(());
        };

        let mut vote_summaries: BTreeMap<VoteSummary, BTreeSet<ValidatorIndex>> = BTreeMap::new();

        for vote in &validator_votes {
            let voter_index = vote.validator_index;
            let voted_root = vote.beacon_block_root;
            let voted_slot = vote.slot;

            let canonical_block_at_slot_or_closest = (start_slot..=voted_slot)
                .rev()
                .find_map(|s| slot_to_block_map.get(&s));

            let summary = match canonical_block_at_slot_or_closest {
                Some(canonical_block) if canonical_block.root == voted_root => VoteSummary::Correct,
                Some(canonical_block) => {
                    let mut ancestors =
                        core::iter::successors(Some(canonical_block), |block_with_root| {
                            root_to_block_map.get(&block_with_root.block.message().parent_root())
                        });

                    let canonical_ancestor =
                        ancestors.find(|block_with_root| block_with_root.root == voted_root);
                    let canonical_root = canonical_block.root;

                    if let Some(&ancestor_with_root) = canonical_ancestor {
                        let ancestor_slot = ancestor_with_root.block.message().slot();
                        let slot_diff = voted_slot - ancestor_slot;

                        VoteSummary::Outdated {
                            voted_root,
                            voted_slot,
                            canonical_root,
                            slot_diff,
                        }
                    } else {
                        VoteSummary::NonCanonical {
                            voted_root,
                            voted_slot,
                            canonical_root,
                        }
                    }
                }
                None => VoteSummary::MissingBlock {
                    voted_root,
                    voted_slot,
                },
            };

            vote_summaries
                .entry(summary)
                .or_default()
                .insert(voter_index);
        }

        for (summary, validator_indices) in vote_summaries {
            match summary {
                VoteSummary::Correct => {
                    let total_correct = validator_indices.len();
                    let total = validator_votes.len();

                    debug!(
                        "{total_correct} of {total} validators \
                         voted correctly in epoch {epoch_to_check}",
                    );
                }
                VoteSummary::MissingBlock {
                    voted_slot,
                    voted_root,
                } => {
                    warn!(
                        "cannot find beacon block that validators {validator_indices:?} voted for \
                         at slot {voted_slot} (voted for block {voted_root:?})",
                    );
                }
                VoteSummary::NonCanonical {
                    voted_slot,
                    voted_root,
                    canonical_root,
                } => {
                    warn!(
                        "validators {validator_indices:?} voted for \
                         non-canonical block {voted_root:?} at slot {voted_slot} \
                         (expected to vote for block {canonical_root:?})",
                    );
                }
                VoteSummary::Outdated {
                    voted_slot,
                    voted_root,
                    canonical_root,
                    slot_diff,
                } => {
                    warn!(
                        "validators {validator_indices:?} voted for \
                         outdated head {voted_root:?} (by {slot_diff} slots) at slot {voted_slot} \
                         (expected to vote for block {canonical_root:?})",
                    );
                }
            }
        }

        Ok(())
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
                        ValidatorToApi::ContributionAndProof(Box::new(contribution_and_proof))
                            .send(&self.validator_to_api_tx);
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

    const fn start_of_epoch(epoch: Epoch) -> Slot {
        misc::compute_start_slot_at_epoch::<P>(epoch)
    }

    fn refresh_signer_keys(&self) {
        let signer = self.signer.clone_arc();

        tokio::spawn(async move {
            signer.load_keys_from_web3signer().await;
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
                .collect_vec();

            // Do not submit requests in parallel. Doing so causes all of them to be timed out.
            for registration in signed_registrations.chunks(MAX_VALIDATORS_PER_REGISTRATION) {
                if let Err(error) = builder_api.register_validators(registration).await {
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

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "validator_votes",
                self.validator_votes.values().map(Vec::len).sum(),
            );

            self.block_producer.track_collection_metrics().await;
        }
    }
}

struct ValidatorVote {
    validator_index: ValidatorIndex,
    beacon_block_root: H256,
    slot: Slot,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum VoteSummary {
    Correct,
    MissingBlock {
        voted_slot: Slot,
        voted_root: H256,
    },
    NonCanonical {
        voted_slot: Slot,
        voted_root: H256,
        canonical_root: H256,
    },
    Outdated {
        voted_slot: Slot,
        voted_root: H256,
        canonical_root: H256,
        slot_diff: u64,
    },
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
