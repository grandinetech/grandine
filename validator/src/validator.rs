//! <https://github.com/ethereum/consensus-specs/blob/b2f42bf4d79432ee21e2f2b3912ff4bbf7898ada/specs/phase0/validator.md>

use core::{error::Error as StdError, sync::atomic::AtomicUsize, time::Duration};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::SystemTime,
};

use anyhow::{Error as AnyhowError, Result, ensure};
use block_producer::{BlockBuildOptions, BlockProducer, ValidatorBlindedBlock};
use bls::{PublicKeyBytes, Signature, SignatureBytes};
use builder_api::{
    BuilderApi,
    consts::EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION,
    unphased::containers::{SignedValidatorRegistrationV1, ValidatorRegistrationV1},
};
use clock::{Tick, TickKind};
use debug_info::HealthCheck;
use dedicated_executor::DedicatedExecutor;
use derive_more::Display;
use doppelganger_protection::{DoppelgangerProtection, Error as DoppelgangerProtectionError};
use eth1_api::ApiController;
use eth2_libp2p::GossipId;
use features::Feature;
use fork_choice_control::{Event, EventChannels, Topic, ValidatorMessage, Wait};
use fork_choice_store::{ChainLink, StateCacheError};
use futures::{
    channel::{
        mpsc::{UnboundedReceiver, UnboundedSender},
        oneshot::Sender,
    },
    future::{Either as EitherFuture, OptionFuture, join_all},
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
use liveness_tracker::{ApiToLiveness, ValidatorToLiveness};
use logging::{debug_with_peers, error_with_peers, info_with_peers, warn_with_peers};
use once_cell::sync::OnceCell;
use operation_pools::{
    AttestationAggPool, AttestationKey, Origin, PayloadAttestationAggPool, PoolAdditionOutcome,
    SyncCommitteeAggPool,
};
use p2p::{P2pToValidator, ToSubnetService, ValidatorToP2p};
use prometheus_metrics::Metrics;
use signer::{Signer, SigningMessage, SigningTriple, Snapshot};
use slasher::{SlasherToValidator, ValidatorToSlasher};
use slashing_protection::SlashingProtector;
use ssz::{BitList, ContiguousList, ReadError};
use static_assertions::assert_not_impl_any;
use std_ext::ArcExt;
use tap::{Conv as _, Pipe as _};
use tokio::time::timeout;
use tracing::instrument;
use try_from_iterator::TryFromIterator as _;
use types::{
    altair::{
        containers::{ContributionAndProof, SignedContributionAndProof, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::{
        AggregateAndProof, Attestation, AttesterSlashing, BeaconState, SignedAggregateAndProof,
        SignedBeaconBlock, SignedBlindedBeaconBlock,
    },
    config::Config as ChainConfig,
    deneb::primitives::Blob,
    electra::containers::{
        AggregateAndProof as ElectraAggregateAndProof,
        SignedAggregateAndProof as ElectraSignedAggregateAndProof, SingleAttestation,
    },
    gloas::{
        consts::BUILDER_INDEX_SELF_BUILD,
        containers::{
            AggregateAndProof as GloasAggregateAndProof, ExecutionPayloadEnvelope,
            PayloadAttestationData, PayloadAttestationMessage, ProposerPreferences,
            SignedAggregateAndProof as GloasSignedAggregateAndProof,
            SignedExecutionPayloadEnvelope, SignedProposerPreferences,
        },
    },
    nonstandard::{CustodyMode, KzgProofs, OwnAttestation, Phase, WithBlobsAndMev, WithStatus},
    phase0::{
        consts::GENESIS_SLOT,
        containers::{
            AggregateAndProof as Phase0AggregateAndProof, Attestation as Phase0Attestation,
            ProposerSlashing, SignedAggregateAndProof as Phase0SignedAggregateAndProof,
            SignedVoluntaryExit,
        },
        primitives::{Epoch, ExecutionBlockHash, H256, Slot, ValidatorIndex},
    },
    preset::Preset,
    redacting_url::RedactingUrl,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};
use validator_statistics::ValidatorStatistics;

use crate::{
    beacon_node_api::BeaconNodeApi as _,
    beacon_nodes::BeaconNodes,
    local_beacon_node::LocalBeaconNode,
    messages::{ApiToValidator, InternalMessage},
    misc::{
        Aggregator, DutySource, SignedBeaconBlockOrBlockRoot, SyncCommitteeMember, ValidatorMode,
    },
    own_beacon_committee_members::{BeaconCommitteeMember, OwnBeaconCommitteeMembers},
    own_ptc_members::{OwnPTCMembers, PTCMember},
    own_sync_committee_subscriptions::OwnSyncCommitteeSubscriptions,
    own_validator_indices::OwnValidatorIndices,
    remote_beacon_node::RemoteBeaconNode,
    remote_beacon_nodes::RemoteBeaconNodes,
    slot_head::SlotHead,
    tasks::{
        OwnSyncCommitteeMembers, PrefetchSyncCommitteeDutiesTask,
        UpdateBeaconCommitteeSubscriptionsTask,
    },
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

/// The head at a slot and the state the built-in beacon node holds for it.
type LocalHead<P> = (SlotHead<P>, Arc<BeaconState<P>>);

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
    pub api_to_liveness_tx: Option<UnboundedSender<ApiToLiveness>>,
    pub api_to_validator_rx: UnboundedReceiver<ApiToValidator<P>>,
    pub fork_choice_rx: UnboundedReceiver<ValidatorMessage<P, W>>,
    pub p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
    pub p2p_to_validator_rx: UnboundedReceiver<P2pToValidator<P, W>>,
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
    p2p_to_validator_rx: UnboundedReceiver<P2pToValidator<P, W>>,
    last_tick: Option<Tick>,
    next_graffiti_index: usize,
    attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    own_beacon_committee_members: Arc<OwnBeaconCommitteeMembers>,
    own_singular_attestations: OnceCell<Vec<OwnAttestation<P>>>,
    own_sync_committee_members: Arc<OwnSyncCommitteeMembers>,
    own_validator_indices: Arc<OwnValidatorIndices>,
    own_sync_committee_subscriptions: OwnSyncCommitteeSubscriptions<P>,
    sent_sync_committee_subscriptions_for: Option<Epoch>,
    own_ptc_members: Arc<OwnPTCMembers>,
    own_payload_attestations: OnceCell<Vec<PayloadAttestationMessage>>,
    published_own_sync_committee_messages_for: Option<SlotHead<P>>,
    // Contributions must aggregate the root the messages voted for, which is the head of the
    // beacon node the duty was performed against rather than the head this validator sees.
    own_sync_committee_message_root: Option<H256>,
    own_aggregators: BTreeMap<AttestationKey, Vec<Aggregator>>,
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
    payload_attestation_agg_pool: Arc<PayloadAttestationAggPool<P, W>>,
    sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    metrics: Option<Arc<Metrics>>,
    validator_statistics: Option<Arc<ValidatorStatistics>>,
    internal_tx: UnboundedSender<InternalMessage>,
    internal_rx: UnboundedReceiver<InternalMessage>,
    api_to_liveness_tx: Option<UnboundedSender<ApiToLiveness>>,
    validator_to_liveness_tx: Option<UnboundedSender<ValidatorToLiveness<P>>>,
    validator_to_slasher_tx: Option<UnboundedSender<ValidatorToSlasher>>,
    last_cgc_update_epoch: Option<Epoch>,
    dedicated_executor_normal_priority: Arc<DedicatedExecutor>,
    dedicated_executor_low_priority: Arc<DedicatedExecutor>,
    last_proposer_preferences_epoch: Option<Epoch>,
    published_proposer_preferences: HashSet<(H256, Slot, ValidatorIndex)>,
    remote_beacon_nodes: Arc<RemoteBeaconNodes>,
    mode: ValidatorMode,
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
        payload_attestation_agg_pool: Arc<PayloadAttestationAggPool<P, W>>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
        metrics: Option<Arc<Metrics>>,
        validator_statistics: Option<Arc<ValidatorStatistics>>,
        channels: Channels<P, W>,
        _network_dir: Option<&Path>,
        dedicated_executor_normal_priority: Arc<DedicatedExecutor>,
        dedicated_executor_low_priority: Arc<DedicatedExecutor>,
        beacon_node_urls: Vec<RedactingUrl>,
        disable_local_beacon_node: bool,
    ) -> Self {
        let chain_config = controller.chain_config().clone_arc();
        let serving_count = Arc::new(AtomicUsize::new(beacon_node_urls.len()));

        let remote_beacon_nodes = beacon_node_urls
            .into_iter()
            .map(|url| {
                Arc::new(RemoteBeaconNode::new(
                    chain_config.clone_arc(),
                    signer.load().client().clone(),
                    url,
                    validator_config.max_empty_slots,
                    serving_count.clone_arc(),
                ))
            })
            .collect::<Vec<_>>();

        let mode = ValidatorMode::new(disable_local_beacon_node, !remote_beacon_nodes.is_empty());

        let Channels {
            api_to_liveness_tx,
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

        let own_ptc_members = Arc::new(OwnPTCMembers::new(signer.clone_arc()));

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
            own_sync_committee_members: Arc::new(OwnSyncCommitteeMembers::new()),
            own_validator_indices: Arc::new(OwnValidatorIndices::new(signer.clone_arc())),
            own_sync_committee_subscriptions: OwnSyncCommitteeSubscriptions::default(),
            sent_sync_committee_subscriptions_for: None,
            own_ptc_members,
            own_payload_attestations: OnceCell::new(),
            published_own_sync_committee_messages_for: None,
            own_sync_committee_message_root: None,
            own_aggregators: BTreeMap::new(),
            builder_api,
            doppelganger_protection,
            event_channels,
            last_registration_epoch: None,
            proposer_configs,
            signer,
            slashing_protector,
            payload_attestation_agg_pool,
            sync_committee_agg_pool,
            slasher_to_validator_rx,
            subnet_service_tx,
            registered_validators: BTreeMap::new(),
            metrics,
            validator_statistics,
            internal_rx,
            internal_tx,
            api_to_liveness_tx,
            validator_to_liveness_tx,
            validator_to_slasher_tx,
            last_cgc_update_epoch: None,
            dedicated_executor_normal_priority,
            dedicated_executor_low_priority,
            last_proposer_preferences_epoch: None,
            published_proposer_preferences: HashSet::new(),
            remote_beacon_nodes: Arc::new(RemoteBeaconNodes::new(remote_beacon_nodes)),
            mode,
        }
    }

    fn beacon_nodes(&self, source: &DutySource<P>, wait_group: &W) -> BeaconNodes<P, W> {
        let slot_head = source.slot_head();

        let local = source
            .beacon_state()
            .filter(|_| self.mode.uses_local_node())
            .map(|beacon_state| {
                LocalBeaconNode::new(
                    self.controller.clone_arc(),
                    slot_head.clone(),
                    beacon_state.clone_arc(),
                    self.attestation_agg_pool.clone_arc(),
                    self.sync_committee_agg_pool.clone_arc(),
                    self.payload_attestation_agg_pool.clone_arc(),
                    self.signer.clone_arc(),
                    self.p2p_tx.clone(),
                    self.subnet_service_tx.clone(),
                    self.api_to_liveness_tx.clone(),
                    wait_group.clone(),
                )
            });

        BeaconNodes::new(
            local,
            slot_head.slot(),
            self.validator_config.max_empty_slots,
            &self.remote_beacon_nodes,
            self.validator_config.publish_to_every_node.clone(),
        )
    }

    async fn remote_slot_head(&self, slot: Slot) -> Result<Option<SlotHead<P>>> {
        if !self.mode.has_remote_nodes() {
            return Ok(None);
        }

        let slot_head = self.remote_beacon_nodes_at(slot).slot_head(slot).await?;

        if slot_head.is_none() {
            warn_with_peers!(
                "no beacon node given with --beacon-node-urls reported a head recent enough to \
                 perform duties for slot {slot}",
            );
        }

        Ok(slot_head)
    }

    fn remote_beacon_nodes_at(&self, slot: Slot) -> BeaconNodes<P, W> {
        BeaconNodes::new(
            None,
            slot,
            self.validator_config.max_empty_slots,
            &self.remote_beacon_nodes,
            self.validator_config.publish_to_every_node.clone(),
        )
    }

    pub async fn run(self) -> Result<()> {
        if !self.mode.supports_block_production() {
            warn_with_peers!(
                "--disable-local-beacon-node does not support block production; \
                 any such duties will be missed",
            );
        }

        self.remote_beacon_nodes
            .check_on_startup(self.controller.slot())
            .await?;
        self.remote_beacon_nodes.spawn_head_streams::<P>();
        self.run_internal().await
    }

    async fn run_internal(mut self) -> Result<()> {
        let mut health_check = HealthCheck::new("validator");

        loop {
            let mut slasher_to_validator_rx = self
                .slasher_to_validator_rx
                .as_mut()
                .map(EitherFuture::Left)
                .unwrap_or_else(|| EitherFuture::Right(futures::stream::pending()));

            select! {
                _ = health_check.interval.select_next_some() => {
                    health_check.check();
                },

                message = self.internal_rx.select_next_some() => match message {
                    InternalMessage::DoppelgangerProtectionResult(result) => {
                        if let Err(error) = result {
                            // The typed error must reach the application restart loop intact:
                            // it exits for good on `DoppelgangersDetected` instead of retrying.
                            if error.downcast_ref::<DoppelgangerProtectionError>().is_some() {
                                return Err(error);
                            }

                            // A failed liveness query postpones activation instead.
                            warn_with_peers!("doppelganger liveness check failed: {error:?}");
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
                        self.handle_head_message(wait_group, head).await
                    }
                    ValidatorMessage::ValidAttestation(wait_group, attestation) => {
                        self.attestation_agg_pool
                            .insert_attestation(wait_group, attestation.clone_arc(), None);

                        if let Some(validator_to_liveness_tx) = &self.validator_to_liveness_tx {
                            ValidatorToLiveness::ValidAttestation(attestation)
                                .send(validator_to_liveness_tx);
                        }
                    },
                    ValidatorMessage::ValidPayloadAttestation(wait_group, payload_attestation) => {
                        let span = tracing::debug_span!("ValidatorMessage::ValidPayloadAttestation", service = "validator");
                        let _enter = span.enter();

                        self.payload_attestation_agg_pool
                            .insert_payload_attestation(wait_group, payload_attestation);

                        // TODO(gloas): apply payload attestation to liveness_tracker
                        //
                        // if let Some(validator_to_liveness_tx) = &self.validator_to_liveness_tx {
                        //     ValidatorToLiveness::ValidPayloadAttestation(payload_attestation)
                        //         .send(validator_to_liveness_tx);
                        // }
                    },
                    ValidatorMessage::PrepareExecutionPayload(slot, safe_execution_payload_hash, finalized_execution_payload_hash) => {
                        self.prepare_execution_payload(slot, safe_execution_payload_hash, finalized_execution_payload_hash).await
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
                    P2pToValidator::AttesterSlashing(slashing, gossip_id, wait_group) => {
                        self.handle_attester_slashing(slashing, gossip_id, wait_group).await
                    }
                    P2pToValidator::ProposerSlashing(slashing, gossip_id, wait_group) => {
                        self.handle_propser_slashing(*slashing, gossip_id, wait_group).await
                    }
                    P2pToValidator::VoluntaryExit(voluntary_exit, gossip_id, wait_group) => {
                        self.handle_voluntary_exit(*voluntary_exit, gossip_id, wait_group).await
                    }
                },

                api_message = self.api_to_validator_rx.select_next_some() => {
                    let success = match api_message {
                        ApiToValidator::RegisteredValidators(sender) => {
                            self.handle_registered_validators(sender)
                        },
                        ApiToValidator::SignedContributionsAndProofs(sender, contributions_and_proofs) => {
                            self.handle_signed_contributions_and_proofs(sender, contributions_and_proofs).await
                        },
                        ApiToValidator::ValidatorRegistrations(validator_registrations) => {
                            self.handle_validator_registrations(validator_registrations)
                        }
                    };

                    if !success {
                        debug_with_peers!("send to HTTP API failed because the receiver was dropped");
                    }
                }

                complete => break,
            }
        }

        Ok(())
    }

    #[instrument(parent = None, level = "debug", fields(service = "validator"), skip_all)]
    fn handle_registered_validators(&self, sender: Sender<HashSet<PublicKeyBytes>>) -> bool {
        let registered_pubkeys = self
            .registered_validators
            .values()
            .flat_map(BTreeMap::keys)
            .copied()
            .collect();

        sender.send(registered_pubkeys).is_ok()
    }

    #[instrument(parent = None, level = "debug", fields(service = "validator"), skip_all)]
    fn handle_validator_registrations(
        &mut self,
        validator_registrations: Vec<(ValidatorRegistrationV1, Signature)>,
    ) -> bool {
        let current_slot = self.controller.slot();
        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);

        let registrations = validator_registrations
            .into_iter()
            .map(|registration| (registration.0.pubkey, registration))
            .collect();

        self.registered_validators
            .entry(current_epoch)
            .and_modify(|map| map.extend(&registrations))
            .or_insert(registrations);

        true
    }

    #[instrument(parent = None, level = "debug", fields(service = "validator"), skip_all)]
    async fn handle_signed_contributions_and_proofs(
        &self,
        sender: Sender<Option<Vec<(usize, AnyhowError)>>>,
        contributions_and_proofs: Vec<SignedContributionAndProof<P>>,
    ) -> bool {
        let current_slot = self.controller.slot();
        let slot_head = self.safe_slot_head(current_slot).await;

        let failures = slot_head
            .map(|(slot_head, _)| {
                self.handle_external_contributions_and_proofs(slot_head, contributions_and_proofs)
            })
            .conv::<OptionFuture<_>>()
            .await;

        sender.send(failures).is_ok()
    }

    #[instrument(parent = None, level = "debug", fields(service = "validator"), skip_all)]
    async fn handle_propser_slashing(
        &self,
        slashing: ProposerSlashing,
        gossip_id: GossipId,
        _wait_group: W,
    ) {
        let outcome = match self
            .block_producer
            .handle_external_proposer_slashing(slashing)
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                warn_with_peers!("failed to handle proposer slashing: {error}");
                return;
            }
        };

        if matches!(outcome, PoolAdditionOutcome::Accept) {
            self.event_channels.send_proposer_slashing_event(slashing);
        }

        self.handle_pool_addition_outcome_for_p2p(outcome, gossip_id);
    }

    #[instrument(parent = None, level = "debug", fields(service = "validator"), skip_all)]
    async fn handle_attester_slashing(
        &self,
        slashing: Box<AttesterSlashing<P>>,
        gossip_id: GossipId,
        _wait_group: W,
    ) {
        let outcome = match self
            .block_producer
            .handle_external_attester_slashing(*slashing.clone())
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                warn_with_peers!("failed to handle attester slashing: {error}");
                return;
            }
        };

        if matches!(outcome, PoolAdditionOutcome::Accept) {
            self.event_channels.send_attester_slashing_event(slashing);
        }

        self.handle_pool_addition_outcome_for_p2p(outcome, gossip_id);
    }

    #[instrument(parent = None, level = "debug", fields(service = "validator"), skip_all)]
    async fn handle_voluntary_exit(
        &self,
        voluntary_exit: SignedVoluntaryExit,
        gossip_id: GossipId,
        _wait_group: W,
    ) {
        let outcome = match self
            .block_producer
            .handle_external_voluntary_exit(voluntary_exit)
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                warn_with_peers!("failed to handle voluntary exit: {error}");
                return;
            }
        };

        if matches!(outcome, PoolAdditionOutcome::Accept) {
            self.event_channels
                .send_voluntary_exit_event(voluntary_exit);
        }

        self.handle_pool_addition_outcome_for_p2p(outcome, gossip_id);
    }

    #[instrument(parent = None, level = "debug", fields(service = "validator"), skip_all)]
    async fn handle_head_message(&mut self, wait_group: W, head: ChainLink<P>) {
        if let Some(validator_to_liveness_tx) = &self.validator_to_liveness_tx {
            let state = self.controller.state_by_chain_link(&head);
            ValidatorToLiveness::Head(head.block.clone_arc(), state).send(validator_to_liveness_tx);
        }

        self.attest_gossip_block(&wait_group, head).await;
    }

    #[instrument(
        parent = None,
        level = "debug",
        fields(
            service = "validator",
            slot = %slot,
        ),
        skip_all
    )]
    async fn prepare_execution_payload(
        &self,
        slot: Slot,
        safe_execution_payload_hash: ExecutionBlockHash,
        finalized_execution_payload_hash: ExecutionBlockHash,
    ) {
        let slot_head = self.safe_slot_head(slot).await;

        if let Some((slot_head, beacon_state)) = slot_head {
            let proposer_index = match slot_head.proposer_index(&beacon_state) {
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
                || self
                    .attestation_agg_pool
                    .is_registered_validator(proposer_index)
                    .await;

            if !should_prepare_execution_payload {
                return;
            }

            let block_build_context = self.block_producer.new_build_context(
                beacon_state.clone_arc(),
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

            if let Some(state) = beacon_state.post_bellatrix() {
                let payload = state.latest_execution_payload_header();

                self.event_channels.send_payload_attributes_event(
                    slot_head.phase(),
                    slot,
                    proposer_index,
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

    #[expect(clippy::too_many_lines)]
    #[instrument(
        parent = None,
        level = "debug",
        fields(
            service = "validator",
            tick = ?tick,
        ),
        skip_all
    )]
    async fn handle_tick(&mut self, wait_group: W, tick: Tick) -> Result<()> {
        if let Some(metrics) = self.metrics.as_ref()
            && tick.is_start_of_interval()
        {
            let tick_delay = tick.delay::<P>(&self.chain_config, self.controller.genesis_time())?;
            debug_with_peers!("tick_delay: {tick_delay:?} for {tick:?}");
            metrics.set_tick_delay(tick.kind.as_ref(), tick_delay);
        }

        let Tick { slot, kind } = tick;

        let current_epoch = misc::compute_epoch_at_slot::<P>(slot);

        if self.last_registration_epoch != Some(current_epoch) {
            self.register_validators(current_epoch).await;
        }

        let no_validators = self.signer.load().no_keys()
            && self.registered_validators.is_empty()
            && self.block_producer.no_prepared_proposers().await;

        debug_with_peers!("{kind:?} tick in slot {slot}");

        if kind == TickKind::ProposeFourth {
            let remote_beacon_nodes = self.remote_beacon_nodes.clone_arc();
            tokio::spawn(async move { remote_beacon_nodes.check_status(slot).await });
        }

        if tick.is_start_of_epoch::<P>() {
            let _timer = self
                .metrics
                .as_ref()
                .map(|metrics| metrics.validator_epoch_processing_times.start_timer());

            if let Some(validator_to_slasher_tx) = &self.validator_to_slasher_tx {
                ValidatorToSlasher::Epoch(current_epoch).send(validator_to_slasher_tx);
            }

            if let Some(validator_to_liveness_tx) = &self.validator_to_liveness_tx {
                ValidatorToLiveness::Epoch(current_epoch).send(validator_to_liveness_tx);
            }

            self.discard_old_proposer_preferences(current_epoch);
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

        let own_validator_indices = self
            .attestation_agg_pool
            .registered_validator_indices()
            .await;

        if self.last_cgc_update_epoch != Some(current_epoch)
            && self.validator_config.custody_mode != CustodyMode::Super
            && self.chain_config.is_peerdas_scheduled()
            && !own_validator_indices.is_empty()
        {
            self.handle_custody_requirements_update(slot, &own_validator_indices);
        }

        self.track_collection_metrics().await;

        let local_head = if no_validators || !self.mode.uses_local_node() {
            None
        } else {
            self.slot_head(slot)
                .await?
                .map_err(|head_far_behind| warn_with_peers!("{head_far_behind}"))
                .ok()
        };

        // Fallback if local node has no slot head
        let duty_source = match local_head {
            Some((slot_head, beacon_state)) => Some(DutySource::Local {
                slot_head,
                beacon_state,
            }),
            None if no_validators => None,
            None => self
                .remote_slot_head(slot)
                .await?
                .map(|slot_head| DutySource::Remote { slot_head }),
        };

        if let Err(error) = self
            .update_subnet_subscriptions(&wait_group, tick, duty_source.as_ref())
            .await
        {
            warn_with_peers!("failed to update subnet subscriptions: {error:?}");
        }

        if misc::is_epoch_start::<P>(slot) && kind == TickKind::AggregateFourth {
            self.refresh_signer_keys();
        }

        let Some(duty_source) = duty_source else {
            return Ok(());
        };

        if tick.is_start_of_slot()
            && let Some(doppelganger_protection) = &self.doppelganger_protection
        {
            let doppelganger_protection = doppelganger_protection.clone_arc();
            let internal_tx = self.internal_tx.clone();
            let beacon_nodes = self.beacon_nodes(&duty_source, &wait_group);
            let own_validator_indices = self.own_validator_indices.clone_arc();

            tokio::spawn(async move {
                own_validator_indices
                    .update(&beacon_nodes, misc::compute_epoch_at_slot::<P>(slot))
                    .await;

                let indices_by_pubkey = own_validator_indices.indices_by_pubkey().await;

                let result = doppelganger_protection
                    .detect_doppelgangers::<P, _, _>(
                        slot,
                        &indices_by_pubkey,
                        |epoch, validator_indices| {
                            let beacon_nodes = &beacon_nodes;

                            async move {
                                let liveness =
                                    beacon_nodes.liveness(epoch, &validator_indices).await?;

                                Ok(liveness
                                    .into_iter()
                                    .map(|response| (response.index, response.is_live))
                                    .collect())
                            }
                        },
                    )
                    .await;

                InternalMessage::DoppelgangerProtectionResult(result).send(&internal_tx);
            });
        }

        // Only the built-in beacon node has a state, and only it performs these.
        if let DutySource::Local {
            slot_head,
            beacon_state,
        } = &duty_source
        {
            self.attestation_agg_pool
                .compute_proposer_indices(beacon_state.clone_arc());

            if self.last_proposer_preferences_epoch != Some(current_epoch)
                && (beacon_state.post_gloas().is_some()
                    || self.chain_config.gloas_fork_epoch == current_epoch.saturating_add(1))
            {
                self.publish_proposer_preferences(slot_head, beacon_state);
                self.last_proposer_preferences_epoch = Some(current_epoch);
            }
        }

        match kind {
            TickKind::Propose => {
                let _timer = self
                    .metrics
                    .as_ref()
                    .map(|metrics| metrics.validator_propose_tick_times.start_timer());

                // TODO(Gloas): review and fix
                // let duty_source = self.wait_for_fully_validated_head(duty_source).await;

                self.discard_previous_slot_attestations();
                self.discard_previous_slot_payload_attestations();
                self.propose(wait_group, Some(&duty_source)).await?;
                self.published_own_sync_committee_messages_for = None;
                self.own_sync_committee_message_root = None;
            }
            TickKind::Attest => {
                let _timer = self
                    .metrics
                    .as_ref()
                    .map(|metrics| metrics.validator_attest_tick_times.start_timer());

                // TODO(Gloas): review and fix
                // let duty_source = self.wait_for_fully_validated_head(duty_source).await;

                if let Err(error) = self
                    .attest_and_start_aggregating(&wait_group, Some(&duty_source))
                    .await
                {
                    error_with_peers!("failed to produce and publish own attestations: {error:?}");
                }

                if let Err(error) = self
                    .publish_sync_committee_messages(&wait_group, Some(&duty_source))
                    .await
                {
                    error_with_peers!(
                        "failed to produce and publish own sync_committee messages: {error:?}"
                    );
                }
            }
            TickKind::Aggregate => {
                let _timer = self
                    .metrics
                    .as_ref()
                    .map(|metrics| metrics.validator_aggregate_tick_times.start_timer());

                // TODO(Gloas): review and fix
                // let duty_source = self.wait_for_fully_validated_head(duty_source).await;

                self.publish_aggregates_and_proofs(&wait_group, Some(&duty_source))
                    .await;

                self.publish_contributions_and_proofs(&wait_group, Some(&duty_source))
                    .await;
            }
            TickKind::PayloadAttest => {
                // TODO(Gloas): review and fix
                // let duty_source = self.wait_for_fully_validated_head(duty_source).await;

                if let Err(error) = self.attest_payload(&wait_group, Some(&duty_source)).await {
                    error_with_peers!(
                        "failed to produce and publish own payload attestations: {error:?}"
                    );
                }
            }
            _ => {}
        }

        if misc::is_epoch_start::<P>(slot) && tick.is_end_of_slot::<P>(&self.chain_config) {
            self.spawn_pruning(slot);
        }

        self.last_tick = Some(tick);

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    async fn safe_slot_head(&self, slot: Slot) -> Option<LocalHead<P>> {
        self.slot_head(slot)
            .await
            .map(Result::ok)
            .map_err(|error| error_with_peers!("state transition to slot {slot} failed: {error:?}"))
            .unwrap_or_default()
    }

    // The nested `Result` is inspired by `sled`:
    // <https://sled.rs/errors.html#making-unhandled-errors-unrepresentable>
    #[instrument(level = "debug", skip_all, fields(slot = slot))]
    async fn slot_head(&self, slot: Slot) -> Result<Result<LocalHead<P>, HeadFarBehind>> {
        let WithStatus {
            value: head,
            status,
            ..
        } = self.controller.head();

        let block_root = head.block_root;
        let state = self.controller.state_by_chain_link(&head);
        let head_slot = head.slot();
        let max_empty_slots = self.validator_config.max_empty_slots;

        if head_slot.saturating_add(max_empty_slots) < slot {
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

        let slot_head = SlotHead {
            config: self.chain_config.clone_arc(),
            slot,
            beacon_block_root: block_root,
            fork_info: beacon_state.as_ref().into(),
            optimistic: status.is_optimistic(),
        };

        Ok(Ok((slot_head, beacon_state)))
    }

    /// <https://github.com/ethereum/consensus-specs/blob/b2f42bf4d79432ee21e2f2b3912ff4bbf7898ada/specs/phase0/validator.md#block-proposal>
    #[expect(clippy::too_many_lines)]
    #[instrument(level = "debug", skip_all)]
    async fn propose(&mut self, wait_group: W, source: Option<&DutySource<P>>) -> Result<()> {
        let Some(source) = source else {
            warn_with_peers!(
                "validator cannot produce a block because \
                 chain head has not been fully verified by an execution engine",
            );
            return Ok(());
        };

        // Blocks are produced by the built-in beacon node alone.
        let DutySource::Local {
            slot_head,
            beacon_state,
        } = source
        else {
            return Ok(());
        };

        if slot_head.slot() == GENESIS_SLOT {
            // All peers should already have the genesis block.
            // It would fail multiple validations if it were published like non-genesis blocks.
            return Ok(());
        }

        let proposer_index =
            tokio::task::block_in_place(|| slot_head.proposer_index(beacon_state))?;

        let public_key = accessors::public_key(beacon_state.as_ref(), proposer_index)?;
        let signer_snapshot = self.signer.load();

        if !signer_snapshot.has_key(*public_key) {
            return Ok(());
        }

        let doppelganger_protection = self
            .doppelganger_protection
            .as_deref()
            .map(DoppelgangerProtection::load);

        if let Some(doppelganger_protection) = &doppelganger_protection
            && !doppelganger_protection.is_validator_active(*public_key)
        {
            info_with_peers!(
                "Validator {public_key:?} skipping proposer duty in slot {} \
                     since not enough time has passed to ensure there are \
                     no doppelganger validators participating on network. \
                     Validator will start performing duties on slot {}.",
                slot_head.slot(),
                doppelganger_protection.tracking_end_slot::<P>(*public_key),
            );

            return Ok(());
        }

        info_with_peers!(
            "starting block proposal task for validator {proposer_index} at slot {}",
            slot_head.slot()
        );

        let _propose_timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.validator_propose_times.start_timer());

        let graffiti = self
            .proposer_configs
            .graffiti_bytes(*public_key)?
            .or_else(|| self.next_graffiti());

        let block_build_context = self.block_producer.new_build_context(
            beacon_state.clone_arc(),
            slot_head.beacon_block_root,
            proposer_index,
            BlockBuildOptions {
                graffiti,
                disable_blockprint_graffiti: self.validator_config.disable_blockprint_graffiti,
                builder_boost_factor: self.validator_config.builder_boost_factor(*public_key),
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
                RandaoEpoch::from(epoch)
                    .signing_root_from_fork_info(&self.chain_config, slot_head.fork_info),
                Some(slot_head.fork_info),
                *public_key,
            )
            .await;

        let randao_reveal = match result {
            Ok(signature) => signature.into(),
            Err(error) => {
                warn_with_peers!(
                    "failed to sign RANDAO reveal (epoch: {epoch}, public_key: {public_key}): \
                    {error:?}",
                );

                return Ok(());
            }
        };

        info_with_peers!(
            "block producer starting block production task at slot {}",
            slot_head.slot()
        );

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
                warn_with_peers!("failed to produce beacon block: {error}");
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
            warn_with_peers!(
                "validator {} skipping beacon block proposal in slot {}",
                proposer_index,
                slot_head.slot(),
            );
            return Ok(());
        };

        info_with_peers!(
            "block producer finished block production task at slot {}",
            slot_head.slot()
        );

        let beacon_block_or_root = match validator_blinded_block {
            ValidatorBlindedBlock::BlindedBeaconBlock(blinded_block) => {
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

                match self
                    .post_blinded_block(
                        slot_head,
                        signed_blinded_block,
                        &mut block_blobs,
                        &mut block_proofs,
                    )
                    .await?
                {
                    Some(signed_block) => signed_block,
                    None => return Ok(()),
                }
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
                    Some(signature) => SignedBeaconBlockOrBlockRoot::Block(Box::new(
                        block.with_signature(signature),
                    )),
                    None => return Ok(()),
                }
            }
        };

        match beacon_block_or_root {
            SignedBeaconBlockOrBlockRoot::Root(block_root) => info_with_peers!(
                "validator {} proposing beacon block with root {:?} in slot {} using builder",
                proposer_index,
                block_root,
                slot_head.slot(),
            ),
            SignedBeaconBlockOrBlockRoot::Block(beacon_block) => {
                let beacon_block_root = beacon_block.message().hash_tree_root();
                let parent_beacon_block_root = beacon_block.message().parent_root();

                if let Some(payload_bid) = beacon_block.payload_bid()
                    && payload_bid.builder_index != BUILDER_INDEX_SELF_BUILD
                {
                    info_with_peers!(
                        "validator {} proposing beacon block with root {:?} in slot {} using builder {}",
                        proposer_index,
                        beacon_block_root,
                        slot_head.slot(),
                        payload_bid.builder_index
                    );
                } else {
                    info_with_peers!(
                        "validator {} proposing beacon block with root {:?} in slot {}",
                        proposer_index,
                        beacon_block_root,
                        slot_head.slot(),
                    );
                }

                debug_with_peers!("beacon block: {beacon_block:?}");

                let block = Arc::new(*beacon_block);

                let self_built = block
                    .payload_bid()
                    .is_some_and(|bid| bid.builder_index == BUILDER_INDEX_SELF_BUILD);

                if (slot_head.phase() < Phase::Gloas || self_built)
                    && let Some(blobs) = block_blobs
                    && !blobs.is_empty()
                {
                    self.publish_blob_data(&wait_group, slot_head, &block, blobs, block_proofs)
                        .await?;
                }

                self.controller
                    .on_own_block(wait_group.clone(), block.clone_arc());

                ValidatorToP2p::PublishBeaconBlock(block).send(&self.p2p_tx);

                // If self-building:
                // Publish the execution payload envelope after the beacon block so PTC members
                // have seen the block (and its SignedExecutionPayloadBid) before attesting
                if self_built
                    && let Some((envelope, ..)) = self
                        .block_producer
                        .build_local_execution_payload_envelope_contents(
                            beacon_block_root,
                            parent_beacon_block_root,
                        )
                        .await
                {
                    self.publish_execution_payload_envelope(
                        slot_head,
                        beacon_block_root,
                        envelope,
                        proposer_index,
                        &signer_snapshot,
                        public_key,
                    )
                    .await?;
                }
            }
        }

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.validator_propose_successes.inc();
        }

        Ok(())
    }

    async fn post_blinded_block(
        &self,
        slot_head: &SlotHead<P>,
        signed_blinded_block: SignedBlindedBeaconBlock<P>,
        block_blobs: &mut Option<ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>>,
        block_proofs: &mut Option<KzgProofs<P>>,
    ) -> Result<Option<SignedBeaconBlockOrBlockRoot<P>>> {
        let builder_api = self
            .builder_api
            .as_ref()
            .expect("Builder API should be present as it was used to query ExecutionPayloadHeader");

        let signed_block = if slot_head.phase() >= Phase::Fulu
            && builder_api
                .post_blinded_block_post_fulu(
                    &self.chain_config,
                    self.controller.genesis_time(),
                    &signed_blinded_block,
                )
                .await
                .is_ok()
        {
            debug_with_peers!("submitted blinded block to the builder node");

            Some(SignedBeaconBlockOrBlockRoot::Root(
                signed_blinded_block.message().hash_tree_root(),
            ))
        } else {
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
                    if let Some(reqwest_error) = error.downcast_ref::<reqwest::Error>() {
                        if reqwest_error.is_timeout() {
                            // If posting signed blinded beacon block to builder fails, don't print a warning,
                            // because builder should publish the block anyway, just cannot respond in a timely
                            // manner. We cannot do anything else here either, but exit early from propose, due
                            // to the risk of slashing.
                            debug_with_peers!(
                                "failed to post blinded block to the builder node: {error:?}"
                            );
                        }

                        return Ok(None);
                    }

                    warn_with_peers!("failed to post blinded block to the builder node: {error:?}");

                    return Ok(None);
                }
            };

            *block_proofs = proofs;
            *block_blobs = blobs;

            debug_with_peers!(
                "received execution payload from the builder node: {execution_payload:?}"
            );

            let (message, signature) = signed_blinded_block.split();

            Some(SignedBeaconBlockOrBlockRoot::Block(Box::new(
                message
                    .with_execution_payload(execution_payload)?
                    .with_signature(signature),
            )))
        };

        Ok(signed_block)
    }

    async fn publish_blob_data(
        &self,
        wait_group: &W,
        slot_head: &SlotHead<P>,
        block: &Arc<SignedBeaconBlock<P>>,
        blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
        block_proofs: Option<KzgProofs<P>>,
    ) -> Result<()> {
        if slot_head.phase().is_peerdas_activated() {
            let data_column_sidecars = eip_7594::construct_data_column_sidecars_from_blobs(
                block.clone_arc().into(),
                blobs.into_iter(),
                block_proofs
                    .unwrap_or_else(KzgProofs::empty_fulu)
                    .into_iter()
                    .collect_vec(),
                self.controller.store_config().kzg_backend,
                self.metrics.clone(),
                self.dedicated_executor_normal_priority.clone_arc(),
            )
            .await?;

            for data_column_sidecar in data_column_sidecars {
                if self
                    .controller
                    .sampling_columns()
                    .into_iter()
                    .contains(&data_column_sidecar.index())
                {
                    self.controller
                        .on_own_data_column_sidecar(
                            wait_group.clone(),
                            data_column_sidecar.clone_arc(),
                        )
                        .await;
                }

                ValidatorToP2p::PublishDataColumnSidecar(data_column_sidecar).send(&self.p2p_tx);
            }
        } else {
            for blob_sidecar in misc::construct_blob_sidecars(
                block,
                blobs,
                block_proofs.unwrap_or_else(KzgProofs::empty_deneb),
            )? {
                let blob_sidecar = Arc::new(blob_sidecar);

                self.controller
                    .on_own_blob_sidecar(wait_group.clone(), blob_sidecar.clone_arc());
            }
        }

        Ok(())
    }

    /// Create and sign Gloas execution payload envelope for self-build proposers.
    /// Returns None if envelope data is not available (i.e., not self-building).
    async fn publish_execution_payload_envelope(
        &self,
        slot_head: &SlotHead<P>,
        beacon_block_root: H256,
        envelope: ExecutionPayloadEnvelope<P>,
        proposer_index: ValidatorIndex,
        signer_snapshot: &Snapshot,
        public_key: &PublicKeyBytes,
    ) -> Result<()> {
        // Sign the envelope
        let envelope_sig = match signer_snapshot
            .sign_without_slashing_protection(
                SigningMessage::ExecutionPayloadEnvelope(&envelope),
                envelope.signing_root_from_fork_info(&self.chain_config, slot_head.fork_info),
                Some(slot_head.fork_info),
                *public_key,
            )
            .await
        {
            Ok(signature) => signature.into(),
            Err(error) => {
                warn_with_peers!(
                    "failed to sign execution payload envelope (slot: {}, public_key: {public_key}): \
                    {error:?}",
                    slot_head.slot(),
                );

                return Ok(());
            }
        };

        let signed_envelope = Arc::new(SignedExecutionPayloadEnvelope {
            message: envelope,
            signature: envelope_sig,
        });

        debug_with_peers!(
            "validator {} publishing execution payload envelope for block {:?} in slot {}",
            proposer_index,
            beacon_block_root,
            slot_head.slot(),
        );

        // Publish envelope to controller and P2P
        self.controller
            .on_own_execution_payload_envelope(signed_envelope.clone_arc());

        ValidatorToP2p::PublishExecutionPayloadEnvelope(signed_envelope).send(&self.p2p_tx);

        Ok(())
    }

    /// See:
    /// - <https://github.com/ethereum/consensus-specs/blob/b2f42bf4d79432ee21e2f2b3912ff4bbf7898ada/specs/phase0/validator.md#attesting>
    /// - <https://github.com/ethereum/consensus-specs/blob/b2f42bf4d79432ee21e2f2b3912ff4bbf7898ada/specs/phase0/validator.md#attestation-aggregation>
    #[expect(clippy::too_many_lines)]
    #[instrument(level = "debug", skip_all)]
    async fn attest_and_start_aggregating(
        &mut self,
        wait_group: &W,
        source: Option<&DutySource<P>>,
    ) -> Result<()> {
        let Some(source) = source else {
            warn_with_peers!(
                "validator cannot participate in attestation because \
                 chain head has not been fully verified by an execution engine",
            );
            return Ok(());
        };

        let slot_head = source.slot_head();

        // Skip attesting if validators already attested at slot
        if self.attested_in_current_slot() {
            return Ok(());
        }

        let timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.validator_attest_times.start_timer());

        let beacon_nodes = self.beacon_nodes(source, wait_group);

        let Some((own_members, needs_to_update_subscriptions)) = self
            .own_beacon_committee_members
            .get_or_init_at_slot(&self.controller, source.beacon_state(), slot_head.slot())
            .await?
        else {
            return Ok(());
        };

        if needs_to_update_subscriptions
            && let Err(error) = beacon_nodes
                .subscribe_to_beacon_committees(
                    slot_head.slot(),
                    &own_members
                        .iter()
                        .copied()
                        .map(Into::into)
                        .collect::<Vec<_>>(),
                )
                .await
        {
            warn_with_peers!("failed to update beacon committee subscriptions: {error:?}");
        }

        let own_singular_attestations = self
            .own_singular_attestations(slot_head, &own_members, &beacon_nodes)
            .await?;

        if own_singular_attestations.is_empty() {
            prometheus_metrics::stop_and_discard(timer);
            return Ok(());
        }

        info_with_peers!(
            "validators [{}] attesting in slot {}",
            own_singular_attestations
                .iter()
                .map(|a| a.validator_index)
                .join(", "),
            slot_head.slot(),
        );

        for own_attestation in own_singular_attestations {
            let OwnAttestation {
                validator_index,
                attestation,
                ..
            } = own_attestation;

            let committee_index = misc::committee_index(attestation);

            debug_with_peers!(
                "validator {} of committee {} attesting in slot {}: {:?}",
                validator_index,
                committee_index,
                slot_head.slot(),
                attestation,
            );
        }

        if let Err(error) = beacon_nodes
            .publish_singular_attestations(own_singular_attestations)
            .await
        {
            warn_with_peers!("failed to publish attestations: {error:?}");
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

                let data = own_attestation.attestation.data();
                let key = AttestationKey {
                    data,
                    committee_index,
                };

                Some((key, aggregator))
            })
            .pipe(group_into_btreemap);

        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    #[instrument(level = "debug", skip_all)]
    async fn publish_aggregates_and_proofs(&self, wait_group: &W, source: Option<&DutySource<P>>) {
        let Some(source) = source else {
            warn_with_peers!(
                "validators cannot participate in aggregation because \
                 chain head has not been fully verified by an execution engine",
            );
            return;
        };

        let slot_head = source.slot_head();
        let config = &self.chain_config;
        let beacon_nodes = self.beacon_nodes(source, wait_group);

        let (triples, proofs): (Vec<_>, Vec<_>) = self
            .own_aggregators
            .iter()
            .map(|(key, aggregators)| {
                let beacon_nodes = &beacon_nodes;

                async move {
                    let aggregate = match beacon_nodes
                        .aggregate_attestation(key.data, key.committee_index)
                        .await
                    {
                        Ok(aggregate) => aggregate,
                        Err(error) => {
                            warn_with_peers!(
                                "failed to obtain an aggregate attestation for committee {} \
                                 in slot {}: {error:?}",
                                key.committee_index,
                                key.data.slot,
                            );
                            return vec![];
                        }
                    };

                    aggregators
                        .iter()
                        .filter_map(|aggregator| {
                            let Aggregator {
                                aggregator_index,
                                position_in_committee,
                                public_key,
                                selection_proof,
                            } = *aggregator;

                            if !aggregated_by(&aggregate, position_in_committee)? {
                                return None;
                            }

                            let aggregate_and_proof = match aggregate.clone() {
                                Attestation::Phase0(aggregate) => {
                                    AggregateAndProof::from(Phase0AggregateAndProof {
                                        aggregator_index,
                                        aggregate,
                                        selection_proof,
                                    })
                                }
                                Attestation::Electra(aggregate) => {
                                    AggregateAndProof::from(ElectraAggregateAndProof {
                                        aggregator_index,
                                        aggregate,
                                        selection_proof,
                                    })
                                }
                                Attestation::Gloas(aggregate) => {
                                    AggregateAndProof::from(GloasAggregateAndProof {
                                        aggregator_index,
                                        aggregate,
                                        selection_proof,
                                    })
                                }
                                Attestation::Single(_) => return None,
                            };

                            let triple = SigningTriple {
                                message: SigningMessage::AggregateAndProof(Box::new(
                                    aggregate_and_proof.clone(),
                                )),
                                signing_root: aggregate_and_proof
                                    .signing_root_from_fork_info(config, slot_head.fork_info),
                                public_key,
                            };

                            Some((triple, aggregate_and_proof))
                        })
                        .collect_vec()
                }
            })
            .collect::<FuturesOrdered<_>>()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .unzip();

        let signer_snapshot = self.signer.load();

        let sign_result = signer_snapshot
            .sign_triples_without_slashing_protection(triples, Some(slot_head.fork_info))
            .await;

        let signatures = match sign_result {
            Ok(signature) => signature,
            Err(error) => {
                warn_with_peers!("failed to sign aggregates and proofs: {error:?}");
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
                    AggregateAndProof::Gloas(message) => {
                        SignedAggregateAndProof::from(GloasSignedAggregateAndProof {
                            message,
                            signature: signature.into(),
                        })
                    }
                };

                debug_with_peers!("constructed aggregate and proof: {aggregate_and_proof:?}");

                aggregate_and_proof
            })
            .collect_vec();

        let Some(aggregate_and_proof) = aggregates_and_proofs.first() else {
            return;
        };

        info_with_peers!(
            "validators [{}] aggregating in slot {}",
            aggregates_and_proofs
                .iter()
                .map(SignedAggregateAndProof::aggregator_index)
                .join(", "),
            aggregate_and_proof.slot(),
        );

        let aggregates_and_proofs = aggregates_and_proofs
            .into_iter()
            .map(Arc::new)
            .collect_vec();

        if let Err(error) = beacon_nodes
            .publish_aggregates_and_proofs(&aggregates_and_proofs)
            .await
        {
            warn_with_peers!("failed to publish aggregates and proofs: {error:?}");
        }
    }

    /// <https://github.com/ethereum/consensus-specs/blob/v1.1.1/specs/altair/validator.md#broadcast-sync-committee-message>
    #[instrument(level = "debug", skip_all)]
    async fn publish_sync_committee_messages(
        &mut self,
        wait_group: &W,
        source: Option<&DutySource<P>>,
    ) -> Result<()> {
        let Some(source) = source else {
            warn_with_peers!(
                "validator cannot participate in sync committees because \
                 chain head has not been fully verified by an execution engine",
            );
            return Ok(());
        };

        let slot_head = source.slot_head();

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

        let beacon_nodes = self.beacon_nodes(source, wait_group);

        let Some(members) = self
            .sync_committee_members(&beacon_nodes, slot_head.slot())
            .await
        else {
            // A node holding no keys has nothing to prefetch and nothing to sign.
            if self.signer.load().keys().next().is_some() {
                OwnSyncCommitteeMembers::warn_about_missing_duties(slot_head.slot());
            }

            return Ok(());
        };

        if members.is_empty() {
            self.published_own_sync_committee_messages_for = Some(slot_head.clone());
            return Ok(());
        }

        let beacon_block_root = match beacon_nodes.head_block_root().await {
            Ok(beacon_block_root) => beacon_block_root,
            Err(error) => {
                warn_with_peers!(
                    "failed to obtain a head block root for sync committee messages in slot {}: \
                     {error:?}",
                    slot_head.slot(),
                );
                return Ok(());
            }
        };

        let own_messages = self
            .own_sync_committee_messages(slot_head, beacon_block_root, &members)
            .await?;

        for (subcommittee_index, messages) in &own_messages {
            if !messages.is_empty() {
                info_with_peers!(
                    "validators [{}] participating in sync subcommittee {subcommittee_index} in slot {}",
                    messages.iter().map(|m| m.validator_index).join(", "),
                    slot_head.slot(),
                );
            }

            for sync_committee_message in messages {
                debug_with_peers!(
                    "validator {} publishing sync committee message (subnet_id: {}): {:?}",
                    sync_committee_message.validator_index,
                    subcommittee_index,
                    sync_committee_message,
                );
            }
        }

        if let Err(error) = beacon_nodes
            .publish_sync_committee_messages(&own_messages)
            .await
        {
            warn_with_peers!("failed to publish sync committee messages: {error:?}");
        }

        self.published_own_sync_committee_messages_for = Some(slot_head.clone());
        self.own_sync_committee_message_root = Some(beacon_block_root);

        Ok(())
    }

    /// The sync committee members serving in `slot`, or [`None`] when duties were never obtained.
    async fn sync_committee_members(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        slot: Slot,
    ) -> Option<Vec<SyncCommitteeMember>> {
        self.cached_sync_committee_members(beacon_nodes, slot)
            .await
            .map(|members| {
                // A key removed at runtime must not fail the whole signing batch.
                let signer_snapshot = self.signer.load();

                members
                    .iter()
                    .filter(|member| signer_snapshot.has_key(member.public_key))
                    .copied()
                    .collect()
            })
    }

    async fn cached_sync_committee_members(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        slot: Slot,
    ) -> Option<Arc<[SyncCommitteeMember]>> {
        if let Some(members) = self.own_sync_committee_members.get_at_slot::<P>(slot).await {
            return Some(members);
        }

        // A restart may reach the deadline before the prefetch; only the built-in beacon node
        // answers from its state in time.
        if !beacon_nodes.has_local_node() {
            return None;
        }

        let current_epoch = misc::compute_epoch_at_slot::<P>(slot);

        self.own_validator_indices
            .update(beacon_nodes, current_epoch)
            .await;

        let validator_indices = self.own_validator_indices.get().await;

        match self
            .own_sync_committee_members
            .get_or_init_at_slot(&self.chain_config, beacon_nodes, slot, &validator_indices)
            .await
        {
            Ok(members) => members,
            Err(error) => {
                warn_with_peers!(
                    "failed to obtain sync committee duties for slot {slot}: {error:?}",
                );
                None
            }
        }
    }

    /// <https://github.com/ethereum/consensus-specs/blob/v1.1.1/specs/altair/validator.md#broadcast-sync-committee-contribution>
    #[instrument(level = "debug", skip_all)]
    async fn publish_contributions_and_proofs(
        &self,
        wait_group: &W,
        source: Option<&DutySource<P>>,
    ) {
        let Some(source) = source else {
            warn_with_peers!(
                "validator cannot participate in sync committees because \
                 chain head has not been fully verified by an execution engine",
            );
            return;
        };

        // The messages voted for the head of the slot they were signed in, which the
        // contributions must aggregate.
        let slot_head = self
            .published_own_sync_committee_messages_for
            .as_ref()
            .unwrap_or_else(|| source.slot_head());

        if !slot_head.has_sync_committee() {
            return;
        }

        let beacon_nodes = self.beacon_nodes(source, wait_group);

        let Some(members) = self
            .sync_committee_members(&beacon_nodes, slot_head.slot())
            .await
        else {
            return;
        };

        if members.is_empty() {
            return;
        }

        let beacon_block_root = self
            .own_sync_committee_message_root
            .unwrap_or(slot_head.beacon_block_root);

        let contributions = match self
            .own_contributions_and_proofs(&beacon_nodes, slot_head, beacon_block_root, &members)
            .await
        {
            Ok(contributions) => contributions,
            Err(error) => {
                error_with_peers!("error while producing own contributions and proofs: {error:?}");
                return;
            }
        };

        if contributions.is_empty() {
            return;
        }

        info_with_peers!(
            "validators [{}] aggregating in sync committee in slot {}",
            contributions
                .iter()
                .map(|c| c.message.aggregator_index)
                .join(", "),
            slot_head.slot(),
        );

        for contribution_and_proof in &contributions {
            debug_with_peers!(
                "validator {} publishing sync committee contribution and proof: {:?}",
                contribution_and_proof.message.aggregator_index,
                contribution_and_proof,
            );
        }

        if let Err(error) = beacon_nodes
            .publish_contributions_and_proofs(&contributions)
            .await
        {
            warn_with_peers!("failed to publish contributions and proofs: {error:?}");
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn attest_payload(&self, wait_group: &W, source: Option<&DutySource<P>>) -> Result<()> {
        let Some(source) = source else {
            warn_with_peers!(
                "validator cannot participate in payload attestation because \
                 chain head has not been fully verified by an execution engine",
            );

            return Ok(());
        };

        let slot_head = source.slot_head();
        let slot = slot_head.slot();

        if slot_head.phase() < Phase::Gloas {
            return Ok(());
        }

        // Skip attesting if validators already attested at slot
        if self.payload_attested_in_current_slot() {
            return Ok(());
        }

        let _timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.validator_attest_payload_times.start_timer());

        let beacon_nodes = self.beacon_nodes(source, wait_group);

        let own_members = match source {
            DutySource::Local { beacon_state, .. } => {
                let dependent_root = self
                    .controller
                    .attestation_committee_dependent_root_for_slot(beacon_state, slot)?;

                self.own_ptc_members
                    .get_or_init_at_slot(beacon_state, dependent_root, slot)
                    .await
            }
            DutySource::Remote { .. } => {
                self.own_ptc_members_from_duties(&beacon_nodes, slot_head)
                    .await?
            }
        };

        let Some(own_members) = own_members else {
            return Ok(());
        };

        if own_members.is_empty() {
            return Ok(());
        }

        // Skip attesting if no beacon node has seen a beacon block for the assigned slot
        let Some(data) = beacon_nodes.payload_attestation_data(slot).await? else {
            debug_with_peers!("no beacon block seen for slot {slot}; skipping payload attestation");
            return Ok(());
        };

        let own_payload_attestations = self
            .own_payload_attestations(slot_head, data, &own_members)
            .await?;

        if own_payload_attestations.is_empty() {
            return Ok(());
        }

        debug_with_peers!(
            "validators [{}] attesting to payload in slot {slot}",
            own_payload_attestations
                .iter()
                .map(|a| a.validator_index)
                .join(", "),
        );

        let messages = own_payload_attestations
            .iter()
            .copied()
            .map(Arc::new)
            .collect::<Vec<_>>();

        if let Err(error) = beacon_nodes.publish_payload_attestations(&messages).await {
            warn_with_peers!("failed to publish payload attestations: {error:?}");
        }

        Ok(())
    }

    /// Own PTC members of the slot from duties, for a head without a state to compute them from.
    async fn own_ptc_members_from_duties(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        slot_head: &SlotHead<P>,
    ) -> Result<Option<Arc<[PTCMember]>>> {
        let slot = slot_head.slot();
        let epoch = slot_head.current_epoch();

        // The same dependent root attester duties were fetched under, as the committees are drawn
        // from the same shuffling.
        let Some(dependent_root) = self
            .own_beacon_committee_members
            .cached_dependent_root(epoch)
            .await
        else {
            warn_with_peers!(
                "no attester duties were prefetched for slot {slot}, so no payload attestation \
                 will be produced; check that the beacon nodes given with --beacon-node-urls are \
                 reachable",
            );

            return Ok(None);
        };

        if let Some(members) = self.own_ptc_members.get_at_slot(dependent_root, slot).await {
            return Ok(Some(members));
        }

        self.own_validator_indices.update(beacon_nodes, epoch).await;

        let validator_indices = self.own_validator_indices.get().await;

        if validator_indices.is_empty() {
            return Ok(None);
        }

        self.own_ptc_members
            .init_at_epoch(beacon_nodes, epoch, dependent_root, &validator_indices)
            .await?;

        Ok(self.own_ptc_members.get_at_slot(dependent_root, slot).await)
    }

    #[instrument(level = "debug", skip_all)]
    async fn attest_gossip_block(&mut self, wait_group: &W, head: ChainLink<P>) {
        let Some(last_tick) = self.last_tick else {
            return;
        };

        if !(last_tick.slot == head.slot() && last_tick.is_before_attesting_interval()) {
            return;
        }

        // The early-publish paths act on the head of the built-in beacon node.
        if !self.mode.uses_local_node() {
            return;
        }

        let beacon_state = self.controller.state_by_chain_link(&head);

        let slot_head = SlotHead {
            config: self.chain_config.clone_arc(),
            slot: head.slot(),
            beacon_block_root: head.block_root,
            fork_info: beacon_state.as_ref().into(),
            // Validator is only notified about new fully validated chain heads
            // (ValidatorMessage::Head event does not inform validator about optimistic heads)
            optimistic: false,
        };

        let duty_source = DutySource::Local {
            slot_head,
            beacon_state,
        };

        // Publish attestations late by default.
        // This noticeably improves rewards in Goerli.
        // This is a deviation from the Honest Validator specification.
        if (duty_source.slot_head().phase() >= Phase::Gloas
            || Feature::PublishAttestationsEarly.is_enabled())
            && let Err(error) = self
                .attest_and_start_aggregating(wait_group, Some(&duty_source))
                .await
        {
            error_with_peers!("failed to produce and publish own attestations: {error:?}");
        }

        // Publish sync committee messages late by default.
        // This noticeably improves rewards in Goerli.
        // This is a deviation from the Honest Validator specification.
        if Feature::PublishSyncCommitteeMessagesEarly.is_enabled()
            && let Err(error) = self
                .publish_sync_committee_messages(wait_group, Some(&duty_source))
                .await
        {
            error_with_peers!(
                "failed to produce and publish own sync_committee messages: {error:?}"
            );
        }
    }

    fn next_graffiti(&mut self) -> Option<H256> {
        if self.validator_config.graffiti.is_empty() {
            return None;
        }

        let index = self.next_graffiti_index;

        if let Some(next_graffiti_index) = index
            .saturating_add(1)
            .checked_rem(self.validator_config.graffiti.len())
        {
            self.next_graffiti_index = next_graffiti_index;
        } else {
            return None;
        }

        Some(self.validator_config.graffiti[index])
    }

    fn own_public_keys(&self) -> HashSet<PublicKeyBytes> {
        self.signer.load().keys().copied().collect::<HashSet<_>>()
    }

    #[expect(clippy::too_many_lines)]
    #[instrument(level = "debug", skip_all)]
    async fn own_singular_attestations(
        &self,
        slot_head: &SlotHead<P>,
        own_members: &[BeaconCommitteeMember],
        beacon_nodes: &BeaconNodes<P, W>,
    ) -> Result<&[OwnAttestation<P>]> {
        if let Some(own_attestations) = self.own_singular_attestations.get() {
            return Ok(own_attestations);
        }

        if own_members.is_empty() {
            return Ok(&[]);
        }

        let phase = slot_head.phase();
        let slot = slot_head.slot();

        // From Electra on the committee index is not part of the produced data,
        // so a single request covers every member.
        let committee_indices = if phase >= Phase::Electra {
            vec![0]
        } else {
            own_members
                .iter()
                .map(|member| member.committee_index)
                .unique()
                .collect()
        };

        // Fetched concurrently, and each committee stands on its own: one that cannot be served
        // only costs its own members their attestation, rather than the whole slot's.
        let attestation_data = committee_indices
            .into_iter()
            .map(|committee_index| async move {
                let data = beacon_nodes.attestation_data(slot, committee_index).await?;
                let produced_for = data.slot;

                ensure!(
                    produced_for == slot,
                    "beacon node produced attestation data for slot {produced_for}, \
                     expected {slot}",
                );

                Ok::<_, AnyhowError>((committee_index, data))
            })
            .pipe(join_all)
            .await
            .into_iter()
            .filter_map(|result| {
                result
                    .inspect_err(|error| {
                        warn_with_peers!(
                            "unable to produce attestation data in slot {slot}: {error:?}",
                        );
                    })
                    .ok()
            })
            .collect::<HashMap<_, _>>();

        let (triples, other_data): (Vec<_>, Vec<_>) = tokio::task::block_in_place(|| {
            let doppelganger_protection = self
                .doppelganger_protection
                .as_deref()
                .map(DoppelgangerProtection::load);

            own_members
                .iter()
                .filter_map(|member| {
                    if let Some(doppelganger_protection) = &doppelganger_protection
                        && !doppelganger_protection.is_validator_active(member.public_key)
                    {
                        info_with_peers!(
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

                    let committee_index = if phase >= Phase::Electra {
                        0
                    } else {
                        member.committee_index
                    };

                    let data = *attestation_data.get(&committee_index)?;

                    let triple = SigningTriple {
                        message: SigningMessage::<P>::Attestation(data),
                        signing_root: data
                            .signing_root_from_fork_info(&self.chain_config, slot_head.fork_info),
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
                slot_head.fork_info,
                slot_head.current_epoch(),
                self.slashing_protector.clone_arc(),
            )
            .await;

        let signatures = match result {
            Ok(signatures) => signatures,
            Err(error) => {
                warn_with_peers!("failed to sign attestations: {error:?}");
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
                                Some(Attestation::from(SingleAttestation {
                                    committee_index: member.committee_index,
                                    attester_index: member.validator_index,
                                    data,
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

    #[instrument(level = "debug", skip_all)]
    async fn own_sync_committee_messages(
        &self,
        slot_head: &SlotHead<P>,
        beacon_block_root: H256,
        members: &[SyncCommitteeMember],
    ) -> Result<BTreeMap<SubcommitteeIndex, Vec<SyncCommitteeMessage>>> {
        let indices_with_pubkeys = members
            .iter()
            .map(|member| (member.validator_index, member.public_key));

        let messages = match slot_head
            .sync_committee_messages(
                slot_head.slot(),
                beacon_block_root,
                indices_with_pubkeys,
                &self.signer,
            )
            .await
        {
            Ok(messages) => messages,
            Err(error) => {
                warn_with_peers!(
                    "failed to sign sync committee messages (slot: {}): {:?}",
                    slot_head.slot(),
                    error,
                );
                return Ok(BTreeMap::new());
            }
        };

        Ok(messages
            .into_iter()
            .zip(members)
            .flat_map(|(message, member)| {
                core::iter::zip(member.subnets, 0..)
                    .filter(|(in_subnet, _)| *in_subnet)
                    .map(move |(_, subcommittee_index)| (subcommittee_index, message))
            })
            .pipe(group_into_btreemap))
    }

    async fn own_contributions_and_proofs(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        slot_head: &SlotHead<P>,
        beacon_block_root: H256,
        members: &[SyncCommitteeMember],
    ) -> Result<Vec<SignedContributionAndProof<P>>> {
        let subcommittee_aggregators = self
            .own_subcommittee_aggregators(slot_head, members)
            .await?;

        let fetches = subcommittee_aggregators.into_iter().map(
            |(subcommittee_index, aggregators)| async move {
                let contribution = beacon_nodes
                    .sync_committee_contribution(
                        slot_head.slot(),
                        subcommittee_index,
                        beacon_block_root,
                    )
                    .await
                    .inspect_err(|error| {
                        warn_with_peers!(
                            "failed to obtain a contribution for sync subcommittee \
                             {subcommittee_index} in slot {}: {error:?}",
                            slot_head.slot(),
                        );
                    })
                    .ok();

                (contribution, aggregators)
            },
        );

        // Concurrent, so that one slow node does not spend the deadline of every subcommittee.
        let (triples, proofs): (Vec<_>, Vec<_>) = join_all(fetches)
            .await
            .into_iter()
            .flat_map(|(contribution, aggregators)| {
                aggregators
                    .into_iter()
                    .filter_map(move |(aggregator, selection_proof)| {
                        let contribution_and_proof = ContributionAndProof {
                            aggregator_index: aggregator.validator_index,
                            contribution: contribution?,
                            selection_proof,
                        };

                        let triple = SigningTriple {
                            message: SigningMessage::ContributionAndProof(contribution_and_proof),
                            signing_root: contribution_and_proof.signing_root_from_fork_info(
                                &self.chain_config,
                                slot_head.fork_info,
                            ),
                            public_key: aggregator.public_key,
                        };

                        Some((triple, contribution_and_proof))
                    })
            })
            .unzip();

        let signer_snapshot = self.signer.load();

        let result = signer_snapshot
            .sign_triples_without_slashing_protection(triples, Some(slot_head.fork_info))
            .await;

        let signatures = match result {
            Ok(signatures) => signatures,
            Err(error) => {
                warn_with_peers!("failed to sign contributions and proofs: {error:?}");
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

    async fn own_payload_attestations(
        &self,
        slot_head: &SlotHead<P>,
        data: PayloadAttestationData,
        own_members: &[PTCMember],
    ) -> Result<&[PayloadAttestationMessage]> {
        if let Some(own_payload_attestations) = self.own_payload_attestations.get() {
            return Ok(own_payload_attestations);
        }

        let (triples, other_data): (Vec<_>, Vec<_>) = tokio::task::block_in_place(|| {
            let doppelganger_protection = self
                .doppelganger_protection
                .as_deref()
                .map(DoppelgangerProtection::load);

            own_members
                .iter()
                .filter_map(|member| {
                    if let Some(doppelganger_protection) = &doppelganger_protection
                        && !doppelganger_protection.is_validator_active(member.public_key)
                    {
                        info_with_peers!(
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

                    let triple = SigningTriple {
                        message: SigningMessage::<P>::PayloadAttestation(data),
                        signing_root: data
                            .signing_root_from_fork_info(&self.chain_config, slot_head.fork_info),
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
                slot_head.fork_info,
                slot_head.current_epoch(),
                self.slashing_protector.clone_arc(),
            )
            .await;

        let signatures = match result {
            Ok(signatures) => signatures,
            Err(error) => {
                warn_with_peers!("failed to sign payload attestations: {error:?}");
                return Ok(&[]);
            }
        };

        self.own_payload_attestations
            .get_or_try_init(|| {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    metrics
                        .validator_own_payload_attestations_init_times
                        .start_timer()
                });

                let own_payload_attestations = signatures
                    .zip(other_data)
                    .filter_map(|(signature, (data, member))| {
                        signature.map(|signature| PayloadAttestationMessage {
                            validator_index: member.validator_index,
                            data,
                            signature: signature.into(),
                        })
                    })
                    .collect();

                Ok(own_payload_attestations)
            })
            .map(Vec::as_slice)
    }

    async fn own_subcommittee_aggregators<'members>(
        &self,
        slot_head: &SlotHead<P>,
        members: &'members [SyncCommitteeMember],
    ) -> Result<BTreeMap<SubcommitteeIndex, Vec<(&'members SyncCommitteeMember, SignatureBytes)>>>
    {
        let subcommittee_members = members
            .iter()
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
                warn_with_peers!(
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
        // Aggregation duties are per-slot; a leftover entry would request a stale aggregate.
        self.own_aggregators.clear();
    }

    fn payload_attested_in_current_slot(&self) -> bool {
        self.own_payload_attestations.get().is_some()
    }

    fn discard_previous_slot_payload_attestations(&mut self) {
        self.own_payload_attestations.take();
    }

    fn discard_old_proposer_preferences(&mut self, current_epoch: Epoch) {
        let current_epoch_start = misc::compute_start_slot_at_epoch::<P>(current_epoch);

        self.published_proposer_preferences
            .retain(|(_, proposal_slot, _)| *proposal_slot >= current_epoch_start);
    }

    fn discard_old_registered_validators(&mut self, current_epoch: Epoch) {
        if let Some(epoch_boundary) =
            current_epoch.checked_sub(EPOCHS_TO_KEEP_REGISTERED_VALIDATORS)
        {
            self.registered_validators = self.registered_validators.split_off(&epoch_boundary);
        }
    }

    fn spawn_pruning(&self, current_slot: Slot) {
        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);
        let own_members = self.own_beacon_committee_members.clone_arc();
        let own_ptc_members = self.own_ptc_members.clone_arc();
        let slashing_protector = self.slashing_protector.clone_arc();

        self.dedicated_executor_low_priority
            .spawn(async move {
                if let Err(error) = slashing_protector.lock().await.prune::<P>(current_epoch) {
                    warn_with_peers!("error while pruning slashing protection history: {error:?}");
                }

                let up_to_slot = misc::compute_start_slot_at_epoch::<P>(current_epoch);
                own_members.prune::<P>(up_to_slot).await;
                own_ptc_members.prune(up_to_slot).await;
                Ok::<_, AnyhowError>(())
            })
            .detach()
    }

    fn spawn_update_beacon_committee_subscriptions(&self, wait_group: W, source: &DutySource<P>) {
        let task = UpdateBeaconCommitteeSubscriptionsTask {
            chain_config: self.chain_config.clone_arc(),
            controller: self.controller.clone_arc(),
            source: source.clone(),
            own_beacon_committee_members: self.own_beacon_committee_members.clone_arc(),
            own_ptc_members: self.own_ptc_members.clone_arc(),
            own_validator_indices: self.own_validator_indices.clone_arc(),
            beacon_nodes: self.beacon_nodes(source, &wait_group),
            wait_group,
        };

        self.dedicated_executor_normal_priority
            .spawn(task.run())
            .detach()
    }

    fn spawn_prefetch_sync_committee_duties(&self, wait_group: W, source: &DutySource<P>) {
        let task = PrefetchSyncCommitteeDutiesTask {
            chain_config: self.chain_config.clone_arc(),
            current_slot: source.slot_head().slot(),
            own_sync_committee_members: self.own_sync_committee_members.clone_arc(),
            own_validator_indices: self.own_validator_indices.clone_arc(),
            beacon_nodes: self.beacon_nodes(source, &wait_group),
            wait_group,
        };

        self.dedicated_executor_normal_priority
            .spawn(task.run())
            .detach()
    }

    async fn update_sync_committee_subscriptions(
        &mut self,
        wait_group: &W,
        source: &DutySource<P>,
    ) -> Result<()> {
        // Subscriptions are built from the sync committees a state carries.
        let Some(beacon_state) = source.beacon_state() else {
            return Ok(());
        };

        let Some(post_altair_state) = beacon_state.post_altair() else {
            return Ok(());
        };

        let own_public_keys = self.own_public_keys();

        self.own_sync_committee_subscriptions
            .build(post_altair_state, &own_public_keys)?;

        let current_epoch = accessors::get_current_epoch(beacon_state);

        // Sent once an epoch rather than once a period, so that a beacon node which was down or
        // still starting up when the period began is subscribed by the next epoch.
        if self.sent_sync_committee_subscriptions_for == Some(current_epoch) {
            return Ok(());
        }

        let subscriptions = self
            .own_sync_committee_subscriptions
            .epoch_subscriptions(current_epoch);

        if subscriptions.is_empty() {
            return Ok(());
        }

        if let Err(error) = self
            .beacon_nodes(source, wait_group)
            .subscribe_to_sync_committees(current_epoch, &subscriptions)
            .await
        {
            warn_with_peers!("failed to update sync committee subscriptions: {error:?}");
            return Ok(());
        }

        self.sent_sync_committee_subscriptions_for = Some(current_epoch);

        Ok(())
    }

    async fn update_subnet_subscriptions(
        &mut self,
        wait_group: &W,
        tick: Tick,
        source: Option<&DutySource<P>>,
    ) -> Result<()> {
        let source = match source {
            Some(source) => source.clone(),
            // Duties must not fall back to the state of the disabled built-in node.
            None if !self.mode.uses_local_node() => return Ok(()),
            // A node that is still syncing holds a state too old to drive duties.
            None if !self.controller.is_forward_synced() => return Ok(()),
            None => {
                let beacon_state = match self.controller.preprocessed_state_at_current_slot().await
                {
                    Ok(state) => state,
                    Err(error) => {
                        let is_too_many_empty_slots = matches!(
                            error.downcast_ref(),
                            Some(StateCacheError::StateFarBehind { .. })
                        );

                        if !is_too_many_empty_slots {
                            warn_with_peers!(
                                "failed to obtain beacon state for current slot: {error}"
                            );
                        }

                        return Ok(());
                    }
                };

                let head = self.controller.head_block_root();

                let slot_head = SlotHead {
                    config: self.chain_config.clone_arc(),
                    slot: beacon_state.slot(),
                    beacon_block_root: head.value,
                    fork_info: beacon_state.as_ref().into(),
                    optimistic: head.status.is_optimistic(),
                };

                DutySource::Local {
                    slot_head,
                    beacon_state,
                }
            }
        };

        if tick.is_start_of_slot() {
            self.spawn_update_beacon_committee_subscriptions(wait_group.clone(), &source);
            self.spawn_prefetch_sync_committee_duties(wait_group.clone(), &source);
        }

        self.update_sync_committee_subscriptions(wait_group, &source)
            .await
    }

    #[instrument(level = "debug", skip_all)]
    fn handle_custody_requirements_update(
        &mut self,
        current_slot: Slot,
        own_validator_indices: &HashSet<ValidatorIndex>,
    ) {
        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);
        let last_finalized_state = self.controller.last_finalized_state().value;
        let validator_custody_requirement = eip_7594::get_validator_custody_requirement(
            &self.chain_config,
            &last_finalized_state,
            own_validator_indices,
        );

        let current_sampling_size: u64 = self
            .controller
            .sampling_columns_count()
            .try_into()
            .expect("sampling size should be able to fit into u64");

        let Some(current_custody_requirements) =
            current_sampling_size.checked_div(self.chain_config.columns_per_group::<P>())
        else {
            return;
        };

        if validator_custody_requirement > current_custody_requirements
            || self.last_cgc_update_epoch.is_none()
        {
            // Refresh data column subnets subscriptions in network globals and sampling columns fork choice store
            ValidatorToP2p::UpdateDataColumnSubnets(
                validator_custody_requirement.max(current_custody_requirements),
            )
            .send(&self.p2p_tx);
        }

        self.last_cgc_update_epoch = Some(current_epoch);
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

    #[instrument(level = "debug", skip_all)]
    fn refresh_signer_keys(&self) {
        let signer = self.signer.clone_arc();
        let current_slot = self.controller.slot();

        tokio::spawn(async move {
            signer.load_keys_from_web3signer().await;
            signer.update_doppelganger_protection_pubkeys(current_slot);
        });
    }

    #[instrument(level = "debug", skip_all)]
    async fn register_validators(&mut self, current_epoch: Epoch) {
        if let Some(last_registration_epoch) = self.last_registration_epoch {
            let next_registration_epoch = last_registration_epoch
                .saturating_add(EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION);

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
                        fee_recipient: proposer_configs.fee_recipient(pubkey),
                        gas_limit: proposer_configs.gas_limit(pubkey),
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
                    warn_with_peers!("failed to collect validator registrations: {error:?}")
                })?;

            // Do not submit requests in parallel. Doing so causes all of them to be timed out.
            for registrations in signed_registrations {
                if let Err(error) = builder_api.register_validators::<P>(registrations).await {
                    warn_with_peers!("failed to register validator batch: {error}");
                }
            }

            Ok::<_, AnyhowError>(())
        });

        self.last_registration_epoch = Some(current_epoch);
    }

    #[expect(clippy::too_many_lines)]
    #[instrument(level = "debug", skip_all)]
    fn publish_proposer_preferences(
        &mut self,
        slot_head: &SlotHead<P>,
        beacon_state: &Arc<BeaconState<P>>,
    ) {
        let signer_snapshot = self.signer.load().clone_arc();

        if signer_snapshot.no_keys() {
            return;
        }

        let beacon_state = beacon_state.clone_arc();
        let beacon_block_root = slot_head.beacon_block_root;

        let pubkeys_by_index = signer_snapshot
            .keys()
            .filter_map(|pubkey| {
                let validator_index = accessors::index_of_public_key(&beacon_state, pubkey)?;
                Some((validator_index, *pubkey))
            })
            .collect::<HashMap<_, _>>();

        let validator_indices = pubkeys_by_index.keys().copied().collect::<HashSet<_>>();
        let mut dependent_roots = HashMap::<Epoch, Option<H256>>::new();

        let preferences = accessors::get_upcoming_proposal_slots(
            &self.chain_config,
            &beacon_state,
            &validator_indices,
        )
        .filter_map(|(proposal_slot, validator_index)| {
            let proposal_epoch = misc::compute_epoch_at_slot::<P>(proposal_slot);

            let dependent_root = dependent_roots
                .entry(proposal_epoch)
                .or_insert_with(|| {
                    let dependent_root = self
                        .controller
                        .shuffling_dependent_root(beacon_block_root, proposal_epoch);

                    if dependent_root.is_none() {
                        warn_with_peers!(
                            "failed to compute shuffling dependent root for proposer \
                            preferences (epoch {proposal_epoch})"
                        );
                    }

                    dependent_root
                })
                .as_ref()
                .copied()?;

            if self.published_proposer_preferences.contains(&(
                dependent_root,
                proposal_slot,
                validator_index,
            )) {
                return None;
            }

            let pubkey = pubkeys_by_index.get(&validator_index).copied()?;

            Some((
                pubkey,
                ProposerPreferences {
                    dependent_root,
                    proposal_slot,
                    validator_index,
                    fee_recipient: self.proposer_configs.fee_recipient(pubkey),
                    target_gas_limit: self.proposer_configs.gas_limit(pubkey),
                },
            ))
        })
        .collect_vec();

        if preferences.is_empty() {
            return;
        }

        self.published_proposer_preferences
            .extend(preferences.iter().map(|(_, pref)| {
                (
                    pref.dependent_root,
                    pref.proposal_slot,
                    pref.validator_index,
                )
            }));

        let chain_config = self.chain_config.clone_arc();
        let controller = self.controller.clone_arc();
        let p2p_tx = self.p2p_tx.clone();

        tokio::spawn(async move {
            let triples = preferences
                .iter()
                .map(|(pubkey, pref)| SigningTriple {
                    message: SigningMessage::ProposerPreferences(*pref),
                    signing_root: pref.signing_root(&chain_config, beacon_state.as_ref()),
                    public_key: *pubkey,
                })
                .collect_vec();

            let fork_info = Some(beacon_state.as_ref().into());

            let signatures = match signer_snapshot
                .sign_triples_without_slashing_protection(triples, fork_info)
                .await
            {
                Ok(signatures) => signatures,
                Err(error) => {
                    warn_with_peers!("failed to sign proposer preferences: {error}");
                    return;
                }
            };

            // Publish each signed preference
            for ((_, pref), signature) in preferences.into_iter().zip(signatures) {
                debug_with_peers!(
                    "publishing proposer preferences for (validator: {}, slot: {})",
                    pref.validator_index,
                    pref.proposal_slot
                );

                let signed_preferences = Arc::new(SignedProposerPreferences {
                    message: pref,
                    signature: signature.into(),
                });

                // Pass into own fork-choice store so bids for this slot pass the
                // `accepted_proposer_preferences` gate in validate_execution_payload_bid.
                controller.on_own_proposer_preferences(signed_preferences.clone_arc());

                ValidatorToP2p::PublishProposerPreferences(signed_preferences).send(&p2p_tx);
            }
        });
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
                "own_beacon_committee_members",
                self.own_beacon_committee_members.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "own_payload_attestations",
                self.own_payload_attestations
                    .get()
                    .map(Vec::len)
                    .unwrap_or(0),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "own_ptc_members",
                self.own_ptc_members.len(),
            );

            self.block_producer.track_collection_metrics().await;
        }

        if let Some(validator_statistics) = self.validator_statistics.as_ref() {
            validator_statistics.track_collection_metrics().await;
        }
    }

    // TODO(Gloas): fix optimistic head handling in Gloas
    #[expect(dead_code)]
    #[instrument(level = "debug", skip_all)]
    async fn wait_for_fully_validated_head(&self, slot_head: SlotHead<P>) -> Option<SlotHead<P>> {
        const BLOCK_EVENT_WAIT_TIMEOUT: Duration = Duration::from_secs(1);

        let is_optimistic = match slot_head.is_optimistic(&self.controller) {
            Ok(is_optimistic) => is_optimistic,
            Err(error) => {
                warn_with_peers!("error while checking if slot head is optimistic: {error:?}");
                return None;
            }
        };

        if !is_optimistic && !self.should_wait_for_late_block() {
            return Some(slot_head);
        }

        let result = timeout(BLOCK_EVENT_WAIT_TIMEOUT, async {
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

                if block_event.execution_optimistic {
                    continue;
                }

                if block_event.block == slot_head.beacon_block_root {
                    debug_with_peers!(
                        "fork choice head became fully validated (block event: {block_event:?})",
                    );
                    break None;
                }

                let head = self.controller.head().value;

                if block_event.block == head.block_root && self.controller.slot() == head.slot() {
                    debug_with_peers!("fork choice head changed (block event: {block_event:?})");

                    let beacon_state = self.controller.state_by_chain_link(&head);

                    break Some(SlotHead {
                        config: self.chain_config.clone_arc(),
                        slot: head.slot(),
                        beacon_block_root: head.block_root,
                        fork_info: beacon_state.as_ref().into(),
                        optimistic: head.is_optimistic(),
                    });
                }
            }
        })
        .await;

        match result {
            Ok(Some(new_slot_head)) => Some(new_slot_head),
            Ok(None) => Some(slot_head),
            Err(error) => {
                if is_optimistic {
                    debug_with_peers!(
                        "timed out while waiting for chain head to become fully validated: {error:?}",
                    );
                    None
                } else {
                    debug_with_peers!(
                        "timed out while waiting for current slot block to be processed: {error:?}",
                    );
                    Some(slot_head)
                }
            }
        }
    }

    fn should_wait_for_late_block(&self) -> bool {
        !self.validator_config.disable_wait_for_late_blocks
            && self.controller.has_current_slot_blocks_in_processing()
    }
}

fn aggregated_by<P: Preset>(
    aggregate: &Attestation<P>,
    position_in_committee: usize,
) -> Option<bool> {
    match aggregate {
        Attestation::Phase0(aggregate) => aggregate.aggregation_bits.get(position_in_committee),
        Attestation::Electra(aggregate) => aggregate.aggregation_bits.get(position_in_committee),
        Attestation::Gloas(aggregate) => aggregate.aggregation_bits.get(position_in_committee),
        Attestation::Single(_) => None,
    }
    .map(|bit| *bit)
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
