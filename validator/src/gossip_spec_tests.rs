use std::{collections::HashSet, path::PathBuf, sync::Arc};

use anyhow::Result;
use attestation_verifier::AttestationVerifier;
use block_producer::{BlockProducer, Options as BlockProducerOptions};
use clock::{Tick, TickKind};
use crossbeam_utils::sync::WaitGroup;
use database::Database;
use dedicated_executor::DedicatedExecutor;
use duplicate::duplicate_item;
use eth1::Eth1Config;
use eth1_api::{ApiController, Eth1Api, Eth1ExecutionEngine};
use eth2_libp2p::{GossipId, NetworkConfig};
use execution_engine::{PayloadStatusV1, PayloadValidationStatus};
use features::Feature;
use fork_choice_control::{
    Controller, DEFAULT_ARCHIVAL_EPOCH_INTERVAL, EventChannels, P2pMessage, Storage,
    controller::MutatorHandle,
};
use fork_choice_store::{AnchorBlock, AnchorState, StoreConfig};
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    lock::Mutex,
};
use keymanager::KeyManager;
use operation_pools::{
    AttestationAggPool, BlsToExecutionChangePool, Origin, PayloadAttestationAggPool,
    PoolAdditionOutcome, PoolToP2pMessage, SyncCommitteeAggPool,
};
use p2p::{P2pToValidator, ValidatorToP2p};
use pubkey_cache::PubkeyCache;
use reqwest::Client;
use scc::HashMap as SccHashMap;
use serde::Deserialize;
use signer::{Signer, Web3SignerConfig};
use slashing_protection::{DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT, SlashingProtector};
use spec_test_utils::{BlsSetting, Case};
use std_ext::ArcExt;
use test_generator::test_resources;
use transition_functions::unphased::StateRootPolicy;
use typenum::Unsigned as _;
use types::{
    altair::containers::{SignedContributionAndProof, SyncCommitteeMessage},
    capella::containers::SignedBlsToExecutionChange,
    combined::{
        Attestation, AttesterSlashing, BeaconState, DataColumnSidecar, SignedAggregateAndProof,
        SignedBeaconBlock,
    },
    config::Config,
    deneb::containers::BlobSidecar,
    nonstandard::{Phase, StorageMode},
    phase0::{
        containers::{Checkpoint, ProposerSlashing, SignedVoluntaryExit},
        primitives::{Epoch, H256, SubnetId},
    },
    preset::{Mainnet, Minimal, Preset},
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::{Validator, ValidatorChannels, ValidatorConfig};

pub struct Context<P: Preset> {
    controller: ApiController<P, WaitGroup>,
    bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
    sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, WaitGroup>>,
    #[expect(
        dead_code,
        reason = "Keep the `MutatorHandle` around to avoid joining the mutator thread prematurely."
    )]
    mutator_handle: MutatorHandle<P, WaitGroup>,
    fc_to_p2p_rx: UnboundedReceiver<P2pMessage<P>>,
    p2p_to_validator_tx: UnboundedSender<P2pToValidator<P, WaitGroup>>,
    pool_to_p2p_rx: UnboundedReceiver<PoolToP2pMessage>,
    validator_to_p2p_rx: UnboundedReceiver<ValidatorToP2p<P>>,
}

impl<P: Preset> Context<P> {
    #[expect(clippy::too_many_lines)]
    pub fn new(
        chain_config: Arc<Config>,
        anchor_block: AnchorBlock<P>,
        anchor_state: Arc<BeaconState<P>>,
        blacklisted_blocks: HashSet<H256>,
    ) -> Result<Self> {
        // Enable features that make behaviour more spec-compliant
        Feature::CacheTargetStates.enable();
        Feature::IgnoreAttestationsForUnknownBlocks.enable();
        Feature::IgnoreFutureAttestations.enable();

        let (_, api_to_validator_rx) = futures::channel::mpsc::unbounded();
        let (fc_to_attestation_verifier_tx, fc_to_attestation_verifier_rx) =
            futures::channel::mpsc::unbounded();
        let (fc_to_p2p_tx, fc_to_p2p_rx) = futures::channel::mpsc::unbounded();
        let (fc_to_pool_tx, _) = futures::channel::mpsc::unbounded();
        let (fc_to_subnet_tx, _) = futures::channel::mpsc::unbounded();
        let (fc_to_sync_tx, _) = futures::channel::mpsc::unbounded();
        let (fc_to_validator_tx, fc_to_validator_rx) = futures::channel::mpsc::unbounded();
        let (p2p_to_validator_tx, p2p_to_validator_rx) =
            futures::channel::mpsc::unbounded::<P2pToValidator<P, WaitGroup>>();
        let (pool_to_p2p_tx, pool_to_p2p_rx) = futures::channel::mpsc::unbounded();
        let (subnet_service_tx, _) = futures::channel::mpsc::unbounded();
        let (validator_to_p2p_tx, validator_to_p2p_rx) = futures::channel::mpsc::unbounded();
        let (execution_service_tx, _) = futures::channel::mpsc::unbounded();

        let genesis_validators_root = anchor_state.genesis_validators_root();
        let store_config = StoreConfig::aggressive(&chain_config);
        let eth1_config = Arc::new(Eth1Config::default());
        let client = Client::new();

        let eth1_api = Arc::new(Eth1Api::new(
            chain_config.clone_arc(),
            client.clone(),
            eth1_config.eth1_auth.clone_arc(),
            eth1_config.eth1_rpc_urls.clone(),
            None,
            None,
        ));

        let execution_engine = Arc::new(Eth1ExecutionEngine::new(
            chain_config.clone_arc(),
            eth1_api.clone_arc(),
            execution_service_tx,
        ));

        let pubkey_cache = Arc::new(PubkeyCache::default());

        let storage = Arc::new(Storage::new(
            chain_config.clone_arc(),
            pubkey_cache.clone_arc(),
            Database::in_memory(),
            DEFAULT_ARCHIVAL_EPOCH_INTERVAL,
            StorageMode::default(),
        ));

        let event_channels = Arc::new(EventChannels::default());
        let sidecars_construction_started = Arc::new(SccHashMap::new());
        let is_peerdas_activated = anchor_state.phase().is_peerdas_activated();

        let (controller, mutator_handle) = Controller::<P, _, _, WaitGroup>::new(
            chain_config,
            pubkey_cache,
            store_config,
            anchor_block,
            AnchorState::Test(anchor_state),
            Tick {
                slot: 0,
                kind: TickKind::Propose,
            },
            event_channels.clone_arc(),
            execution_engine.clone_arc(),
            None,
            fc_to_attestation_verifier_tx,
            fc_to_p2p_tx,
            fc_to_pool_tx,
            fc_to_subnet_tx,
            fc_to_sync_tx,
            fc_to_validator_tx,
            storage,
            core::iter::empty(),
            true,
            blacklisted_blocks,
            sidecars_construction_started,
        )?;

        if is_peerdas_activated {
            controller.on_store_sampling_columns((0..P::NumberOfColumns::U64).collect());
        }

        let dedicated_executor = Arc::new(DedicatedExecutor::new(
            "dedicated-executor",
            num_cpus::get(),
            None,
            None,
        ));

        let signer = Arc::new(Signer::new(
            core::iter::empty(),
            client,
            Web3SignerConfig::default(),
            None,
        ));

        let slashing_protector =
            SlashingProtector::in_memory(DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT)?;

        let slashing_protector = Arc::new(Mutex::new(slashing_protector));

        let validator_config = Arc::new(ValidatorConfig {
            disable_blockprint_graffiti: true,
            ..Default::default()
        });

        let keymanager = Arc::new(KeyManager::new_in_memory(
            signer.clone_arc(),
            slashing_protector.clone_arc(),
            genesis_validators_root,
            validator_config.suggested_fee_recipient,
            validator_config.default_gas_limit,
            H256::default(),
        ));

        let attestation_verifier = AttestationVerifier::new(
            controller.clone_arc(),
            dedicated_executor.clone_arc(),
            None,
            fc_to_attestation_verifier_rx,
        );

        let attestation_agg_pool = AttestationAggPool::new(
            controller.clone_arc(),
            dedicated_executor.clone_arc(),
            None,
            None,
        );

        let sync_committee_agg_pool = SyncCommitteeAggPool::new(
            dedicated_executor.clone_arc(),
            controller.clone_arc(),
            None,
            pool_to_p2p_tx.clone(),
            None,
            None,
        );

        let (bls_to_execution_change_pool, bls_to_execution_change_pool_service) =
            BlsToExecutionChangePool::new(
                controller.clone_arc(),
                event_channels.clone_arc(),
                pool_to_p2p_tx,
                None,
            );

        let payload_attestation_agg_pool = PayloadAttestationAggPool::new(
            controller.clone_arc(),
            dedicated_executor.clone_arc(),
            None,
        );

        let block_producer = Arc::new(BlockProducer::new(
            keymanager.proposer_configs().clone_arc(),
            None,
            controller.clone_arc(),
            dedicated_executor.clone_arc(),
            execution_engine,
            attestation_agg_pool.clone_arc(),
            bls_to_execution_change_pool.clone_arc(),
            sync_committee_agg_pool.clone_arc(),
            payload_attestation_agg_pool.clone_arc(),
            None,
            Some(BlockProducerOptions {
                fake_execution_payloads: true,
            }),
        ));

        let validator_channels = ValidatorChannels {
            api_to_validator_rx,
            fork_choice_rx: fc_to_validator_rx,
            p2p_tx: validator_to_p2p_tx,
            p2p_to_validator_rx,
            slasher_to_validator_rx: None,
            subnet_service_tx,
            validator_to_liveness_tx: None,
            validator_to_slasher_tx: None,
        };

        let network_config = Arc::new(NetworkConfig::default());

        let validator = Validator::new(
            validator_config.clone_arc(),
            block_producer.clone_arc(),
            controller.clone_arc(),
            attestation_agg_pool.clone_arc(),
            None,
            None,
            event_channels.clone_arc(),
            keymanager.proposer_configs().clone_arc(),
            signer,
            slashing_protector,
            payload_attestation_agg_pool,
            sync_committee_agg_pool.clone_arc(),
            None,
            None,
            validator_channels,
            network_config.network_dir.as_deref(),
            dedicated_executor.clone_arc(),
            dedicated_executor.clone_arc(),
        );

        // Spawn the validator so it processes incoming gossip messages and sends responses
        // Synchronization is achieved by passing wait_group along with gossip message
        tokio::spawn(attestation_verifier.run());
        tokio::spawn(bls_to_execution_change_pool_service.run());
        tokio::spawn(validator.run());

        Ok(Self {
            controller,
            bls_to_execution_change_pool,
            sync_committee_agg_pool,
            mutator_handle,
            fc_to_p2p_rx,
            p2p_to_validator_tx,
            pool_to_p2p_rx,
            validator_to_p2p_rx,
        })
    }

    fn on_tick(&mut self, tick: Tick) {
        let old_slot = self.controller.slot();
        let new_slot = tick.slot;

        self.controller.on_tick(tick);
        self.controller.wait_for_tasks();

        // Some artifacts, like blob sidecars, require current slot state for validation.
        let _unused = self
            .controller
            .preprocessed_state_at_current_slot_blocking();

        if old_slot < new_slot {
            assert!(matches!(
                self.next_p2p_message(),
                Some(P2pMessage::Slot(slot)) if slot == new_slot,
            ));
        }
    }

    fn on_aggregate_and_proof(
        &mut self,
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
        expected: Option<ExpectedResult>,
        reason: Option<&str>,
    ) {
        self.controller
            .on_gossip_aggregate_and_proof(aggregate_and_proof, GossipId::default());

        self.controller.wait_for_tasks();

        let response = self.next_p2p_message();

        Self::check_expected_message_from_fork_choice(
            expected,
            response.as_ref(),
            reason,
            Topic::BeaconAggregateAndProof,
        );
    }

    fn on_attestation(
        &mut self,
        attestation: Arc<Attestation<P>>,
        subnet_id: SubnetId,
        expected: ExpectedResult,
        reason: Option<&str>,
    ) {
        self.controller
            .on_gossip_singular_attestation(attestation, subnet_id, GossipId::default());

        self.controller.wait_for_tasks();

        let response = self.next_p2p_message();

        Self::check_expected_message_from_fork_choice(
            Some(expected),
            response.as_ref(),
            reason,
            Topic::BeaconAttestation,
        );
    }

    fn on_attester_slashing(
        &mut self,
        attester_slashing: AttesterSlashing<P>,
        expected: ExpectedResult,
        reason: Option<&str>,
    ) {
        let wait_group = WaitGroup::new();

        self.send_to_validator_and_assert(
            P2pToValidator::AttesterSlashing(
                attester_slashing.into(),
                GossipId::default(),
                wait_group.clone(),
            ),
            expected,
            reason,
            wait_group,
        );
    }

    fn on_blob_sidecar(
        &mut self,
        blob_sidecar: Arc<BlobSidecar<P>>,
        subnet_id: SubnetId,
        expected: Option<ExpectedResult>,
        reason: Option<&str>,
    ) {
        self.controller
            .on_gossip_blob_sidecar(blob_sidecar, subnet_id, GossipId::default(), false);

        self.controller.wait_for_tasks();

        let response = self.next_p2p_message();

        Self::check_expected_message_from_fork_choice(
            expected,
            response.as_ref(),
            reason,
            Topic::BlobSidecar,
        );
    }

    async fn on_bls_to_execution_change(
        &self,
        signed_bls_to_execution_change: Box<SignedBlsToExecutionChange>,
        expected: ExpectedResult,
    ) -> Result<()> {
        let response = self
            .bls_to_execution_change_pool
            .handle_external_signed_bls_to_execution_change(
                signed_bls_to_execution_change,
                Origin::Gossip(GossipId::default()),
            )
            .await?;

        match expected {
            ExpectedResult::Valid => {
                assert!(matches!(response, PoolAdditionOutcome::Accept));
            }
            ExpectedResult::Ignore => {
                assert!(matches!(response, PoolAdditionOutcome::Ignore));
            }
            ExpectedResult::Reject => {
                assert!(matches!(response, PoolAdditionOutcome::Reject(..)));
            }
        }

        Ok(())
    }

    fn on_block(
        &mut self,
        block: &Arc<SignedBeaconBlock<P>>,
        bls_setting: BlsSetting,
        state_root_policy: StateRootPolicy,
        payload_status: Option<BlockPayloadStatus>,
        expected: Option<ExpectedResult>,
        reason: Option<&str>,
    ) {
        let beacon_block_root = block.message().hash_tree_root();

        self.controller.on_test_block(
            block.clone_arc(),
            GossipId::default(),
            bls_setting,
            state_root_policy,
        );

        self.controller.wait_for_tasks();

        if let Some(payload_status) = payload_status {
            let execution_block_hash = block
                .execution_block_hash()
                .expect("execution_block_hash should be available");

            let payload_status_v1 = match payload_status {
                BlockPayloadStatus::Valid => PayloadStatusV1 {
                    status: PayloadValidationStatus::Valid,
                    latest_valid_hash: Some(execution_block_hash),
                    validation_error: None,
                },
                BlockPayloadStatus::Invalidated => PayloadStatusV1 {
                    status: PayloadValidationStatus::Invalid,
                    latest_valid_hash: None,
                    validation_error: None,
                },
                BlockPayloadStatus::NotValidated => PayloadStatusV1 {
                    status: PayloadValidationStatus::Syncing,
                    latest_valid_hash: None,
                    validation_error: None,
                },
            };

            self.controller.on_notified_new_payload(
                beacon_block_root,
                execution_block_hash,
                payload_status_v1,
            );

            self.controller.wait_for_tasks();
        }

        let response = self.next_p2p_message();

        Self::check_expected_message_from_fork_choice(
            expected,
            response.as_ref(),
            reason,
            Topic::BeaconBlock,
        );
    }

    async fn on_data_column_sidecar(
        &mut self,
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        subnet_id: SubnetId,
        expected: Option<ExpectedResult>,
        reason: Option<&str>,
    ) {
        self.controller
            .on_gossip_data_column_sidecar(
                data_column_sidecar,
                subnet_id,
                GossipId::default(),
                false,
            )
            .await;

        self.controller.wait_for_tasks();

        let response = self.next_p2p_message();

        Self::check_expected_message_from_fork_choice(
            expected,
            response.as_ref(),
            reason,
            Topic::DataColumnSidecar,
        );
    }

    fn on_proposer_slashing(
        &mut self,
        proposer_slashing: ProposerSlashing,
        expected: ExpectedResult,
        reason: Option<&str>,
    ) {
        let wait_group = WaitGroup::new();

        self.send_to_validator_and_assert(
            P2pToValidator::ProposerSlashing(
                proposer_slashing.into(),
                GossipId::default(),
                wait_group.clone(),
            ),
            expected,
            reason,
            wait_group,
        );
    }

    fn on_sync_committee_message(
        &mut self,
        sync_committee_message: SyncCommitteeMessage,
        subnet_id: SubnetId,
        expected: ExpectedResult,
        reason: Option<&str>,
    ) {
        let wait_group = WaitGroup::new();

        self.sync_committee_agg_pool
            .handle_external_message_detached(
                wait_group.clone(),
                sync_committee_message,
                subnet_id,
                Origin::Gossip(GossipId::default()),
            );

        wait_group.wait();

        let response = self.next_pool_p2p_message_verbose();

        Self::check_expected_message_from_pool(expected, response.as_ref(), reason);
    }

    fn on_sync_contribution_and_proof(
        &mut self,
        signed_contribution_and_proof: SignedContributionAndProof<P>,
        expected: ExpectedResult,
        reason: Option<&str>,
    ) {
        let wait_group = WaitGroup::new();

        self.sync_committee_agg_pool
            .handle_external_contribution_and_proof_detached(
                wait_group.clone(),
                signed_contribution_and_proof,
                Origin::Gossip(GossipId::default()),
            );

        wait_group.wait();

        let response = self.next_pool_p2p_message_verbose();

        Self::check_expected_message_from_pool(expected, response.as_ref(), reason);
    }

    fn on_voluntary_exit(
        &mut self,
        voluntary_exit: SignedVoluntaryExit,
        expected: ExpectedResult,
        reason: Option<&str>,
    ) {
        let wait_group = WaitGroup::new();

        self.send_to_validator_and_assert(
            P2pToValidator::VoluntaryExit(
                voluntary_exit.into(),
                GossipId::default(),
                wait_group.clone(),
            ),
            expected,
            reason,
            wait_group,
        );
    }

    fn send_to_validator_and_assert(
        &mut self,
        p2p_message: P2pToValidator<P, WaitGroup>,
        expected: ExpectedResult,
        reason: Option<&str>,
        wait_group: WaitGroup,
    ) {
        p2p_message.send(&self.p2p_to_validator_tx);

        wait_group.wait();

        let response = self.next_validator_p2p_message_verbose();

        Self::check_expected_message_from_validator(expected, response.as_ref(), reason);
    }

    fn check_expected_message_from_fork_choice(
        expected: Option<ExpectedResult>,
        response: Option<&P2pMessage<P>>,
        reason: Option<&str>,
        topic: Topic,
    ) {
        let description = format!(
            "message expected: {expected:?}, received: {response:?}, expected reason: {reason:?}"
        );

        match expected {
            None => {
                assert!(response.is_none(), "{description}");
            }
            Some(ExpectedResult::Valid) => {
                assert!(
                    matches!(response, Some(P2pMessage::Accept(_))),
                    "{description}"
                );
            }
            Some(ExpectedResult::Ignore) => match topic {
                Topic::BeaconBlock => {
                    assert!(
                        matches!(
                            response,
                            // same relaxed requirements as in spec_tests for blocks
                            Some(P2pMessage::Ignore(_) | P2pMessage::Reject(_, _))
                        ),
                        "{description}"
                    );
                }
                _ => {
                    assert!(
                        matches!(response, Some(P2pMessage::Ignore(_))),
                        "{description}"
                    );
                }
            },
            Some(ExpectedResult::Reject) => {
                assert!(
                    matches!(response, Some(P2pMessage::Reject(_, _))),
                    "{description}"
                );
            }
        }
    }

    fn check_expected_message_from_validator(
        expected: ExpectedResult,
        response: Option<&ValidatorToP2p<P>>,
        reason: Option<&str>,
    ) {
        let description = format!(
            "gossip message status: {expected:?}, received: {response:?}, reason: {reason:?}"
        );

        match expected {
            ExpectedResult::Valid => {
                assert!(
                    matches!(response, Some(ValidatorToP2p::Accept(_))),
                    "{description}"
                );
            }
            ExpectedResult::Ignore => {
                assert!(
                    matches!(response, Some(ValidatorToP2p::Ignore(_))),
                    "{description}"
                );
            }
            ExpectedResult::Reject => {
                assert!(
                    matches!(response, Some(ValidatorToP2p::Reject(_, _))),
                    "{description}"
                );
            }
        }
    }

    fn check_expected_message_from_pool(
        expected: ExpectedResult,
        response: Option<&PoolToP2pMessage>,
        reason: Option<&str>,
    ) {
        let description = format!(
            "gossip message status: {expected:?}, received: {response:?}, reason: {reason:?}"
        );

        match expected {
            ExpectedResult::Valid => {
                assert!(
                    matches!(response, Some(PoolToP2pMessage::Accept(_))),
                    "{description}"
                );
            }
            ExpectedResult::Ignore => {
                assert!(
                    matches!(response, Some(PoolToP2pMessage::Ignore(_))),
                    "{description}"
                );
            }
            ExpectedResult::Reject => {
                assert!(
                    matches!(response, Some(PoolToP2pMessage::Reject(_, _))),
                    "{description}"
                );
            }
        }
    }

    fn next_p2p_message(&mut self) -> Option<P2pMessage<P>> {
        loop {
            let option = self.next_p2p_message_verbose();

            if let Some(
                P2pMessage::BlockNeeded(_, _)
                | P2pMessage::FinalizedCheckpoint(_)
                | P2pMessage::HeadChanged(_)
                | P2pMessage::Stop,
            ) = option
            {
                continue;
            }

            return option;
        }
    }

    fn next_p2p_message_verbose(&mut self) -> Option<P2pMessage<P>> {
        self.fc_to_p2p_rx.try_recv().ok()
    }

    fn next_validator_p2p_message_verbose(&mut self) -> Option<ValidatorToP2p<P>> {
        self.validator_to_p2p_rx.try_recv().ok()
    }

    fn next_pool_p2p_message_verbose(&mut self) -> Option<PoolToP2pMessage> {
        self.pool_to_p2p_rx.try_recv().ok()
    }
}

#[duplicate_item(
    glob                                                                                                         function_name                                                    preset    phase;
    ["consensus-spec-tests/tests/mainnet/phase0/networking/gossip_attester_slashing/*/*"]                        [phase0_mainnet_gossip_attester_slashing]                        [Mainnet] [Phase0];
    ["consensus-spec-tests/tests/minimal/phase0/networking/gossip_attester_slashing/*/*"]                        [phase0_minimal_gossip_attester_slashing]                        [Minimal] [Phase0];
    ["consensus-spec-tests/tests/mainnet/altair/networking/gossip_attester_slashing/*/*"]                        [altair_mainnet_gossip_attester_slashing]                        [Mainnet] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/networking/gossip_attester_slashing/*/*"]                        [altair_minimal_gossip_attester_slashing]                        [Minimal] [Altair];
    ["consensus-spec-tests/tests/mainnet/bellatrix/networking/gossip_attester_slashing/*/*"]                     [bellatrix_mainnet_gossip_attester_slashing]                     [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/networking/gossip_attester_slashing/*/*"]                     [bellatrix_minimal_gossip_attester_slashing]                     [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/capella/networking/gossip_attester_slashing/*/*"]                       [capella_mainnet_gossip_attester_slashing]                       [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/networking/gossip_attester_slashing/*/*"]                       [capella_minimal_gossip_attester_slashing]                       [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/networking/gossip_attester_slashing/*/*"]                         [deneb_mainnet_gossip_attester_slashing]                         [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/networking/gossip_attester_slashing/*/*"]                         [deneb_minimal_gossip_attester_slashing]                         [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/electra/networking/gossip_attester_slashing/*/*"]                       [electra_mainnet_gossip_attester_slashing]                       [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/networking/gossip_attester_slashing/*/*"]                       [electra_minimal_gossip_attester_slashing]                       [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/fulu/networking/gossip_attester_slashing/*/*"]                          [fulu_mainnet_gossip_attester_slashing]                          [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/networking/gossip_attester_slashing/*/*"]                          [fulu_minimal_gossip_attester_slashing]                          [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/gloas/networking/gossip_attester_slashing/*/*"]                         [gloas_mainnet_gossip_attester_slashing]                         [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/networking/gossip_attester_slashing/*/*"]                         [gloas_minimal_gossip_attester_slashing]                         [Minimal] [Gloas];
    ["consensus-spec-tests/tests/mainnet/phase0/networking/gossip_beacon_block/*/*"]                             [phase0_mainnet_gossip_beacon_block]                             [Mainnet] [Phase0];
    ["consensus-spec-tests/tests/minimal/phase0/networking/gossip_beacon_block/*/*"]                             [phase0_minimal_gossip_beacon_block]                             [Minimal] [Phase0];
    ["consensus-spec-tests/tests/mainnet/altair/networking/gossip_beacon_block/*/*"]                             [altair_mainnet_gossip_beacon_block]                             [Mainnet] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/networking/gossip_beacon_block/*/*"]                             [altair_minimal_gossip_beacon_block]                             [Minimal] [Altair];
    ["consensus-spec-tests/tests/mainnet/bellatrix/networking/gossip_beacon_block/*/*"]                          [bellatrix_mainnet_gossip_beacon_block]                          [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/networking/gossip_beacon_block/*/*"]                          [bellatrix_minimal_gossip_beacon_block]                          [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/capella/networking/gossip_beacon_block/*/*"]                            [capella_mainnet_gossip_beacon_block]                            [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/networking/gossip_beacon_block/*/*"]                            [capella_minimal_gossip_beacon_block]                            [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/networking/gossip_beacon_block/*/*"]                              [deneb_mainnet_gossip_beacon_block]                              [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/networking/gossip_beacon_block/*/*"]                              [deneb_minimal_gossip_beacon_block]                              [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/electra/networking/gossip_beacon_block/*/*"]                            [electra_mainnet_gossip_beacon_block]                            [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/networking/gossip_beacon_block/*/*"]                            [electra_minimal_gossip_beacon_block]                            [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/fulu/networking/gossip_beacon_block/*/*"]                               [fulu_mainnet_gossip_beacon_block]                               [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/networking/gossip_beacon_block/*/*"]                               [fulu_minimal_gossip_beacon_block]                               [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/phase0/networking/gossip_beacon_aggregate_and_proof/*/*"]               [phase0_mainnet_gossip_beacon_aggregate_and_proof]               [Mainnet] [Phase0];
    ["consensus-spec-tests/tests/minimal/phase0/networking/gossip_beacon_aggregate_and_proof/*/*"]               [phase0_minimal_gossip_beacon_aggregate_and_proof]               [Minimal] [Phase0];
    ["consensus-spec-tests/tests/mainnet/altair/networking/gossip_beacon_aggregate_and_proof/*/*"]               [altair_mainnet_gossip_beacon_aggregate_and_proof]               [Mainnet] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/networking/gossip_beacon_aggregate_and_proof/*/*"]               [altair_minimal_gossip_beacon_aggregate_and_proof]               [Minimal] [Altair];
    ["consensus-spec-tests/tests/mainnet/bellatrix/networking/gossip_beacon_aggregate_and_proof/*/*"]            [bellatrix_mainnet_gossip_beacon_aggregate_and_proof]            [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/networking/gossip_beacon_aggregate_and_proof/*/*"]            [bellatrix_minimal_gossip_beacon_aggregate_and_proof]            [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/capella/networking/gossip_beacon_aggregate_and_proof/*/*"]              [capella_mainnet_gossip_beacon_aggregate_and_proof]              [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/networking/gossip_beacon_aggregate_and_proof/*/*"]              [capella_minimal_gossip_beacon_aggregate_and_proof]              [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/networking/gossip_beacon_aggregate_and_proof/*/*"]                [deneb_mainnet_gossip_beacon_aggregate_and_proof]                [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/networking/gossip_beacon_aggregate_and_proof/*/*"]                [deneb_minimal_gossip_beacon_aggregate_and_proof]                [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/electra/networking/gossip_beacon_aggregate_and_proof/*/*"]              [electra_mainnet_gossip_beacon_aggregate_and_proof]              [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/networking/gossip_beacon_aggregate_and_proof/*/*"]              [electra_minimal_gossip_beacon_aggregate_and_proof]              [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/fulu/networking/gossip_beacon_aggregate_and_proof/*/*"]                 [fulu_mainnet_gossip_beacon_aggregate_and_proof]                 [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/networking/gossip_beacon_aggregate_and_proof/*/*"]                 [fulu_minimal_gossip_beacon_aggregate_and_proof]                 [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/phase0/networking/gossip_beacon_attestation/*/*"]                       [phase0_mainnet_gossip_beacon_attestation]                       [Mainnet] [Phase0];
    ["consensus-spec-tests/tests/minimal/phase0/networking/gossip_beacon_attestation/*/*"]                       [phase0_minimal_gossip_beacon_attestation]                       [Minimal] [Phase0];
    ["consensus-spec-tests/tests/mainnet/altair/networking/gossip_beacon_attestation/*/*"]                       [altair_mainnet_gossip_beacon_attestation]                       [Mainnet] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/networking/gossip_beacon_attestation/*/*"]                       [altair_minimal_gossip_beacon_attestation]                       [Minimal] [Altair];
    ["consensus-spec-tests/tests/mainnet/bellatrix/networking/gossip_beacon_attestation/*/*"]                    [bellatrix_mainnet_gossip_beacon_attestation]                    [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/networking/gossip_beacon_attestation/*/*"]                    [bellatrix_minimal_gossip_beacon_attestation]                    [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/capella/networking/gossip_beacon_attestation/*/*"]                      [capella_mainnet_gossip_beacon_attestation]                      [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/networking/gossip_beacon_attestation/*/*"]                      [capella_minimal_gossip_beacon_attestation]                      [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/networking/gossip_beacon_attestation/*/*"]                        [deneb_mainnet_gossip_beacon_attestation]                        [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/networking/gossip_beacon_attestation/*/*"]                        [deneb_minimal_gossip_beacon_attestation]                        [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/electra/networking/gossip_beacon_attestation/*/*"]                      [electra_mainnet_gossip_beacon_attestation]                      [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/networking/gossip_beacon_attestation/*/*"]                      [electra_minimal_gossip_beacon_attestation]                      [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/fulu/networking/gossip_beacon_attestation/*/*"]                         [fulu_mainnet_gossip_beacon_attestation]                         [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/networking/gossip_beacon_attestation/*/*"]                         [fulu_minimal_gossip_beacon_attestation]                         [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/deneb/networking/gossip_blob_sidecar/*/*"]                              [deneb_mainnet_gossip_blob_sidecar]                              [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/networking/gossip_blob_sidecar/*/*"]                              [deneb_minimal_gossip_blob_sidecar]                              [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/electra/networking/gossip_blob_sidecar/*/*"]                            [electra_mainnet_gossip_blob_sidecar]                            [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/networking/gossip_blob_sidecar/*/*"]                            [electra_minimal_gossip_blob_sidecar]                            [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/capella/networking/gossip_bls_to_execution_change/*/*"]                 [capella_mainnet_gossip_bls_to_execution_change]                 [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/networking/gossip_bls_to_execution_change/*/*"]                 [capella_minimal_gossip_bls_to_execution_change]                 [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/networking/gossip_bls_to_execution_change/*/*"]                   [deneb_mainnet_gossip_bls_to_execution_change]                   [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/networking/gossip_bls_to_execution_change/*/*"]                   [deneb_minimal_gossip_bls_to_execution_change]                   [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/fulu/networking/gossip_bls_to_execution_change/*/*"]                    [fulu_mainnet_gossip_bls_to_execution_change]                    [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/networking/gossip_bls_to_execution_change/*/*"]                    [fulu_minimal_gossip_bls_to_execution_change]                    [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/electra/networking/gossip_bls_to_execution_change/*/*"]                 [electra_mainnet_gossip_bls_to_execution_change]                 [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/networking/gossip_bls_to_execution_change/*/*"]                 [electra_minimal_gossip_bls_to_execution_change]                 [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/gloas/networking/gossip_bls_to_execution_change/*/*"]                   [gloas_mainnet_gossip_bls_to_execution_change]                   [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/networking/gossip_bls_to_execution_change/*/*"]                   [gloas_minimal_gossip_bls_to_execution_change]                   [Minimal] [Gloas];
    ["consensus-spec-tests/tests/mainnet/fulu/networking/gossip_data_column_sidecar/*/*"]                        [fulu_mainnet_data_column_sidecar]                               [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/networking/gossip_data_column_sidecar/*/*"]                        [fulu_minimal_data_column_sidecar]                               [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/phase0/networking/gossip_proposer_slashing/*/*"]                        [phase0_mainnet_gossip_proposer_slashing]                        [Mainnet] [Phase0];
    ["consensus-spec-tests/tests/minimal/phase0/networking/gossip_proposer_slashing/*/*"]                        [phase0_minimal_gossip_proposer_slashing]                        [Minimal] [Phase0];
    ["consensus-spec-tests/tests/mainnet/altair/networking/gossip_proposer_slashing/*/*"]                        [altair_mainnet_gossip_proposer_slashing]                        [Mainnet] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/networking/gossip_proposer_slashing/*/*"]                        [altair_minimal_gossip_proposer_slashing]                        [Minimal] [Altair];
    ["consensus-spec-tests/tests/mainnet/bellatrix/networking/gossip_proposer_slashing/*/*"]                     [bellatrix_mainnet_gossip_proposer_slashing]                     [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/networking/gossip_proposer_slashing/*/*"]                     [bellatrix_minimal_gossip_proposer_slashing]                     [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/capella/networking/gossip_proposer_slashing/*/*"]                       [capella_mainnet_gossip_proposer_slashing]                       [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/networking/gossip_proposer_slashing/*/*"]                       [capella_minimal_gossip_proposer_slashing]                       [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/networking/gossip_proposer_slashing/*/*"]                         [deneb_mainnet_gossip_proposer_slashing]                         [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/networking/gossip_proposer_slashing/*/*"]                         [deneb_minimal_gossip_proposer_slashing]                         [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/fulu/networking/gossip_proposer_slashing/*/*"]                          [fulu_mainnet_gossip_proposer_slashing]                          [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/networking/gossip_proposer_slashing/*/*"]                          [fulu_minimal_gossip_proposer_slashing]                          [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/electra/networking/gossip_proposer_slashing/*/*"]                       [electra_mainnet_gossip_proposer_slashing]                       [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/networking/gossip_proposer_slashing/*/*"]                       [electra_minimal_gossip_proposer_slashing]                       [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/gloas/networking/gossip_proposer_slashing/*/*"]                         [gloas_mainnet_gossip_proposer_slashing]                         [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/networking/gossip_proposer_slashing/*/*"]                         [gloas_minimal_gossip_proposer_slashing]                         [Minimal] [Gloas];
    ["consensus-spec-tests/tests/mainnet/altair/networking/gossip_sync_committee_contribution_and_proof/*/*"]    [altair_mainnet_gossip_sync_committee_contribution_and_proof]    [Mainnet] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/networking/gossip_sync_committee_contribution_and_proof/*/*"]    [altair_minimal_gossip_sync_committee_contribution_and_proof]    [Minimal] [Altair];
    ["consensus-spec-tests/tests/mainnet/bellatrix/networking/gossip_sync_committee_contribution_and_proof/*/*"] [bellatrix_mainnet_gossip_sync_committee_contribution_and_proof] [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/networking/gossip_sync_committee_contribution_and_proof/*/*"] [bellatrix_minimal_gossip_sync_committee_contribution_and_proof] [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/capella/networking/gossip_sync_committee_contribution_and_proof/*/*"]   [capella_mainnet_gossip_sync_committee_contribution_and_proof]   [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/networking/gossip_sync_committee_contribution_and_proof/*/*"]   [capella_minimal_gossip_sync_committee_contribution_and_proof]   [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/networking/gossip_sync_committee_contribution_and_proof/*/*"]     [deneb_mainnet_gossip_sync_committee_contribution_and_proof]     [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/networking/gossip_sync_committee_contribution_and_proof/*/*"]     [deneb_minimal_gossip_sync_committee_contribution_and_proof]     [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/electra/networking/gossip_sync_committee_contribution_and_proof/*/*"]   [electra_mainnet_gossip_sync_committee_contribution_and_proof]   [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/networking/gossip_sync_committee_contribution_and_proof/*/*"]   [electra_minimal_gossip_sync_committee_contribution_and_proof]   [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/fulu/networking/gossip_sync_committee_contribution_and_proof/*/*"]      [fulu_mainnet_gossip_sync_committee_contribution_and_proof]      [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/networking/gossip_sync_committee_contribution_and_proof/*/*"]      [fulu_minimal_gossip_sync_committee_contribution_and_proof]      [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/gloas/networking/gossip_sync_committee_contribution_and_proof/*/*"]     [gloas_mainnet_gossip_sync_committee_contribution_and_proof]     [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/networking/gossip_sync_committee_contribution_and_proof/*/*"]     [gloas_minimal_gossip_sync_committee_contribution_and_proof]     [Minimal] [Gloas];
    ["consensus-spec-tests/tests/mainnet/altair/networking/gossip_sync_committee_message/*/*"]                   [altair_mainnet_gossip_sync_committee_message]                   [Mainnet] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/networking/gossip_sync_committee_message/*/*"]                   [altair_minimal_gossip_sync_committee_message]                   [Minimal] [Altair];
    ["consensus-spec-tests/tests/mainnet/bellatrix/networking/gossip_sync_committee_message/*/*"]                [bellatrix_mainnet_gossip_sync_committee_message]                [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/networking/gossip_sync_committee_message/*/*"]                [bellatrix_minimal_gossip_sync_committee_message]                [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/capella/networking/gossip_sync_committee_message/*/*"]                  [capella_mainnet_gossip_sync_committee_message]                  [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/networking/gossip_sync_committee_message/*/*"]                  [capella_minimal_gossip_sync_committee_message]                  [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/networking/gossip_sync_committee_message/*/*"]                    [deneb_mainnet_gossip_sync_committee_message]                    [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/networking/gossip_sync_committee_message/*/*"]                    [deneb_minimal_gossip_sync_committee_message]                    [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/fulu/networking/gossip_sync_committee_message/*/*"]                     [fulu_mainnet_gossip_sync_committee_message]                     [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/networking/gossip_sync_committee_message/*/*"]                     [fulu_minimal_gossip_sync_committee_message]                     [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/electra/networking/gossip_sync_committee_message/*/*"]                  [electra_mainnet_gossip_sync_committee_message]                  [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/networking/gossip_sync_committee_message/*/*"]                  [electra_minimal_gossip_sync_committee_message]                  [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/gloas/networking/gossip_sync_committee_message/*/*"]                    [gloas_mainnet_gossip_sync_committee_message]                    [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/networking/gossip_sync_committee_message/*/*"]                    [gloas_minimal_gossip_sync_committee_message]                    [Minimal] [Gloas];
    ["consensus-spec-tests/tests/mainnet/phase0/networking/gossip_voluntary_exit/*/*"]                           [phase0_mainnet_gossip_voluntary_exit]                           [Mainnet] [Phase0];
    ["consensus-spec-tests/tests/minimal/phase0/networking/gossip_voluntary_exit/*/*"]                           [phase0_minimal_gossip_voluntary_exit]                           [Minimal] [Phase0];
    ["consensus-spec-tests/tests/mainnet/altair/networking/gossip_voluntary_exit/*/*"]                           [altair_mainnet_gossip_voluntary_exit]                           [Mainnet] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/networking/gossip_voluntary_exit/*/*"]                           [altair_minimal_gossip_voluntary_exit]                           [Minimal] [Altair];
    ["consensus-spec-tests/tests/mainnet/bellatrix/networking/gossip_voluntary_exit/*/*"]                        [bellatrix_mainnet_gossip_voluntary_exit]                        [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/networking/gossip_voluntary_exit/*/*"]                        [bellatrix_minimal_gossip_voluntary_exit]                        [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/capella/networking/gossip_voluntary_exit/*/*"]                          [capella_mainnet_gossip_voluntary_exit]                          [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/networking/gossip_voluntary_exit/*/*"]                          [capella_minimal_gossip_voluntary_exit]                          [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/networking/gossip_voluntary_exit/*/*"]                            [deneb_mainnet_gossip_voluntary_exit]                            [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/networking/gossip_voluntary_exit/*/*"]                            [deneb_minimal_gossip_voluntary_exit]                            [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/electra/networking/gossip_voluntary_exit/*/*"]                          [electra_mainnet_gossip_voluntary_exit]                          [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/networking/gossip_voluntary_exit/*/*"]                          [electra_minimal_gossip_voluntary_exit]                          [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/fulu/networking/gossip_voluntary_exit/*/*"]                             [fulu_mainnet_gossip_voluntary_exit]                             [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/networking/gossip_voluntary_exit/*/*"]                             [fulu_minimal_gossip_voluntary_exit]                             [Minimal] [Fulu];
)]
#[test_resources(glob)]
fn function_name(case: Case<'_>) {
    let rt = tokio::runtime::Runtime::new().expect("Tokio runtime starts successfully in tests");

    let config = Arc::new(
        case.try_yaml("config")
            .unwrap_or_else(preset::default_config)
            .start_and_stay_in(Phase::phase),
    );

    rt.block_on(async {
        run_gossip_case::<preset>(&config, case)
            .await
            .expect("test returns without errors");
    });
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "SCREAMING_SNAKE_CASE")]
enum BlockPayloadStatus {
    Valid,
    Invalidated,
    NotValidated,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockMeta {
    pub block: PathBuf,
    pub failed: Option<bool>,
    pub payload_status: Option<BlockPayloadStatus>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizedCheckpoint {
    epoch: Epoch,
    root: Option<H256>,
    block: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    pub blocks: Option<Vec<BlockMeta>>,
    pub bls_setting: Option<BlsSetting>,
    pub current_time_ms: Option<u64>,
    pub finalized_checkpoint: Option<FinalizedCheckpoint>,
    pub messages: Vec<Message>,
    pub topic: Topic,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum ExpectedResult {
    Valid,
    Ignore,
    Reject,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum Topic {
    AttesterSlashing,
    BeaconAggregateAndProof,
    BeaconAttestation,
    BeaconBlock,
    BlobSidecar,
    BlsToExecutionChange,
    DataColumnSidecar,
    ProposerSlashing,
    SyncCommittee,
    SyncCommitteeContributionAndProof,
    VoluntaryExit,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    pub offset_ms: Option<u64>,
    pub subnet_id: Option<u64>,
    pub message: PathBuf,
    pub expected: ExpectedResult,
    pub reason: Option<String>,
}

#[expect(clippy::too_many_lines)]
async fn run_gossip_case<P: Preset>(config: &Arc<Config>, case: Case<'_>) -> Result<()> {
    let Meta {
        blocks,
        bls_setting,
        current_time_ms,
        finalized_checkpoint,
        messages,
        topic,
    } = case.yaml::<Meta>("meta");

    let mut time: u64 = 0;
    let anchor_state = case.ssz::<_, Arc<BeaconState<P>>>(config.as_ref(), "state");
    let genesis_time = anchor_state.genesis_time();
    let bls_setting = bls_setting.unwrap_or_default();

    let (anchor_block, blocks): (Vec<_>, Vec<_>) = blocks
        .unwrap_or_default()
        .into_iter()
        .map(|block_meta| {
            let BlockMeta {
                block,
                failed,
                payload_status,
            } = block_meta;

            let block = case.ssz::<_, Arc<SignedBeaconBlock<P>>>(config.as_ref(), block);
            let is_valid = !failed.unwrap_or_default();

            (block, is_valid, payload_status)
        })
        .partition(|(block, is_valid, _)| {
            *is_valid && block.message().slot() == anchor_state.slot()
        });

    let anchor_block = anchor_block
        .into_iter()
        .next()
        .map(|(block, _, _)| AnchorBlock::Real(block))
        .unwrap_or_else(|| {
            AnchorBlock::Test(Arc::new(genesis::beacon_block_from_state(&anchor_state)))
        });

    // Collect "invalid" block roots to be imported before validation and blacklist them.
    // These are actually valid blocks but should be rejected for testing-purposes.
    // One way mark blocks as rejected is to blacklist their roots and then try importing them.
    let blacklisted_blocks = blocks
        .iter()
        .filter(|&(_, is_valid, _)| !is_valid)
        .map(|(block, _, _)| block.message().hash_tree_root())
        .collect();

    let anchor_state_slot = anchor_state.slot();

    let mut context = Context::<P>::new(
        config.clone_arc(),
        anchor_block,
        anchor_state,
        blacklisted_blocks,
    )?;

    let tick_at_time = |time| {
        Tick::at_time_in_ms::<P>(config, time, genesis_time)
            .expect("configurations used in tests have valid values of milliseconds")
    };

    if let Some(current_time) = current_time_ms {
        time = time.saturating_add(current_time);

        let tick = tick_at_time(current_time);
        context.on_tick(tick);
    } else {
        context.on_tick(Tick::start_of_slot(anchor_state_slot));
    }

    for (block, is_valid, payload_status) in blocks {
        let expected = if is_valid {
            if block.message().slot() < anchor_state_slot {
                ExpectedResult::Ignore
            } else {
                ExpectedResult::Valid
            }
        } else {
            ExpectedResult::Reject
        };

        context.on_block(
            &block,
            bls_setting,
            StateRootPolicy::Verify,
            payload_status,
            Some(expected),
            None,
        );
    }

    if let Some(checkpoint) = finalized_checkpoint {
        let FinalizedCheckpoint { epoch, root, block } = checkpoint;

        if let Some(block_path) = block {
            let block = case.ssz::<_, Arc<SignedBeaconBlock<P>>>(config.as_ref(), block_path);
            let root = block.message().hash_tree_root();

            assert!(root == context.controller.finalized_checkpoint().root);

            context
                .controller
                .override_finalized_checkpoint(Checkpoint { epoch, root });

            context.controller.wait_for_tasks();
        } else if root.is_some()
            && case
                .case_path_relative_to_workspace_root
                .contains("ignore_finalized_not_ancestor")
        {
            // These test sets a finalized checkpoint whose root is not an ancestor of the
            // imported blocks. In Grandine, prune_after_finalization removes such blocks
            // immediately when finalization advances, so the inconsistent state this test
            // requires is unreachable.
            return Ok(());
        } else if let Some(root) = root {
            context
                .controller
                .override_finalized_checkpoint(Checkpoint { epoch, root });

            context.controller.wait_for_tasks();
        }
    }

    for test_message in messages {
        let Message {
            offset_ms,
            subnet_id,
            message,
            mut expected,
            reason,
        } = test_message;

        if let Some(offset_ms) = offset_ms {
            let tick = tick_at_time(time.saturating_add(offset_ms));
            context.on_tick(tick);
        }

        match topic {
            Topic::AttesterSlashing => {
                let attester_slashing = match config.genesis_phase() {
                    Phase::Phase0
                    | Phase::Altair
                    | Phase::Bellatrix
                    | Phase::Capella
                    | Phase::Deneb => AttesterSlashing::Phase0(case.ssz(config, message)),
                    Phase::Electra | Phase::Fulu | Phase::Gloas => {
                        AttesterSlashing::Electra(case.ssz(config, message))
                    }
                };

                context.on_attester_slashing(attester_slashing, expected, reason.as_deref());
            }
            Topic::BeaconAggregateAndProof => {
                let aggregate_and_proof = match config.genesis_phase() {
                    Phase::Phase0
                    | Phase::Altair
                    | Phase::Bellatrix
                    | Phase::Capella
                    | Phase::Deneb => {
                        SignedAggregateAndProof::<P>::Phase0(case.ssz(config, message))
                    }
                    Phase::Electra | Phase::Fulu | Phase::Gloas => {
                        SignedAggregateAndProof::<P>::Electra(case.ssz(config, message))
                    }
                };

                let mut expected = Some(expected);

                // TODO: implement `MAXIMUM_GOSSIP_CLOCK_DISPARITY` checks
                if case
                    .case_path_relative_to_workspace_root
                    .contains("valid_within_clock_disparity")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("accepts_one_millisecond_before_slot_start")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("accepts_last_slot_one_millisecond_before_slot_start")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("accepts_first_slot_when_epoch_window_closes")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("accepts_first_slot_when_epoch_window_opens")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("accepts_last_slot_when_epoch_window_closes")
                {
                    expected = Some(ExpectedResult::Ignore)
                }

                context.on_aggregate_and_proof(
                    aggregate_and_proof.into(),
                    expected,
                    reason.as_deref(),
                );
            }
            Topic::BeaconAttestation => {
                let attestation: Arc<Attestation<P>> = case.ssz_default(message);

                // TODO: implement `MAXIMUM_GOSSIP_CLOCK_DISPARITY` checks
                if case
                    .case_path_relative_to_workspace_root
                    .contains("valid_within_clock_disparity")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("accepts_one_millisecond_before_slot_start")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("accepts_last_slot_one_millisecond_before_slot_start")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("accepts_first_slot_when_epoch_window_closes")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("accepts_first_slot_when_epoch_window_opens")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("accepts_last_slot_when_epoch_window_closes")
                {
                    expected = ExpectedResult::Ignore;
                }

                context.on_attestation(
                    attestation,
                    subnet_id.expect("subnet_id must be present for attestation test"),
                    expected,
                    reason.as_deref(),
                );
            }
            Topic::BeaconBlock => {
                let block = case.ssz::<_, Arc<SignedBeaconBlock<P>>>(config.as_ref(), message);

                // TODO: implement `MAXIMUM_GOSSIP_CLOCK_DISPARITY` checks
                let expected = if case
                    .case_path_relative_to_workspace_root
                    .contains("valid_within_clock_disparity")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("ignore_future_slot")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("ignore_parent_not_seen")
                {
                    // Block is delayed
                    None
                } else {
                    Some(expected)
                };

                // These tests contain test message with randao_reveal set to zero and mark the block as valid
                let state_root_policy = if case
                    .case_path_relative_to_workspace_root
                    .contains("valid_parent_execution_verified_valid")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("valid_parent_optimistic")
                {
                    StateRootPolicy::Trust
                } else {
                    StateRootPolicy::Verify
                };

                context.on_block(
                    &block,
                    bls_setting,
                    state_root_policy,
                    None,
                    expected,
                    reason.as_deref(),
                );
            }
            Topic::BlsToExecutionChange => {
                let signed_bls_to_execution_change =
                    case.ssz::<_, Box<SignedBlsToExecutionChange>>(config.as_ref(), message);

                // test Config has CAPELLA_FORK_EPOCH=1 and yet store is initialized with Capella genesis state at slot 0
                if case
                    .case_path_relative_to_workspace_root
                    .contains("ignore_pre_capella")
                {
                    expected = ExpectedResult::Valid;
                }

                context
                    .on_bls_to_execution_change(signed_bls_to_execution_change, expected)
                    .await?;
            }
            Topic::BlobSidecar => {
                let blob_sidecar = case.ssz::<_, Arc<BlobSidecar<P>>>(config.as_ref(), message);

                // TODO: implement `MAXIMUM_GOSSIP_CLOCK_DISPARITY` checks
                let expected = if case
                    .case_path_relative_to_workspace_root
                    .contains("valid_within_clock_disparity")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("valid_slot_within_clock_disparity")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("ignore_future_slot")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("ignore_parent_not_seen")
                {
                    // Blob sidecar is delayed
                    None
                } else {
                    Some(expected)
                };

                context.on_blob_sidecar(
                    blob_sidecar,
                    subnet_id.expect("subnet_id must be present for blob sidecar"),
                    expected,
                    reason.as_deref(),
                );
            }
            Topic::DataColumnSidecar => {
                let data_column_sidecar =
                    case.ssz::<_, Arc<DataColumnSidecar<P>>>(config.as_ref(), message);

                // TODO: implement `MAXIMUM_GOSSIP_CLOCK_DISPARITY` checks
                let expected = if case
                    .case_path_relative_to_workspace_root
                    .contains("valid_within_clock_disparity")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("valid_slot_within_clock_disparity")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("ignore_future_slot")
                    || case
                        .case_path_relative_to_workspace_root
                        .contains("ignore_parent_not_seen")
                {
                    // Data Columns Sidecar is delayed
                    None
                } else {
                    Some(expected)
                };

                context
                    .on_data_column_sidecar(
                        data_column_sidecar,
                        subnet_id.expect("subnet_id must be present for data column sidecar"),
                        expected,
                        reason.as_deref(),
                    )
                    .await;
            }
            Topic::ProposerSlashing => {
                let proposer_slashing = case.ssz::<_, ProposerSlashing>(config.as_ref(), message);
                context.on_proposer_slashing(proposer_slashing, expected, reason.as_deref());
            }
            Topic::SyncCommittee => {
                let sync_committee_message =
                    case.ssz::<_, SyncCommitteeMessage>(config.as_ref(), message);

                context.on_sync_committee_message(
                    sync_committee_message,
                    subnet_id.expect("subnet_id must be present for sync committee message"),
                    expected,
                    reason.as_deref(),
                );
            }
            Topic::SyncCommitteeContributionAndProof => {
                let signed_contribution_and_proof =
                    case.ssz::<_, SignedContributionAndProof<P>>(config.as_ref(), message);

                context.on_sync_contribution_and_proof(
                    signed_contribution_and_proof,
                    expected,
                    reason.as_deref(),
                );
            }
            Topic::VoluntaryExit => {
                let voluntary_exit = case.ssz::<_, SignedVoluntaryExit>(config.as_ref(), message);
                context.on_voluntary_exit(voluntary_exit, expected, reason.as_deref());
            }
        }
    }

    Ok(())
}
