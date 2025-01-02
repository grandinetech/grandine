use core::{future::Future, net::Ipv4Addr};
use std::sync::Arc;

use anyhow::Result;
use attestation_verifier::AttestationVerifier;
use block_producer::{BlockProducer, Options as BlockProducerOptions};
use bls::{traits::SecretKey as _, PublicKeyBytes, SecretKey};
use clock::Tick;
use database::Database;
use dedicated_executor::DedicatedExecutor;
use deposit_tree::DepositTree;
use enum_iterator::Sequence as _;
use eth1::{Eth1Chain, Eth1Config};
use eth1_api::{Eth1Api, Eth1ExecutionEngine, ExecutionService};
#[cfg(feature = "eth2-cache")]
use eth2_cache_utils::mainnet;
use features::Feature;
use fork_choice_control::{
    Controller, StateLoadStrategy, Storage, DEFAULT_ARCHIVAL_EPOCH_INTERVAL,
};
use fork_choice_store::StoreConfig;
use futures::{future::FutureExt as _, lock::Mutex, select_biased};
use genesis::AnchorCheckpointProvider;
use http_api_utils::EventChannels;
use keymanager::KeyManager;
use liveness_tracker::LivenessTracker;
use once_cell::sync::OnceCell;
use operation_pools::{AttestationAggPool, BlsToExecutionChangePool, SyncCommitteeAggPool};
use p2p::{NetworkConfig, SubnetService, SyncToApi};
use reqwest::Client;
use signer::{KeyOrigin, Signer, Web3SignerConfig};
use slashing_protection::{SlashingProtector, DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT};
use snapshot_test_utils::Case;
use std_ext::ArcExt as _;
use tap::Pipe as _;
use tokio::runtime::Builder;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config as ChainConfig,
    nonstandard::{FinalizedCheckpoint, Phase},
    phase0::primitives::{NodeId, H256},
    preset::{Mainnet, Minimal, Preset},
    traits::BeaconState as _,
};
use validator::{Validator, ValidatorChannels, ValidatorConfig};

use crate::{
    http_api_config::HttpApiConfig,
    middleware,
    routing::{self, TestState},
    task::{Channels, HttpApi},
};

const IDENTIFY_AGENT_VERSION: &str = "deterministic-version-for-snapshot-tests";

#[must_use]
pub struct Context<P: Preset> {
    chain_config: ChainConfig,
    anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    anchor_block: Arc<SignedBeaconBlock<P>>,
    anchor_state: Arc<BeaconState<P>>,
    deposit_tree: Option<DepositTree>,
    extra_blocks: Vec<Arc<SignedBeaconBlock<P>>>,
    validator_keys: Vec<(PublicKeyBytes, Arc<SecretKey>, KeyOrigin)>,
}

impl<P: Preset> Context<P> {
    pub fn run_case(self, case: Case) {
        block_on(self.try_run_case(case)).unwrap_or_else(|error| panic!("{error:?}"))
    }

    #[expect(clippy::too_many_lines)]
    async fn try_run_case(self, case: Case<'_>) -> Result<()> {
        Feature::ServeCostlyEndpoints.enable();
        Feature::ServeLeakyEndpoints.enable();

        let Self {
            chain_config,
            anchor_checkpoint_provider,
            anchor_block,
            anchor_state,
            deposit_tree,
            extra_blocks,
            validator_keys,
            ..
        } = self;

        let (api_to_liveness_tx, api_to_liveness_rx) = futures::channel::mpsc::unbounded();
        let (api_to_p2p_tx, api_to_p2p_rx) = futures::channel::mpsc::unbounded();
        let (api_to_validator_tx, api_to_validator_rx) = futures::channel::mpsc::unbounded();
        let (fc_to_attestation_verifier_tx, fc_to_attestation_verifier_rx) =
            futures::channel::mpsc::unbounded();
        let (fc_to_p2p_tx, fc_to_p2p_rx) = futures::channel::mpsc::unbounded();
        let (fc_to_pool_tx, _) = futures::channel::mpsc::unbounded();
        let (fc_to_subnet_tx, fc_to_subnet_rx) = futures::channel::mpsc::unbounded();
        let (fc_to_sync_tx, fc_to_sync_rx) = futures::channel::mpsc::unbounded();
        let (fc_to_validator_tx, fc_to_validator_rx) = futures::channel::mpsc::unbounded();
        let (_, p2p_to_validator_rx) = futures::channel::mpsc::unbounded();
        let (pool_to_liveness_tx, pool_to_liveness_rx) = futures::channel::mpsc::unbounded();
        let (pool_to_p2p_tx, pool_to_p2p_rx) = futures::channel::mpsc::unbounded();
        let (subnet_service_to_p2p_tx, _subnet_service_to_p2p_rx) =
            futures::channel::mpsc::unbounded();
        let (sync_to_api_tx, sync_to_api_rx) = futures::channel::mpsc::unbounded();
        let (subnet_service_tx, subnet_service_rx) = futures::channel::mpsc::unbounded();
        let (validator_to_liveness_tx, validator_to_liveness_rx) =
            futures::channel::mpsc::unbounded();
        let (validator_to_p2p_tx, validator_to_p2p_rx) = futures::channel::mpsc::unbounded();
        let (execution_service_tx, execution_service_rx) = futures::channel::mpsc::unbounded();

        let chain_config = Arc::new(chain_config);
        let store_config = StoreConfig::aggressive(&chain_config);

        let eth1_config = Arc::new(Eth1Config {
            default_deposit_tree: deposit_tree,
            ..Eth1Config::default()
        });

        let client = Client::new();

        let eth1_chain = Eth1Chain::new(
            chain_config.clone_arc(),
            eth1_config.clone_arc(),
            client.clone(),
            Database::in_memory(),
            None,
            None,
        )?;

        eth1_chain.spawn_unfinalized_blocks_tracker_task()?;

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

        let storage = Arc::new(Storage::new(
            chain_config.clone_arc(),
            Database::in_memory(),
            DEFAULT_ARCHIVAL_EPOCH_INTERVAL,
            false,
        ));

        let state_load_strategy = StateLoadStrategy::Anchor {
            block: anchor_block,
            state: anchor_state,
        };

        let ((anchor_state, anchor_block, mut unfinalized_blocks), loaded_from_remote) =
            storage.load(&client, state_load_strategy).await?;

        assert!(unfinalized_blocks.next().is_none());
        assert!(!loaded_from_remote);

        drop(unfinalized_blocks);

        // If any extra blocks are available, the fork choice store has to be advanced to the slot
        // of the latest one. This should be done using the `tick` parameter of `Controller::new`.
        // Calling `Controller::on_slot` causes `Validator` to attempt to carry out duties and fail.
        let tick = extra_blocks
            .last()
            .unwrap_or(&anchor_block)
            .pipe(Tick::block_proposal);

        let event_channels = Arc::new(EventChannels::default());

        let (controller, mutator_handle) = Controller::new(
            chain_config,
            store_config,
            anchor_block,
            anchor_state.clone_arc(),
            tick,
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
        )?;

        for block in extra_blocks {
            // Strictly speaking the blocks are not requested from anywhere, but we want them to be
            // fully validated, so `Controller::on_requested_block` fits the best.
            controller.on_requested_block(block, None);
        }

        let execution_service = ExecutionService::new(
            eth1_api.clone_arc(),
            controller.clone_arc(),
            execution_service_rx,
        );

        let signer = Arc::new(Signer::new(
            validator_keys,
            client,
            Web3SignerConfig::default(),
            None,
        ));

        let signer_snapshot = signer.load();

        let validator_keys = Arc::new(signer_snapshot.keys().copied().collect());

        let mut slashing_protector =
            SlashingProtector::in_memory(DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT)?;

        slashing_protector.register_validators(signer_snapshot.keys().copied())?;

        let slashing_protector = Arc::new(Mutex::new(slashing_protector));

        let validator_config = Arc::new(ValidatorConfig::default());

        let keymanager = Arc::new(KeyManager::new_in_memory(
            signer.clone_arc(),
            slashing_protector.clone_arc(),
            anchor_state.genesis_validators_root(),
            validator_config.suggested_fee_recipient,
            validator_config.default_gas_limit,
            H256::default(),
        ));

        let dedicated_executor = Arc::new(DedicatedExecutor::new(
            "dedicated-executor",
            num_cpus::get(),
            None,
            None,
        ));

        let attestation_verifier = AttestationVerifier::new(
            controller.clone_arc(),
            dedicated_executor.clone_arc(),
            None,
            fc_to_attestation_verifier_rx,
        );

        let attestation_agg_pool =
            AttestationAggPool::new(controller.clone_arc(), dedicated_executor.clone_arc(), None);

        let sync_committee_agg_pool = SyncCommitteeAggPool::new(
            dedicated_executor.clone_arc(),
            controller.clone_arc(),
            Some(pool_to_liveness_tx),
            pool_to_p2p_tx.clone(),
            None,
        );

        let (bls_to_execution_change_pool, bls_to_execution_change_pool_service) =
            BlsToExecutionChangePool::new(
                controller.clone_arc(),
                event_channels.clone_arc(),
                pool_to_p2p_tx,
                None,
            );

        let liveness_tracker = LivenessTracker::new(
            controller.clone_arc(),
            None,
            api_to_liveness_rx,
            pool_to_liveness_rx,
            validator_to_liveness_rx,
        );

        let block_producer = Arc::new(BlockProducer::new(
            keymanager.proposer_configs().clone_arc(),
            None,
            controller.clone_arc(),
            dedicated_executor,
            eth1_chain,
            execution_engine,
            attestation_agg_pool.clone_arc(),
            bls_to_execution_change_pool.clone_arc(),
            sync_committee_agg_pool.clone_arc(),
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
            subnet_service_tx: subnet_service_tx.clone(),
            validator_to_liveness_tx: Some(validator_to_liveness_tx),
            validator_to_slasher_tx: None,
        };

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
            sync_committee_agg_pool.clone_arc(),
            None,
            validator_channels,
        );

        let mut network_config = NetworkConfig::default();
        network_config.identify_agent_version = Some(IDENTIFY_AGENT_VERSION.to_owned());
        let network_config = Arc::new(network_config);

        let subnet_service = SubnetService::new(
            attestation_agg_pool.clone_arc(),
            NodeId::ZERO,
            subnet_service_to_p2p_tx,
            fc_to_subnet_rx,
            subnet_service_rx,
        );

        let http_api_config = HttpApiConfig::with_address(Ipv4Addr::LOCALHOST, 0);
        let listener = http_api_config.listener().await?;
        let actual_address = listener.local_addr()?;

        let channels = Channels {
            api_to_liveness_tx: Some(api_to_liveness_tx),
            api_to_p2p_tx,
            api_to_validator_tx,
            subnet_service_tx,
            sync_to_api_rx,
        };

        let http_api = HttpApi {
            block_producer,
            controller,
            anchor_checkpoint_provider,
            eth1_api,
            event_channels,
            validator_keys,
            validator_config,
            network_config,
            http_api_config,
            attestation_agg_pool,
            sync_committee_agg_pool,
            bls_to_execution_change_pool,
            channels,
            metrics: None,
        };

        let test_state = TestState {
            api_to_p2p_rx: Arc::new(Mutex::new(api_to_p2p_rx)),
            fc_to_p2p_rx: Arc::new(Mutex::new(fc_to_p2p_rx)),
            fc_to_sync_rx: Arc::new(Mutex::new(fc_to_sync_rx)),
            pool_to_p2p_rx: Arc::new(Mutex::new(pool_to_p2p_rx)),
            validator_to_p2p_rx: Arc::new(Mutex::new(validator_to_p2p_rx)),
        };

        let run_http_api = http_api.run_internal(
            |normal_state, router| {
                // Apply `middleware::wait_for_tasks` to all routes.
                // This makes block publishing and tick endpoints deterministic.
                router
                    .merge(routing::test_routes(normal_state.clone(), test_state))
                    .layer(axum::middleware::map_request_with_state(
                        normal_state,
                        middleware::wait_for_tasks,
                    ))
            },
            listener,
        );

        let join_mutator = async { tokio::task::spawn_blocking(|| mutator_handle.join()).await? };
        let submit_requests = case.run(should_update_responses(), actual_address);

        SyncToApi::SyncStatus(true).send(&sync_to_api_tx);
        SyncToApi::BackSyncStatus(true).send(&sync_to_api_tx);

        // Poll the HTTP API first to ensure it handles the messages sent above before any requests.
        // This could also be done by polling it once using `core::future::poll_fn`.
        select_biased! {
            result = run_http_api.fuse() => result,
            result = join_mutator.fuse() => result,
            result = execution_service.run().fuse() => result,
            result = attestation_verifier.run().fuse() => result,
            result = bls_to_execution_change_pool_service.run().fuse() => result,
            result = liveness_tracker.run().fuse() => result,
            result = validator.run().fuse() => result,
            result = subnet_service.run().fuse() => result,
            result = submit_requests.fuse() => result,
        }
    }

    fn interop_validator_keys(count: u64) -> Vec<(PublicKeyBytes, Arc<SecretKey>, KeyOrigin)> {
        (0..count)
            .map(interop::secret_key)
            .map(|secret_key| {
                let secret_key = Arc::new(secret_key);
                let public_key = secret_key.to_public_key().into();
                (public_key, secret_key, KeyOrigin::LocalFileSystem)
            })
            .collect()
    }
}

impl Context<Mainnet> {
    pub fn mainnet_genesis_none() -> Self {
        let anchor_checkpoint_provider = predefined_chains::mainnet();

        let FinalizedCheckpoint {
            block: anchor_block,
            state: anchor_state,
        } = anchor_checkpoint_provider.checkpoint().value;

        Self {
            chain_config: ChainConfig::mainnet(),
            anchor_checkpoint_provider,
            anchor_block,
            anchor_state,
            deposit_tree: None,
            extra_blocks: vec![],
            validator_keys: vec![],
        }
    }

    #[cfg(feature = "eth2-cache")]
    pub fn mainnet_genesis_128_slots() -> Self {
        let anchor_checkpoint_provider = predefined_chains::mainnet();

        let FinalizedCheckpoint {
            block: anchor_block,
            state: anchor_state,
        } = anchor_checkpoint_provider.checkpoint().value;

        Self {
            chain_config: ChainConfig::mainnet(),
            anchor_checkpoint_provider,
            anchor_block,
            anchor_state,
            deposit_tree: None,
            extra_blocks: mainnet::BEACON_BLOCKS_UP_TO_SLOT_128.force().to_vec(),
            validator_keys: vec![],
        }
    }

    #[cfg(feature = "eth2-cache")]
    pub fn mainnet_epoch_96214_128_slots() -> Self {
        let extra_blocks = mainnet::ALTAIR_BEACON_BLOCKS_FROM_128_SLOTS
            .force()
            .to_vec();

        Self {
            chain_config: ChainConfig::mainnet(),
            anchor_checkpoint_provider: predefined_chains::mainnet(),
            anchor_block: mainnet::ALTAIR_BEACON_BLOCK.force().clone_arc(),
            anchor_state: mainnet::ALTAIR_BEACON_STATE.force().clone_arc(),
            deposit_tree: None,
            extra_blocks,
            validator_keys: vec![],
        }
    }

    #[cfg(feature = "eth2-cache")]
    pub fn mainnet_epoch_244816_128_slots() -> Self {
        let extra_blocks = mainnet::CAPELLA_BEACON_BLOCKS_FROM_244816_SLOTS
            .force()
            .to_vec();

        Self {
            chain_config: ChainConfig::mainnet(),
            anchor_checkpoint_provider: predefined_chains::mainnet(),
            anchor_block: mainnet::CAPELLA_BEACON_BLOCK.force().clone_arc(),
            anchor_state: mainnet::CAPELLA_BEACON_STATE.force().clone_arc(),
            deposit_tree: None,
            extra_blocks,
            validator_keys: vec![],
        }
    }
}

impl Context<Minimal> {
    pub fn minimal_minimal_all_keys() -> Self {
        let chain_config = ChainConfig::minimal();
        let (genesis_state, deposit_tree) = Self::min_genesis_state(&chain_config);
        let validator_keys = Self::interop_validator_keys(genesis_state.validators().len_u64());

        let anchor_checkpoint_provider =
            AnchorCheckpointProvider::custom_from_genesis(genesis_state);

        let FinalizedCheckpoint {
            block: anchor_block,
            state: anchor_state,
        } = anchor_checkpoint_provider.checkpoint().value;

        Self {
            chain_config,
            anchor_checkpoint_provider,
            anchor_block,
            anchor_state,
            deposit_tree: Some(deposit_tree),
            extra_blocks: vec![],
            validator_keys,
        }
    }

    pub fn minimal_minimal_4_epochs() -> Self {
        let chain_config = ChainConfig::minimal();
        let (genesis_state, deposit_tree) = Self::min_genesis_state(&chain_config);
        let anchor_checkpoint_provider =
            AnchorCheckpointProvider::custom_from_genesis(genesis_state.clone_arc());

        let extra_blocks = factory::full_blocks_up_to_epoch(&chain_config, genesis_state, 4)
            .expect("blocks should be constructed successfully");

        let FinalizedCheckpoint {
            block: anchor_block,
            state: anchor_state,
        } = anchor_checkpoint_provider.checkpoint().value;

        Self {
            chain_config,
            anchor_checkpoint_provider,
            anchor_block,
            anchor_state,
            deposit_tree: Some(deposit_tree),
            extra_blocks,
            validator_keys: vec![],
        }
    }

    pub fn minimal_rapid_upgrade_none() -> Self {
        let chain_config = ChainConfig::minimal().rapid_upgrade();
        let (genesis_state, deposit_tree) = Self::min_genesis_state(&chain_config);
        let anchor_checkpoint_provider =
            AnchorCheckpointProvider::custom_from_genesis(genesis_state);

        let FinalizedCheckpoint {
            block: anchor_block,
            state: anchor_state,
        } = anchor_checkpoint_provider.checkpoint().value;

        Self {
            chain_config,
            anchor_checkpoint_provider,
            anchor_block,
            anchor_state,
            deposit_tree: Some(deposit_tree),
            extra_blocks: vec![],
            validator_keys: vec![],
        }
    }

    pub fn minimal_rapid_upgrade_all_keys() -> Self {
        let chain_config = ChainConfig::minimal().rapid_upgrade();
        let (genesis_state, deposit_tree) = Self::min_genesis_state(&chain_config);
        let validator_keys = Self::interop_validator_keys(genesis_state.validators().len_u64());
        let anchor_checkpoint_provider =
            AnchorCheckpointProvider::custom_from_genesis(genesis_state);

        let FinalizedCheckpoint {
            block: anchor_block,
            state: anchor_state,
        } = anchor_checkpoint_provider.checkpoint().value;

        Self {
            chain_config,
            anchor_checkpoint_provider,
            anchor_block,
            anchor_state,
            deposit_tree: Some(deposit_tree),
            extra_blocks: vec![],
            validator_keys,
        }
    }

    pub fn minimal_rapid_upgrade_all_phases_all_keys() -> Self {
        let chain_config = ChainConfig::minimal().rapid_upgrade();
        let (genesis_state, deposit_tree) = Self::min_genesis_state(&chain_config);
        let anchor_checkpoint_provider =
            AnchorCheckpointProvider::custom_from_genesis(genesis_state.clone_arc());
        let validator_keys = Self::interop_validator_keys(genesis_state.validators().len_u64());

        let extra_blocks = factory::full_blocks_up_to_epoch(
            &chain_config,
            genesis_state,
            Phase::CARDINALITY
                .try_into()
                .expect("number of phases should fit in u64"),
        )
        .expect("blocks should be constructed successfully");

        let FinalizedCheckpoint {
            block: anchor_block,
            state: anchor_state,
        } = anchor_checkpoint_provider.checkpoint().value;

        Self {
            chain_config,
            anchor_checkpoint_provider,
            anchor_block,
            anchor_state,
            deposit_tree: Some(deposit_tree),
            extra_blocks,
            validator_keys,
        }
    }

    fn min_genesis_state(chain_config: &ChainConfig) -> (Arc<BeaconState<Minimal>>, DepositTree) {
        factory::min_genesis_state(chain_config)
            .expect("configurations used in this impl block should be valid")
    }
}

// Responses can be updated by setting the `UPDATE_RESPONSES` environment variable to `true`:
// ```shell
// UPDATE_RESPONSES=true cargo test
// ```
// Setting it to any other value has the same effect as leaving it unset.
#[must_use]
pub fn should_update_responses() -> bool {
    static UPDATE_RESPONSES: OnceCell<bool> = OnceCell::new();

    *UPDATE_RESPONSES.get_or_init(|| {
        std::env::var("UPDATE_RESPONSES")
            .ok()
            .and_then(|string| string.parse().ok())
            .unwrap_or_default()
    })
}

// This is roughly what `#[tokio::test(flavor = "multi_thread", worker_threads = 1)]` expands to.
// See <https://github.com/tokio-rs/tokio/blob/7096a8007502526b23ee1707a6cb37c68c4f0a84/tokio-macros/src/entry.rs#L361-L398>.
// The multi-threaded runtime is needed because `Validator` uses `tokio::task::block_in_place`.
// `tokio::task::block_in_place` panics when called from a `current_thread` runtime.
fn block_on(future: impl Future<Output = Result<()>>) -> Result<()> {
    Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?
        .block_on(future)
}
