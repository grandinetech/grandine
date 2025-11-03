use core::{
    convert::Infallible as Never, future::Future, net::SocketAddr, panic::AssertUnwindSafe,
    pin::pin,
};
use std::{
    collections::HashSet,
    net::{TcpListener, UdpSocket},
    path::PathBuf,
    sync::Arc,
};

use allocator as _;
use anyhow::{bail, ensure, Result};
use attestation_verifier::AttestationVerifier;
use binary_utils::TracingHandle;
use block_producer::BlockProducer;
use builder_api::{BuilderApi, BuilderConfig};
use bytesize::ByteSize;
use clock::Tick;
use dashmap::DashMap;
use data_dumper::DataDumper;
use database::{Database, DatabaseMode, RestartMessage};
use dedicated_executor::DedicatedExecutor;
use doppelganger_protection::DoppelgangerProtection;
use eth1::{Eth1Chain, Eth1Config};
use eth1_api::{
    Auth, Eth1Api, Eth1ApiToMetrics, Eth1ConnectionData, Eth1ExecutionEngine, Eth1Metrics,
    ExecutionBlobFetcher, ExecutionService, RealController,
};
use features::Feature;
use fork_choice_control::{Controller, EventChannels, StateLoadStrategy, Storage};
use fork_choice_store::StoreConfig;
use futures::{
    channel::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
    future::Either,
    lock::Mutex,
    stream::StreamExt as _,
};
use genesis::AnchorCheckpointProvider;
use grandine_version::{
    APPLICATION_NAME_WITH_VERSION_AND_COMMIT, APPLICATION_VERSION_WITH_COMMIT_AND_PLATFORM,
};
use helper_functions::misc;
use http_api::{Channels as HttpApiChannels, HttpApi, HttpApiConfig};
use keymanager::KeyManager;
use liveness_tracker::LivenessTracker;
use logging::{error_with_peers, info_with_peers, warn_with_peers, PEER_LOG_METRICS};
use metrics::{run_metrics_server, MetricsChannels, MetricsServerConfig, MetricsService};
use operation_pools::{
    AttestationAggPool, BlobReconstructionPool, BlsToExecutionChangePool, Manager,
    SyncCommitteeAggPool,
};
use p2p::{
    BlockSyncService, BlockSyncServiceChannels, Channels, ListenAddr, Network, NetworkConfig,
    SubnetService,
};
use pubkey_cache::PubkeyCache;
use reqwest::{Client, ClientBuilder};
use signer::{KeyOrigin, Signer};
use slasher::{Databases, Slasher, SlasherConfig};
use slashing_protection::{interchange_format::InterchangeData, SlashingProtector};
use ssz::SszRead as _;
use std_ext::ArcExt as _;
use thiserror::Error;
use tokio::{runtime::Builder, select};
use types::{
    config::Config as ChainConfig,
    phase0::{
        consts::GENESIS_SLOT,
        primitives::{ExecutionBlockNumber, Slot, H256},
    },
    preset::{Preset, PresetName},
    redacting_url::RedactingUrl,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};
use validator::{
    run_validator_api, Validator, ValidatorApiConfig, ValidatorChannels, ValidatorConfig,
};
use validator_key_cache::ValidatorKeyCache;
use validator_statistics::ValidatorStatistics;

use crate::{
    commands::{GrandineCommand, InterchangeCommand},
    db_info, db_stats,
    grandine_args::GrandineArgs,
    grandine_config::GrandineConfig,
    initialize_schema,
    misc::{MetricsConfig, StorageConfig},
    predefined_network::PredefinedNetwork,
};

#[cfg(any(feature = "preset-mainnet", test))]
use types::preset::Mainnet;
#[cfg(any(feature = "preset-minimal", test))]
use types::preset::Minimal;

#[cfg(unix)]
use tokio::signal::unix::SignalKind;

#[expect(clippy::struct_excessive_bools)]
pub struct RuntimeConfig {
    pub back_sync_enabled: bool,
    pub detect_doppelgangers: bool,
    pub max_events: usize,
    pub slashing_protection_history_limit: u64,
    pub track_liveness: bool,
    pub validator_enabled: bool,
}

#[expect(clippy::too_many_arguments)]
#[expect(clippy::too_many_lines)]
pub async fn run_after_genesis<P: Preset>(
    chain_config: Arc<ChainConfig>,
    pubkey_cache: Arc<PubkeyCache>,
    runtime_config: RuntimeConfig,
    store_config: StoreConfig,
    validator_api_config: Option<ValidatorApiConfig>,
    validator_config: Arc<ValidatorConfig>,
    network_config: NetworkConfig,
    anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    state_load_strategy: StateLoadStrategy<P>,
    eth1_config: Arc<Eth1Config>,
    storage_config: StorageConfig,
    builder_config: Option<BuilderConfig>,
    signer: Arc<Signer>,
    slasher_config: Option<SlasherConfig>,
    http_api_config: HttpApiConfig,
    metrics_config: MetricsConfig,
    blacklisted_blocks: HashSet<H256>,
    report_validator_performance: bool,
    tracing_handle: Option<TracingHandle>,
    eth1_api_to_metrics_tx: Option<UnboundedSender<Eth1ApiToMetrics>>,
    eth1_api_to_metrics_rx: Option<UnboundedReceiver<Eth1ApiToMetrics>>,
    restart_tx: UnboundedSender<RestartMessage>,
    restart_rx: UnboundedReceiver<RestartMessage>,
) -> Result<()> {
    let RuntimeConfig {
        back_sync_enabled,
        detect_doppelgangers,
        max_events,
        slashing_protection_history_limit,
        track_liveness,
        validator_enabled,
    } = runtime_config;

    let MetricsConfig {
        metrics,
        metrics_server_config,
        metrics_service_config,
    } = metrics_config;

    let StorageConfig {
        in_memory,
        ref directories,
        archival_epoch_interval,
        storage_mode,
        ..
    } = storage_config;

    let signer_snapshot = signer.load();

    if !signer_snapshot.is_empty() {
        info_with_peers!("loaded {} validator key(s)", signer_snapshot.keys().len());
    } else if validator_enabled {
        warn_with_peers!("failed to load validator keys");
    }

    let (blob_fetcher_to_p2p_tx, blob_fetcher_to_p2p_rx) = mpsc::unbounded();
    let (execution_service_to_blob_fetcher_tx, execution_service_to_blob_fetcher_rx) =
        mpsc::unbounded();
    let (execution_service_tx, execution_service_rx) = mpsc::unbounded();
    let (fork_choice_to_attestation_verifier_tx, fork_choice_to_attestation_verifier_rx) =
        mpsc::unbounded();
    let (fork_choice_to_p2p_tx, fork_choice_to_p2p_rx) = mpsc::unbounded();
    let (fork_choice_to_subnet_tx, fork_choice_to_subnet_rx) = mpsc::unbounded();
    let (fork_choice_to_validator_tx, fork_choice_to_validator_rx) = mpsc::unbounded();
    let (p2p_to_sync_tx, p2p_to_sync_rx) = mpsc::unbounded();
    let (fork_choice_to_pool_tx, fork_choice_to_pool_rx) = mpsc::unbounded();
    let (p2p_to_validator_tx, p2p_to_validator_rx) = mpsc::unbounded();
    let (sync_to_p2p_tx, sync_to_p2p_rx) = mpsc::unbounded();
    let (validator_to_p2p_tx, validator_to_p2p_rx) = mpsc::unbounded();
    let (api_to_p2p_tx, api_to_p2p_rx) = mpsc::unbounded();
    let (sync_to_api_tx, sync_to_api_rx) = mpsc::unbounded();
    let (api_to_validator_tx, api_to_validator_rx) = mpsc::unbounded();
    let (pool_to_p2p_tx, pool_to_p2p_rx) = mpsc::unbounded();
    let (subnet_service_to_p2p_tx, subnet_service_to_p2p_rx) = mpsc::unbounded();
    let (subnet_service_tx, subnet_service_rx) = mpsc::unbounded();

    let (fork_choice_to_sync_tx, fork_choice_to_sync_rx) =
        back_sync_enabled.then(mpsc::unbounded).unzip();

    let mut api_to_liveness_tx = None;
    let mut network_to_slasher_tx = None;
    let mut pool_to_liveness_tx = None;
    let mut slasher_to_validator_rx = None;
    let mut sync_to_metrics_tx = None;
    let mut validator_to_slasher_tx = None;
    let mut validator_to_liveness_tx = None;

    let num_of_cpus = num_cpus::get();

    let dedicated_executor_low_priority = Arc::new(DedicatedExecutor::new(
        "de-low",
        (num_of_cpus / 4).max(1),
        Some(19),
        metrics.clone(),
    ));

    let dedicated_executor_normal_priority = Arc::new(DedicatedExecutor::new(
        "de-normal",
        num_of_cpus,
        None,
        metrics.clone(),
    ));

    let dedicated_executor_for_reconstruction =
        DedicatedExecutor::new("de-reconstruct", 1, None, metrics.clone());

    let eth1_api = Arc::new(Eth1Api::new(
        chain_config.clone_arc(),
        signer_snapshot.client().clone(),
        eth1_config.eth1_auth.clone_arc(),
        eth1_config.eth1_rpc_urls.clone(),
        eth1_api_to_metrics_tx,
        metrics.clone(),
    ));

    eth1_api::spawn_exchange_capabilities_and_versions_task(
        eth1_api.clone_arc(),
        &dedicated_executor_low_priority,
    );

    let execution_engine = Arc::new(Eth1ExecutionEngine::new(
        chain_config.clone_arc(),
        eth1_api.clone_arc(),
        execution_service_tx,
    ));

    let storage_database = if in_memory {
        Database::in_memory()
    } else {
        storage_config.beacon_fork_choice_database(
            None,
            DatabaseMode::ReadWrite,
            Some(restart_tx),
        )?
    };

    let storage = Arc::new(Storage::new(
        chain_config.clone_arc(),
        pubkey_cache.clone_arc(),
        storage_database,
        archival_epoch_interval,
        storage_mode,
    ));

    let ((anchor_state, anchor_block, unfinalized_blocks), loaded_from_remote) = storage
        .load(signer_snapshot.client(), state_load_strategy)
        .await?;

    let is_anchor_genesis = anchor_block.message().slot() == GENESIS_SLOT;

    let mut slashing_protector = if in_memory {
        SlashingProtector::in_memory(slashing_protection_history_limit)?
    } else {
        let genesis_validators_root = anchor_state.genesis_validators_root();

        SlashingProtector::persistent(
            directories
                .store_directory
                .clone()
                .unwrap_or_default()
                .as_path(),
            directories
                .validator_dir
                .clone()
                .unwrap_or_default()
                .as_path(),
            slashing_protection_history_limit,
            genesis_validators_root,
        )?
    };

    slashing_protector.register_validators(signer_snapshot.keys().copied())?;

    let slashing_protector = Arc::new(Mutex::new(slashing_protector));

    let current_tick = Tick::current(&chain_config, anchor_state.genesis_time())?;

    let event_channels = Arc::new(EventChannels::new(max_events));

    let sidecars_construction_started = Arc::new(DashMap::new());

    let (controller, mutator_handle) = Controller::new(
        chain_config.clone_arc(),
        pubkey_cache.clone_arc(),
        store_config,
        anchor_block,
        anchor_state.clone_arc(),
        current_tick,
        event_channels.clone_arc(),
        execution_engine.clone_arc(),
        metrics.clone(),
        fork_choice_to_attestation_verifier_tx,
        fork_choice_to_p2p_tx,
        fork_choice_to_pool_tx,
        fork_choice_to_subnet_tx,
        fork_choice_to_sync_tx,
        fork_choice_to_validator_tx,
        storage.clone_arc(),
        unfinalized_blocks,
        !back_sync_enabled || is_anchor_genesis,
        blacklisted_blocks,
        sidecars_construction_started.clone_arc(),
    )?;

    let received_blob_sidecars = Arc::new(DashMap::new());
    let received_data_column_sidecars = Arc::new(DashMap::new());

    let execution_service = ExecutionService::new(
        eth1_api.clone_arc(),
        controller.clone_arc(),
        dedicated_executor_low_priority.clone_arc(),
        execution_service_rx,
        execution_service_to_blob_fetcher_tx,
    );

    let execution_blob_fetcher = ExecutionBlobFetcher::new(
        eth1_api.clone_arc(),
        controller.clone_arc(),
        received_blob_sidecars.clone_arc(),
        received_data_column_sidecars.clone_arc(),
        metrics.clone(),
        blob_fetcher_to_p2p_tx,
        execution_service_to_blob_fetcher_rx,
    );

    let validator_keys = Arc::new(signer_snapshot.keys().copied().collect::<HashSet<_>>());

    let attestation_verifier = AttestationVerifier::new(
        controller.clone_arc(),
        dedicated_executor_low_priority,
        metrics.clone(),
        fork_choice_to_attestation_verifier_rx,
    );

    let metrics_service = metrics_service_config.map(|metrics_config| {
        let (sync_tx, sync_to_metrics_rx) = mpsc::unbounded();

        sync_to_metrics_tx = Some(sync_tx);

        let eth1_connection_data = Eth1ConnectionData {
            sync_eth1_connected: !eth1_config.eth1_rpc_urls.is_empty(),
            sync_eth1_fallback_connected: false,
        };

        let eth1_metrics = Eth1Metrics {
            eth1_connection_data,
            sync_eth1_fallback_configured: eth1_config.eth1_rpc_urls.len() > 1,
        };

        let channels = MetricsChannels {
            eth1_api_to_metrics_rx,
            sync_to_metrics_rx,
        };

        MetricsService::new(
            metrics_config,
            controller.clone_arc(),
            eth1_metrics,
            metrics
                .clone()
                .expect("metrics registry must be present for metrics service"),
            slasher_config.is_some(),
            validator_keys.clone_arc(),
            channels,
        )
    });

    let (liveness_tracker, doppelganger_protection) = if track_liveness {
        let (api_tx, api_to_liveness_rx) = mpsc::unbounded();
        let (pool_tx, pool_to_liveness_rx) = mpsc::unbounded();
        let (validator_tx, validator_to_liveness_rx) = mpsc::unbounded();

        api_to_liveness_tx = Some(api_tx.clone());
        pool_to_liveness_tx = Some(pool_tx);
        validator_to_liveness_tx = Some(validator_tx);

        let liveness_tracker = Some(LivenessTracker::new(
            controller.clone_arc(),
            metrics.clone(),
            api_to_liveness_rx,
            pool_to_liveness_rx,
            validator_to_liveness_rx,
        ));

        let doppelganger_protection =
            detect_doppelgangers.then(|| Arc::new(DoppelgangerProtection::new(api_tx)));

        (liveness_tracker, doppelganger_protection)
    } else {
        (None, None)
    };

    if let Some(doppelganger_protection) = doppelganger_protection.as_ref() {
        signer.enable_doppelganger_protection(doppelganger_protection);

        signer.update_doppelganger_protection_pubkeys(
            &controller.head_state().value,
            controller.slot(),
        );
    }

    let data_dumper = Arc::new(DataDumper::new(&controller.chain_config().config_name)?);

    let validator_statistics =
        report_validator_performance.then(|| Arc::new(ValidatorStatistics::new(metrics.clone())));

    let builder_api = builder_config.map(|builder_config| {
        Arc::new(BuilderApi::new(
            builder_config,
            pubkey_cache,
            signer_snapshot.client().clone(),
            metrics.clone(),
        ))
    });

    let slasher = slasher_config
        .map(|slasher_config| -> Result<_> {
            let fork_version = chain_config.genesis_fork_version;

            let databases = if in_memory {
                Databases {
                    votes_db: Database::in_memory(),
                    attestations_db: Database::in_memory(),
                    min_targets_db: Database::in_memory(),
                    max_targets_db: Database::in_memory(),
                    blocks_db: Database::in_memory(),
                }
            } else {
                let db_size = ByteSize::gib(128);

                Databases {
                    votes_db: Database::persistent(
                        "SLASHER_ATTESTATION_VOTES",
                        directories
                            .store_directory
                            .clone()
                            .unwrap_or_default()
                            .join(format!("slasher_attestation_votes_{fork_version:?}_db")),
                        db_size,
                        DatabaseMode::ReadWrite,
                        None,
                    )?,
                    attestations_db: Database::persistent(
                        "SLASHER_INDEXED_ATTESTATIONS",
                        directories
                            .store_directory
                            .clone()
                            .unwrap_or_default()
                            .join(format!("slasher_indexed_attestations_{fork_version:?}_db")),
                        db_size,
                        DatabaseMode::ReadWrite,
                        None,
                    )?,
                    min_targets_db: Database::persistent(
                        "SLASHER_MIN_TARGETS",
                        directories
                            .store_directory
                            .clone()
                            .unwrap_or_default()
                            .join(format!("slasher_min_targets_{fork_version:?}_db")),
                        db_size,
                        DatabaseMode::ReadWrite,
                        None,
                    )?,
                    max_targets_db: Database::persistent(
                        "SLASHER_MAX_TARGETS",
                        directories
                            .store_directory
                            .clone()
                            .unwrap_or_default()
                            .join(format!("slasher_max_targets_{fork_version:?}_db")),
                        db_size,
                        DatabaseMode::ReadWrite,
                        None,
                    )?,
                    blocks_db: Database::persistent(
                        "SLASHER_BLOCKS",
                        directories
                            .store_directory
                            .clone()
                            .unwrap_or_default()
                            .join(format!("slasher_blocks_{fork_version:?}_db")),
                        db_size,
                        DatabaseMode::ReadWrite,
                        None,
                    )?,
                }
            };

            let (network_tx, network_to_slasher_rx) = mpsc::unbounded();
            let (slasher_to_validator_tx, validator_rx) = mpsc::unbounded();
            let (validator_tx, validator_to_slasher_rx) = mpsc::unbounded();

            network_to_slasher_tx = Some(network_tx);
            slasher_to_validator_rx = Some(validator_rx);
            validator_to_slasher_tx = Some(validator_tx);

            Ok(Slasher::new(
                slasher_config,
                controller.clone_arc(),
                fork_version,
                databases,
                slasher_to_validator_tx,
                network_to_slasher_rx,
                validator_to_slasher_rx,
            ))
        })
        .transpose()?;

    let graffiti = validator_config
        .graffiti
        .first()
        .copied()
        .unwrap_or_else(|| {
            if validator_config.disable_blockprint_graffiti {
                H256::default()
            } else {
                misc::parse_graffiti(APPLICATION_NAME_WITH_VERSION_AND_COMMIT).unwrap_or_default()
            }
        });

    let keymanager = if in_memory {
        Arc::new(KeyManager::new_in_memory(
            signer.clone_arc(),
            slashing_protector.clone_arc(),
            anchor_state.genesis_validators_root(),
            validator_config.suggested_fee_recipient,
            validator_config.default_gas_limit,
            graffiti,
        ))
    } else {
        Arc::new(KeyManager::new_persistent(
            signer.clone_arc(),
            slashing_protector.clone_arc(),
            anchor_state.genesis_validators_root(),
            directories.validator_dir.clone().unwrap_or_default(),
            validator_config.keystore_storage_password_file.as_deref(),
            validator_config.suggested_fee_recipient,
            validator_config.default_gas_limit,
            graffiti,
        )?)
    };

    let attestation_agg_pool = AttestationAggPool::new(
        controller.clone_arc(),
        dedicated_executor_normal_priority.clone_arc(),
        metrics.clone(),
        validator_statistics.clone(),
    );

    let blob_reconstruction_pool = BlobReconstructionPool::new(
        controller.clone_arc(),
        dedicated_executor_for_reconstruction,
        metrics.clone(),
    );

    let sync_committee_agg_pool = SyncCommitteeAggPool::new(
        dedicated_executor_normal_priority.clone_arc(),
        controller.clone_arc(),
        pool_to_liveness_tx,
        pool_to_p2p_tx.clone(),
        metrics.clone(),
        validator_statistics.clone(),
    );

    let (bls_to_execution_change_pool, bls_to_execution_change_pool_service) =
        BlsToExecutionChangePool::new(
            controller.clone_arc(),
            event_channels.clone_arc(),
            pool_to_p2p_tx,
            metrics.clone(),
        );

    let pool_manager = Manager::new(
        attestation_agg_pool.clone_arc(),
        blob_reconstruction_pool,
        bls_to_execution_change_pool.clone_arc(),
        sync_committee_agg_pool.clone_arc(),
        fork_choice_to_pool_rx,
    );

    let block_producer = Arc::new(BlockProducer::new(
        keymanager.proposer_configs().clone_arc(),
        builder_api.clone(),
        controller.clone_arc(),
        dedicated_executor_normal_priority.clone_arc(),
        execution_engine,
        attestation_agg_pool.clone_arc(),
        bls_to_execution_change_pool.clone_arc(),
        sync_committee_agg_pool.clone_arc(),
        metrics.clone(),
        None,
    ));

    let validator_channels = ValidatorChannels {
        api_to_validator_rx,
        fork_choice_rx: fork_choice_to_validator_rx,
        p2p_tx: validator_to_p2p_tx,
        p2p_to_validator_rx,
        slasher_to_validator_rx,
        subnet_service_tx: subnet_service_tx.clone(),
        validator_to_liveness_tx,
        validator_to_slasher_tx,
    };

    let validator = Validator::new(
        validator_config.clone_arc(),
        block_producer.clone_arc(),
        controller.clone_arc(),
        attestation_agg_pool.clone_arc(),
        builder_api,
        doppelganger_protection,
        event_channels.clone_arc(),
        keymanager.proposer_configs().clone_arc(),
        signer.clone_arc(),
        slashing_protector,
        sync_committee_agg_pool.clone_arc(),
        metrics.clone(),
        validator_statistics.clone(),
        validator_channels,
        network_config.network_dir.as_deref(),
        network_config.subscribe_all_data_column_subnets,
    );

    let p2p_channels = Channels {
        api_to_p2p_rx,
        blob_fetcher_to_p2p_rx,
        fork_choice_to_p2p_rx,
        pool_to_p2p_rx,
        p2p_to_sync_tx,
        p2p_to_validator_tx,
        sync_to_p2p_rx,
        validator_to_p2p_rx,
        network_to_slasher_tx,
        subnet_service_to_p2p_rx,
    };

    // Prometheus registry for deep gossipsub protocol metrics.
    // This has to be passed to both `libp2p` to collect metrics
    // and the metrics server to convert collected metrics to an HTTP response for Prometheus.
    let gossip_registry = prometheus_client::registry::Registry::default();
    let mut registry = network_config.metrics_enabled.then_some(gossip_registry);
    let network_config = Arc::new(network_config);

    let network = Network::new(
        network_config.clone_arc(),
        controller.clone_arc(),
        current_tick.slot,
        p2p_channels,
        dedicated_executor_normal_priority,
        sync_committee_agg_pool.clone_arc(),
        bls_to_execution_change_pool.clone_arc(),
        metrics.clone(),
        registry.as_mut(),
        data_dumper.clone_arc(),
        validator_config.backfill_custody_groups,
    )
    .await?;

    let block_sync_service_channels = BlockSyncServiceChannels {
        fork_choice_to_sync_rx,
        p2p_to_sync_rx,
        sync_to_p2p_tx,
        sync_to_api_tx,
        sync_to_metrics_tx,
    };

    let block_sync_database = if in_memory {
        Database::in_memory()
    } else {
        storage_config.sync_database(None, DatabaseMode::ReadWrite)?
    };

    let mut block_sync_service = BlockSyncService::new(
        chain_config.clone_arc(),
        block_sync_database,
        anchor_checkpoint_provider.clone(),
        controller.clone_arc(),
        metrics.clone(),
        validator_statistics,
        block_sync_service_channels,
        back_sync_enabled,
        loaded_from_remote,
        storage_config.storage_mode,
        network_config.target_peers,
        received_blob_sidecars,
        received_data_column_sidecars,
        data_dumper,
        network.network_globals().clone_arc(),
    )?;

    block_sync_service.try_to_spawn_back_sync_states_archiver()?;

    let subnet_service = SubnetService::new(
        attestation_agg_pool.clone_arc(),
        network.node_id(),
        subnet_service_to_p2p_tx,
        fork_choice_to_subnet_rx,
        subnet_service_rx,
    );

    let http_api_channels = HttpApiChannels {
        api_to_liveness_tx,
        api_to_p2p_tx,
        api_to_validator_tx,
        subnet_service_tx,
        sync_to_api_rx,
    };

    let http_api = HttpApi {
        block_producer,
        controller: controller.clone_arc(),
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
        channels: http_api_channels,
        metrics: metrics.clone(),
        tracing_handle,
    };

    let join_mutator = async { tokio::task::spawn_blocking(|| mutator_handle.join()).await? };

    let (stop_clock_tx, stop_clock_rx) = oneshot::channel();
    let run_clock = run_clock(controller.clone_arc(), stop_clock_rx);

    let run_slasher = match slasher {
        Some(slasher) => Either::Left(slasher.run()),
        None => Either::Right(core::future::pending()),
    };

    let run_metrics_server = match metrics_server_config {
        Some(config) => Either::Left(run_metrics_server(
            config,
            registry.take(),
            metrics
                .clone()
                .expect("metrics registry must be present for metrics server"),
        )),
        None => Either::Right(core::future::pending()),
    };

    let run_metrics_service = match metrics_service {
        Some(service) => Either::Left(service.run()),
        None => Either::Right(core::future::pending()),
    };

    let run_liveness_tracker = match liveness_tracker {
        Some(service) => Either::Left(service.run()),
        None => Either::Right(core::future::pending()),
    };

    let run_validator_api = match validator_api_config {
        Some(validator_api_config) => Either::Left(run_validator_api(
            validator_api_config,
            controller.clone_arc(),
            directories.clone_arc(),
            keymanager,
            signer,
            metrics,
        )),
        None => Either::Right(core::future::pending()),
    };

    select! {
        result = join_mutator => result,
        result = spawn_fallible(execution_service.run()) => result,
        result = spawn_fallible(execution_blob_fetcher.run()) => result,
        result = spawn_fallible(validator.run()) => result,
        result = spawn_fallible(attestation_verifier.run()) => result,
        result = spawn_fallible(block_sync_service.run()) => result,
        result = spawn_fallible(network.run()) => result,
        result = spawn_fallible(http_api.run()) => result,
        result = spawn_fallible(run_clock) => result,
        result = spawn_fallible(run_slasher) => result.map(from_never),
        result = spawn_fallible(bls_to_execution_change_pool_service.run()) => result,
        result = spawn_fallible(pool_manager.run()) => result,
        result = spawn_fallible(run_metrics_server) => result,
        result = spawn_fallible(run_metrics_service) => result,
        result = spawn_fallible(run_liveness_tracker) => result,
        result = spawn_fallible(run_validator_api) => result,
        result = spawn_fallible(subnet_service.run()) => result,
        result = wait_for_signal_or_restart(restart_rx) => result,
    }?;

    if stop_clock_tx.send(()).is_err() {
        warn_with_peers!("failed to send the message to stop the clock");
    }

    controller.stop();

    info_with_peers!("saving current chain before exit…");

    Ok(())
}

async fn run_clock<P: Preset>(
    controller: RealController<P>,
    mut stop_clock_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let mut ticks = clock::ticks(controller.chain_config(), controller.genesis_time())?.fuse();

    loop {
        select! {
            tick = ticks.select_next_some() => {
                controller.on_tick(tick?);
            }
            _ = &mut stop_clock_rx => {
                break;
            }
        }
    }

    Ok(())
}

async fn wait_for_signal_or_restart(error_rx: UnboundedReceiver<RestartMessage>) -> Result<()> {
    select! {
        result = wait_for_restart(error_rx) => result,
        result = wait_for_signal() => result,
    }
}

async fn wait_for_restart(mut rx: UnboundedReceiver<RestartMessage>) -> Result<()> {
    if let Some(message) = rx.next().await {
        match message {
            RestartMessage::StorageMapFull(error) => return Err(error.into()),
        }
    }

    Ok(())
}

async fn wait_for_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut interrupt = tokio::signal::unix::signal(SignalKind::interrupt())?;
        let mut terminate = tokio::signal::unix::signal(SignalKind::terminate())?;

        select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;

    Ok(())
}

// This exists mainly to flatten the nested `Result` returned by `tokio::spawn`.
async fn spawn_fallible<T: Send + 'static>(
    task: impl Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    tokio::spawn(task).await?
}

const fn from_never<T>(never: Never) -> T {
    match never {}
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "False positive. The `bool`s are independent."
)]
#[derive(Clone)]
struct Context {
    predefined_network: Option<PredefinedNetwork>,
    chain_config: Arc<ChainConfig>,
    store_config: StoreConfig,
    deposit_contract_starting_block: Option<ExecutionBlockNumber>,
    genesis_state_file: Option<PathBuf>,
    genesis_state_download_url: Option<RedactingUrl>,
    validator_api_config: Option<ValidatorApiConfig>,
    validator_config: Arc<ValidatorConfig>,
    checkpoint_sync_url: Option<RedactingUrl>,
    force_checkpoint_sync: bool,
    back_sync_enabled: bool,
    eth1_rpc_urls: Vec<RedactingUrl>,
    network_config: NetworkConfig,
    storage_config: StorageConfig,
    command: Option<GrandineCommand>,
    builder_config: Option<BuilderConfig>,
    signer: Arc<Signer>,
    slasher_config: Option<SlasherConfig>,
    state_slot: Option<Slot>,
    eth1_auth: Arc<Auth>,
    http_api_config: HttpApiConfig,
    max_events: usize,
    metrics_config: MetricsConfig,
    track_liveness: bool,
    tracing_handle: Option<TracingHandle>,
    detect_doppelgangers: bool,
    slashing_protection_history_limit: u64,
    validator_enabled: bool,
    blacklisted_blocks: HashSet<H256>,
    report_validator_performance: bool,
}

impl Context {
    fn run_with_restart<P: Preset>(self) -> Result<()> {
        let mut db_size_modifier = 1;

        loop {
            // `Context` surprisingly does not implement `UnwindSafe`.
            // Remove the `AssertUnwindSafe` to see the offending types.
            // It is probably unwind safe in practice.
            // All the offending types are trait objects without `UnwindSafe` bounds.
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let mut context = self.clone();

                context.storage_config = context
                    .storage_config
                    .with_increased_db_sizes(db_size_modifier);

                if db_size_modifier > 1 {
                    context.storage_config.print_db_sizes();
                }

                let run = context.run::<P>();
                block_on(run)
            }))
            .map_err(panics::payload_into_error);

            if Feature::InhibitApplicationRestart.is_enabled() {
                break result?;
            }

            match result {
                Ok(Ok(())) => break Ok(()),
                Ok(Err(error)) => {
                    error_with_peers!("application runtime failed: {error:?}");

                    if error.downcast_ref::<libmdbx::Error>() == Some(&libmdbx::Error::MapFull) {
                        info_with_peers!("increasing environment map size limits");
                        db_size_modifier *= 2;
                    }

                    if matches!(
                        error.downcast_ref::<doppelganger_protection::Error>(),
                        Some(&doppelganger_protection::Error::DoppelgangersDetected { .. })
                    ) {
                        break Err(error);
                    }
                }
                Err(error) => error_with_peers!("application runtime panicked: {error:?}"),
            }
        }
    }

    #[expect(clippy::too_many_lines)]
    async fn run<P: Preset>(self) -> Result<()> {
        let Self {
            predefined_network,
            chain_config,
            store_config,
            mut deposit_contract_starting_block,
            genesis_state_file,
            genesis_state_download_url,
            validator_api_config,
            validator_config,
            checkpoint_sync_url,
            force_checkpoint_sync,
            back_sync_enabled,
            eth1_rpc_urls,
            network_config,
            storage_config,
            command,
            builder_config,
            signer,
            slasher_config,
            state_slot,
            eth1_auth,
            http_api_config,
            max_events,
            metrics_config,
            track_liveness,
            tracing_handle,
            detect_doppelgangers,
            slashing_protection_history_limit,
            validator_enabled,
            blacklisted_blocks,
            report_validator_performance,
        } = self;

        // Load keys early so we can validate `eth1_rpc_urls`.
        signer.load_keys_from_web3signer().await;

        let signer_snapshot = signer.load();

        if eth1_rpc_urls.is_empty() {
            ensure!(
                signer_snapshot.no_keys(),
                Error::MissingEth1RpcUrlsWithValidators,
            );
        }

        let default_deposit_tree = predefined_network.map(PredefinedNetwork::genesis_deposit_tree);

        if let Some(deposit_tree) = default_deposit_tree {
            deposit_contract_starting_block.get_or_insert(deposit_tree.last_added_block_number + 1);
        }

        let eth1_config = Arc::new(Eth1Config {
            eth1_auth,
            eth1_rpc_urls,
            deposit_contract_starting_block,
            default_deposit_tree,
        });

        let (eth1_api_to_metrics_tx, eth1_api_to_metrics_rx) = metrics_config
            .metrics_service_config
            .as_ref()
            .and_then(|metrics_config| metrics_config.remote_metrics_url.as_ref())
            .is_some()
            .then(mpsc::unbounded)
            .unzip();

        let (restart_tx, restart_rx) = mpsc::unbounded();

        let pubkey_cache_database = if storage_config.in_memory {
            Database::in_memory()
        } else {
            storage_config.pubkey_cache_database(
                None,
                DatabaseMode::ReadWrite,
                Some(restart_tx.clone()),
            )?
        };

        let pubkey_cache = Arc::new(PubkeyCache::load(pubkey_cache_database));

        let anchor_checkpoint_provider = genesis_checkpoint_provider::<P>(
            &chain_config,
            &eth1_config,
            &pubkey_cache,
            &storage_config,
            genesis_state_file,
            predefined_network,
            signer_snapshot.client(),
            genesis_state_download_url,
            &metrics_config,
            eth1_api_to_metrics_tx.as_ref(),
            &restart_tx,
        )
        .await?;

        if let Some(command) = command {
            return handle_command(
                chain_config,
                &pubkey_cache,
                &storage_config,
                command,
                &anchor_checkpoint_provider,
                slashing_protection_history_limit,
            );
        }

        let state_load_strategy = if force_checkpoint_sync {
            StateLoadStrategy::Remote {
                checkpoint_sync_url: checkpoint_sync_url.expect(
                    "the requires attribute for force_checkpoint_sync \
                     ensures checkpoint_sync_url is present",
                ),
            }
        } else {
            StateLoadStrategy::Auto {
                state_slot,
                checkpoint_sync_url,
                anchor_checkpoint_provider: anchor_checkpoint_provider.clone(),
            }
        };

        run_after_genesis(
            chain_config,
            pubkey_cache,
            RuntimeConfig {
                back_sync_enabled,
                detect_doppelgangers,
                max_events,
                slashing_protection_history_limit,
                track_liveness,
                validator_enabled,
            },
            store_config,
            validator_api_config,
            validator_config,
            network_config,
            anchor_checkpoint_provider,
            state_load_strategy,
            eth1_config,
            storage_config,
            builder_config,
            signer,
            slasher_config,
            http_api_config,
            metrics_config,
            blacklisted_blocks,
            report_validator_performance,
            tracing_handle,
            eth1_api_to_metrics_tx,
            eth1_api_to_metrics_rx,
            restart_tx,
            restart_rx,
        )
        .await
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("{preset_name} preset is not included in this executable")]
    PresetNotIncluded { preset_name: PresetName },
    #[error("--eth1-rpc-urls must be specified when validators are present")]
    MissingEth1RpcUrlsWithValidators,
    #[error(
        "{service} port ({port}) is unavailable; \
         make sure no other instance of the application is running \
         or specify a different port with {option} (error: {error:?})"
    )]
    PortInUse {
        port: u16,
        service: &'static str,
        option: &'static str,
        error: anyhow::Error,
    },
}

#[expect(clippy::too_many_lines)]
pub fn run(parsed_args: GrandineArgs) -> Result<()> {
    let data_dir = parsed_args.data_dir();

    let log_handle = binary_utils::initialize_tracing_logger(
        module_path!(),
        &data_dir,
        cfg!(feature = "logger-always-write-style"),
    )?;

    binary_utils::initialize_rayon()?;

    let config = parsed_args.try_into_config().map_err(GrandineArgs::clap_error)?;

    info_with_peers!("starting beacon node");

    config.report();

    let GrandineConfig {
        predefined_network,
        chain_config,
        deposit_contract_starting_block,
        genesis_state_file,
        genesis_state_download_url,
        checkpoint_sync_url,
        force_checkpoint_sync,
        back_sync_enabled,
        eth1_rpc_urls,
        data_dir,
        validators,
        keystore_storage_password_file,
        disable_blockprint_graffiti,
        graffiti,
        max_empty_slots,
        suggested_fee_recipient,
        default_builder_boost_factor,
        default_gas_limit,
        network_config,
        storage_config,
        request_timeout,
        max_epochs_to_retain_states_in_cache,
        state_cache_lock_timeout,
        unfinalized_states_in_memory,
        command,
        slashing_enabled,
        slashing_history_limit,
        state_slot,
        auth_options,
        builder_config,
        web3signer_config,
        http_api_config,
        max_events,
        metrics_config,
        track_liveness,
        detect_doppelgangers,
        use_validator_key_cache,
        slashing_protection_history_limit,
        in_memory,
        validator_api_config,
        kzg_backend,
        blacklisted_blocks,
        report_validator_performance,
        withhold_data_columns_publishing,
        backfill_custody_groups,
        disable_engine_getblobs,
        sync_without_reconstruction,
    } = config;

    PEER_LOG_METRICS.set_target_peer_count(network_config.target_peers);

    let MetricsConfig {
        metrics,
        metrics_server_config,
        ..
    } = &metrics_config;

    // Don't check ports for command runs. None of the commands need a network connection.
    // Check ports before `Context::run_with_restart` to avoid logging an error repeatedly.
    // The ports could in theory be freed or taken between restarts, but it's not likely.
    if command.is_none() {
        ensure_ports_not_in_use(
            http_api_config.address,
            &network_config,
            metrics_server_config.as_ref(),
            validator_api_config.as_ref(),
        )
        .map_err(GrandineArgs::clap_error)?;
    }

    if !in_memory {
        initialize_schema(data_dir)?;
    }

    let validator_config = Arc::new(ValidatorConfig {
        disable_blockprint_graffiti,
        graffiti,
        max_empty_slots,
        suggested_fee_recipient,
        default_builder_boost_factor,
        default_gas_limit,
        keystore_storage_password_file,
        withhold_data_columns_publishing,
        backfill_custody_groups,
    });

    let store_config = StoreConfig {
        max_empty_slots,
        max_epochs_to_retain_states_in_cache,
        state_cache_lock_timeout,
        unfinalized_states_in_memory,
        kzg_backend,
        disable_engine_getblobs,
        sync_without_reconstruction,
    };

    let eth1_auth = Arc::new(Auth::new(auth_options)?);

    // Creating multiple `reqwest::Client`s seems to leak memory.
    // See <https://github.com/seanmonstar/reqwest/issues?q=is%3Aissue+memory>.
    // Create a single one for the whole application and reuse it through `Signer::client`.
    let client = ClientBuilder::new()
        .timeout(request_timeout)
        .user_agent(APPLICATION_VERSION_WITH_COMMIT_AND_PLATFORM)
        .connection_verbose(true)
        .build()?;

    let mut cache = use_validator_key_cache.then(|| {
        ValidatorKeyCache::new(
            storage_config
                .directories
                .validator_dir
                .clone()
                .unwrap_or_default(),
        )
    });

    let keystore_storage = match &validator_config.keystore_storage_password_file {
        Some(password_path) => {
            let password = keymanager::load_key_storage_password(password_path)?;

            keymanager::load_key_storage(
                &password,
                storage_config
                    .directories
                    .validator_dir
                    .clone()
                    .unwrap_or_default(),
            )?
        }
        None => ValidatorKeyCache::default(),
    };

    let validator_enabled = validator_api_config.is_some()
        || cache.is_some()
        || !web3signer_config.is_empty()
        || validators.is_some()
        || validator_config.keystore_storage_password_file.is_some();

    if validator_enabled {
        info_with_peers!("started loading validator keys");
    }

    let mut validator_keys = validators
        .map(|validators| {
            validators
                .normalize(cache.as_mut())
                .expect("unable to load local validator keys")
        })
        .unwrap_or_default();

    validator_keys.extend(
        keystore_storage
            .keypairs()
            .map(|(public_key, secret_key)| (public_key, secret_key, KeyOrigin::KeymanagerAPI)),
    );

    let signer = Arc::new(Signer::new(
        validator_keys,
        client,
        web3signer_config,
        metrics.clone(),
    ));

    if let Some(cache) = cache {
        if let Err(error) = cache.save() {
            warn_with_peers!("Unable to save validator key cache: {error:?}");
        }
    }

    let slasher_config = slashing_enabled.then_some(SlasherConfig {
        slashing_history_limit,
    });

    let context = Context {
        predefined_network,
        chain_config,
        store_config,
        deposit_contract_starting_block,
        genesis_state_file,
        genesis_state_download_url,
        validator_api_config,
        validator_config,
        checkpoint_sync_url,
        force_checkpoint_sync,
        back_sync_enabled,
        eth1_rpc_urls,
        network_config,
        storage_config,
        command,
        builder_config,
        signer,
        slasher_config,
        state_slot,
        eth1_auth,
        http_api_config,
        max_events,
        metrics_config,
        track_liveness,
        tracing_handle: Some(log_handle),
        detect_doppelgangers,
        slashing_protection_history_limit,
        validator_enabled,
        blacklisted_blocks,
        report_validator_performance,
    };

    match context.chain_config.preset_base {
        #[cfg(any(feature = "preset-mainnet", test))]
        PresetName::Mainnet => context.run_with_restart::<Mainnet>(),
        #[cfg(any(feature = "preset-minimal", test))]
        PresetName::Minimal => context.run_with_restart::<Minimal>(),
        preset_name => bail!(Error::PresetNotIncluded { preset_name }),
    }
}

// Ports are checked before binding them for actual use.
// This is a TOCTOU race condition, but the only consequence of it is slightly worse error messages.
fn ensure_ports_not_in_use(
    http_address: SocketAddr,
    network_config: &NetworkConfig,
    metrics_server_config: Option<&MetricsServerConfig>,
    validator_api_config: Option<&ValidatorApiConfig>,
) -> Result<()> {
    TcpListener::bind(http_address).map_err(|error| Error::PortInUse {
        port: http_address.port(),
        service: "HTTP API",
        option: "--http-port",
        error: error.into(),
    })?;

    if let Some(listen_addr) = network_config.listen_addrs().v4() {
        let ListenAddr {
            addr,
            disc_port,
            quic_port,
            tcp_port,
        } = listen_addr.clone();

        TcpListener::bind((addr, tcp_port)).map_err(|error| Error::PortInUse {
            port: tcp_port,
            service: "libp2p",
            option: "--libp2p-port",
            error: error.into(),
        })?;

        if !network_config.disable_discovery {
            UdpSocket::bind((addr, disc_port)).map_err(|error| Error::PortInUse {
                port: disc_port,
                service: "discv5",
                option: "--discovery-port",
                error: error.into(),
            })?;
        }

        if !network_config.disable_quic_support {
            UdpSocket::bind((addr, quic_port)).map_err(|error| Error::PortInUse {
                port: quic_port,
                service: "quic",
                option: "--quic-port",
                error: error.into(),
            })?;
        }
    }

    if let Some(listen_addr) = network_config.listen_addrs().v6() {
        let ListenAddr {
            addr,
            disc_port,
            quic_port,
            tcp_port,
        } = listen_addr.clone();

        TcpListener::bind((addr, tcp_port)).map_err(|error| Error::PortInUse {
            port: tcp_port,
            service: "libp2p",
            option: "--libp2p-port-ipv6",
            error: error.into(),
        })?;

        if !network_config.disable_discovery {
            UdpSocket::bind((addr, disc_port)).map_err(|error| Error::PortInUse {
                port: disc_port,
                service: "discv5",
                option: "--discovery-port-ipv6",
                error: error.into(),
            })?;
        }

        if !network_config.disable_quic_support {
            UdpSocket::bind((addr, quic_port)).map_err(|error| Error::PortInUse {
                port: quic_port,
                service: "libp2p",
                option: "--quic-port-ipv6",
                error: error.into(),
            })?;
        }
    }

    // Port numbers in ENR fields are not used to open any sockets.

    if let Some(config) = metrics_server_config {
        let metrics_port = config.metrics_port;

        TcpListener::bind(SocketAddr::from(config)).map_err(|error| Error::PortInUse {
            port: metrics_port,
            service: "Metrics",
            option: "--metrics-port",
            error: error.into(),
        })?;
    }

    if let Some(config) = validator_api_config {
        TcpListener::bind(config.address).map_err(|error| Error::PortInUse {
            port: config.address.port(),
            service: "Validator",
            option: "--validator-api-port",
            error: error.into(),
        })?;
    }

    Ok(())
}

#[expect(clippy::too_many_lines)]
fn handle_command<P: Preset>(
    chain_config: Arc<ChainConfig>,
    pubkey_cache: &Arc<PubkeyCache>,
    storage_config: &StorageConfig,
    command: GrandineCommand,
    anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
    slashing_protection_history_limit: u64,
) -> Result<()> {
    Feature::InhibitApplicationRestart.enable();

    let StorageConfig {
        archival_epoch_interval,
        storage_mode,
        ..
    } = storage_config;

    match command {
        GrandineCommand::DbInfo { database, path } => {
            db_info::print(storage_config, database, path)?
        }
        GrandineCommand::DbStats { path } => db_stats::print::<P>(storage_config, path)?,
        GrandineCommand::Export {
            from,
            to,
            output_dir,
        } => {
            let storage_database =
                storage_config.beacon_fork_choice_database(None, DatabaseMode::ReadOnly, None)?;

            let storage = Storage::new(
                chain_config,
                pubkey_cache.clone_arc(),
                storage_database,
                *archival_epoch_interval,
                *storage_mode,
            );

            let output_dir = output_dir.unwrap_or(std::env::current_dir()?);

            fork_choice_control::export_state_and_blocks(
                pubkey_cache,
                &storage,
                from,
                to,
                &output_dir,
                anchor_checkpoint_provider,
            )?;

            info_with_peers!("state and blocks exported to {}", output_dir.display());
        }
        GrandineCommand::Replay {
            from,
            to,
            input_dir,
        } => {
            let input_dir = input_dir.unwrap_or(std::env::current_dir()?);
            fork_choice_control::replay_blocks::<P>(
                &chain_config,
                pubkey_cache,
                &input_dir,
                from,
                to,
            )?;
        }
        GrandineCommand::Interchange(interchange_command) => {
            let genesis_validators_root = anchor_checkpoint_provider
                .checkpoint()
                .value
                .state
                .genesis_validators_root();

            let mut slashing_protector = SlashingProtector::persistent(
                storage_config
                    .directories
                    .store_directory
                    .clone()
                    .unwrap_or_default()
                    .as_path(),
                storage_config
                    .directories
                    .validator_dir
                    .clone()
                    .unwrap_or_default()
                    .as_path(),
                slashing_protection_history_limit,
                genesis_validators_root,
            )?;

            match interchange_command {
                InterchangeCommand::Import { file_path } => {
                    let import_report = slashing_protector
                        .import_interchange_file(&file_path, genesis_validators_root)?;

                    info_with_peers!(
                        "interchange file imported (imported records: {}, failed records: {})",
                        import_report.imported_records(),
                        import_report.failed_records(),
                    );
                }
                InterchangeCommand::Export { file_path } => {
                    let interchange = slashing_protector
                        .export_to_interchange_file(&file_path, genesis_validators_root)?;

                    if interchange.is_empty() {
                        warn_with_peers!(
                            "no records were exported. \
                            This may indicate an issue if active validators are present. \
                            Please verify your configuration settings.",
                        );
                    } else {
                        for data in interchange.data {
                            let InterchangeData {
                                pubkey,
                                signed_attestations,
                                signed_blocks,
                            } = data;

                            info_with_peers!(
                                "exported {} records for {pubkey:?}",
                                signed_attestations.len() + signed_blocks.len(),
                            );
                        }
                    }

                    info_with_peers!("interchange file exported to {}", file_path.display());
                }
            }
        }
    }

    Ok(())
}

#[expect(clippy::too_many_arguments)]
async fn genesis_checkpoint_provider<P: Preset>(
    chain_config: &Arc<ChainConfig>,
    eth1_config: &Arc<Eth1Config>,
    pubkey_cache: &PubkeyCache,
    storage_config: &StorageConfig,
    genesis_state_file: Option<PathBuf>,
    predefined_network: Option<PredefinedNetwork>,
    client: &Client,
    genesis_state_download_url: Option<RedactingUrl>,
    metrics_config: &MetricsConfig,
    eth1_api_to_metrics_tx: Option<&UnboundedSender<Eth1ApiToMetrics>>,
    restart_tx: &UnboundedSender<RestartMessage>,
) -> Result<AnchorCheckpointProvider<P>> {
    if let Some(file_path) = genesis_state_file {
        let bytes = fs_err::read(file_path)?;
        let genesis_state = Arc::from_ssz(chain_config.as_ref(), bytes)?;
        return Ok(AnchorCheckpointProvider::custom_from_genesis(genesis_state));
    }

    let store_directory = storage_config
        .directories
        .store_directory
        .clone()
        .unwrap_or_default();

    if let Some(predefined_network) = predefined_network {
        return predefined_network
            .genesis_checkpoint_provider::<P>(
                client,
                store_directory.as_path(),
                genesis_state_download_url,
            )
            .await;
    }

    // Code that waits for genesis by tracking deposits starts here
    // (may be removed in the future)

    let eth1_database = if storage_config.in_memory {
        Database::in_memory()
    } else {
        storage_config.eth1_database(restart_tx.clone())?
    };

    let eth1_chain = Eth1Chain::new(
        chain_config.clone_arc(),
        eth1_config.clone_arc(),
        client.clone(),
        eth1_database,
        eth1_api_to_metrics_tx.cloned(),
        metrics_config.metrics.clone(),
    )?;

    let eth1_block_stream = pin!(eth1_chain.stream_blocks()?);

    let genesis_state = eth1::wait_for_genesis(
        chain_config,
        pubkey_cache,
        store_directory,
        eth1_block_stream,
        &eth1_chain,
    )
    .await?;

    Ok(AnchorCheckpointProvider::custom_from_genesis(Arc::new(
        genesis_state,
    )))
}

// Some parts of the application spawn and detach long-running Tokio tasks.
// They own resources like databases and network connections, making application restarts fail.
// We work around that by recreating the Tokio runtime on every restart.
// Doing so drops all tasks in the old runtime, freeing resources in detached tasks.
// See <https://docs.rs/tokio/1.28.0/tokio/runtime/struct.Runtime.html#shutdown>.
fn block_on(future: impl Future<Output = Result<()>>) -> Result<()> {
    // This is roughly what `#[tokio::main]` expands to.
    // See <https://github.com/tokio-rs/tokio/blob/7096a8007502526b23ee1707a6cb37c68c4f0a84/tokio-macros/src/entry.rs#L361-L398>.
    Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(future)
}
