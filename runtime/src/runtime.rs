use core::{convert::Infallible as Never, future::Future};
use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use attestation_verifier::AttestationVerifier;
use block_producer::BlockProducer;
use builder_api::{BuilderApi, BuilderConfig};
use bytesize::ByteSize;
use clock::Tick;
use dashmap::DashMap;
use data_dumper::DataDumper;
use database::{Database, DatabaseMode, RestartMessage};
use dedicated_executor::DedicatedExecutor;
use doppelganger_protection::DoppelgangerProtection;
use eth1::Eth1Config;
use eth1_api::{
    Eth1Api, Eth1ApiToMetrics, Eth1ConnectionData, Eth1ExecutionEngine, Eth1Metrics,
    ExecutionBlobFetcher, ExecutionService, RealController,
};
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
use grandine_version::APPLICATION_NAME_WITH_VERSION_AND_COMMIT;
use helper_functions::misc;
use http_api::{Channels as HttpApiChannels, HttpApi, HttpApiConfig};
use keymanager::KeyManager;
use liveness_tracker::LivenessTracker;
use log::{info, warn};
use metrics::{run_metrics_server, MetricsChannels, MetricsService};
use operation_pools::{
    AttestationAggPool, BlsToExecutionChangePool, Manager, SyncCommitteeAggPool,
};
use p2p::{
    BlockSyncService, BlockSyncServiceChannels, Channels, Network, NetworkConfig, SubnetService,
};
use pubkey_cache::PubkeyCache;
use signer::Signer;
use slasher::{Databases, Slasher, SlasherConfig};
use slashing_protection::SlashingProtector;
use std_ext::ArcExt as _;
use tokio::select;
use types::{
    config::Config as ChainConfig,
    phase0::{consts::GENESIS_SLOT, primitives::H256},
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};
use validator::{
    run_validator_api, Validator, ValidatorApiConfig, ValidatorChannels, ValidatorConfig,
};
use validator_statistics::ValidatorStatistics;

use crate::misc::{MetricsConfig, StorageConfig};

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

#[expect(clippy::cognitive_complexity)]
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
        info!("loaded {} validator key(s)", signer_snapshot.keys().len());
    } else if validator_enabled {
        warn!("failed to load validator keys");
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
        sidecars_construction_started,
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
        warn!("failed to send the message to stop the clock");
    }

    controller.stop();

    info!("saving current chain before exit…");

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
