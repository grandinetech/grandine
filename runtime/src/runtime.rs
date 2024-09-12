use core::{convert::Infallible as Never, future::Future};
use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use builder_api::{BuilderApi, BuilderConfig};
use bytesize::ByteSize;
use clock::Tick;
use database::Database;
use dedicated_executor::DedicatedExecutor;
use eth1::{Eth1Chain, Eth1Config};
use eth1_api::{
    Eth1Api, Eth1ApiToMetrics, Eth1ConnectionData, Eth1ExecutionEngine, Eth1Metrics,
    ExecutionService, RealController,
};
use fork_choice_control::{Controller, StateLoadStrategy, Storage};
use fork_choice_store::StoreConfig;
use futures::{
    channel::mpsc::{self, UnboundedReceiver, UnboundedSender},
    future::Either,
    lock::Mutex,
    stream::TryStreamExt as _,
};
use genesis::AnchorCheckpointProvider;
use http_api::{Channels as HttpApiChannels, HttpApi, HttpApiConfig};
use keymanager::KeyManager;
use liveness_tracker::LivenessTracker;
use log::{info, warn};
use metrics::{run_metrics_server, MetricsChannels, MetricsService};
use operation_pools::{AttestationAggPool, BlsToExecutionChangePool, SyncCommitteeAggPool};
use p2p::{
    AttestationVerifier, BlockSyncService, BlockSyncServiceChannels, Channels, Network,
    NetworkConfig, SubnetService,
};
use signer::Signer;
use slasher::{Databases, Slasher, SlasherConfig};
use slashing_protection::SlashingProtector;
use std_ext::ArcExt as _;
use tokio::select;
use types::{config::Config as ChainConfig, preset::Preset, traits::BeaconState as _};
use validator::{
    run_validator_api, Validator, ValidatorApiConfig, ValidatorChannels, ValidatorConfig,
};

use crate::misc::{MetricsConfig, StorageConfig};

#[cfg(unix)]
use tokio::signal::unix::SignalKind;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub async fn run_after_genesis<P: Preset>(
    chain_config: Arc<ChainConfig>,
    store_config: StoreConfig,
    validator_api_config: Option<ValidatorApiConfig>,
    validator_config: Arc<ValidatorConfig>,
    network_config: NetworkConfig,
    anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    state_load_strategy: StateLoadStrategy<P>,
    eth1_chain: Eth1Chain,
    eth1_config: Arc<Eth1Config>,
    storage_config: StorageConfig,
    builder_config: Option<BuilderConfig>,
    signer: Arc<Signer>,
    slasher_config: Option<SlasherConfig>,
    http_api_config: HttpApiConfig,
    back_sync_enabled: bool,
    metrics_config: MetricsConfig,
    track_liveness: bool,
    eth1_api_to_metrics_tx: Option<UnboundedSender<Eth1ApiToMetrics>>,
    eth1_api_to_metrics_rx: Option<UnboundedReceiver<Eth1ApiToMetrics>>,
    slashing_protection_history_limit: u64,
    validator_enabled: bool,
) -> Result<()> {
    let MetricsConfig {
        metrics,
        metrics_server_config,
        metrics_service_config,
    } = metrics_config;

    let StorageConfig {
        in_memory,
        db_size,
        directories,
        archival_epoch_interval,
        prune_storage,
        ..
    } = storage_config;

    let signer_snapshot = signer.load();

    if !signer_snapshot.is_empty() {
        info!("loaded {} validator key(s)", signer_snapshot.keys().len());
    } else if validator_enabled {
        warn!("failed to load validator keys");
    }

    let (execution_service_tx, execution_service_rx) = mpsc::unbounded();
    let (fork_choice_to_p2p_tx, fork_choice_to_p2p_rx) = mpsc::unbounded();
    let (fork_choice_to_subnet_tx, fork_choice_to_subnet_rx) = mpsc::unbounded();
    let (fork_choice_to_validator_tx, fork_choice_to_validator_rx) = mpsc::unbounded();
    let (p2p_to_attestation_verifier_tx, p2p_to_attestation_verifier_rx) = mpsc::unbounded();
    let (p2p_to_sync_tx, p2p_to_sync_rx) = mpsc::unbounded();
    let (p2p_to_validator_tx, p2p_to_validator_rx) = mpsc::unbounded();
    let (sync_to_p2p_tx, sync_to_p2p_rx) = mpsc::unbounded();
    let (validator_to_p2p_tx, validator_to_p2p_rx) = mpsc::unbounded();
    let (api_to_p2p_tx, api_to_p2p_rx) = mpsc::unbounded();
    let (sync_to_api_tx, sync_to_api_rx) = mpsc::unbounded();
    let (fc_to_api_tx, fc_to_api_rx) = mpsc::unbounded();
    let (api_to_validator_tx, api_to_validator_rx) = mpsc::unbounded();
    let (validator_to_api_tx, validator_to_api_rx) = mpsc::unbounded();
    let (pool_to_api_tx, pool_to_api_rx) = mpsc::unbounded();
    let (pool_to_p2p_tx, pool_to_p2p_rx) = mpsc::unbounded();
    let (subnet_service_to_p2p_tx, subnet_service_to_p2p_rx) = mpsc::unbounded();
    let (subnet_service_tx, subnet_service_rx) = mpsc::unbounded();

    let (fork_choice_to_sync_tx, fork_choice_to_sync_rx) =
        back_sync_enabled.then(mpsc::unbounded).unzip();

    let mut api_to_liveness_tx = None;
    let mut api_to_metrics_tx = None;
    let mut metrics_to_metrics_tx = None;
    let mut network_to_slasher_tx = None;
    let mut pool_to_liveness_tx = None;
    let mut slasher_to_validator_rx = None;
    let mut sync_to_metrics_tx = None;
    let mut validator_to_slasher_tx = None;
    let mut validator_to_liveness_tx = None;

    let eth1_api = Arc::new(Eth1Api::new(
        chain_config.clone_arc(),
        signer_snapshot.client().clone(),
        eth1_config.eth1_auth.clone_arc(),
        eth1_config.eth1_rpc_urls.clone(),
        eth1_api_to_metrics_tx,
        metrics.clone(),
    ));

    let execution_engine = Arc::new(Eth1ExecutionEngine::new(
        chain_config.clone_arc(),
        eth1_api.clone_arc(),
        execution_service_tx,
    ));

    let storage_database = if in_memory {
        Database::in_memory()
    } else {
        Database::persistent(
            "beacon_fork_choice",
            directories
                .store_directory
                .clone()
                .unwrap_or_default()
                .join("beacon_fork_choice"),
            db_size,
        )?
    };

    let storage = Arc::new(Storage::new(
        chain_config.clone_arc(),
        storage_database,
        archival_epoch_interval,
        prune_storage,
    ));

    let ((anchor_state, anchor_block, unfinalized_blocks), loaded_from_remote) = storage
        .load(signer_snapshot.client(), state_load_strategy)
        .await?;

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

    let (controller, mutator_handle) = Controller::new(
        chain_config.clone_arc(),
        store_config,
        anchor_block,
        anchor_state.clone_arc(),
        current_tick,
        execution_engine.clone_arc(),
        metrics.clone(),
        fc_to_api_tx,
        fork_choice_to_p2p_tx,
        fork_choice_to_subnet_tx,
        fork_choice_to_sync_tx,
        fork_choice_to_validator_tx,
        storage.clone_arc(),
        unfinalized_blocks,
    )?;

    let execution_service =
        ExecutionService::new(eth1_api, controller.clone_arc(), execution_service_rx);

    let validator_keys = Arc::new(signer_snapshot.keys().copied().collect::<HashSet<_>>());

    let num_of_cpus = num_cpus::get();

    let dedicated_executor_low_priority = DedicatedExecutor::new(
        "de-low",
        (num_of_cpus / 4).max(1),
        Some(19),
        metrics.clone(),
    );

    let dedicated_executor_normal_priority = Arc::new(DedicatedExecutor::new(
        "de-normal",
        num_of_cpus,
        None,
        metrics.clone(),
    ));

    let attestation_verifier = AttestationVerifier::new(
        controller.clone_arc(),
        dedicated_executor_low_priority,
        metrics.clone(),
        p2p_to_attestation_verifier_rx,
    );

    let metrics_service = metrics_service_config.map(|metrics_config| {
        let (api_tx, api_to_metrics_rx) = mpsc::unbounded();
        let (sync_tx, sync_to_metrics_rx) = mpsc::unbounded();
        let (metrics_tx, metrics_to_metrics_rx) = mpsc::unbounded();

        api_to_metrics_tx = Some(api_tx);
        sync_to_metrics_tx = Some(sync_tx);
        metrics_to_metrics_tx = Some(metrics_tx);

        let eth1_connection_data = Eth1ConnectionData {
            sync_eth1_connected: !eth1_config.eth1_rpc_urls.is_empty(),
            sync_eth1_fallback_connected: false,
        };

        let eth1_metrics = Eth1Metrics {
            eth1_connection_data,
            sync_eth1_fallback_configured: eth1_config.eth1_rpc_urls.len() > 1,
        };

        let channels = MetricsChannels {
            api_to_metrics_rx,
            eth1_api_to_metrics_rx,
            metrics_to_metrics_rx,
            sync_to_metrics_rx,
        };

        MetricsService::new(
            metrics_config,
            controller.clone_arc(),
            eth1_metrics,
            slasher_config.is_some(),
            validator_keys.clone_arc(),
            channels,
        )
    });

    let liveness_tracker = track_liveness.then(|| {
        let (api_tx, api_to_liveness_rx) = mpsc::unbounded();
        let (pool_tx, pool_to_liveness_rx) = mpsc::unbounded();
        let (validator_tx, validator_to_liveness_rx) = mpsc::unbounded();

        api_to_liveness_tx = Some(api_tx);
        pool_to_liveness_tx = Some(pool_tx);
        validator_to_liveness_tx = Some(validator_tx);

        LivenessTracker::new(
            controller.clone_arc(),
            metrics.clone(),
            api_to_liveness_rx,
            pool_to_liveness_rx,
            validator_to_liveness_rx,
        )
    });

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
        Database::persistent(
            "sync",
            directories
                .store_directory
                .clone()
                .unwrap_or_default()
                .join("sync"),
            db_size,
        )?
    };

    let mut block_sync_service = BlockSyncService::new(
        block_sync_database,
        anchor_checkpoint_provider.clone(),
        controller.clone_arc(),
        metrics.clone(),
        block_sync_service_channels,
        back_sync_enabled,
        loaded_from_remote,
    )?;

    block_sync_service.try_to_spawn_back_sync_states_archiver()?;

    let builder_api = builder_config.map(|builder_config| {
        Arc::new(BuilderApi::new(
            builder_config,
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
                    )?,
                    attestations_db: Database::persistent(
                        "SLASHER_INDEXED_ATTESTATIONS",
                        directories
                            .store_directory
                            .clone()
                            .unwrap_or_default()
                            .join(format!("slasher_indexed_attestations_{fork_version:?}_db")),
                        db_size,
                    )?,
                    min_targets_db: Database::persistent(
                        "SLASHER_MIN_TARGETS",
                        directories
                            .store_directory
                            .clone()
                            .unwrap_or_default()
                            .join(format!("slasher_min_targets_{fork_version:?}_db")),
                        db_size,
                    )?,
                    max_targets_db: Database::persistent(
                        "SLASHER_MAX_TARGETS",
                        directories
                            .store_directory
                            .clone()
                            .unwrap_or_default()
                            .join(format!("slasher_max_targets_{fork_version:?}_db")),
                        db_size,
                    )?,
                    blocks_db: Database::persistent(
                        "SLASHER_BLOCKS",
                        directories
                            .store_directory
                            .clone()
                            .unwrap_or_default()
                            .join(format!("slasher_blocks_{fork_version:?}_db")),
                        db_size,
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
        .unwrap_or_default();

    let keymanager = if in_memory {
        Arc::new(KeyManager::new_in_memory(
            signer.clone_arc(),
            slashing_protector.clone_arc(),
            anchor_state.genesis_validators_root(),
            validator_config.suggested_fee_recipient,
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
            graffiti,
        )?)
    };

    let attestation_agg_pool = AttestationAggPool::new(
        controller.clone_arc(),
        dedicated_executor_normal_priority.clone_arc(),
        metrics.clone(),
    );

    let sync_committee_agg_pool = SyncCommitteeAggPool::new(
        dedicated_executor_normal_priority.clone_arc(),
        controller.clone_arc(),
        pool_to_liveness_tx,
        pool_to_p2p_tx.clone(),
        metrics.clone(),
    );

    let (bls_to_execution_change_pool, bls_to_execution_change_pool_service) =
        BlsToExecutionChangePool::new(
            controller.clone_arc(),
            pool_to_api_tx,
            pool_to_p2p_tx,
            metrics.clone(),
        );

    let validator_channels = ValidatorChannels {
        api_to_validator_rx,
        fork_choice_rx: fork_choice_to_validator_rx,
        p2p_tx: validator_to_p2p_tx,
        p2p_to_validator_rx,
        slasher_to_validator_rx,
        subnet_service_tx: subnet_service_tx.clone(),
        validator_to_api_tx,
        validator_to_liveness_tx,
        validator_to_slasher_tx,
    };

    let validator = Validator::new(
        eth1_chain,
        validator_config.clone_arc(),
        controller.clone_arc(),
        execution_engine,
        attestation_agg_pool.clone_arc(),
        builder_api,
        keymanager.proposer_configs().clone_arc(),
        signer.clone_arc(),
        slashing_protector,
        sync_committee_agg_pool.clone_arc(),
        bls_to_execution_change_pool.clone_arc(),
        metrics.clone(),
        validator_channels,
    );

    let p2p_channels = Channels {
        api_to_p2p_rx,
        fork_choice_to_p2p_rx,
        pool_to_p2p_rx,
        p2p_to_attestation_verifier_tx,
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

    let network = Network::new(
        &network_config,
        controller.clone_arc(),
        current_tick.slot,
        p2p_channels,
        dedicated_executor_normal_priority,
        sync_committee_agg_pool.clone_arc(),
        bls_to_execution_change_pool.clone_arc(),
        metrics.clone(),
        registry.as_mut(),
    )
    .await?;

    if chain_config.is_eip7594_enabled() {
        let custody_columns = network.network_globals().custody_columns();
        controller.on_store_custody_columns(custody_columns);
    }

    let subnet_service = SubnetService::new(
        attestation_agg_pool.clone_arc(),
        network.node_id(),
        subnet_service_to_p2p_tx,
        fork_choice_to_subnet_rx,
        subnet_service_rx,
    );

    let http_api_channels = HttpApiChannels {
        api_to_liveness_tx,
        api_to_metrics_tx,
        api_to_p2p_tx,
        api_to_validator_tx,
        fc_to_api_rx,
        pool_to_api_rx,
        subnet_service_tx,
        sync_to_api_rx,
        validator_to_api_rx,
    };

    let http_api = HttpApi {
        controller: controller.clone_arc(),
        anchor_checkpoint_provider,
        validator_keys,
        validator_config,
        network_config: Arc::new(network_config),
        http_api_config,
        attestation_agg_pool,
        sync_committee_agg_pool,
        bls_to_execution_change_pool,
        channels: http_api_channels,
        metrics: metrics.clone(),
    };

    let join_mutator = async { tokio::task::spawn_blocking(|| mutator_handle.join()).await? };
    let run_clock = run_clock(controller.clone_arc());

    let run_slasher = match slasher {
        Some(slasher) => Either::Left(slasher.run()),
        None => Either::Right(core::future::pending()),
    };

    let run_metrics_server = match metrics_server_config {
        Some(config) => Either::Left(run_metrics_server(
            config,
            controller.clone_arc(),
            registry.take(),
            metrics
                .clone()
                .expect("Metrics registry must be present for metrics server"),
            metrics_to_metrics_tx,
            network.network_globals().clone_arc(),
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
            controller,
            directories,
            keymanager,
            signer,
            metrics,
        )),
        None => Either::Right(core::future::pending()),
    };

    select! {
        result = join_mutator => result,
        result = spawn_fallible(execution_service.run()) => result,
        result = spawn_fallible(validator.run()) => result,
        result = spawn_fallible(attestation_verifier.run()) => result,
        result = spawn_fallible(block_sync_service.run()) => result.map(from_never),
        result = spawn_fallible(network.run()) => result.map(from_never),
        result = spawn_fallible(http_api.run()) => result,
        result = spawn_fallible(run_clock) => result,
        result = spawn_fallible(run_slasher) => result.map(from_never),
        result = spawn_fallible(bls_to_execution_change_pool_service.run()) => result,
        result = spawn_fallible(run_metrics_server) => result,
        result = spawn_fallible(run_metrics_service) => result,
        result = spawn_fallible(run_liveness_tracker) => result,
        result = spawn_fallible(run_validator_api) => result,
        result = spawn_fallible(subnet_service.run()) => result,
        result = wait_for_signal() => result,
    }?;

    info!("saving current chain before exit…");

    Ok(())
}

async fn run_clock<P: Preset>(controller: RealController<P>) -> Result<()> {
    let mut ticks = clock::ticks(controller.chain_config(), controller.genesis_time())?;

    while let Some(tick) = ticks.try_next().await? {
        controller.on_tick(tick);
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
