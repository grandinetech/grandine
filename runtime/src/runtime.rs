use core::{
    convert::Infallible as Never, future::Future, net::SocketAddr, panic::AssertUnwindSafe,
    pin::pin, time::Duration,
};
#[cfg(feature = "embed")]
use std::sync::LazyLock;
use std::{
    collections::HashSet,
    io::ErrorKind,
    net::{TcpListener, UdpSocket},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use allocator as _;
use anyhow::{Context as _, Result, bail, ensure};
use attestation_verifier::AttestationVerifier;
use binary_utils::TracingHandle;
use block_producer::BlockProducer;
use builder_api::{BuilderApi, BuilderConfig};
use bytesize::ByteSize;
use clock::Tick;
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
use fork_choice_control::{
    Controller, EventChannels, MutatorHandle, StateLoadStrategy, Storage, ValidatorMessage,
};
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
use keymanager::{
    DefinitionsStorage, KeyManager, LegacyMigration, ValidatorDefinitions,
    ValidatorDefinitionsWithStorage,
};
use liveness_tracker::LivenessTracker;
use logging::{
    PEER_LOG_METRICS, debug_with_peers, error_with_peers, info_with_peers, warn_with_peers,
};
use metrics::{
    MetricsChannels, MetricsServerConfig, MetricsService, MetricsServiceConfig, run_metrics_server,
};
use operation_pools::{
    AttestationAggPool, BlobReconstructionPool, BlsToExecutionChangePool,
    BlsToExecutionChangePoolService, Manager, PayloadAttestationAggPool, SyncCommitteeAggPool,
};
use p2p::{
    BlockSyncService, BlockSyncServiceChannels, Channels, ListenAddr, Network, NetworkConfig,
    SubnetService,
};
use prometheus_client::registry::Registry;
use prometheus_metrics::Metrics;
use pubkey_cache::PubkeyCache;
use reqwest::{Client, ClientBuilder};
use scc::HashMap as SccHashMap;
use signer::{KeyOrigin, Signer, Web3SignerClientOptions, build_web3signer_client};
use slasher::{Databases, Slasher, SlasherConfig};
use slashing_protection::{SlashingProtector, interchange_format::InterchangeData};
use ssz::SszRead as _;
use std_ext::ArcExt as _;
use thiserror::Error;
use tokio::{runtime::Builder, select, time::sleep};
#[cfg(feature = "embed")]
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use types::{
    config::Config as ChainConfig,
    phase0::{
        consts::GENESIS_SLOT,
        primitives::{ExecutionBlockNumber, H256, Slot, UnixSeconds},
    },
    preset::{Preset, PresetName},
    redacting_url::RedactingUrl,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};
use validator::{
    ChainSource, Genesis, OwnValidatorIndices, RemoteBeaconNode, RemoteBeaconNodes, Validator,
    ValidatorApiConfig, ValidatorChannels, ValidatorConfig, ValidatorStartupError,
    run_validator_api,
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
    validators::normalize_definitions,
};

#[cfg(any(feature = "preset-mainnet", test))]
use types::preset::Mainnet;
#[cfg(any(feature = "preset-minimal", test))]
use types::preset::Minimal;

#[cfg(all(unix, not(feature = "embed")))]
use tokio::signal::unix::SignalKind;

pub struct RuntimeConfig {
    pub detect_doppelgangers: bool,
    pub slashing_protection_history_limit: u64,
    pub validator_enabled: bool,
    pub remote_beacon_nodes: Arc<RemoteBeaconNodes>,
    pub genesis: Genesis,
    pub pubkey_cache: Arc<PubkeyCache>,
}

/// What the built-in beacon node is built from; absent with `--disable-local-beacon-node`.
struct LocalNodeConfig<P: Preset> {
    store_config: StoreConfig,
    network_config: NetworkConfig,
    anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    state_load_strategy: StateLoadStrategy<P>,
    eth1_config: Arc<Eth1Config>,
    slasher_config: Option<SlasherConfig>,
    http_api_config: Option<HttpApiConfig>,
    blacklisted_blocks: HashSet<H256>,
    report_validator_performance: bool,
    tracing_handle: Option<TracingHandle>,
    eth1_api_to_metrics_tx: Option<UnboundedSender<Eth1ApiToMetrics>>,
    eth1_api_to_metrics_rx: Option<UnboundedReceiver<Eth1ApiToMetrics>>,
    restart_tx: UnboundedSender<RestartMessage>,
    restart_rx: UnboundedReceiver<RestartMessage>,
    back_sync_enabled: bool,
    max_events: usize,
    reconstruction_delay: Duration,
    track_liveness: bool,
}

/// What the validator and the built-in beacon node have in common.
struct Shared<'a> {
    chain_config: &'a Arc<ChainConfig>,
    pubkey_cache: &'a Arc<PubkeyCache>,
    validator_config: &'a Arc<ValidatorConfig>,
    storage_config: &'a StorageConfig,
    signer: &'a Arc<Signer>,
    metrics: &'a Option<Arc<Metrics>>,
    keymanager: &'a Arc<KeyManager>,
    builder_api: &'a Option<Arc<BuilderApi>>,
    dedicated_executor_normal_priority: &'a Arc<DedicatedExecutor>,
    dedicated_executor_low_priority: &'a Arc<DedicatedExecutor>,
    genesis_time: UnixSeconds,
}

/// The chain the validator performs duties against when the built-in beacon node runs.
struct LocalChain<P: Preset> {
    controller: RealController<P>,
    block_producer: Arc<BlockProducer<P, ()>>,
    attestation_agg_pool: Arc<AttestationAggPool<P, ()>>,
    sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, ()>>,
    payload_attestation_agg_pool: Arc<PayloadAttestationAggPool<P, ()>>,
    event_channels: Arc<EventChannels<P>>,
    validator_statistics: Option<Arc<ValidatorStatistics>>,
}

impl<P: Preset> LocalChain<P> {
    fn chain_source(
        &self,
        own_validator_indices: Arc<OwnValidatorIndices>,
        remote_beacon_nodes: Arc<RemoteBeaconNodes>,
    ) -> ChainSource<P, ()> {
        if remote_beacon_nodes.is_empty() {
            ChainSource::Local {
                controller: self.controller.clone_arc(),
                attestation_agg_pool: self.attestation_agg_pool.clone_arc(),
                block_producer: self.block_producer.clone_arc(),
                event_channels: self.event_channels.clone_arc(),
                own_validator_indices,
                payload_attestation_agg_pool: self.payload_attestation_agg_pool.clone_arc(),
                sync_committee_agg_pool: self.sync_committee_agg_pool.clone_arc(),
            }
        } else {
            ChainSource::Mixed {
                controller: self.controller.clone_arc(),
                attestation_agg_pool: self.attestation_agg_pool.clone_arc(),
                block_producer: self.block_producer.clone_arc(),
                event_channels: self.event_channels.clone_arc(),
                own_validator_indices,
                payload_attestation_agg_pool: self.payload_attestation_agg_pool.clone_arc(),
                remote_beacon_nodes,
                sync_committee_agg_pool: self.sync_committee_agg_pool.clone_arc(),
            }
        }
    }
}

/// What the clock drives: fork choice when the built-in node runs, otherwise the validator.
#[derive(Clone)]
enum ClockTarget<P: Preset> {
    ForkChoice(RealController<P>),
    Validator(UnboundedSender<ValidatorMessage<P, ()>>),
}

impl<P: Preset> ClockTarget<P> {
    fn on_tick(&self, tick: Tick) {
        match self {
            Self::ForkChoice(controller) => controller.on_tick(tick),
            Self::Validator(validator_tx) => ValidatorMessage::Tick((), tick).send(validator_tx),
        }
    }

    fn stop(&self) {
        match self {
            Self::ForkChoice(controller) => {
                controller.stop();
                info_with_peers!("saving current chain before exit…");
            }
            Self::Validator(validator_tx) => ValidatorMessage::Stop.send(validator_tx),
        }
    }
}

/// What the built-in beacon node hands the validator, and the tasks that keep the node going.
struct LocalServices<P: Preset> {
    validator_channels: ValidatorChannels<P, ()>,
    clock_target: ClockTarget<P>,
    metrics_registry: Option<Registry>,
    tasks: LocalTasks<P>,
}

struct LocalTasks<P: Preset> {
    mutator_handle: MutatorHandle<P, ()>,
    restart_rx: UnboundedReceiver<RestartMessage>,
    execution_service: ExecutionService<P, ()>,
    execution_blob_fetcher: ExecutionBlobFetcher<P, ()>,
    attestation_verifier: AttestationVerifier<P, ()>,
    block_sync_service: BlockSyncService<P>,
    network: Network<P, ()>,
    bls_to_execution_change_pool_service: BlsToExecutionChangePoolService<P, ()>,
    pool_manager: Manager<P, ()>,
    subnet_service: SubnetService<P, ()>,
    http_api: Option<HttpApi<P, ()>>,
    slasher: Option<Slasher<P>>,
    metrics_service: Option<MetricsService<P>>,
    liveness_tracker: Option<LivenessTracker<P, ()>>,
}

impl<P: Preset> LocalTasks<P> {
    async fn run(self) -> Result<()> {
        let Self {
            mutator_handle,
            restart_rx,
            execution_service,
            execution_blob_fetcher,
            attestation_verifier,
            block_sync_service,
            network,
            bls_to_execution_change_pool_service,
            pool_manager,
            subnet_service,
            http_api,
            slasher,
            metrics_service,
            liveness_tracker,
        } = self;

        let join_mutator = async { tokio::task::spawn_blocking(|| mutator_handle.join()).await? };

        let run_http_api = match http_api {
            Some(http_api) => Either::Left(http_api.run()),
            None => Either::Right(core::future::pending()),
        };

        let run_slasher = match slasher {
            Some(slasher) => Either::Left(slasher.run()),
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

        select! {
            result = join_mutator => result,
            result = spawn_fallible(execution_service.run()) => result,
            result = spawn_fallible(execution_blob_fetcher.run()) => result,
            result = spawn_fallible(attestation_verifier.run()) => result,
            result = spawn_fallible(block_sync_service.run()) => result,
            result = spawn_fallible(network.run()) => result,
            result = spawn_fallible(run_http_api) => result,
            result = spawn_fallible(run_slasher) => result.map(from_never),
            result = spawn_fallible(bls_to_execution_change_pool_service.run()) => result,
            result = spawn_fallible(pool_manager.run()) => result,
            result = spawn_fallible(run_metrics_service) => result,
            result = spawn_fallible(run_liveness_tracker) => result,
            result = spawn_fallible(subnet_service.run()) => result,
            result = wait_for_restart(restart_rx) => result,
        }
    }
}

#[expect(clippy::too_many_lines)]
async fn build_local_node<P: Preset>(
    config: LocalNodeConfig<P>,
    shared: &Shared<'_>,
    metrics_service_config: Option<MetricsServiceConfig>,
) -> Result<(LocalChain<P>, LocalServices<P>)> {
    let LocalNodeConfig {
        store_config,
        network_config,
        anchor_checkpoint_provider,
        state_load_strategy,
        eth1_config,
        slasher_config,
        http_api_config,
        blacklisted_blocks,
        report_validator_performance,
        tracing_handle,
        eth1_api_to_metrics_tx,
        eth1_api_to_metrics_rx,
        restart_tx,
        restart_rx,
        back_sync_enabled,
        max_events,
        reconstruction_delay,
        track_liveness,
    } = config;

    let Shared {
        chain_config,
        pubkey_cache,
        validator_config,
        storage_config,
        signer,
        metrics,
        keymanager,
        builder_api,
        dedicated_executor_normal_priority,
        dedicated_executor_low_priority,
        genesis_time,
    } = *shared;

    let StorageConfig {
        in_memory,
        ref directories,
        archival_epoch_interval,
        storage_mode,
        ..
    } = *storage_config;

    let signer_snapshot = signer.load();

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

    let dedicated_executor_for_reconstruction =
        DedicatedExecutor::new("de-reconstruct", 1, Some(19), metrics.clone());

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
        dedicated_executor_low_priority,
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
    let current_tick = Tick::current::<P>(chain_config, genesis_time)?;
    let event_channels = Arc::new(EventChannels::new(max_events));
    let sidecars_construction_started = Arc::new(SccHashMap::new());

    let (controller, mutator_handle) = Controller::new(
        chain_config.clone_arc(),
        pubkey_cache.clone_arc(),
        store_config,
        anchor_block,
        anchor_state,
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
        sidecars_construction_started,
        None,
    )?;

    let received_blob_sidecars = Arc::new(SccHashMap::new());
    let received_data_column_sidecars = Arc::new(SccHashMap::new());

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
        dedicated_executor_normal_priority.clone_arc(),
    );

    let validator_keys = Arc::new(signer_snapshot.keys().copied().collect::<HashSet<_>>());

    let attestation_verifier = AttestationVerifier::new(
        controller.clone_arc(),
        dedicated_executor_low_priority.clone_arc(),
        metrics.clone(),
        fork_choice_to_attestation_verifier_rx,
    );

    let metrics_service = metrics_service_config.map(|metrics_config| {
        let (sync_tx, sync_to_metrics_rx) = mpsc::unbounded();

        sync_to_metrics_tx = Some(sync_tx);

        let eth1_connection_data = Eth1ConnectionData {
            sync_eth1_connected: cfg!(feature = "embed") || !eth1_config.eth1_rpc_urls.is_empty(),
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
                .expect("metrics must be enabled for the metrics service"),
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

    let data_dumper = Arc::new(DataDumper::new(&controller.chain_config().config_name)?);

    let validator_statistics =
        report_validator_performance.then(|| Arc::new(ValidatorStatistics::new(metrics.clone())));

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
        dedicated_executor_low_priority.clone_arc(),
    );

    let payload_attestation_agg_pool = PayloadAttestationAggPool::new(
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
        payload_attestation_agg_pool.clone_arc(),
        sync_committee_agg_pool.clone_arc(),
        fork_choice_to_pool_rx,
        reconstruction_delay,
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
        payload_attestation_agg_pool.clone_arc(),
        metrics.clone(),
        None,
    ));

    let validator_channels = ValidatorChannels::Local {
        api_to_validator_rx,
        fork_choice_rx: fork_choice_to_validator_rx,
        p2p_tx: validator_to_p2p_tx,
        p2p_to_validator_rx,
        slasher_to_validator_rx,
        subnet_service_tx: subnet_service_tx.clone(),
        api_to_liveness_tx: api_to_liveness_tx.clone(),
        validator_to_liveness_tx,
        validator_to_slasher_tx,
    };

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
    let gossip_registry = Registry::default();
    let mut metrics_registry = network_config.metrics_enabled.then_some(gossip_registry);
    let network_config = Arc::new(network_config);

    if let Some(metrics) = metrics.as_ref()
        && let Some(grandine_version) = network_config.identify_agent_version.as_ref()
    {
        metrics.set_grandine_version(grandine_version);
    }

    let network = Network::new(
        network_config.clone_arc(),
        controller.clone_arc(),
        current_tick.slot,
        p2p_channels,
        dedicated_executor_normal_priority.clone_arc(),
        sync_committee_agg_pool.clone_arc(),
        bls_to_execution_change_pool.clone_arc(),
        metrics.clone(),
        metrics_registry.as_mut(),
        data_dumper.clone_arc(),
        validator_config.backfill_custody_groups,
        validator_config.custody_mode,
        storage_mode,
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
        validator_statistics.clone(),
        block_sync_service_channels,
        back_sync_enabled,
        loaded_from_remote,
        storage_mode,
        network_config.target_peers,
        received_blob_sidecars,
        received_data_column_sidecars,
        data_dumper,
        network.network_globals().clone_arc(),
        dedicated_executor_low_priority.clone_arc(),
    )
    .await?;

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

    let http_api = http_api_config.map(|http_api_config| HttpApi {
        block_producer: block_producer.clone_arc(),
        controller: controller.clone_arc(),
        anchor_checkpoint_provider,
        eth1_api,
        event_channels: event_channels.clone_arc(),
        validator_keys,
        validator_config: validator_config.clone_arc(),
        network_config,
        http_api_config,
        attestation_agg_pool: attestation_agg_pool.clone_arc(),
        sync_committee_agg_pool: sync_committee_agg_pool.clone_arc(),
        bls_to_execution_change_pool,
        payload_attestation_agg_pool: payload_attestation_agg_pool.clone_arc(),
        channels: http_api_channels,
        metrics: metrics.clone(),
        tracing_handle,
        dedicated_executor: dedicated_executor_low_priority.clone_arc(),
    });

    let tasks = LocalTasks {
        mutator_handle,
        restart_rx,
        execution_service,
        execution_blob_fetcher,
        attestation_verifier,
        block_sync_service,
        network,
        bls_to_execution_change_pool_service,
        pool_manager,
        subnet_service,
        http_api,
        slasher,
        metrics_service,
        liveness_tracker,
    };

    let local_services = LocalServices {
        validator_channels,
        clock_target: ClockTarget::ForkChoice(controller.clone_arc()),
        metrics_registry,
        tasks,
    };

    let chain = LocalChain {
        controller,
        block_producer,
        attestation_agg_pool,
        sync_committee_agg_pool,
        payload_attestation_agg_pool,
        event_channels,
        validator_statistics,
    };

    Ok((chain, local_services))
}

#[expect(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_node<P: Preset>(
    chain_config: Arc<ChainConfig>,
    runtime_config: RuntimeConfig,
    validator_api_config: Option<ValidatorApiConfig>,
    validator_config: Arc<ValidatorConfig>,
    storage_config: StorageConfig,
    builder_config: Option<BuilderConfig>,
    signer: Arc<Signer>,
    metrics_config: MetricsConfig,
    local_node: Option<LocalNodeConfig<P>>,
) -> Result<()> {
    let RuntimeConfig {
        detect_doppelgangers,
        slashing_protection_history_limit,
        validator_enabled,
        remote_beacon_nodes,
        genesis,
        pubkey_cache,
    } = runtime_config;

    let MetricsConfig {
        metrics,
        metrics_server_config,
        metrics_service_config,
    } = metrics_config;

    let StorageConfig {
        in_memory,
        ref directories,
        ..
    } = storage_config;

    let signer_snapshot = signer.load();

    if !signer_snapshot.is_empty() {
        info_with_peers!("loaded {} validator key(s)", signer_snapshot.keys().len());
    } else if validator_enabled {
        warn_with_peers!("failed to load validator keys");
    }

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

    let genesis_validators_root = genesis.genesis_validators_root;

    let mut slashing_protector = if in_memory {
        SlashingProtector::in_memory(slashing_protection_history_limit)?
    } else {
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
            genesis_validators_root,
            validator_config.suggested_fee_recipient,
            validator_config.default_gas_limit,
            graffiti,
            validator_config.validator_definitions.clone_arc(),
        ))
    } else {
        Arc::new(KeyManager::new_persistent(
            signer.clone_arc(),
            slashing_protector.clone_arc(),
            genesis_validators_root,
            directories.validator_dir.clone().unwrap_or_default(),
            directories.secrets_dir.clone().unwrap_or_default(),
            validator_config.keystore_storage_password_file.as_deref(),
            validator_config.suggested_fee_recipient,
            validator_config.default_gas_limit,
            graffiti,
            validator_config.validator_definitions.clone_arc(),
        )?)
    };

    let doppelganger_protection =
        detect_doppelgangers.then(|| Arc::new(DoppelgangerProtection::new()));

    if let Some(doppelganger_protection) = doppelganger_protection.as_ref() {
        signer.enable_doppelganger_protection(doppelganger_protection);

        let current_slot = Tick::current::<P>(&chain_config, genesis.genesis_time)?.slot;
        signer.update_doppelganger_protection_pubkeys(current_slot);
    }

    let builder_api = builder_config.map(|builder_config| {
        Arc::new(BuilderApi::new(
            builder_config,
            pubkey_cache.clone_arc(),
            signer_snapshot.client().clone(),
            metrics.clone(),
        ))
    });

    // Shared between the validator and the Validator API.
    let own_validator_indices = Arc::new(OwnValidatorIndices::new(signer.clone_arc()));

    let shared = Shared {
        chain_config: &chain_config,
        pubkey_cache: &pubkey_cache,
        validator_config: &validator_config,
        storage_config: &storage_config,
        signer: &signer,
        metrics: &metrics,
        keymanager: &keymanager,
        builder_api: &builder_api,
        dedicated_executor_normal_priority: &dedicated_executor_normal_priority,
        dedicated_executor_low_priority: &dedicated_executor_low_priority,
        genesis_time: genesis.genesis_time,
    };

    let (chain, local_services) = match local_node {
        Some(config) => {
            let (chain, services) =
                build_local_node(config, &shared, metrics_service_config).await?;

            (Some(chain), Some(services))
        }
        None => (None, None),
    };

    let validator_statistics = chain
        .as_ref()
        .and_then(|chain| chain.validator_statistics.clone());

    let chain_source = Arc::new(match chain {
        Some(chain) => chain.chain_source(own_validator_indices, remote_beacon_nodes),
        None => ChainSource::Remote {
            chain_config: chain_config.clone_arc(),
            genesis_time: genesis.genesis_time,
            own_validator_indices,
            remote_beacon_nodes,
        },
    });

    // Without the built-in node's fork choice the validator receives ticks straight from the clock.
    let (validator_channels, clock_target, metrics_registry, tasks) = match local_services {
        Some(LocalServices {
            validator_channels,
            clock_target,
            metrics_registry,
            tasks,
        }) => (
            validator_channels,
            clock_target,
            metrics_registry,
            Some(tasks),
        ),
        None => {
            let (runtime_tx, runtime_rx) = mpsc::unbounded();

            (
                ValidatorChannels::Remote { runtime_rx },
                ClockTarget::Validator(runtime_tx),
                None,
                None,
            )
        }
    };

    let run_local_node = match tasks {
        Some(tasks) => Either::Left(tasks.run()),
        None => Either::Right(core::future::pending()),
    };

    let validator = Validator::new(
        validator_config,
        chain_source.clone_arc(),
        builder_api,
        doppelganger_protection,
        keymanager.proposer_configs().clone_arc(),
        signer.clone_arc(),
        slashing_protector,
        metrics.clone(),
        validator_statistics,
        validator_channels,
        dedicated_executor_normal_priority,
        dedicated_executor_low_priority,
    );

    let (stop_clock_tx, stop_clock_rx) = oneshot::channel();

    let run_clock = run_clock::<P>(
        chain_config,
        genesis.genesis_time.saturating_mul(1000),
        clock_target.clone(),
        stop_clock_rx,
    );

    let run_validator_api = match validator_api_config {
        Some(validator_api_config) => Either::Left(run_validator_api(
            validator_api_config,
            chain_source,
            directories.clone_arc(),
            keymanager,
            signer,
            metrics.clone(),
        )),
        None => Either::Right(core::future::pending()),
    };

    let run_metrics_server = match metrics_server_config {
        Some(config) => Either::Left(run_metrics_server(
            config,
            metrics_registry,
            metrics.expect("metrics must be enabled for the metrics server"),
        )),
        None => Either::Right(core::future::pending()),
    };

    select! {
        result = spawn_fallible(validator.run()) => result,
        result = spawn_fallible(run_clock) => result,
        result = spawn_fallible(run_validator_api) => result,
        result = spawn_fallible(run_metrics_server) => result,
        result = spawn_fallible(run_local_node) => result,
        result = wait_for_signal() => result,
    }?;

    if stop_clock_tx.send(()).is_err() {
        warn_with_peers!("failed to send the message to stop the clock");
    }

    clock_target.stop();

    Ok(())
}

async fn run_clock<P: Preset>(
    chain_config: Arc<ChainConfig>,
    genesis_time_in_ms: u64,
    clock_target: ClockTarget<P>,
    mut stop_clock_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let mut ticks = clock::ticks::<P>(&chain_config, genesis_time_in_ms)?.fuse();

    loop {
        select! {
            tick = ticks.select_next_some() => clock_target.on_tick(tick?),
            _ = &mut stop_clock_rx => break,
        }
    }

    Ok(())
}

async fn wait_for_restart(mut rx: UnboundedReceiver<RestartMessage>) -> Result<()> {
    if let Some(message) = rx.next().await {
        match message {
            RestartMessage::StorageMapFull(error) => return Err(error.into()),
        }
    }

    Ok(())
}

#[cfg(feature = "embed")]
static SHUTDOWN_TOKEN: LazyLock<CancellationToken> = LazyLock::new(|| CancellationToken::new());

#[cfg(feature = "embed")]
async fn wait_for_signal() -> Result<()> {
    SHUTDOWN_TOKEN.cancelled().await;

    Ok(())
}

#[cfg(feature = "embed")]
pub fn shutdown() {
    SHUTDOWN_TOKEN.cancel();
}

#[cfg(not(feature = "embed"))]
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
    http_api_config: Option<HttpApiConfig>,
    max_events: usize,
    metrics_config: MetricsConfig,
    track_liveness: bool,
    tracing_handle: Option<TracingHandle>,
    detect_doppelgangers: bool,
    slashing_protection_history_limit: u64,
    validator_enabled: bool,
    blacklisted_blocks: HashSet<H256>,
    reconstruction_delay: Duration,
    report_validator_performance: bool,
    beacon_node_urls: Vec<RedactingUrl>,
    disable_local_beacon_node: bool,
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
                    // don't reset database on restart
                    context.storage_config.reset_databases = false;
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
                        db_size_modifier = db_size_modifier.saturating_mul(2);
                    }

                    if matches!(
                        error.downcast_ref::<doppelganger_protection::Error>(),
                        Some(&doppelganger_protection::Error::DoppelgangersDetected { .. })
                    ) || error.downcast_ref::<ValidatorStartupError>().is_some()
                    {
                        break Err(error);
                    }
                }
                Err(error) => error_with_peers!("application runtime panicked: {error:?}"),
            }
        }
    }

    #[expect(clippy::too_many_lines)]
    async fn run<P: Preset>(self) -> Result<()> {
        const GENESIS_RETRY_DELAY: Duration = Duration::from_secs(2);

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
            reconstruction_delay,
            report_validator_performance,
            beacon_node_urls,
            disable_local_beacon_node,
        } = self;

        // The databases are the built-in node's; without it there is nothing to remove.
        if storage_config.reset_databases && !disable_local_beacon_node {
            match remove_database_dir(storage_config.eth1_database_path().as_path()) {
                Ok(()) => info!("successfully removed eth1 database"),
                Err(error) => warn!("failed to remove eth1 database: {error:?}"),
            }

            match remove_database_dir(storage_config.beacon_fork_choice_database_path().as_path()) {
                Ok(()) => info!("successfully removed beacon_fork_choice database"),
                Err(error) => warn!("failed to remove beacon_fork_choice database: {error:?}"),
            }

            match remove_database_dir(storage_config.pubkey_cache_database_path().as_path()) {
                Ok(()) => info!("successfully removed pubkey_cache database"),
                Err(error) => warn!("failed to remove pubkey_cache database: {error:?}"),
            }

            match remove_database_dir(storage_config.sync_database_path().as_path()) {
                Ok(()) => info!("successfully removed sync database"),
                Err(error) => warn!("failed to remove sync database: {error:?}"),
            }
        }

        // Load keys early so we can validate `eth1_rpc_urls`.
        signer.load_keys_from_web3signer().await;

        let signer_snapshot = signer.load();

        // An execution layer is for the built-in node's blocks; a validator without it has none.
        if cfg!(not(feature = "embed")) && eth1_rpc_urls.is_empty() && !disable_local_beacon_node {
            ensure!(
                signer_snapshot.no_keys(),
                Error::MissingEth1RpcUrlsWithValidators,
            );
        }

        let default_deposit_tree = predefined_network.map(PredefinedNetwork::genesis_deposit_tree);

        if let Some(deposit_tree) = default_deposit_tree {
            deposit_contract_starting_block
                .get_or_insert_with(|| deposit_tree.last_added_block_number.saturating_add(1));
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

        // The built-in node's cache; a validator without the node keeps nothing on disk for it.
        let pubkey_cache_database = if storage_config.in_memory || disable_local_beacon_node {
            Database::in_memory()
        } else {
            storage_config.pubkey_cache_database(
                None,
                DatabaseMode::ReadWrite,
                Some(restart_tx.clone()),
            )?
        };

        let pubkey_cache = Arc::new(PubkeyCache::load(pubkey_cache_database));

        // A validator on a custom network with no built-in node has no genesis state to load and
        // no execution layer to build one from; it asks the remote nodes for genesis instead.
        let anchor_checkpoint_provider = if disable_local_beacon_node
            && predefined_network.is_none()
            && genesis_state_file.is_none()
        {
            None
        } else {
            Some(
                genesis_checkpoint_provider::<P>(
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
                .await?,
            )
        };

        if let Some(command) = command {
            let Some(anchor_checkpoint_provider) = anchor_checkpoint_provider.as_ref() else {
                bail!("commands need a genesis state or the built-in beacon node");
            };

            return handle_command(
                chain_config,
                &pubkey_cache,
                &storage_config,
                command,
                anchor_checkpoint_provider,
                slashing_protection_history_limit,
            )
            .inspect_err(|error| error!("error occurred while executing command: {error:?}"));
        }

        let serving_count = Arc::new(core::sync::atomic::AtomicUsize::new(beacon_node_urls.len()));

        let remote_beacon_nodes = Arc::new(RemoteBeaconNodes::new(
            beacon_node_urls
                .into_iter()
                .map(|url| {
                    Arc::new(RemoteBeaconNode::new(
                        chain_config.clone_arc(),
                        signer_snapshot.client().clone(),
                        url,
                        validator_config.max_empty_slots,
                        serving_count.clone_arc(),
                    ))
                })
                .collect(),
        ));

        let anchor_genesis = anchor_checkpoint_provider.as_ref().map(|provider| {
            let genesis_state = provider.checkpoint().value.state;

            Genesis {
                genesis_time: genesis_state.genesis_time(),
                genesis_fork_version: chain_config.genesis_fork_version,
                genesis_validators_root: genesis_state.genesis_validators_root(),
            }
        });

        let remote_genesis = loop {
            match remote_beacon_nodes.agreed_genesis().await? {
                Some(genesis) => break Some(genesis),
                None if anchor_genesis.is_some() || remote_beacon_nodes.is_empty() => break None,
                // A validator with no genesis of its own has nothing to do until a node answers.
                None => {
                    warn_with_peers!(
                        "no beacon node given with --beacon-node-urls reported genesis; \
                         retrying in {} s",
                        GENESIS_RETRY_DELAY.as_secs(),
                    );

                    sleep(GENESIS_RETRY_DELAY).await;
                }
            }
        };

        let genesis = match (anchor_genesis, remote_genesis) {
            (Some(anchor), Some(remote)) => {
                ensure!(
                    anchor.genesis_validators_root == remote.genesis_validators_root,
                    ValidatorStartupError::UnexpectedChain {
                        expected: anchor.genesis_validators_root,
                        actual: remote.genesis_validators_root,
                    },
                );

                anchor
            }
            (Some(anchor), None) => anchor,
            (None, Some(remote)) => remote,
            (None, None) => bail!("no beacon node given with --beacon-node-urls reported genesis"),
        };

        // Nodes unreachable now are held to the agreed root on their first poll.
        remote_beacon_nodes.seed_genesis_validators_root(genesis.genesis_validators_root);

        // The built-in node runs only when it is enabled and has an anchor to start from.
        let local_node = match anchor_checkpoint_provider {
            Some(anchor_checkpoint_provider) if !disable_local_beacon_node => {
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

                Feature::DebugAttestationPacker.enable();
                Feature::LogBlockProcessingTime.enable();

                Some(LocalNodeConfig {
                    store_config,
                    network_config,
                    anchor_checkpoint_provider,
                    state_load_strategy,
                    eth1_config,
                    slasher_config,
                    http_api_config,
                    blacklisted_blocks,
                    report_validator_performance,
                    tracing_handle,
                    eth1_api_to_metrics_tx,
                    eth1_api_to_metrics_rx,
                    restart_tx,
                    restart_rx,
                    back_sync_enabled,
                    max_events,
                    reconstruction_delay,
                    track_liveness,
                })
            }
            _ => None,
        };

        run_node(
            chain_config,
            RuntimeConfig {
                detect_doppelgangers,
                slashing_protection_history_limit,
                validator_enabled,
                remote_beacon_nodes,
                genesis,
                pubkey_cache,
            },
            validator_api_config,
            validator_config,
            storage_config,
            builder_config,
            signer,
            metrics_config,
            local_node,
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
        data_dir.as_deref(),
        parsed_args.telemetry_config(),
        cfg!(feature = "logger-always-write-style"),
    )?;

    binary_utils::initialize_rayon()?;

    debug_with_peers!("grandine args - {parsed_args:?}");

    let config = parsed_args
        .try_into_config()
        .map_err(GrandineArgs::clap_error)?;

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
        reconstruction_delay,
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
        builder_circuit_breaker,
        mut web3signer_config,
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
        backfill_custody_groups,
        sync_without_reconstruction,
        custody_mode,
        disable_wait_for_late_blocks,
        beacon_node_urls,
        disable_local_beacon_node,
        publish_to_every_node,
        ..
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
            http_api_config.as_ref().map(|config| config.address),
            (!disable_local_beacon_node).then_some(&network_config),
            metrics_server_config.as_ref(),
            validator_api_config.as_ref(),
        )
        .map_err(GrandineArgs::clap_error)?;
    }

    if !in_memory {
        initialize_schema(data_dir)?;
    }

    // Build the validator definitions: discover keystores, migrate the legacy database, and persist.
    let validators_config_path = (!in_memory)
        .then(|| storage_config.directories.validator_dir.clone())
        .flatten()
        .map(|validator_dir| ValidatorDefinitions::file_path(&validator_dir));

    let mut validator_definitions = match &validators_config_path {
        Some(path) => ValidatorDefinitions::load_or_default(path)?,
        None => ValidatorDefinitions::default(),
    };

    if let Some(validators) = validators.as_ref() {
        validators
            .discover(&mut validator_definitions)
            .context("unable to discover validator keystores")?;
    }

    let keystore_storage = match &keystore_storage_password_file {
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

    validator_definitions
        .add_storage_keystores(keystore_storage.keypairs().map(|(pubkey, _)| pubkey));

    let legacy_database_dir = (!in_memory)
        .then(|| storage_config.directories.validator_dir.as_deref())
        .flatten();

    let legacy_migration = legacy_database_dir
        .map(|validator_dir| {
            keymanager::migrate_legacy_database(&mut validator_definitions, validator_dir)
        })
        .transpose()?
        .flatten();

    if let Some(migration) = &legacy_migration {
        debug_with_peers!("migrated legacy proposer-configs database: {migration:?}");
    }

    if let Some(path) = &validators_config_path {
        validator_definitions.save(path)?;
    }

    // Prune only after the save, so an earlier failure retries the migration instead of losing settings.
    if let Some(LegacyMigration { migrated, skipped }) = legacy_migration
        && let Some(validator_dir) = legacy_database_dir
    {
        match keymanager::prune_legacy_database(validator_dir, &migrated) {
            Ok(true) => {
                info!("successfully migrated legacy proposer configs database");
            }
            Ok(false) => warn!(
                "keeping the legacy proposer configs database: it still holds settings for \
                 validators with no entry in validators.yml ({skipped:?})",
            ),
            Err(error) => warn!("unable to prune legacy proposer configs database: {error}"),
        }
    }

    // Fold the `web3signer` entries into the per-URL key policy: each requires its key from its URL.
    for (url, pubkey) in validator_definitions.web3signer_definitions() {
        web3signer_config.require_key(url.parse::<RedactingUrl>()?, pubkey);
    }

    for pubkey in validator_definitions.disabled_pubkeys() {
        info_with_peers!(
            "validator {pubkey:?} is disabled in validators.yml and will not be loaded"
        );
    }

    let validator_definitions = Arc::new(ValidatorDefinitionsWithStorage::new(
        Arc::new(RwLock::new(validator_definitions)),
        match validators_config_path {
            Some(path) => DefinitionsStorage::Persistent(path),
            None => DefinitionsStorage::InMemory,
        },
    ));

    let validator_config = Arc::new(ValidatorConfig {
        disable_blockprint_graffiti,
        graffiti,
        max_empty_slots,
        suggested_fee_recipient,
        default_builder_boost_factor,
        default_gas_limit,
        keystore_storage_password_file,
        backfill_custody_groups,
        custody_mode,
        disable_wait_for_late_blocks,
        validator_definitions: validator_definitions.clone_arc(),
        publish_to_every_node,
    });

    let store_config = StoreConfig {
        max_empty_slots,
        max_epochs_to_retain_states_in_cache,
        state_cache_lock_timeout,
        unfinalized_states_in_memory,
        kzg_backend,
        sync_without_reconstruction,
        builder_circuit_breaker,
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

    let mut validator_key_cache = use_validator_key_cache.then(|| {
        ValidatorKeyCache::new(
            storage_config
                .directories
                .validator_dir
                .clone()
                .unwrap_or_default(),
        )
    });

    let validator_enabled = validator_api_config.is_some()
        || validator_key_cache.is_some()
        || !web3signer_config.is_empty()
        || !validator_definitions.read().is_empty()
        || validator_config.keystore_storage_password_file.is_some();

    if validator_enabled {
        info_with_peers!("started loading validator keys");
    }

    let mut validator_keys = normalize_definitions(
        &validator_definitions.read(),
        storage_config.directories.validator_dir.as_deref(),
        validator_key_cache.as_mut(),
    )
    .context("unable to load validator keys")?;

    {
        // Take only the blob keys still declared as `keystore_storage`; anything else is stale.
        let definitions = validator_definitions.read();

        validator_keys.extend(
            keystore_storage
                .keypairs()
                .filter(|(public_key, _)| definitions.loads_from_storage(*public_key))
                .map(|(public_key, secret_key)| (public_key, secret_key, KeyOrigin::Internal)),
        );
    }

    // A single Web3Signer client, separate from `client` so its TLS material never reaches other
    // requests. `web3signer_options` hard-errors on conflicting definitions in `validators.yml`.
    let web3signer_options = validator_definitions.read().web3signer_options()?;

    let web3signer_client = match web3signer_options {
        Some(options) => build_web3signer_client(
            ClientBuilder::new()
                .timeout(request_timeout)
                .user_agent(APPLICATION_VERSION_WITH_COMMIT_AND_PLATFORM)
                .connection_verbose(true),
            &Web3SignerClientOptions {
                root_certificate_path: options.root_certificate_path,
                request_timeout: options.request_timeout_ms.map(Duration::from_millis),
                client_identity_path: options.client_identity_path,
                client_identity_password: options
                    .client_identity_password
                    .as_ref()
                    .map(|password| password.as_str().to_owned()),
            },
        )?,
        None => client.clone(),
    };

    let signer = Arc::new(Signer::new(
        validator_keys,
        client,
        web3signer_client,
        web3signer_config,
        metrics.clone(),
    ));

    if let Some(cache) = validator_key_cache
        && let Err(error) = cache.save()
    {
        warn_with_peers!("Unable to save validator key cache: {error:?}");
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
        reconstruction_delay,
        report_validator_performance,
        beacon_node_urls,
        disable_local_beacon_node,
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
fn ensure_network_ports_not_in_use(network_config: &NetworkConfig) -> Result<()> {
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

    Ok(())
}

fn ensure_ports_not_in_use(
    http_address: Option<SocketAddr>,
    network_config: Option<&NetworkConfig>,
    metrics_server_config: Option<&MetricsServerConfig>,
    validator_api_config: Option<&ValidatorApiConfig>,
) -> Result<()> {
    if let Some(network_config) = network_config {
        ensure_network_ports_not_in_use(network_config)?;
    }

    if let Some(http_address) = http_address {
        TcpListener::bind(http_address).map_err(|error| Error::PortInUse {
            port: http_address.port(),
            service: "HTTP API",
            option: "--http-port",
            error: error.into(),
        })?;
    }

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
                                signed_attestations
                                    .len()
                                    .saturating_add(signed_blocks.len()),
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

fn remove_database_dir(path: &Path) -> std::io::Result<()> {
    if let Err(error) = fs_err::remove_dir_all(path)
        && error.kind() != ErrorKind::NotFound
    {
        return Err(error);
    }

    Ok(())
}
