use core::{future::Future, net::SocketAddr, panic::AssertUnwindSafe, pin::pin};
use std::{
    collections::HashSet,
    net::{TcpListener, UdpSocket},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
};

use allocator as _;
use anyhow::{bail, ensure, Result};
use builder_api::BuilderConfig;
use clap::{Error as ClapError, Parser as _};
use database::{Database, DatabaseMode, RestartMessage};
use eth1::{Eth1Chain, Eth1Config};
use eth1_api::{Auth, Eth1ApiToMetrics};
use features::Feature;
use fork_choice_control::{StateLoadStrategy, Storage};
use fork_choice_store::StoreConfig;
use futures::channel::mpsc::UnboundedSender;
use genesis::AnchorCheckpointProvider;
use grandine_version::APPLICATION_VERSION_WITH_COMMIT_AND_PLATFORM;
use http_api::HttpApiConfig;
use log::{error, info, warn};
use logging::PEER_LOG_METRICS;
use metrics::MetricsServerConfig;
use p2p::{ListenAddr, NetworkConfig};
use pubkey_cache::PubkeyCache;
use reqwest::{Client, ClientBuilder};
use runtime::{MetricsConfig, RuntimeConfig, StorageConfig};
use signer::{KeyOrigin, Signer};
use slasher::SlasherConfig;
use slashing_protection::{interchange_format::InterchangeData, SlashingProtector};
use ssz::SszRead as _;
use std_ext::ArcExt as _;
use thiserror::Error;
use tokio::runtime::Builder;
use types::{
    config::Config as ChainConfig,
    phase0::primitives::{ExecutionBlockNumber, Slot, H256},
    preset::{Preset, PresetName},
    redacting_url::RedactingUrl,
    traits::BeaconState as _,
};
use validator::{ValidatorApiConfig, ValidatorConfig};
use validator_key_cache::ValidatorKeyCache;

use crate::{
    commands::{GrandineCommand, InterchangeCommand},
    grandine_args::GrandineArgs,
    grandine_config::GrandineConfig,
    predefined_network::PredefinedNetwork,
};

#[cfg(any(feature = "preset-mainnet", test))]
use types::preset::Mainnet;
#[cfg(any(feature = "preset-minimal", test))]
use types::preset::Minimal;

mod commands;
mod config_dir;
mod consts;
mod db_info;
mod db_stats;
mod grandine_args;
mod grandine_config;
mod predefined_network;
mod validators;

#[cfg(not(any(feature = "preset-any", test, doc)))]
compile_error! {
    "at least one preset must be enabled; \
     pass --features … to Cargo; \
     see grandine/Cargo.toml for a list of features"
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
                    error!("application runtime failed: {error:?}");

                    if error.downcast_ref::<libmdbx::Error>() == Some(&libmdbx::Error::MapFull) {
                        info!("increasing environment map size limits");
                        db_size_modifier *= 2;
                    }

                    if matches!(
                        error.downcast_ref::<doppelganger_protection::Error>(),
                        Some(&doppelganger_protection::Error::DoppelgangersDetected { .. })
                    ) {
                        break Err(error);
                    }
                }
                Err(error) => error!("application runtime panicked: {error:?}"),
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
            .then(futures::channel::mpsc::unbounded)
            .unzip();

        let (restart_tx, restart_rx) = futures::channel::mpsc::unbounded();

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

        runtime::run_after_genesis(
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

fn main() -> ExitCode {
    if let Err(error) = try_main() {
        error.downcast_ref().map(ClapError::exit);
        error!("{error:?}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[expect(clippy::too_many_lines)]
fn try_main() -> Result<()> {
    binary_utils::initialize_logger(module_path!(), cfg!(feature = "logger-always-write-style"))?;
    binary_utils::initialize_rayon()?;

    let config = GrandineArgs::try_parse()?
        .try_into_config()
        .map_err(GrandineArgs::clap_error)?;

    info!("starting beacon node");
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
        runtime::initialize_schema(data_dir)?;
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
        info!("started loading validator keys");
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
            warn!("Unable to save validator key cache: {error:?}");
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

            info!("state and blocks exported to {}", output_dir.display());
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

                    info!(
                        "interchange file imported (imported records: {}, failed records: {})",
                        import_report.imported_records(),
                        import_report.failed_records(),
                    );
                }
                InterchangeCommand::Export { file_path } => {
                    let interchange = slashing_protector
                        .export_to_interchange_file(&file_path, genesis_validators_root)?;

                    if interchange.is_empty() {
                        warn!(
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

                            info!(
                                "exported {} records for {pubkey:?}",
                                signed_attestations.len() + signed_blocks.len(),
                            );
                        }
                    }

                    info!("interchange file exported to {}", file_path.display());
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
