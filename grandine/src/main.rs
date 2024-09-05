use core::{future::Future, net::SocketAddr, panic::AssertUnwindSafe, pin::pin};
use std::{
    net::{TcpListener, UdpSocket},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
};

use allocator as _;
use anyhow::{bail, ensure, Context as _, Result};
use builder_api::BuilderConfig;
use clap::{Error as ClapError, Parser as _};
use database::Database;
use eth1::{Eth1Chain, Eth1Config};
use eth1_api::Auth;
use features::Feature;
use fork_choice_control::{StateLoadStrategy, Storage};
use fork_choice_store::StoreConfig;
use genesis::AnchorCheckpointProvider;
use grandine_version::APPLICATION_VERSION_WITH_PLATFORM;
use http_api::HttpApiConfig;
use log::{error, info, warn};
use logging::PEER_LOG_METRICS;
use metrics::MetricsServerConfig;
use p2p::{ListenAddr, NetworkConfig};
use reqwest::{Client, ClientBuilder, Url};
use runtime::{MetricsConfig, StorageConfig};
use signer::{KeyOrigin, Signer};
use slasher::SlasherConfig;
use slashing_protection::SlashingProtector;
use ssz::SszRead as _;
use std_ext::ArcExt as _;
use thiserror::Error;
use tokio::runtime::Builder;
use types::{
    config::Config as ChainConfig,
    phase0::primitives::{ExecutionBlockNumber, Slot},
    preset::{Preset, PresetName},
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

// False positive. The `bool`s are independent.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone)]
struct Context {
    predefined_network: Option<PredefinedNetwork>,
    chain_config: Arc<ChainConfig>,
    store_config: StoreConfig,
    deposit_contract_starting_block: Option<ExecutionBlockNumber>,
    genesis_state_file: Option<PathBuf>,
    genesis_state_download_url: Option<Url>,
    validator_api_config: Option<ValidatorApiConfig>,
    validator_config: Arc<ValidatorConfig>,
    checkpoint_sync_url: Option<Url>,
    force_checkpoint_sync: bool,
    back_sync: bool,
    eth1_rpc_urls: Vec<Url>,
    network_config: NetworkConfig,
    storage_config: StorageConfig,
    command: Option<GrandineCommand>,
    builder_config: Option<BuilderConfig>,
    signer: Arc<Signer>,
    slasher_config: Option<SlasherConfig>,
    state_slot: Option<Slot>,
    eth1_auth: Arc<Auth>,
    http_api_config: HttpApiConfig,
    metrics_config: MetricsConfig,
    track_liveness: bool,
    slashing_protection_history_limit: u64,
    validator_enabled: bool,
}

impl Context {
    fn run_with_restart<P: Preset>(self) -> Result<()> {
        loop {
            // `Context` surprisingly does not implement `UnwindSafe`.
            // Remove the `AssertUnwindSafe` to see the offending types.
            // It is probably unwind safe in practice.
            // All the offending types are trait objects without `UnwindSafe` bounds.
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let run = self.clone().run::<P>();
                block_on(run)
            }))
            .map_err(panics::payload_into_error);

            if Feature::InhibitApplicationRestart.is_enabled() {
                break result?;
            }

            match result {
                Ok(Ok(())) => break Ok(()),
                Ok(Err(error)) => error!("application runtime failed: {error:?}"),
                Err(error) => error!("application runtime panicked: {error:?}"),
            }
        }
    }

    #[allow(clippy::too_many_lines)]
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
            back_sync,
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
            metrics_config,
            track_liveness,
            slashing_protection_history_limit,
            validator_enabled,
        } = self;

        let StorageConfig {
            in_memory,
            eth1_db_size,
            ..
        } = storage_config;

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

        let eth1_database = if in_memory {
            Database::in_memory()
        } else {
            Database::persistent(
                "eth1",
                storage_config
                    .directories
                    .store_directory
                    .clone()
                    .unwrap_or_default()
                    .join("eth1_cache"),
                eth1_db_size,
            )?
        };

        let eth1_chain = Eth1Chain::new(
            chain_config.clone_arc(),
            eth1_config.clone_arc(),
            signer_snapshot.client().clone(),
            eth1_database,
            eth1_api_to_metrics_tx.clone(),
            metrics_config.metrics.clone(),
        )?;

        eth1_chain.spawn_unfinalized_blocks_tracker_task()?;

        let anchor_checkpoint_provider = anchor_checkpoint_provider::<P>(
            &chain_config,
            genesis_state_file,
            predefined_network,
            signer_snapshot.client(),
            storage_config
                .directories
                .store_directory
                .clone()
                .unwrap_or_default(),
            checkpoint_sync_url.clone(),
            genesis_state_download_url,
            &eth1_chain,
        )
        .await?;

        if let Some(command) = command {
            return handle_command(
                chain_config,
                storage_config,
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
            store_config,
            validator_api_config,
            validator_config,
            network_config,
            anchor_checkpoint_provider,
            state_load_strategy,
            eth1_chain,
            eth1_config,
            storage_config,
            builder_config,
            signer,
            slasher_config,
            http_api_config,
            back_sync,
            metrics_config,
            track_liveness,
            eth1_api_to_metrics_tx,
            eth1_api_to_metrics_rx,
            slashing_protection_history_limit,
            validator_enabled,
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
        "{service} port ({port}) is already in use; \
         make sure no other instance of the application is running \
         or specify a different port with {option}"
    )]
    PortInUse {
        port: u16,
        service: &'static str,
        option: &'static str,
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

#[allow(clippy::too_many_lines)]
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
        back_sync,
        eth1_rpc_urls,
        data_dir,
        validators,
        keystore_storage_password_file,
        graffiti,
        max_empty_slots,
        suggested_fee_recipient,
        network_config,
        storage_config,
        request_timeout,
        state_cache_lock_timeout,
        unfinalized_states_in_memory,
        command,
        slashing_enabled,
        slashing_history_limit,
        features,
        state_slot,
        auth_options,
        builder_config,
        web3signer_config,
        http_api_config,
        metrics_config,
        track_liveness,
        use_validator_key_cache,
        slashing_protection_history_limit,
        in_memory,
        validator_api_config,
    } = config;

    features.into_iter().for_each(Feature::enable);

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
        graffiti,
        max_empty_slots,
        suggested_fee_recipient,
        keystore_storage_password_file,
    });

    let store_config = StoreConfig {
        max_empty_slots,
        state_cache_lock_timeout,
        unfinalized_states_in_memory,
    };

    let eth1_auth = Arc::new(Auth::new(auth_options)?);

    // Creating multiple `reqwest::Client`s seems to leak memory.
    // See <https://github.com/seanmonstar/reqwest/issues?q=is%3Aissue+memory>.
    // Create a single one for the whole application and reuse it through `Signer::client`.
    let client = ClientBuilder::new()
        .timeout(request_timeout)
        .user_agent(APPLICATION_VERSION_WITH_PLATFORM)
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
        };
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
        back_sync,
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
        metrics_config,
        track_liveness,
        slashing_protection_history_limit,
        validator_enabled,
    };

    match context.chain_config.preset_base {
        #[cfg(any(feature = "preset-mainnet", test))]
        PresetName::Mainnet => context.run_with_restart::<Mainnet>(),
        #[cfg(any(feature = "preset-minimal", test))]
        PresetName::Minimal => context.run_with_restart::<Minimal>(),
        #[allow(unreachable_patterns)]
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
    TcpListener::bind(http_address).context(Error::PortInUse {
        port: http_address.port(),
        service: "HTTP API",
        option: "--http-port",
    })?;

    if let Some(listen_addr) = network_config.listen_addrs().v4() {
        let ListenAddr {
            addr,
            disc_port,
            quic_port,
            tcp_port,
        } = listen_addr.clone();

        TcpListener::bind((addr, tcp_port)).context(Error::PortInUse {
            port: tcp_port,
            service: "libp2p",
            option: "--libp2p-port",
        })?;

        if !network_config.disable_discovery {
            UdpSocket::bind((addr, disc_port)).context(Error::PortInUse {
                port: disc_port,
                service: "discv5",
                option: "--discovery-port",
            })?;
        }

        if !network_config.disable_quic_support {
            UdpSocket::bind((addr, quic_port)).context(Error::PortInUse {
                port: quic_port,
                service: "quic",
                option: "--quic-port",
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

        TcpListener::bind((addr, tcp_port)).context(Error::PortInUse {
            port: tcp_port,
            service: "libp2p",
            option: "--libp2p-port-v6",
        })?;

        if !network_config.disable_discovery {
            UdpSocket::bind((addr, disc_port)).context(Error::PortInUse {
                port: disc_port,
                service: "discv5",
                option: "--discovery-port-v6",
            })?;
        }

        if !network_config.disable_quic_support {
            UdpSocket::bind((addr, quic_port)).context(Error::PortInUse {
                port: quic_port,
                service: "libp2p",
                option: "--quic-port-v6",
            })?;
        }
    }

    // Port numbers in ENR fields are not used to open any sockets.

    if let Some(config) = metrics_server_config {
        let metrics_port = config.metrics_port;

        TcpListener::bind(SocketAddr::from(config)).context(Error::PortInUse {
            port: metrics_port,
            service: "Metrics",
            option: "--metrics-port",
        })?;
    }

    if let Some(config) = validator_api_config {
        TcpListener::bind(config.address).context(Error::PortInUse {
            port: config.address.port(),
            service: "Validator",
            option: "--validator-api-port",
        })?;
    }

    Ok(())
}

fn handle_command<P: Preset>(
    chain_config: Arc<ChainConfig>,
    storage_config: StorageConfig,
    command: GrandineCommand,
    anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
    slashing_protection_history_limit: u64,
) -> Result<()> {
    let StorageConfig {
        db_size,
        directories,
        archival_epoch_interval,
        ..
    } = storage_config;

    match command {
        GrandineCommand::Export {
            from,
            to,
            output_dir,
        } => {
            let storage_database = Database::persistent(
                "beacon_fork_choice",
                directories
                    .store_directory
                    .clone()
                    .unwrap_or_default()
                    .join("beacon_fork_choice"),
                db_size,
            )?;

            let storage = Storage::new(
                chain_config,
                storage_database,
                archival_epoch_interval,
                false,
            );

            let output_dir = output_dir.unwrap_or(std::env::current_dir()?);

            fork_choice_control::export_state_and_blocks(
                &storage,
                from,
                to,
                &output_dir,
                anchor_checkpoint_provider,
            )?;

            info!("state and blocks exported to {output_dir:?}");
        }
        GrandineCommand::Replay {
            from,
            to,
            input_dir,
        } => {
            let input_dir = input_dir.unwrap_or(std::env::current_dir()?);
            fork_choice_control::replay_blocks::<P>(&chain_config, &input_dir, from, to)?;
        }
        GrandineCommand::Interchange(interchange_command) => {
            let genesis_validators_root = anchor_checkpoint_provider
                .checkpoint()
                .value
                .state
                .genesis_validators_root();

            let mut slashing_protector = SlashingProtector::persistent(
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
                    slashing_protector
                        .export_to_interchange_file(&file_path, genesis_validators_root)?;

                    info!("interchange file exported to {file_path:?}");
                }
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn anchor_checkpoint_provider<P: Preset>(
    chain_config: &ChainConfig,
    genesis_state_file: Option<PathBuf>,
    predefined_network: Option<PredefinedNetwork>,
    client: &Client,
    store_directory: PathBuf,
    checkpoint_sync_url: Option<Url>,
    genesis_state_download_url: Option<Url>,
    eth1_chain: &Eth1Chain,
) -> Result<AnchorCheckpointProvider<P>> {
    if let Some(file_path) = genesis_state_file {
        let bytes = fs_err::read(file_path)?;
        let genesis_state = Arc::from_ssz(chain_config, bytes)?;
        return Ok(AnchorCheckpointProvider::custom_from_genesis(genesis_state));
    }

    if let Some(predefined_network) = predefined_network {
        return predefined_network
            .anchor_checkpoint_provider::<P>(
                client,
                store_directory.as_path(),
                checkpoint_sync_url,
                genesis_state_download_url,
            )
            .await;
    }

    let eth1_block_stream = pin!(eth1_chain.stream_blocks()?);

    let genesis_state =
        eth1::wait_for_genesis(chain_config, store_directory, eth1_block_stream, eth1_chain)
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
