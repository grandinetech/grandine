#![expect(
    clippy::doc_markdown,
    reason = "Adding backquotes to doc comments affects `--help` output. \
             `clap` derive macros preserve backquotes even if `verbatim_doc_comment` is disabled."
)]

use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::{NonZeroU16, NonZeroU64},
    ops::Not as _,
    time::Duration,
};
use std::{collections::HashSet, ffi::OsString, path::PathBuf, sync::Arc};

use anyhow::{Result, anyhow, bail, ensure};
use binary_utils::TelemetryConfig;
use bls::PublicKeyBytes;
use builder_api::{BuilderApiFormat, BuilderConfig, PREFERRED_EXECUTION_GAS_LIMIT};
use bytesize::ByteSize;
use clap::{
    Arg, Args, CommandFactory as _, Error as ClapError, Parser, ValueEnum,
    builder::{PossibleValuesParser, TypedValueParser},
    error::ErrorKind,
    parser::ValueSource,
};
use derivative::Derivative;
use derive_more::Display;
use directories::Directories;
use enum_iterator::Sequence;
use eth1_api::AuthOptions;
use eth2_libp2p::{
    PeerIdSerialized,
    rpc::config::{InboundRateLimiterConfig, OutboundRateLimiterConfig},
};
use features::Feature;
use fork_choice_control::{DEFAULT_ARCHIVAL_EPOCH_INTERVAL, DEFAULT_MAX_EVENTS};
use fork_choice_store::{
    BuilderCircuitBreakerConfig, DEFAULT_CACHE_LOCK_TIMEOUT_MILLIS, StoreConfig,
};
use grandine_version::{APPLICATION_NAME, APPLICATION_VERSION};
use helper_functions::misc;
use http_api::HttpApiConfig;
use itertools::{EitherOrBoth, Itertools as _};
use kzg_utils::{DEFAULT_KZG_BACKEND, KzgBackend};
use logging::{info_with_peers, warn_with_peers};
use metrics::{MetricsServerConfig, MetricsServiceConfig};
use p2p::{Enr, Multiaddr, NetworkConfig};
use prometheus_metrics::{METRICS, Metrics};
use reqwest::header::HeaderValue;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use signer::{Web3SignerConfig, Web3SignerUrlPolicy};
use slasher::SlasherConfig;
use slashing_protection::DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT;
use ssz::Uint256;
use std_ext::ArcExt as _;
use strum::VariantNames as _;
use thiserror::Error;
use tower_http::cors::AllowOrigin;
use tracing::Level;
use types::{
    bellatrix::primitives::{Difficulty, Gas},
    config::Config as ChainConfig,
    nonstandard::{
        CustodyMode, DEFAULT_BUILDER_MAX_SKIPPED_SLOTS,
        DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH, Phase, PublishedDuty, StorageMode,
    },
    phase0::primitives::{
        Epoch, ExecutionAddress, ExecutionBlockHash, ExecutionBlockNumber, H256, Slot,
    },
    preset::PresetName,
    redacting_url::RedactingUrl,
};
use validator::{ValidatorApiConfig, ValidatorConfig};

use crate::{
    DEFAULT_ETH1_DB_SIZE, DEFAULT_ETH2_DB_SIZE, DEFAULT_LIBP2P_IPV4_PORT, DEFAULT_LIBP2P_IPV6_PORT,
    DEFAULT_LIBP2P_QUIC_IPV4_PORT, DEFAULT_LIBP2P_QUIC_IPV6_PORT, DEFAULT_METRICS_PORT,
    DEFAULT_METRICS_UPDATE_INTERVAL_SECONDS, DEFAULT_REQUEST_TIMEOUT, DEFAULT_TARGET_PEERS,
    DEFAULT_TARGET_SUBNET_PEERS, DEFAULT_TIMEOUT, MetricsConfig, StorageConfig,
    commands::GrandineCommand,
    config_dir::{
        self, CONFIG_FILE, DEPOSIT_CONTRACT_BLOCK_FILE, GENESIS_STATE_FILE, PLAIN_BOOTNODES_FILE,
    },
    consts::GRANDINE_DONATION_ADDRESS,
    default_network_config,
    defaults::DEFAULT_RECONSTRUCTION_DELAY_MS,
    grandine_config::GrandineConfig,
    predefined_network::PredefinedNetwork,
    validators::Validators,
};

/// Grandine Team <info@grandine.io>
/// High performance Ethereum consensus layer client
#[derive(Debug, Parser)]
#[clap(display_name = APPLICATION_NAME, verbatim_doc_comment, version = APPLICATION_VERSION)]
pub struct GrandineArgs {
    /// Load command-line options from a YAML file. Keys are long option names (e.g. `http-port`).
    #[clap(long, value_name = "YAML_FILE")]
    args_file: Option<PathBuf>,

    #[clap(flatten)]
    chain_options: ChainOptions,

    #[clap(flatten)]
    beacon_node_options: BeaconNodeOptions,

    #[clap(flatten)]
    http_api_options: HttpApiOptions,

    #[clap(flatten)]
    network_config_options: NetworkConfigOptions,

    #[expect(
        dead_code,
        reason = "TODO(Grandine Team): The slasher is not working properly and should not be used."
    )]
    #[clap(skip)]
    slasher_options: SlasherOptions,

    #[clap(flatten)]
    validator_options: ValidatorOptions,

    #[clap(flatten)]
    remote_validator_options: RemoteValidatorOptions,

    #[clap(flatten)]
    validator_api_options: ValidatorApiOptions,

    /// Default block graffiti. Blockprint graffiti will be appended when sufficient space is available.
    /// See `--disable-blockprint-graffiti` to disable this behavior.
    #[clap(long, value_parser = misc::parse_graffiti)]
    graffiti: Vec<H256>,

    /// Disable appending blockprint graffiti. If specified, no blockprint graffiti will be appended.
    #[clap(long)]
    disable_blockprint_graffiti: bool,

    /// List of optional runtime features to enable
    #[clap(long, value_delimiter = ',')]
    features: Vec<Feature>,

    #[clap(subcommand)]
    command: Option<GrandineCommand>,
}

#[derive(Debug, Args)]
struct ChainOptions {
    /// Name of the Eth2 network to connect to
    #[clap(long, value_enum, default_value_t = Network::default())]
    network: Network,

    /// Load configuration from YAML_FILE
    #[clap(long, value_name = "YAML_FILE")]
    configuration_file: Option<PathBuf>,

    /// Load configuration from directory
    #[clap(long, value_name = "DIRECTORY")]
    configuration_directory: Option<PathBuf>,

    /// Verify that Phase 0 variables in preset match YAML_FILE
    #[clap(long, value_name = "YAML_FILE")]
    verify_phase0_preset_file: Option<PathBuf>,

    /// Verify that Altair variables in preset match YAML_FILE
    #[clap(long, value_name = "YAML_FILE")]
    verify_altair_preset_file: Option<PathBuf>,

    /// Verify that Bellatrix variables in preset match YAML_FILE
    #[clap(long, value_name = "YAML_FILE")]
    verify_bellatrix_preset_file: Option<PathBuf>,

    /// Verify that Capella variables in preset match YAML_FILE
    #[clap(long, value_name = "YAML_FILE")]
    verify_capella_preset_file: Option<PathBuf>,

    /// Verify that Deneb variables in preset match YAML_FILE
    #[clap(long, value_name = "YAML_FILE")]
    verify_deneb_preset_file: Option<PathBuf>,

    /// Verify that Electra variables in preset match YAML_FILE
    #[clap(long, value_name = "YAML_FILE")]
    verify_electra_preset_file: Option<PathBuf>,

    /// Verify that Fulu variables in preset match YAML_FILE
    #[clap(long, value_name = "YAML_FILE")]
    verify_fulu_preset_file: Option<PathBuf>,

    /// Verify that configuration matches YAML_FILE
    #[clap(long, value_name = "YAML_FILE")]
    verify_configuration_file: Option<PathBuf>,

    /// Override TERMINAL_TOTAL_DIFFICULTY
    #[clap(long, value_name = "DIFFICULTY")]
    terminal_total_difficulty_override: Option<Difficulty>,

    /// Override TERMINAL_BLOCK_HASH
    #[clap(long, value_name = "BLOCK_HASH")]
    terminal_block_hash_override: Option<ExecutionBlockHash>,

    /// Override TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH
    #[clap(long, value_name = "EPOCH")]
    terminal_block_hash_activation_epoch_override: Option<Epoch>,

    /// Start tracking deposit contract from BLOCK_NUMBER
    #[clap(long, value_name = "BLOCK_NUMBER")]
    deposit_contract_starting_block: Option<ExecutionBlockNumber>,

    /// Load genesis state from SSZ_FILE
    #[clap(long, value_name = "SSZ_FILE")]
    genesis_state_file: Option<PathBuf>,

    /// Download genesis state from specified URL
    #[clap(long, value_name = "URL")]
    genesis_state_download_url: Option<RedactingUrl>,
}

#[derive(Debug, Args)]
struct HttpApiOptions {
    /// Run Grandine without HTTP API server.
    #[clap(long, default_value_t = false)]
    disable_http_api: bool,

    /// HTTP API address
    #[clap(long, default_value_t = HttpApiConfig::default().address.ip())]
    http_address: IpAddr,

    /// HTTP API port
    #[clap(long, default_value_t = HttpApiConfig::default().address.port())]
    http_port: u16,

    /// List of Access-Control-Allow-Origin header values for the HTTP API server.
    /// Defaults to the listening URL of the HTTP API server.
    #[clap(long, value_delimiter = ',')]
    http_allowed_origins: Vec<HeaderValue>,

    /// HTTP API timeout in milliseconds
    #[clap(long, default_value_t = HttpApiOptions::default_timeout())]
    timeout: u64,
}

impl From<HttpApiOptions> for Option<HttpApiConfig> {
    fn from(http_api_options: HttpApiOptions) -> Self {
        let HttpApiOptions {
            disable_http_api,
            http_address,
            http_port,
            http_allowed_origins,
            timeout,
        } = http_api_options;

        if disable_http_api {
            return None;
        }

        let HttpApiConfig {
            address,
            allow_origin,
            ..
        } = HttpApiConfig::with_address(http_address, http_port);

        Some(HttpApiConfig {
            address,
            allow_origin: headers_to_allow_origin(http_allowed_origins).unwrap_or(allow_origin),
            timeout: Some(Duration::from_millis(timeout)),
        })
    }
}

impl HttpApiOptions {
    // `Duration::as_millis` returns `u128`. See <https://github.com/rust-lang/rust/issues/58580>.
    // `#[clap(value_parser = …)]` cannot be used because `Duration` does not implement `Display`.
    fn default_timeout() -> u64 {
        DEFAULT_TIMEOUT
            .as_millis()
            .try_into()
            .expect("default timeout in milliseconds should fit in u64")
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "False positive. The `bool`s are independent."
)]
#[derive(Debug, Args)]
struct BeaconNodeOptions {
    /// Max empty slots
    #[clap(long, default_value_t = ValidatorConfig::default().max_empty_slots)]
    max_empty_slots: u64,

    /// Max number of events stored in a single channel for HTTP API /events api call
    #[clap(long, default_value_t = DEFAULT_MAX_EVENTS)]
    max_events: usize,

    /// Beacon node API URL to load recent finalized checkpoint and sync from it
    /// [default: None]
    #[clap(long)]
    checkpoint_sync_url: Option<RedactingUrl>,

    /// Number of epochs to keep blob or data column sidecars available for peer requests.
    /// Overrides `Config::min_epochs_for_blob_sidecars_requests` and
    /// `Config::min_epochs_for_data_column_sidecars_requests`.
    /// Intended primarily for testing. Use with caution.
    #[clap(
        long,
        conflicts_with("archive_storage"),
        conflicts_with("prune_storage")
    )]
    data_availability_window: Option<u64>,

    /// Force checkpoint sync. Requires --checkpoint-sync-url
    /// [default: disabled]
    #[clap(long, requires = "checkpoint_sync_url")]
    force_checkpoint_sync: bool,

    /// Forcefully deletes the existing local beacon node databases on startup, allowing a fresh sync.
    /// WARNING: This is destructive and will remove local eth1, beacon_fork_choice, sync, pubkey_cache databases.
    /// [default: disabled]
    #[clap(long)]
    force_reset_beacon_db: bool,

    /// List of Eth1 RPC URLs
    #[clap(long, num_args = 1..)]
    eth1_rpc_urls: Vec<RedactingUrl>,

    /// Parent directory for application data files
    /// [default: $HOME/.grandine/{network}]
    #[clap(long)]
    data_dir: Option<PathBuf>,

    /// Directory to store application data files
    /// [default: {data_dir}/beacon]
    #[clap(long)]
    store_directory: Option<PathBuf>,

    /// Directory to store application network files
    /// [default: {data_dir}/network]
    #[clap(long)]
    network_dir: Option<PathBuf>,

    /// Archival epoch interval
    #[clap(long, default_value_t = DEFAULT_ARCHIVAL_EPOCH_INTERVAL)]
    archival_epoch_interval: NonZeroU64,

    /// Enable archival storage mode, where all blocks, states (every --archival-epoch-interval epochs) and blobs are stored in the database
    /// [default: disabled]
    #[clap(long, conflicts_with("prune_storage"))]
    archive_storage: bool,

    /// Enable prune storage mode, where only a single checkpoint state and block are stored in the database
    /// [default: disabled]
    #[clap(long, conflicts_with("archive_storage"))]
    prune_storage: bool,

    /// Number of unfinalized states to keep in memory.
    #[clap(long, default_value_t = StoreConfig::default().unfinalized_states_in_memory)]
    unfinalized_states_in_memory: u64,

    /// Max size of the Eth2 database
    #[clap(long, default_value_t = DEFAULT_ETH2_DB_SIZE)]
    database_size: ByteSize,

    /// Max size of the Eth1 database
    #[clap(long, default_value_t = DEFAULT_ETH1_DB_SIZE)]
    eth1_database_size: ByteSize,

    /// Default data column reconstruction delay in milliseconds for nodes serving more than half of the available data columns.
    #[clap(long, default_value_t = DEFAULT_RECONSTRUCTION_DELAY_MS)]
    reconstruction_delay: u64,

    /// Default global request timeout for various services in milliseconds
    #[clap(long, default_value_t = DEFAULT_REQUEST_TIMEOUT)]
    request_timeout: u64,

    /// Max amount of epochs to retain beacon states in state cache
    #[clap(long, default_value_t = StoreConfig::default().max_epochs_to_retain_states_in_cache)]
    max_epochs_to_retain_states_in_cache: u64,

    /// Default state cache lock timeout in milliseconds
    #[clap(long, default_value_t = DEFAULT_CACHE_LOCK_TIMEOUT_MILLIS)]
    state_cache_lock_timeout: u64,

    /// State slot
    /// [default: None]
    #[clap(long)]
    state_slot: Option<Slot>,

    /// Run in semi-supernode mode, subscribing to half of the data column subnets
    #[clap(
        long,
        conflicts_with("supernode"),
        visible_alias("subscribe-half-data-column-subnets")
    )]
    semi_supernode: bool,

    /// Run in supernode mode, subscribing to all data column subnets
    #[clap(
        long,
        conflicts_with("semi_supernode"),
        visible_alias("subscribe-all-data-column-subnets")
    )]
    supernode: bool,

    /// Subscribe to all attestation and sync committee subnets.
    /// This option does not include data column subnets.
    #[clap(long)]
    subscribe_all_subnets: bool,

    /// Suggested value for the feeRecipient field of the new payload
    #[clap(long, value_name = "EXECUTION_ADDRESS")]
    suggested_fee_recipient: Option<ExecutionAddress>,

    /// Optional CL unique identifier to send to EL in the JWT token claim
    /// [default: None]
    #[clap(long)]
    jwt_id: Option<String>,

    /// Path to a file containing the hex-encoded 256 bit secret key to be used for verifying/generating JWT tokens
    #[clap(long)]
    jwt_secret: Option<PathBuf>,

    /// Optional CL node type/version to send to EL in the JWT token claim
    /// [default: None]
    #[clap(long)]
    jwt_version: Option<String>,

    /// [DEPRECATED] Enable syncing historical data
    /// [default: disabled]
    #[clap(long = "back_sync")]
    back_sync: bool,

    /// Enable syncing historical data.
    /// When used with --archive-storage, it will back-sync to genesis and reconstruct historical states.
    /// When used without --archive-storage, it will back-sync blocks to the `Config::min_epochs_for_block_requests` epoch.
    /// [default: disabled]
    #[clap(long = "back-sync", conflicts_with("prune_storage"))]
    back_sync_enabled: bool,

    /// Collect Prometheus metrics
    #[clap(long = "metrics")]
    metrics_enabled: bool,

    /// Metrics address for metrics endpoint
    #[clap(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    metrics_address: IpAddr,

    /// Listen port for metrics endpoint
    #[clap(long, default_value_t = DEFAULT_METRICS_PORT)]
    metrics_port: u16,

    /// Update system metrics every n seconds
    #[clap(long, default_value_t = DEFAULT_METRICS_UPDATE_INTERVAL_SECONDS)]
    metrics_update_interval: u64,

    /// Optional remote metrics (beaconcha.in metrics) URL that Grandine will periodically send metrics to
    #[clap(long)]
    remote_metrics_url: Option<RedactingUrl>,

    /// The default tracing level controlling how detailed telemetry output will be.
    #[clap(long, requires("telemetry_metrics_url"), default_value_t = Level::INFO)]
    telemetry_level: Level,

    /// Optional OTLP metrics gRPC URL that Grandine will submit tracing and span data to.
    /// WARNING: This feature is experimental, unstable, and subject to change. Use with caution.
    #[clap(long)]
    telemetry_metrics_url: Option<RedactingUrl>,

    /// Optional OTLP service name.
    #[clap(long, requires("telemetry_metrics_url"), default_value_t = APPLICATION_NAME.to_string())]
    telemetry_service_name: String,

    /// Enable validator liveness tracking
    /// [default: disabled]
    #[clap(long)]
    track_liveness: bool,

    /// Enable doppelganger protection (with the built-in beacon node, liveness tracking must be enabled)
    /// [default: disabled]
    #[clap(long)]
    detect_doppelgangers: bool,

    /// Enable in-memory mode.
    /// No data will be stored in data-dir.
    /// [default: disabled]
    #[clap(long)]
    in_memory: bool,

    /// KZG backend
    #[clap(long, default_value_t = DEFAULT_KZG_BACKEND)]
    kzg_backend: KzgBackend,

    /// A list beacon block roots that beacon node rejects unconditionally
    #[clap(long)]
    blacklisted_blocks: Vec<H256>,

    /// Disable reconstruction while syncing the chain
    /// [default: disabled]
    #[clap(long)]
    sync_without_reconstruction: bool,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "False positive. The `bool`s are independent."
)]
#[derive(Debug, Args)]
struct NetworkConfigOptions {
    /// Listen IPv4 address
    /// [default: 0.0.0.0, unless --disable-ipv4 is set]
    #[clap(long)]
    listen_address: Option<Ipv4Addr>,

    /// Listen IPv6 address
    /// [default: None]
    #[clap(long)]
    listen_address_ipv6: Option<Ipv6Addr>,

    /// libp2p IPv4 port
    #[clap(long, default_value_t = DEFAULT_LIBP2P_IPV4_PORT)]
    libp2p_port: NonZeroU16,

    /// libp2p IPv6 port
    #[clap(long, default_value_t = DEFAULT_LIBP2P_IPV6_PORT)]
    libp2p_port_ipv6: NonZeroU16,

    /// Disable QUIC support as a fallback transport to TCP
    #[clap(long)]
    disable_quic: bool,

    /// Disable peer scoring
    #[clap(long)]
    disable_peer_scoring: bool,

    /// Disable rate limiting both inbound and outbound
    #[clap(long)]
    disable_rate_limiting: bool,

    /// Disable NAT traversal via UPnP
    /// [default: enabled]
    #[clap(long)]
    disable_upnp: bool,

    /// Disable enr auto update
    /// [default: enabled]
    #[clap(long)]
    disable_enr_auto_update: bool,

    /// Disable listening on IPv4
    /// [default: enabled]
    #[clap(
        long,
        requires = "listen_address_ipv6",
        conflicts_with_all = [
            "listen_address",
            "enr_address",
            "enr_tcp_port",
            "enr_udp_port",
            "enr_quic_port",
        ],
    )]
    disable_ipv4: bool,

    /// discv5 IPv4 port
    #[clap(long, default_value_t = DEFAULT_LIBP2P_IPV4_PORT)]
    discovery_port: NonZeroU16,

    /// discv5 IPv6 port
    #[clap(long, default_value_t = DEFAULT_LIBP2P_IPV6_PORT)]
    discovery_port_ipv6: NonZeroU16,

    /// QUIC IPv4 port
    #[clap(long, default_value_t = DEFAULT_LIBP2P_QUIC_IPV4_PORT)]
    quic_port: NonZeroU16,

    /// QUIC IPv6 port
    #[clap(long, default_value_t = DEFAULT_LIBP2P_QUIC_IPV6_PORT)]
    quic_port_ipv6: NonZeroU16,

    /// Enable discovery of peers with private IP addresses.
    /// [default: disabled]
    #[clap(long)]
    enable_private_discovery: bool,

    /// ENR IPv4 address
    #[clap(long)]
    enr_address: Option<Ipv4Addr>,

    /// ENR IPv6 address
    #[clap(long)]
    enr_address_ipv6: Option<Ipv6Addr>,

    /// ENR TCP IPv4 port
    #[clap(long)]
    enr_tcp_port: Option<NonZeroU16>,

    /// ENR TCP IPv6 port
    #[clap(long)]
    enr_tcp_port_ipv6: Option<NonZeroU16>,

    /// ENR UDP IPv4 port
    #[clap(long)]
    enr_udp_port: Option<NonZeroU16>,

    /// ENR UDP IPv6 port
    #[clap(long)]
    enr_udp_port_ipv6: Option<NonZeroU16>,

    /// ENR QUIC IPv4 port
    #[clap(long)]
    enr_quic_port: Option<NonZeroU16>,

    /// ENR QUIC IPv6 port
    #[clap(long)]
    enr_quic_port_ipv6: Option<NonZeroU16>,

    /// List of ENR boot node addresses
    #[clap(long, value_delimiter = ',')]
    boot_nodes: Vec<Enr>,

    /// List of Multiaddr node addresses
    #[clap(long, value_delimiter = ',')]
    libp2p_nodes: Vec<Multiaddr>,

    /// Load p2p private key from KEY_FILE
    #[clap(long, value_name = "KEY_FILE")]
    libp2p_private_key_file: Option<PathBuf>,

    /// Target number of network peers
    #[clap(long, default_value_t = DEFAULT_TARGET_PEERS)]
    target_peers: usize,

    /// Target number of subnet peers
    #[clap(long, default_value_t = DEFAULT_TARGET_SUBNET_PEERS)]
    target_subnet_peers: usize,

    /// List of trusted peers
    #[clap(long, value_delimiter = ',')]
    trusted_peers: Vec<PeerIdSerialized>,
}

impl BeaconNodeOptions {
    pub fn telemetry_config(&self) -> Option<TelemetryConfig> {
        if let Some(url) = self.telemetry_metrics_url.clone() {
            return Some(TelemetryConfig {
                url,
                service_name: self.telemetry_service_name.clone(),
                trace_level: self.telemetry_level,
            });
        }

        None
    }
}

impl NetworkConfigOptions {
    #[expect(clippy::too_many_lines)]
    fn into_config(
        self,
        network: Network,
        network_dir: PathBuf,
        metrics_enabled: bool,
        in_memory: bool,
    ) -> NetworkConfig {
        let Self {
            listen_address,
            listen_address_ipv6,
            libp2p_port,
            libp2p_port_ipv6,
            disable_enr_auto_update,
            disable_ipv4,
            disable_quic,
            disable_peer_scoring,
            disable_rate_limiting,
            disable_upnp,
            discovery_port,
            discovery_port_ipv6,
            quic_port,
            quic_port_ipv6,
            enable_private_discovery,
            enr_address,
            enr_address_ipv6,
            enr_tcp_port,
            enr_tcp_port_ipv6,
            enr_udp_port,
            enr_udp_port_ipv6,
            enr_quic_port,
            enr_quic_port_ipv6,
            boot_nodes,
            libp2p_nodes,
            libp2p_private_key_file,
            target_peers,
            target_subnet_peers,
            trusted_peers,
        } = self;

        let mut network_config = network
            .predefined_network()
            .map(PredefinedNetwork::network_config)
            .unwrap_or_else(default_network_config);

        network_config.disable_peer_scoring = disable_peer_scoring;
        network_config.disable_quic_support = disable_quic;
        network_config.discv5_config.enr_update = !disable_enr_auto_update;
        network_config.upnp_enabled = !disable_upnp;
        network_config.network_dir = in_memory.not().then_some(network_dir);
        network_config.metrics_enabled = metrics_enabled;
        network_config.target_peers = target_peers;
        network_config.target_subnet_peers = target_subnet_peers;
        network_config.trusted_peers = trusted_peers;
        network_config.libp2p_private_key_file = libp2p_private_key_file;

        if !disable_rate_limiting {
            network_config.inbound_rate_limiter_config = Some(InboundRateLimiterConfig::default());
            network_config.outbound_rate_limiter_config =
                Some(OutboundRateLimiterConfig::default());
        }

        match (listen_address, listen_address_ipv6) {
            (_, Some(listen_address_ipv6)) if disable_ipv4 => {
                network_config.set_ipv6_listening_address(
                    listen_address_ipv6,
                    libp2p_port_ipv6.into(),
                    discovery_port_ipv6.into(),
                    quic_port_ipv6.into(),
                );
            }
            (listen_address, None) => {
                network_config.set_ipv4_listening_address(
                    listen_address.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    libp2p_port.into(),
                    discovery_port.into(),
                    quic_port.into(),
                );
            }
            (listen_address, Some(listen_address_ipv6)) => {
                network_config.set_ipv4_ipv6_listening_addresses(
                    listen_address.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    libp2p_port.into(),
                    discovery_port.into(),
                    quic_port.into(),
                    listen_address_ipv6,
                    libp2p_port_ipv6.into(),
                    discovery_port_ipv6.into(),
                    quic_port_ipv6.into(),
                );
            }
        }

        network_config.enr_address = (enr_address, enr_address_ipv6);

        // Set ENR fields of `NetworkConfig` only if the value is specified.
        if let Some(enr_tcp_port) = enr_tcp_port {
            network_config.enr_tcp4_port = Some(enr_tcp_port);
        } else if !disable_ipv4 {
            // Don't allow discv5 to overwrite ENR port
            // as it won't be open via Upnp
            network_config.enr_tcp4_port = Some(libp2p_port);
        }

        if let Some(enr_tcp_port_ipv6) = enr_tcp_port_ipv6 {
            network_config.enr_tcp6_port = Some(enr_tcp_port_ipv6);
        }

        if let Some(enr_udp_port) = enr_udp_port {
            network_config.enr_udp4_port = Some(enr_udp_port);
        }

        if let Some(enr_udp_port_ipv6) = enr_udp_port_ipv6 {
            network_config.enr_udp6_port = Some(enr_udp_port_ipv6);
        }

        if let Some(enr_quic_port) = enr_quic_port {
            network_config.enr_quic4_port = Some(enr_quic_port);
        }

        if let Some(enr_quic_port_ipv6) = enr_quic_port_ipv6 {
            network_config.enr_quic6_port = Some(enr_quic_port_ipv6);
        }

        if !boot_nodes.is_empty() {
            network_config.boot_nodes_enr = boot_nodes;
        }

        if !libp2p_nodes.is_empty() {
            network_config.libp2p_nodes = libp2p_nodes;
        }

        if Feature::SubscribeToAllAttestationSubnets.is_enabled() {
            network_config.subscribe_all_subnets = true;
        }

        if Feature::SubscribeToAllDataColumnSubnets.is_enabled() {
            network_config.subscribe_all_data_column_subnets = true;
        }

        // Setting this in the last place to overwrite any changes to table filter from other CLI options
        if enable_private_discovery {
            network_config.discv5_config.table_filter = |_| true;
        }

        network_config
    }

    fn print_upnp_warning(&self) {
        if !self.disable_upnp {
            let mut manual_options = vec![];

            if self.enr_address.is_some() {
                manual_options.push("--enr-address");
            }

            if self.enr_address_ipv6.is_some() {
                manual_options.push("--enr-address-ipv6");
            }

            if self.enr_tcp_port.is_some() {
                manual_options.push("--enr-tcp-port");
            }

            if self.enr_tcp_port_ipv6.is_some() {
                manual_options.push("--enr-tcp-port-ipv6");
            }

            if self.enr_udp_port.is_some() {
                manual_options.push("--enr-udp-port");
            }

            if self.enr_udp_port_ipv6.is_some() {
                manual_options.push("--enr-udp-port-ipv6");
            }

            if !manual_options.is_empty() {
                warn_with_peers!(
                    "UPnP enabled with manual ENR settings: {}; \
                     manual ENR settings might be overridden by UPnP",
                    manual_options.join(", "),
                );
            }
        }
    }
}

#[derive(Debug, Derivative, Args)]
#[derivative(Default)]
struct SlasherOptions {
    /// Enable slasher
    /// [default: disabled]
    #[clap(long)]
    slashing_enabled: bool,

    /// Number of epochs for slasher to search for violations
    #[derivative(Default(value = "SlasherConfig::default().slashing_history_limit"))]
    #[clap(long, default_value_t = SlasherConfig::default().slashing_history_limit)]
    slashing_history_limit: u64,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "False positive. The `bool`s are independent."
)]
#[derive(Debug, Args)]
struct ValidatorOptions {
    /// Path to a directory containing EIP-2335 keystore files
    #[clap(long, requires("keystore_password_file"))]
    keystore_dir: Option<PathBuf>,

    /// Path to a directory containing passwords for keystore files
    #[clap(
        long,
        requires("keystore_dir"),
        conflicts_with("keystore_password_file")
    )]
    keystore_password_dir: Option<PathBuf>,

    /// Path to a file containing password for keystore files
    #[clap(
        long,
        requires("keystore_dir"),
        conflicts_with("keystore_password_dir")
    )]
    keystore_password_file: Option<PathBuf>,

    /// Path to a file containing password for decrypting imported keystores from API
    #[clap(long)]
    keystore_storage_password_file: Option<PathBuf>,

    /// Data format for communication with the builder API
    #[clap(long = "builder-format", default_value_t = BuilderApiFormat::default())]
    builder_api_format: BuilderApiFormat,

    /// [DEPRECATED] External block builder API URL
    #[clap(long)]
    builder_api_url: Option<RedactingUrl>,

    /// External block builder URL
    #[clap(long)]
    builder_url: Option<RedactingUrl>,

    /// Always use specified external block builder without checking for circuit breaker conditions
    #[clap(long)]
    builder_disable_checks: bool,

    /// Max allowed consecutive missing blocks (missing payloads post-Gloas) to trigger circuit breaker condition and switch to local execution engine for payload construction
    #[clap(long, default_value_t = DEFAULT_BUILDER_MAX_SKIPPED_SLOTS)]
    builder_max_skipped_slots: u64,

    /// Max allowed missing blocks (missing payloads post-Gloas) in the last rolling epoch to trigger circuit breaker condition and switch to local execution engine for payload construction
    #[clap(long, default_value_t = DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH)]
    builder_max_skipped_slots_per_epoch: u64,

    /// Percentage multiplier to apply to the builder's payload value when choosing between a builder payload header and payload from the paired execution node
    #[clap(long, default_value_t = ValidatorConfig::default().default_builder_boost_factor)]
    default_builder_boost_factor: Uint256,

    /// Default execution gas limit for all validators
    #[clap(long, default_value_t = PREFERRED_EXECUTION_GAS_LIMIT)]
    default_gas_limit: Gas,

    /// List of public keys to use from Web3Signer
    #[clap(long, num_args = 1.., value_delimiter = ',')]
    web3signer_public_keys: Vec<PublicKeyBytes>,

    /// Refetches keys from Web3Signer once every epoch. This overwrites changes done via Keymanager API for remote keys
    #[clap(long)]
    web3signer_refresh_keys_every_epoch: bool,

    /// [DEPRECATED] List of Web3Signer API URLs
    #[clap(long, num_args = 1..)]
    web3signer_api_urls: Vec<RedactingUrl>,

    /// List of Web3Signer URLs
    #[clap(long, num_args = 1..)]
    web3signer_urls: Vec<RedactingUrl>,

    /// Use validator key cache for faster startup
    #[clap(long)]
    use_validator_key_cache: bool,

    /// Number of epochs to keep slashing protection data for
    #[clap(long, default_value_t = DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT)]
    slashing_protection_history_limit: u64,

    /// Print reports about validator performance
    #[clap(long)]
    report_validator_performance: bool,

    /// Backfill custody groups
    #[clap(long)]
    no_custody_groups_backfill: bool,

    /// Disable additional 1 second wait before attesting for late blocks that are being processed at the start of the attest duty
    #[clap(long)]
    disable_wait_for_late_blocks: bool,
}

#[derive(Debug, Args)]
struct RemoteValidatorOptions {
    /// List of beacon node API URLs to perform validator duties against
    #[clap(long, num_args = 1..)]
    beacon_node_urls: Vec<RedactingUrl>,

    /// Perform validator duties against `--beacon-node-urls` only, without the built-in beacon node
    #[clap(
        long,
        requires = "beacon_node_urls",
        conflicts_with_all = ["http_address", "http_port", "http_allowed_origins", "timeout"],
    )]
    disable_local_beacon_node: bool,

    /// List of duties to publish to every beacon node rather than the first one; `all` covers
    /// every duty
    #[clap(
        long,
        value_delimiter = ',',
        requires = "beacon_node_urls",
        value_parser = published_duty_parser(),
    )]
    publish_to_every_node: Vec<PublishedDuty>,
}

fn published_duty_parser() -> impl TypedValueParser<Value = PublishedDuty> {
    PossibleValuesParser::new(PublishedDuty::VARIANTS).map(|duty| {
        duty.parse()
            .expect("value parser only accepts PublishedDuty variants")
    })
}

#[derive(Debug, Args)]
struct ValidatorApiOptions {
    /// Enable validator API
    #[clap(long)]
    enable_validator_api: bool,

    /// Validator API address
    #[clap(long, default_value_t = ValidatorApiConfig::default().address.ip())]
    validator_api_address: IpAddr,

    /// Listen port for validator API
    #[clap(long, default_value_t = ValidatorApiConfig::default().address.port())]
    validator_api_port: u16,

    /// List of Access-Control-Allow-Origin header values for the validator API server.
    /// Defaults to the listening URL of the validator API server.
    #[clap(long)]
    validator_api_allowed_origins: Vec<HeaderValue>,

    /// Validator API timeout in milliseconds
    #[clap(long, default_value_t = ValidatorApiConfig::default().timeout.as_millis().try_into().expect("ValidatorApiConfig default timeout is valid u64"))]
    validator_api_timeout: u64,

    /// Path to a file containing validator API auth token
    #[clap(long)]
    validator_api_token_file: Option<PathBuf>,
}

impl From<ValidatorApiOptions> for ValidatorApiConfig {
    fn from(validator_api_options: ValidatorApiOptions) -> Self {
        let ValidatorApiOptions {
            validator_api_address,
            validator_api_port,
            validator_api_allowed_origins,
            validator_api_timeout,
            validator_api_token_file,
            ..
        } = validator_api_options;

        let Self {
            address,
            allow_origin,
            ..
        } = Self::with_address(validator_api_address, validator_api_port);

        Self {
            address,
            timeout: Duration::from_millis(validator_api_timeout),
            allow_origin: headers_to_allow_origin(validator_api_allowed_origins)
                .unwrap_or(allow_origin),
            token_file: validator_api_token_file,
        }
    }
}

#[derive(Debug, Clone, Copy, Sequence, ValueEnum)]
enum Network {
    #[cfg(any(feature = "network-mainnet", test))]
    Mainnet,
    #[cfg(any(feature = "network-sepolia", test))]
    Sepolia,
    #[cfg(any(feature = "network-holesky", test))]
    Holesky,
    #[cfg(any(feature = "network-hoodi", test))]
    Hoodi,
    Custom,
}

impl Default for Network {
    fn default() -> Self {
        enum_iterator::first::<Self>().expect("Custom variant should always be present")
    }
}

impl Network {
    const fn predefined_network(self) -> Option<PredefinedNetwork> {
        match self {
            #[cfg(any(feature = "network-mainnet", test))]
            Self::Mainnet => Some(PredefinedNetwork::Mainnet),
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => Some(PredefinedNetwork::Sepolia),
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => Some(PredefinedNetwork::Holesky),
            #[cfg(any(feature = "network-hoodi", test))]
            Self::Hoodi => Some(PredefinedNetwork::Hoodi),
            Self::Custom => None,
        }
    }
}

impl GrandineArgs {
    // This is not a `TryFrom` impl because this has side effects.
    #[expect(clippy::too_many_lines)]
    pub fn try_into_config(self) -> Result<GrandineConfig> {
        let Self {
            chain_options,
            beacon_node_options,
            http_api_options,
            mut network_config_options,
            validator_options,
            remote_validator_options,
            validator_api_options,
            graffiti,
            disable_blockprint_graffiti,
            mut features,
            command,
            ..
        } = self;

        let ChainOptions {
            network,
            mut configuration_file,
            configuration_directory,
            verify_phase0_preset_file,
            verify_altair_preset_file,
            verify_bellatrix_preset_file,
            verify_capella_preset_file,
            verify_deneb_preset_file,
            verify_electra_preset_file,
            verify_fulu_preset_file,
            verify_configuration_file,
            terminal_total_difficulty_override,
            terminal_block_hash_override,
            terminal_block_hash_activation_epoch_override,
            mut deposit_contract_starting_block,
            mut genesis_state_file,
            genesis_state_download_url,
        } = chain_options;

        let telemetry_config = beacon_node_options.telemetry_config();

        let BeaconNodeOptions {
            max_empty_slots,
            max_events,
            checkpoint_sync_url,
            data_availability_window,
            eth1_rpc_urls,
            force_checkpoint_sync,
            force_reset_beacon_db,
            data_dir,
            store_directory,
            network_dir,
            database_size,
            eth1_database_size,
            archival_epoch_interval,
            archive_storage,
            prune_storage,
            unfinalized_states_in_memory,
            reconstruction_delay,
            request_timeout,
            max_epochs_to_retain_states_in_cache,
            state_cache_lock_timeout,
            state_slot,
            semi_supernode,
            supernode,
            subscribe_all_subnets,
            suggested_fee_recipient,
            jwt_id,
            jwt_secret,
            jwt_version,
            back_sync,
            mut back_sync_enabled,
            metrics_enabled,
            metrics_address,
            metrics_port,
            metrics_update_interval,
            remote_metrics_url,
            track_liveness,
            detect_doppelgangers,
            in_memory,
            kzg_backend,
            blacklisted_blocks,
            sync_without_reconstruction,
            ..
        } = beacon_node_options;

        // let SlasherOptions {
        //     slashing_enabled,
        //     slashing_history_limit,
        // } = slasher_options;

        let slashing_enabled = false;
        let slashing_history_limit = SlasherConfig::default().slashing_history_limit;

        let ValidatorOptions {
            keystore_dir,
            keystore_password_dir,
            keystore_password_file,
            keystore_storage_password_file,
            builder_api_format,
            builder_api_url,
            builder_url,
            builder_disable_checks,
            builder_max_skipped_slots,
            builder_max_skipped_slots_per_epoch,
            default_builder_boost_factor,
            default_gas_limit,
            use_validator_key_cache,
            web3signer_public_keys,
            web3signer_refresh_keys_every_epoch,
            web3signer_api_urls,
            web3signer_urls,
            slashing_protection_history_limit,
            report_validator_performance,
            no_custody_groups_backfill,
            disable_wait_for_late_blocks,
        } = validator_options;

        let RemoteValidatorOptions {
            beacon_node_urls,
            disable_local_beacon_node,
            publish_to_every_node,
        } = remote_validator_options;

        // Without the built-in node liveness comes from the remote beacon nodes.
        if detect_doppelgangers && !disable_local_beacon_node {
            ensure!(
                track_liveness,
                Error::DoppelgangerDetectionRequiresLivenessTracking,
            );
        }

        if in_memory {
            warn_with_peers!(
                "running Grandine in in-memory mode; \
                 no data will be stored on disk; \
                 all data will be lost on exit",
            );
        }

        // There's technically nothing wrong with this, but the user may have made a mistake.
        if configuration_file.is_some() && verify_configuration_file.is_some() {
            warn_with_peers!("both --configuration-file and --verify-configuration-file specified");
        }

        if remote_metrics_url.is_some() && !metrics_enabled {
            warn_with_peers!(
                "remote metrics enabled without ---metrics. \
                 Network, system and process metrics will not be available"
            );
        }

        if let Some(directory) = configuration_directory {
            configuration_file = configuration_file
                .inspect(|_| {
                    warn_with_peers!(
                        "both --configuration-directory and --configuration-file specified; \
                         --configuration-file will take precedence",
                    );
                })
                .or_else(|| Some(directory.join(CONFIG_FILE)));

            deposit_contract_starting_block = match deposit_contract_starting_block {
                Some(number) => {
                    warn_with_peers!(
                        "both --configuration-directory and --deposit-contract-starting-block specified; \
                         --deposit-contract-starting-block will take precedence",
                    );
                    Some(number)
                }
                None => {
                    let bytes = fs_err::read(directory.join(DEPOSIT_CONTRACT_BLOCK_FILE))?;
                    Some(serde_yaml::from_slice(bytes.as_slice())?)
                }
            };

            genesis_state_file = genesis_state_file
                .inspect(|_| {
                    warn_with_peers!(
                        "both --configuration-directory and --genesis-state-file specified; \
                         --genesis-state-file will take precedence",
                    );
                })
                .or_else(|| Some(directory.join(GENESIS_STATE_FILE)));

            if network_config_options.boot_nodes.is_empty() {
                let bytes = fs_err::read_to_string(directory.join(PLAIN_BOOTNODES_FILE))?;

                network_config_options.boot_nodes =
                    config_dir::parse_plain_bootnodes(bytes.as_str())?;
            } else {
                warn_with_peers!(
                    "both --configuration-directory and --boot-nodes specified; \
                     --boot-nodes will take precedence",
                );
            }
        }

        let predefined_network = network.predefined_network();

        // A validator without the built-in node takes genesis from the beacon nodes it performs
        // duties against, so it needs neither a genesis state nor an execution layer to build one.
        if cfg!(not(feature = "embed"))
            && predefined_network.is_none()
            && eth1_rpc_urls.is_empty()
            && !disable_local_beacon_node
        {
            ensure!(
                genesis_state_file.is_some(),
                Error::MissingEth1RpcUrlsForCustomWithoutGenesisState,
            );
        }

        let mut chain_config = match configuration_file {
            Some(path) => {
                let bytes = fs_err::read(path)?;
                serde_yaml::from_slice(bytes.as_slice())?
            }
            None => network
                .predefined_network()
                .ok_or(Error::MissingConfigurationFileForCustom)?
                .chain_config(),
        };

        let unknown = core::mem::take(&mut chain_config.unknown);

        if !unknown.is_empty() {
            warn_with_peers!(
                "unknown configuration variables: [{:?}]",
                unknown.keys().join(", "),
            );
        }

        verify_preset(
            &chain_config,
            &chain_config.preset_base.phase0_preset(),
            verify_phase0_preset_file,
            Phase::Phase0,
        )?;

        verify_preset(
            &chain_config,
            &chain_config.preset_base.altair_preset(),
            verify_altair_preset_file,
            Phase::Altair,
        )?;

        verify_preset(
            &chain_config,
            &chain_config.preset_base.bellatrix_preset(),
            verify_bellatrix_preset_file,
            Phase::Bellatrix,
        )?;

        verify_preset(
            &chain_config,
            &chain_config.preset_base.capella_preset(),
            verify_capella_preset_file,
            Phase::Capella,
        )?;

        verify_preset(
            &chain_config,
            &chain_config.preset_base.deneb_preset(),
            verify_deneb_preset_file,
            Phase::Deneb,
        )?;

        verify_preset(
            &chain_config,
            &chain_config.preset_base.electra_preset(),
            verify_electra_preset_file,
            Phase::Electra,
        )?;

        verify_preset(
            &chain_config,
            &chain_config.preset_base.fulu_preset(),
            verify_fulu_preset_file,
            Phase::Fulu,
        )?;

        verify_config(&chain_config, verify_configuration_file)?;

        // Overriding after verifying seems more useful, though neither is strictly better.
        if let Some(value) = terminal_total_difficulty_override {
            chain_config.terminal_total_difficulty = value;
        }

        if let Some(value) = terminal_block_hash_override {
            chain_config.terminal_block_hash = value;
        }

        if let Some(value) = terminal_block_hash_activation_epoch_override {
            chain_config.terminal_block_hash_activation_epoch = value;
        }

        chain_config.validate()?;

        let directories = Arc::new(
            Directories {
                data_dir,
                store_directory,
                network_dir,
                validator_dir: None,
                secrets_dir: None,
            }
            .set_defaults(&chain_config),
        );

        // enable global feature for easier checking
        if metrics_enabled {
            features.push(Feature::PrometheusMetrics);
        }

        // If `--remote-metrics-url` is not specified (for beaconcha.in style metrics) and
        // `--metrics` option (for tracking prometheus metrics) is not enabled and
        // `ServeLeakyEndpoints` (for `GET /system/stats`) is not enabled,
        // there is no need to run the metrics service.
        let metrics_service_config = (remote_metrics_url.is_some()
            || features.contains(&Feature::PrometheusMetrics)
            || features.contains(&Feature::ServeLeakyEndpoints))
        .then(|| MetricsServiceConfig {
            directories: directories.clone_arc(),
            metrics_update_interval: Duration::from_secs(metrics_update_interval),
            remote_metrics_url,
        });

        let metrics_server_config = metrics_enabled.then_some(MetricsServerConfig {
            metrics_address,
            metrics_port,
            timeout: request_timeout,
        });

        let mut services = vec![];

        let validator_api_config = validator_api_options
            .enable_validator_api
            .then(|| ValidatorApiConfig::from(validator_api_options));

        // The beacon node HTTP API is the built-in node's.
        let http_api_config = if disable_local_beacon_node {
            None
        } else {
            Option::<HttpApiConfig>::from(http_api_options)
        };

        if let Some(http_api_config) = http_api_config.as_ref() {
            services.push((http_api_config.address, "HTTP API"));
        }

        if let Some(metrics_server_config) = metrics_server_config.as_ref() {
            services.push((SocketAddr::from(metrics_server_config), "Metrics API"));
        }

        if let Some(validator_api_config) = validator_api_config.as_ref() {
            services.push((validator_api_config.address, "Validator API"));
        }

        for ((address1, service1), (address2, service2)) in
            services.into_iter().tuple_combinations()
        {
            ensure!(
                address1 != address2,
                Error::IdenticalAddresses { service1, service2 },
            );
        }

        let metrics = if metrics_enabled {
            let metrics = Metrics::new()?;
            metrics.register_with_default_metrics()?;
            let metrics = Arc::new(metrics);
            METRICS.get_or_init(|| metrics.clone_arc());
            Some(metrics)
        } else {
            None
        };

        let metrics_config = MetricsConfig {
            metrics,
            metrics_server_config,
            metrics_service_config,
        };

        let validators = keystore_dir
            .zip(keystore_password_file.or(keystore_password_dir))
            .map(|(keystore_dir, keystore_password_file)| Validators {
                keystore_dir,
                keystore_password_file,
            });

        let minimum = StoreConfig::min_unfinalized_states_in_memory(&chain_config);

        ensure!(
            unfinalized_states_in_memory >= minimum,
            Error::UnfinalizedStatesInMemoryTooLow { minimum },
        );

        let features = features
            .into_iter()
            .chain(subscribe_all_subnets.then_some(Feature::SubscribeToAllAttestationSubnets))
            .chain(subscribe_all_subnets.then_some(Feature::SubscribeToAllSyncCommitteeSubnets))
            .chain(supernode.then_some(Feature::SubscribeToAllDataColumnSubnets))
            .collect::<Vec<_>>();

        // enabling these features here, because it being used in below network config conversion
        for feature in &features {
            feature.enable();
        }

        let auth_options = AuthOptions {
            secrets_path: jwt_secret,
            id: jwt_id,
            version: jwt_version,
        };

        if back_sync {
            warn_with_peers!("--back_sync option is deprecated. Use --back-sync instead.");
            back_sync_enabled = true;
        }

        let builder_url = if builder_url.is_none() && builder_api_url.is_some() {
            warn_with_peers!("--builder-api-url option is deprecated. Use --builder-url instead.");
            builder_api_url
        } else {
            builder_url
        };

        let builder_config = builder_url.map(|url| BuilderConfig {
            builder_api_format,
            builder_api_url: url,
            builder_disable_checks,
            builder_max_skipped_slots,
            builder_max_skipped_slots_per_epoch,
        });

        let builder_circuit_breaker = BuilderCircuitBreakerConfig {
            disabled: builder_disable_checks,
            max_skipped_slots: builder_max_skipped_slots,
            max_skipped_slots_per_epoch: builder_max_skipped_slots_per_epoch,
        };

        let web3signer_urls = if web3signer_urls.is_empty() && !web3signer_api_urls.is_empty() {
            warn_with_peers!(
                "--web3signer-api-urls option is deprecated. Use --web3signer-urls instead."
            );
            web3signer_api_urls
        } else {
            web3signer_urls
        };

        // Each CLI URL loads every key it serves; `--web3signer-public-keys` is a global allow-list
        // narrowing that. `validators.yml` entries add their own per-URL keys on top (see
        // `runtime`), and only those entries — not the global list — warn if a key is not served.
        let web3signer_config = Web3SignerConfig {
            allow_to_reload_keys: web3signer_refresh_keys_every_epoch,
            public_keys: web3signer_public_keys.into_iter().collect(),
            urls: web3signer_urls
                .into_iter()
                .map(|url| {
                    (
                        url,
                        Web3SignerUrlPolicy {
                            load_all: true,
                            required: HashSet::new(),
                        },
                    )
                })
                .collect(),
        };

        let custody_mode = if supernode {
            CustodyMode::Super
        } else if semi_supernode {
            CustodyMode::Semi
        } else {
            CustodyMode::Minimal
        };

        let storage_mode = if prune_storage {
            StorageMode::Prune
        } else if archive_storage {
            StorageMode::Archive
        } else {
            StorageMode::Standard {
                custom_data_availability_window: data_availability_window,
            }
        };

        let storage_config = StorageConfig {
            in_memory,
            db_size: database_size,
            directories: directories.clone_arc(),
            eth1_db_size: eth1_database_size,
            archival_epoch_interval,
            reset_databases: force_reset_beacon_db,
            storage_mode,
        };

        network_config_options.print_upnp_warning();

        Ok(GrandineConfig {
            predefined_network,
            chain_config: Arc::new(chain_config),
            deposit_contract_starting_block,
            genesis_state_file,
            genesis_state_download_url,
            checkpoint_sync_url,
            force_checkpoint_sync,
            back_sync_enabled,
            eth1_rpc_urls,
            data_dir: directories.data_dir.clone().unwrap_or_default(),
            validators,
            keystore_storage_password_file,
            graffiti,
            disable_blockprint_graffiti,
            max_empty_slots,
            suggested_fee_recipient: suggested_fee_recipient.unwrap_or(GRANDINE_DONATION_ADDRESS),
            default_builder_boost_factor,
            default_gas_limit,
            network_config: network_config_options.into_config(
                network,
                directories.network_dir.clone().unwrap_or_default(),
                metrics_enabled,
                in_memory,
            ),
            storage_config,
            unfinalized_states_in_memory,
            reconstruction_delay: Duration::from_millis(reconstruction_delay),
            request_timeout: Duration::from_millis(request_timeout),
            max_epochs_to_retain_states_in_cache,
            state_cache_lock_timeout: Duration::from_millis(state_cache_lock_timeout),
            command,
            slashing_enabled,
            slashing_history_limit,
            state_slot,
            auth_options,
            builder_config,
            builder_circuit_breaker,
            web3signer_config,
            http_api_config,
            max_events,
            metrics_config,
            telemetry_config,
            track_liveness,
            detect_doppelgangers,
            use_validator_key_cache,
            slashing_protection_history_limit,
            in_memory,
            validator_api_config,
            kzg_backend,
            blacklisted_blocks: blacklisted_blocks.into_iter().collect(),
            report_validator_performance,
            backfill_custody_groups: !no_custody_groups_backfill,
            sync_without_reconstruction,
            custody_mode,
            disable_wait_for_late_blocks,
            beacon_node_urls,
            disable_local_beacon_node,
            publish_to_every_node,
        })
    }

    #[must_use]
    pub fn clap_error(message: impl core::fmt::Display) -> ClapError {
        Self::command().error(ErrorKind::ValueValidation, message)
    }

    /// Parse `cli_args`; if `--args-file` was given, merge that YAML file's
    /// options underneath the command line and re-parse.
    ///
    /// The command line always wins: any option it set is dropped from the file
    /// (scalars and lists alike), and the remaining file-derived tokens are
    /// spliced in right after the program name so subcommands are preserved.
    /// `cli_args` must start with the program name, as `std::env::args_os` does.
    pub fn parse_and_merge_args_file(cli_args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let cli_args = cli_args.into_iter().collect::<Vec<_>>();

        // Best-effort parse to discover `--args-file` and which options the
        // command line set, without enforcing `requires`/`conflicts` yet — those
        // run on the merged tokens in the strict parse below, so a constraint
        // may be satisfied by the file. `ignore_errors` also skips unknown args
        // and missing values; typos still surface in the final strict parse.
        let command = Self::command();
        let matches = command
            .clone()
            .ignore_errors(true)
            .try_get_matches_from(cli_args.iter().cloned())?;

        let Some(path) = matches.get_one::<PathBuf>("args_file").cloned() else {
            // No file — hand off to the normal strict parse so errors and help
            // are produced exactly as without `--args-file`.
            return Self::try_parse_from(cli_args).map_err(Into::into);
        };

        let yaml = fs_err::read_to_string(&path).map_err(Self::clap_error)?;
        let groups = yaml_to_arg_groups(&yaml).map_err(Self::clap_error)?;

        // Long names of options the command line set. The args file may not
        // override these, which gives lists the same override semantics as
        // scalars (the file's value is dropped, not appended).
        let cli_set_longs = command
            .get_arguments()
            .filter(|arg| {
                matches.value_source(arg.get_id().as_str()) == Some(ValueSource::CommandLine)
            })
            .filter_map(Arg::get_long)
            .map(str::to_owned)
            .collect::<HashSet<_>>();

        let file_tokens = groups
            .into_iter()
            .filter(|(long, _)| !cli_set_longs.contains(long))
            .flat_map(|(_, tokens)| tokens)
            .map(OsString::from);

        let mut cli_args = cli_args.into_iter();
        let program = cli_args
            .next()
            .unwrap_or_else(|| APPLICATION_NAME.to_owned().into());

        let args = core::iter::once(program).chain(file_tokens).chain(cli_args);

        Self::try_parse_from(args).map_err(Into::into)
    }

    #[must_use]
    pub fn data_dir(&self) -> Option<PathBuf> {
        (!self.beacon_node_options.in_memory)
            .then(|| directories::data_directory(self.beacon_node_options.data_dir.as_ref()))
    }

    #[must_use]
    pub fn telemetry_config(&self) -> Option<TelemetryConfig> {
        self.beacon_node_options.telemetry_config()
    }
}

#[derive(Debug, Display)]
#[display("{variable:?}: expected {expected} but found {actual}")]
struct Difference {
    variable: String,
    expected: Value,
    actual: Value,
}

#[derive(Debug, Error)]
enum Error {
    // `clap` cannot check this. `clap::builder::PossibleValue` does not have a `requires` method.
    #[error("--configuration-file must be specified when connecting to custom network")]
    MissingConfigurationFileForCustom,
    #[error(
        "--eth1-rpc-urls must be specified when connecting \
         to custom network without --genesis-state-file"
    )]
    MissingEth1RpcUrlsForCustomWithoutGenesisState,
    #[error(
        "--track-liveness must be specified for --detect-doppelgangers \
         with the built-in beacon node"
    )]
    DoppelgangerDetectionRequiresLivenessTracking,
    #[error(
        "{phase} variables in {preset_name} preset do not match file ({})",
        differences.iter().join(", "),
    )]
    PresetMismatch {
        preset_name: PresetName,
        phase: Phase,
        differences: Vec<Difference>,
    },
    #[error(
        "variables in configuration do not match file ({})",
        differences.iter().join(", "),
    )]
    ConfigMismatch { differences: Vec<Difference> },
    #[error("--unfinalized-states-in-memory must be at least {minimum}")]
    UnfinalizedStatesInMemoryTooLow { minimum: u64 },
    #[error("identical addresses specified for {service1} and {service2}")]
    IdenticalAddresses {
        service1: &'static str,
        service2: &'static str,
    },
}

fn verify_preset<T: DeserializeOwned + Serialize>(
    chain_config: &ChainConfig,
    preset: &T,
    file_path: Option<PathBuf>,
    phase: Phase,
) -> Result<()> {
    let differences = compare_with_file(preset, file_path)?;

    ensure!(
        differences.is_empty(),
        Error::PresetMismatch {
            preset_name: chain_config.preset_base,
            phase,
            differences,
        },
    );

    Ok(())
}

fn verify_config(chain_config: &ChainConfig, file_path: Option<PathBuf>) -> Result<()> {
    let differences = compare_with_file(chain_config, file_path)?;

    ensure!(
        differences.is_empty(),
        Error::ConfigMismatch { differences },
    );

    info_with_peers!("configuration matches the one in configuration file");

    Ok(())
}

// We implement the comparison ourselves with the help of `itertools`.
// `assert-json-diff` outputs differences as a `String` and hardcodes the format.
// `comparable` requires a lot of boilerplate in type definitions.
// `similar-asserts` diffs values as text rather than structurally.
// `treediff` is the closest to what we need but too general.
// Our use case is so limited that all we did was hack around it.
fn compare_with_file<T: DeserializeOwned + Serialize>(
    actual_value: &T,
    file_path: Option<PathBuf>,
) -> Result<Vec<Difference>> {
    let Some(file_path) = file_path else {
        return Ok(vec![]);
    };

    // The file used for verification may have missing variables. Fill in default values by
    // deserializing into `T` instead of `serde_yaml::Value`, then serializing again.
    let expected_bytes = fs_err::read(file_path)?;
    let expected_value = serde_yaml::from_slice::<T>(expected_bytes.as_slice())?;

    // Serialize to `serde_json::Value` instead of `serde_yaml::Value`.
    // `serde_json::Value` and `serde_json::Map` make the comparison easier.
    let expected_json = serde_json::to_value(expected_value)?;
    let actual_json = serde_json::to_value(actual_value)?;

    // Sort explicitly in case the `preserve_order` feature of `serde_json` is enabled.
    //
    // `sorted_by_key` cannot be used for this. See:
    // <https://stackoverflow.com/questions/47121985/why-cant-i-use-a-key-function-that-returns-a-reference-when-sorting-a-vector-wi/47126516#47126516>
    let expected_variables = match expected_json {
        Value::Object(map) => map.into_iter().sorted_by(|(a, _), (b, _)| a.cmp(b)),
        _ => unreachable!("Preset* and ChainConfig are structs with named fields"),
    };

    let actual_variables = match actual_json {
        Value::Object(map) => map.into_iter().sorted_by(|(a, _), (b, _)| a.cmp(b)),
        _ => unreachable!("Preset* and ChainConfig are structs with named fields"),
    };

    let differences = itertools::merge_join_by(
        expected_variables,
        actual_variables,
        |(expected_variable, _), (actual_variable, _)| expected_variable.cmp(actual_variable),
    )
    .filter_map(|either_or_both| match either_or_both {
        EitherOrBoth::Both((_, expected), (_, actual)) if expected == actual => None,
        EitherOrBoth::Both((variable, expected), (_, actual)) => Some(Difference {
            variable,
            expected,
            actual,
        }),
        EitherOrBoth::Left((variable, expected)) => Some(Difference {
            variable,
            expected,
            actual: Value::Null,
        }),
        EitherOrBoth::Right((variable, actual)) => Some(Difference {
            variable,
            expected: Value::Null,
            actual,
        }),
    })
    .collect();

    Ok(differences)
}

fn headers_to_allow_origin(allowed_origins: Vec<HeaderValue>) -> Option<AllowOrigin> {
    if !allowed_origins.is_empty() {
        // `tower_http::cors::AllowOrigin::list` panics if a wildcard is passed to it.
        if allowed_origins.contains(&HeaderValue::from_static("*")) {
            if allowed_origins.len() > 1 {
                warn_with_peers!(
                    "extra values of Access-Control-Allow-Origin specified along with a wildcard; \
                    only the wildcard will be used",
                );
            }

            return Some(AllowOrigin::any());
        }

        return Some(AllowOrigin::list(allowed_origins));
    }

    None
}

/// Turn a flat YAML mapping into clap-style tokens, grouped per option under
/// its normalized long name (e.g. `http-port`).
///
/// Keys are long option names (`_` is accepted as an alias for `-`). Booleans
/// become bare flags (`false` produces no tokens); scalars become
/// `--key value`; sequences repeat the flag once per element. Grouping lets
/// callers drop a whole option, for instance when the command line already set
/// it. Unknown keys are passed through and left for the argument parser to
/// reject.
fn yaml_to_arg_groups(yaml: &str) -> Result<Vec<(String, Vec<String>)>> {
    let mapping = serde_yaml::from_str::<serde_yaml::Mapping>(yaml)?;
    let mut groups = Vec::new();

    for (key, value) in &mapping {
        let key = key
            .as_str()
            .ok_or_else(|| anyhow!("config option keys must be strings"))?;

        let long = key.replace('_', "-");
        let flag = format!("--{long}");
        let mut tokens = Vec::new();

        match value {
            serde_yaml::Value::Bool(true) => tokens.push(flag),
            serde_yaml::Value::Bool(false) => {}
            serde_yaml::Value::Number(_) | serde_yaml::Value::String(_) => {
                tokens.push(flag);
                tokens.push(scalar_to_string(value, key)?);
            }
            // Repeat the flag once per element, e.g. `--boot-nodes a --boot-nodes b`.
            serde_yaml::Value::Sequence(values) => {
                for value in values {
                    tokens.push(flag.clone());
                    tokens.push(scalar_to_string(value, key)?);
                }
            }
            serde_yaml::Value::Null
            | serde_yaml::Value::Mapping(_)
            | serde_yaml::Value::Tagged(_) => {
                bail!("config option `{key}` has an unsupported value")
            }
        }

        groups.push((long, tokens));
    }

    Ok(groups)
}

/// Render a scalar YAML value as a command-line option value.
fn scalar_to_string(value: &serde_yaml::Value, key: &str) -> Result<String> {
    match value {
        serde_yaml::Value::Bool(bool) => Ok(bool.to_string()),
        serde_yaml::Value::Number(number) => Ok(number.to_string()),
        serde_yaml::Value::String(string) => Ok(string.clone()),
        serde_yaml::Value::Null
        | serde_yaml::Value::Sequence(_)
        | serde_yaml::Value::Mapping(_)
        | serde_yaml::Value::Tagged(_) => {
            bail!("config option `{key}` has an unsupported value")
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::io::Write as _;

    use ssz::Uint256;
    use tempfile::NamedTempFile;

    use crate::commands::InterchangeCommand;

    use super::*;

    #[test]
    fn network_config_options() {
        let config = config_from_args(["--discovery-port", "8888"]);

        assert_eq!(config.network_config.libp2p_nodes, []);
        assert_eq!(
            config
                .network_config
                .listen_addrs()
                .v4()
                .map(|addr| addr.disc_port),
            Some(8888),
        );
        assert_eq!(
            config
                .network_config
                .listen_addrs()
                .v4()
                .map(|addr| addr.tcp_port),
            Some(DEFAULT_LIBP2P_IPV4_PORT.into()),
        );
        assert_eq!(config.network_config.enr_udp4_port, None);
        assert_eq!(
            config.network_config.network_dir,
            Some(
                dirs::home_dir()
                    .expect("home directory should be accessible")
                    .join(".grandine/mainnet/network"),
            ),
        );
    }

    #[test]
    fn listen_address_defaults_to_unspecified_ipv4() {
        let config = config_from_args([]);
        let listen_addrs = config.network_config.listen_addrs();

        assert_eq!(
            listen_addrs.v4().map(|addr| addr.addr),
            Some(Ipv4Addr::UNSPECIFIED),
        );

        assert_eq!(listen_addrs.v6().map(|addr| addr.addr), None);
    }

    #[test]
    fn listen_address_ipv4_only_uses_given_address() {
        let config = config_from_args(["--listen-address", "127.0.0.1"]);
        let listen_addrs = config.network_config.listen_addrs();

        let v4 = listen_addrs
            .v4()
            .expect("IPv4 listen address should be set");

        assert_eq!(v4.addr, Ipv4Addr::LOCALHOST);
        assert_eq!(v4.tcp_port, DEFAULT_LIBP2P_IPV4_PORT.get());
        assert_eq!(v4.disc_port, DEFAULT_LIBP2P_IPV4_PORT.get());
        assert_eq!(v4.quic_port, DEFAULT_LIBP2P_QUIC_IPV4_PORT.get());
        assert_eq!(listen_addrs.v6().map(|addr| addr.addr), None);
    }

    #[test]
    fn listen_address_ipv6_defaults_to_dual_stack() {
        let config = config_from_args(["--listen-address-ipv6", "::1"]);
        let listen_addrs = config.network_config.listen_addrs();

        assert_eq!(
            listen_addrs.v4().map(|addr| addr.addr),
            Some(Ipv4Addr::UNSPECIFIED),
        );

        assert_eq!(
            listen_addrs.v6().map(|addr| addr.addr),
            Some(Ipv6Addr::LOCALHOST),
        );
    }

    #[test]
    fn disable_ipv4_produces_ipv6_only() {
        let config = config_from_args(["--disable-ipv4", "--listen-address-ipv6", "::1"]);
        let listen_addrs = config.network_config.listen_addrs();

        assert_eq!(listen_addrs.v4().map(|addr| addr.addr), None);

        let v6 = listen_addrs
            .v6()
            .expect("IPv6 listen address should be set");

        assert_eq!(v6.addr, Ipv6Addr::LOCALHOST);
        assert_eq!(v6.tcp_port, DEFAULT_LIBP2P_IPV6_PORT.get());
        assert_eq!(v6.disc_port, DEFAULT_LIBP2P_IPV6_PORT.get());
        assert_eq!(v6.quic_port, DEFAULT_LIBP2P_QUIC_IPV6_PORT.get());

        // The ENR must not advertise an IPv4 TCP port when IPv4 is disabled.
        assert_eq!(config.network_config.enr_tcp4_port, None);
    }

    #[test]
    fn disable_ipv4_requires_listen_address_ipv6() {
        try_config_from_args(["--disable-ipv4"])
            .expect_err("--disable-ipv4 requires --listen-address-ipv6");
    }

    #[test]
    fn disable_ipv4_conflicts_with_listen_address() {
        try_config_from_args([
            "--disable-ipv4",
            "--listen-address",
            "127.0.0.1",
            "--listen-address-ipv6",
            "::1",
        ])
        .expect_err("--disable-ipv4 conflicts with --listen-address");
    }

    #[test]
    fn disable_ipv4_conflicts_with_enr_tcp_port() {
        try_config_from_args([
            "--disable-ipv4",
            "--listen-address-ipv6",
            "::1",
            "--enr-tcp-port",
            "9000",
        ])
        .expect_err("--disable-ipv4 conflicts with --enr-tcp-port");
    }

    #[test]
    fn listen_address_dual_stack_uses_both_addresses() {
        let config = config_from_args([
            "--listen-address",
            "127.0.0.1",
            "--listen-address-ipv6",
            "::1",
        ]);

        let listen_addrs = config.network_config.listen_addrs();

        assert_eq!(
            listen_addrs.v4().map(|addr| addr.addr),
            Some(Ipv4Addr::LOCALHOST),
        );

        assert_eq!(
            listen_addrs.v6().map(|addr| addr.addr),
            Some(Ipv6Addr::LOCALHOST),
        );
    }

    #[test]
    fn back_sync_disabled_by_default() {
        let config = config_from_args([]);
        assert!(!config.back_sync_enabled);
    }

    #[test]
    fn default_builder_circuit_breaker_settings() {
        let config = config_from_args([]);

        assert_eq!(
            config.builder_circuit_breaker,
            BuilderCircuitBreakerConfig::default(),
        );
    }

    #[test]
    fn builder_disable_checks_disables_the_gloas_circuit_breaker() {
        let config = config_from_args(["--builder-disable-checks"]);

        assert!(config.builder_circuit_breaker.disabled);
    }

    #[test]
    fn skipped_slot_thresholds_are_shared_with_the_gloas_circuit_breaker() {
        let config = config_from_args([
            "--builder-max-skipped-slots",
            "5",
            "--builder-max-skipped-slots-per-epoch",
            "9",
        ]);

        assert_eq!(config.builder_circuit_breaker.max_skipped_slots, 5);
        assert_eq!(
            config.builder_circuit_breaker.max_skipped_slots_per_epoch,
            9,
        );
    }

    #[test]
    fn default_builder_boost_factor() {
        let config = config_from_args([]);
        assert_eq!(config.default_builder_boost_factor, Uint256::from_u64(100));
    }

    #[test]
    fn zero_default_builder_boost_factor() {
        let config = config_from_args(["--default-builder-boost-factor", "0"]);
        assert_eq!(config.default_builder_boost_factor, Uint256::ZERO);
    }

    #[test]
    fn custom_default_builder_boost_factor() {
        let config = config_from_args(["--default-builder-boost-factor", "200"]);
        assert_eq!(config.default_builder_boost_factor, Uint256::from_u64(200));
    }

    #[test]
    fn max_default_builder_boost_facot() {
        let config = config_from_args([
            "--default-builder-boost-factor",
            format!("{}", u64::MAX).as_str(),
        ]);

        assert_eq!(
            config.default_builder_boost_factor,
            Uint256::from_u64(u64::MAX)
        );
    }

    #[test]
    fn invalid_default_builder_boost_factor() {
        try_config_from_args(["--default-builder-boost-factor", "-100"])
            .expect_err("negative --default-builder-boost-factor is invalid");
    }

    #[test]
    fn supports_back_sync_flag() {
        let config = config_from_args(["--back-sync"]);
        assert!(config.back_sync_enabled);
    }

    #[test]
    fn supports_deprecated_back_sync_flag() {
        let config = config_from_args(["--back_sync"]);
        assert!(config.back_sync_enabled);
    }

    #[test]
    fn eth1_rpc_urls_single_value() {
        let config = config_from_args(["--eth1-rpc-urls", "http://localhost:8545"]);

        itertools::assert_equal(
            config.eth1_rpc_urls.iter().map(RedactingUrl::to_string),
            ["http://localhost:8545/"],
        );
    }

    #[test]
    fn eth1_rpc_urls_multiple_values() {
        let config = config_from_args([
            "--eth1-rpc-urls",
            "http://localhost:8545",
            "http://example.com:8545",
        ]);

        itertools::assert_equal(
            config.eth1_rpc_urls.iter().map(RedactingUrl::to_string),
            ["http://localhost:8545/", "http://example.com:8545/"],
        );
    }

    #[test]
    fn eth1_rpc_urls_multiple_occurrences() {
        let config = config_from_args([
            "--eth1-rpc-urls",
            "http://localhost:8545",
            "--eth1-rpc-urls",
            "http://example.com:8545",
        ]);

        itertools::assert_equal(
            config.eth1_rpc_urls.iter().map(RedactingUrl::to_string),
            ["http://localhost:8545/", "http://example.com:8545/"],
        );
    }

    #[test]
    fn eth1_rpc_urls_value_delimiter_not_allowed() {
        try_config_from_args([
            "--eth1-rpc-urls",
            "http://localhost:8545,http://example.com:8545",
        ])
        .expect_err("Url::from_str should fail");
    }

    #[test]
    fn default_store_directory() {
        let config = config_from_args([]);

        assert_eq!(
            config.storage_config.directories.store_directory,
            Some(
                dirs::home_dir()
                    .expect("home directory should be accessible")
                    .join(".grandine/mainnet/beacon")
            ),
        );
    }

    #[test]
    fn data_dir_option() {
        let config = config_from_args(["--data-dir", "/tmp"]);

        assert_eq!(
            config.storage_config.directories.store_directory,
            Some(PathBuf::from("/tmp/mainnet/beacon")),
        );
        assert_eq!(
            config.network_config.network_dir,
            Some(PathBuf::from("/tmp/mainnet/network")),
        );
    }

    #[test]
    fn default_network() {
        assert_eq!(
            config_from_args([]).predefined_network,
            Some(PredefinedNetwork::Mainnet),
        );
    }

    #[test]
    fn http_api_disabled() {
        let config = config_from_args(["--http-port", "1234", "--disable-http-api"]);
        assert!(config.http_api_config.is_none());
    }

    #[test]
    fn http_port_option() {
        let config = config_from_args(["--http-port", "1234"]);

        assert_eq!(
            config.http_api_config.map(|config| config.address),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)),
        );
    }

    #[test]
    fn http_allowed_origins_default() {
        let config = config_from_args([]);

        // `Debug` is the only way to inspect the contents of `AllowOrigin`.
        assert_eq!(
            format!(
                "{:?}",
                config.http_api_config.map(|config| config.allow_origin)
            ),
            "Some(List([\"http://127.0.0.1:5052\"]))",
        );
    }

    #[test]
    fn http_allowed_origins_option_single_occurrence() {
        let config = config_from_args(["--http-allowed-origins", "*"]);

        // `Debug` is the only way to inspect the contents of `AllowOrigin`.
        assert_eq!(
            format!(
                "{:?}",
                config.http_api_config.map(|config| config.allow_origin)
            ),
            "Some(Const(\"*\"))",
        );
    }

    #[test]
    fn http_allowed_origins_option_multiple_occurrences() {
        let config = config_from_args([
            "--http-allowed-origins",
            "http://localhost",
            "--http-allowed-origins",
            "http://example.com",
        ]);

        // `Debug` is the only way to inspect the contents of `AllowOrigin`.
        assert_eq!(
            format!(
                "{:?}",
                config.http_api_config.map(|config| config.allow_origin)
            ),
            "Some(List([\"http://localhost\", \"http://example.com\"]))",
        );
    }

    #[test]
    fn http_allowed_origins_option_multiple_occurrences_including_wildcard() {
        let config = config_from_args([
            "--http-allowed-origins",
            "http://localhost",
            "--http-allowed-origins",
            "http://example.com",
            "--http-allowed-origins",
            "*",
        ]);

        // `Debug` is the only way to inspect the contents of `AllowOrigin`.
        assert_eq!(
            format!(
                "{:?}",
                config.http_api_config.map(|config| config.allow_origin)
            ),
            "Some(Const(\"*\"))",
        );
    }

    #[test]
    fn telemetry_config_disabled_by_default() {
        let config = config_from_args([]);
        assert!(config.telemetry_config.is_none());
    }

    #[test]
    fn telemetry_config_options() {
        let config = config_from_args(["--telemetry-metrics-url", "http://localhost:4317"]);
        let telemetry_config = config.telemetry_config;

        assert_eq!(
            telemetry_config
                .as_ref()
                .map(|config| config.url.to_string()),
            Some("http://localhost:4317/".to_owned()),
        );

        assert_eq!(
            telemetry_config.as_ref().map(|config| config.trace_level),
            Some(Level::INFO),
        );

        assert_eq!(
            telemetry_config.map(|config| config.service_name),
            Some("Grandine".to_owned()),
        );
    }

    #[test]
    fn telemetry_config_custom_service_name() {
        let config = config_from_args([
            "--telemetry-metrics-url",
            "http://localhost:4317",
            "--telemetry-service-name",
            "grandine-bn",
            "--telemetry-level",
            "debug",
        ]);

        let telemetry_config = config.telemetry_config;

        assert_eq!(
            telemetry_config
                .as_ref()
                .map(|config| config.url.to_string()),
            Some("http://localhost:4317/".to_owned()),
        );

        assert_eq!(
            telemetry_config.as_ref().map(|config| config.trace_level),
            Some(Level::DEBUG),
        );

        assert_eq!(
            telemetry_config.map(|config| config.service_name),
            Some("grandine-bn".to_owned()),
        );
    }

    #[test]
    fn telemetry_config_service_name_without_url() {
        try_config_from_args(["--telemetry-service-name", "grandine-bn"]).expect_err(
            "passing --telemetry-service-name without --telemetry-metrics-url should fail",
        );
    }

    #[test]
    fn telemetry_level_without_url() {
        try_config_from_args(["--telemetry-level", "debug"])
            .expect_err("passing --telemetry-level without --telemetry-metrics-url should fail");
    }

    #[test]
    fn validator_api_address_and_port_option_api_enabled() {
        let config = config_from_args([
            "--enable-validator-api",
            "--validator-api-address",
            "0.0.0.0",
            "--validator-api-port",
            "1234",
        ]);

        assert_eq!(
            config
                .validator_api_config
                .as_ref()
                .map(|config| config.address),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1234)),
        );
    }

    #[test]
    fn validator_api_address_and_port_option_api_disabled() {
        let config = config_from_args([
            "--validator-api-address",
            "0.0.0.0",
            "--validator-api-port",
            "1234",
        ]);

        assert_eq!(
            config
                .validator_api_config
                .as_ref()
                .map(|config| config.address),
            None,
        );
    }

    #[test]
    fn validators_from_no_keystore_paths() {
        let config = config_from_args([]);
        assert_eq!(config.validators, None);
    }

    #[test]
    fn validators_from_keystore_password_file() {
        let config = config_from_args([
            "--keystore-dir",
            "dir_value",
            "--keystore-password-file",
            "pass_file",
        ]);

        assert_eq!(
            config.validators,
            Some(Validators {
                keystore_dir: PathBuf::from("dir_value"),
                keystore_password_file: PathBuf::from("pass_file"),
            }),
        );
    }

    #[test]
    fn validators_from_keystore_password_dir() {
        let config = config_from_args([
            "--keystore-dir",
            "dir_value",
            "--keystore-password-dir",
            "pass_dir",
        ]);

        assert_eq!(
            config.validators,
            Some(Validators {
                keystore_dir: PathBuf::from("dir_value"),
                keystore_password_file: PathBuf::from("pass_dir"),
            }),
        );
    }

    #[test]
    fn validators_from_keystore_password_dir_and_file() {
        try_config_from_args([
            "--keystore-dir",
            "dir_value",
            "--keystore-password-file",
            "pass_file",
            "--keystore-password-dir",
            "pass_dir",
        ])
        .expect_err(
            "passing both --keystore-password-file and --keystore-password-dir should fail",
        );
    }

    #[test]
    fn predefined_network_with_customizations() {
        let config = config_from_args([
            "--network",
            "sepolia",
            "--deposit-contract-starting-block",
            "0",
            "--genesis-state-file",
            "custom.ssz",
        ]);

        assert_eq!(config.predefined_network, Some(PredefinedNetwork::Sepolia));
        assert_eq!(config.deposit_contract_starting_block, Some(0));
        assert_eq!(config.genesis_state_file, Some(PathBuf::from("custom.ssz")));
    }

    #[test]
    fn custom_network_without_configuration_file() {
        try_config_from_args([
            "--network",
            "custom",
            "--eth1-rpc-urls",
            "http://localhost:8545",
        ])
        .expect_err("GrandineArgs::try_into_config should fail");
    }

    #[test]
    fn custom_network_without_genesis_state_file_or_eth1_rpc_urls() {
        let configuration_file =
            NamedTempFile::new().expect("creating a named temporary file should succeed");

        let configuration_file = configuration_file
            .path()
            .to_str()
            .expect("temporary file path should be a valid UTF-8 string");

        try_config_from_args([
            "--network",
            "custom",
            "--configuration-file",
            configuration_file,
        ])
        .expect_err("GrandineArgs::try_into_config should fail");
    }

    #[test]
    fn graffiti_option_single_value() {
        let config = config_from_args(["--graffiti", "**test-graffiti**"]);

        assert_eq!(
            config.graffiti,
            [b"**test-graffiti**\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".into()],
        );
    }

    #[test]
    fn graffiti_option_multiple_values() {
        let config = config_from_args([
            "--graffiti",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--graffiti",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--graffiti",
            "cccccccccccccccccccccccccccccccc",
        ]);

        assert_eq!(
            config.graffiti,
            [
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                b"cccccccccccccccccccccccccccccccc".into(),
            ],
        );
    }

    #[test]
    fn graffiti_option_too_long() {
        try_config_from_args(["--graffiti", "**test-graffiti******************"])
            .expect_err("parse_graffiti should fail");
    }

    #[test]
    fn incompatible_back_sync_and_storage_option() {
        try_config_from_args(["--back-sync", "--prune-storage"])
            .expect_err("incompatible back-sync and storage options should fail");
    }

    #[test]
    fn incompatible_storage_options() {
        try_config_from_args(["--archive-storage", "--prune-storage"])
            .expect_err("incompatible storage options should fail");
    }

    #[test]
    fn incompatible_data_column_subnet_subscription_alias_options() {
        try_config_from_args([
            "--subscribe-half-data-column-subnets",
            "--subscribe-all-data-column-subnets",
        ])
        .expect_err("incompatible data column subnet subscription aliased options should fail");
    }

    #[test]
    fn incompatible_data_column_subnet_subscription_options() {
        try_config_from_args(["--semi-supernode", "--supernode"])
            .expect_err("incompatible data column subnet subscription options should fail");
    }

    #[test]
    fn incompatible_data_column_subnet_subscription_options_with_alias_and_non_alias() {
        try_config_from_args(["--subscribe-half-data-column-subnets", "--supernode"]).expect_err(
            "incompatible data column subnet subscription options with alias \
            and non-alias should fail",
        );
    }

    #[test]
    fn interchange_import_subcommand() {
        let config = config_from_args(["interchange", "import", "test.json"]);

        assert_eq!(
            config.command,
            Some(GrandineCommand::Interchange(InterchangeCommand::Import {
                file_path: PathBuf::from("test.json"),
            })),
        );
    }

    #[test]
    fn interchange_export_subcommand() {
        let config = config_from_args(["interchange", "export", "test.json"]);

        assert_eq!(
            config.command,
            Some(GrandineCommand::Interchange(InterchangeCommand::Export {
                file_path: PathBuf::from("test.json"),
            })),
        );
    }

    #[test]
    fn export_subcommand() {
        let config = config_from_args([
            "export",
            "--from",
            "0",
            "--to",
            "20",
            "--output-dir",
            "export",
        ]);

        assert_eq!(
            config.command,
            Some(GrandineCommand::Export {
                from: 0,
                to: 20,
                output_dir: Some(PathBuf::from("export")),
            }),
        );
    }

    #[test]
    fn replay_subcommand() {
        let config =
            config_from_args(["replay", "--from", "0", "--to", "20", "--input-dir", "data"]);

        assert_eq!(
            config.command,
            Some(GrandineCommand::Replay {
                from: 0,
                to: 20,
                input_dir: Some(PathBuf::from("data")),
            }),
        );
    }

    #[test]
    fn yaml_to_args_scalar_string_becomes_flag_and_value() {
        assert_eq!(
            yaml_to_args("http-port: \"5052\"").expect("valid YAML should parse"),
            ["--http-port", "5052"],
        );
    }

    #[test]
    fn yaml_to_args_number_becomes_flag_and_value() {
        assert_eq!(
            yaml_to_args("http-port: 5052").expect("valid YAML should parse"),
            ["--http-port", "5052"],
        );
    }

    #[test]
    fn yaml_to_args_true_becomes_bare_flag() {
        assert_eq!(
            yaml_to_args("back-sync: true").expect("valid YAML should parse"),
            ["--back-sync"],
        );
    }

    #[test]
    fn yaml_to_args_false_is_omitted() {
        assert!(
            yaml_to_args("back-sync: false")
                .expect("valid YAML should parse")
                .is_empty(),
        );
    }

    #[test]
    fn yaml_to_args_underscore_key_becomes_dash() {
        assert_eq!(
            yaml_to_args("back_sync: true").expect("valid YAML should parse"),
            ["--back-sync"],
        );
    }

    #[test]
    fn yaml_to_args_sequence_repeats_flag() {
        assert_eq!(
            yaml_to_args(
                "
                eth1-rpc-urls:
                  - http://localhost:8545
                  - http://example.com:8545
                "
            )
            .expect("valid YAML should parse"),
            [
                "--eth1-rpc-urls",
                "http://localhost:8545",
                "--eth1-rpc-urls",
                "http://example.com:8545",
            ],
        );
    }

    #[test]
    fn yaml_to_args_empty_sequence_emits_nothing() {
        assert!(
            yaml_to_args("eth1-rpc-urls: []")
                .expect("valid YAML should parse")
                .is_empty(),
        );
    }

    #[test]
    fn yaml_to_args_rejects_null_value() {
        yaml_to_args("http-port:").expect_err("a null value should be rejected");
    }

    #[test]
    fn yaml_to_args_rejects_mapping_value() {
        yaml_to_args(
            "
            nested:
              key: value
            ",
        )
        .expect_err("a mapping value should be rejected");
    }

    #[test]
    fn yaml_to_args_rejects_non_string_key() {
        yaml_to_args("123: value").expect_err("a non-string key should be rejected");
    }

    #[test]
    fn merge_args_file_reads_options_from_yaml() {
        let config = try_config_from_args_file(
            "
            discovery-port: 8888
            back-sync: true
            eth1-rpc-urls:
              - http://localhost:8545
              - http://example.com:8545
            ",
        )
        .expect("config should be built from --args-file");

        assert_eq!(
            config
                .network_config
                .listen_addrs()
                .v4()
                .map(|addr| addr.disc_port),
            Some(8888),
        );

        assert!(config.back_sync_enabled);

        itertools::assert_equal(
            config.eth1_rpc_urls.iter().map(RedactingUrl::to_string),
            ["http://localhost:8545/", "http://example.com:8545/"],
        );
    }

    #[test]
    fn args_file_enforces_conflicts() {
        try_config_from_args_file(
            "
            archive-storage: true
            prune-storage: true
            ",
        )
        .expect_err("conflicting options in --args-file should be rejected");
    }

    #[test]
    fn args_file_enforces_required_options() {
        try_config_from_args_file("force-checkpoint-sync: true\n")
            .expect_err("missing required option in --args-file should be rejected");
    }

    #[test]
    fn requires_is_satisfied_across_cli_and_args_file() {
        // `--force-checkpoint-sync` requires `--checkpoint-sync-url`; the
        // requirement is enforced only on the merged tokens, so the command line
        // may set the flag while the args file supplies its dependency.
        let config = try_config_from_args_and_file(
            ["--force-checkpoint-sync"],
            "checkpoint-sync-url: https://checkpoint.example\n",
        )
        .expect("a requirement split across the command line and args file should be satisfied");

        assert!(config.force_checkpoint_sync);

        assert_eq!(
            config.checkpoint_sync_url.map(|url| url.to_string()),
            Some("https://checkpoint.example/".to_owned()),
        );
    }

    #[test]
    fn args_file_empty_sequence_keeps_default() {
        let config = try_config_from_args_file("eth1-rpc-urls: []")
            .expect("an empty sequence should be treated as unset");

        assert!(config.eth1_rpc_urls.is_empty());
    }

    #[test]
    fn args_file_scalar_splits_on_value_delimiter() {
        let config = try_config_from_args_file(
            "libp2p-nodes: /ip4/127.0.0.1/tcp/9000,/ip4/127.0.0.2/tcp/9001",
        )
        .expect("a comma-delimited scalar should split into multiple values");

        itertools::assert_equal(
            config
                .network_config
                .libp2p_nodes
                .iter()
                .map(ToString::to_string),
            ["/ip4/127.0.0.1/tcp/9000", "/ip4/127.0.0.2/tcp/9001"],
        );
    }

    #[test]
    fn args_file_sanity_node_run() {
        let config = try_config_from_args_file(
            "
            network: sepolia
            checkpoint-sync-url: https://checkpoint.sepolia.example
            force-checkpoint-sync: true
            eth1-rpc-urls:
              - http://localhost:8545
              - http://localhost:8546
            back-sync: true
            graffiti:
              - \"**grandine**\"
            default-builder-boost-factor: 90
            max-empty-slots: 5
            discovery-port: 9010
            http-port: 6000
            metrics: true
            metrics-port: 9000
            track-liveness: true
            detect-doppelgangers: true
            ",
        )
        .expect("a full node configuration should be built from --args-file");

        assert_eq!(config.predefined_network, Some(PredefinedNetwork::Sepolia));
        assert_eq!(
            config.checkpoint_sync_url.map(|url| url.to_string()),
            Some("https://checkpoint.sepolia.example/".to_owned()),
        );

        assert!(config.force_checkpoint_sync);
        assert!(config.back_sync_enabled);

        itertools::assert_equal(
            config.eth1_rpc_urls.iter().map(RedactingUrl::to_string),
            ["http://localhost:8545/", "http://localhost:8546/"],
        );

        assert_eq!(
            config.graffiti,
            [b"**grandine**\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".into()],
        );

        assert_eq!(config.default_builder_boost_factor, Uint256::from_u64(90));
        assert_eq!(config.max_empty_slots, 5);
        assert_eq!(
            config
                .network_config
                .listen_addrs()
                .v4()
                .map(|addr| addr.disc_port),
            Some(9010),
        );

        assert_eq!(
            config.http_api_config.map(|config| config.address),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6000)),
        );

        assert_eq!(
            config
                .metrics_config
                .metrics_server_config
                .map(|config| config.metrics_port),
            Some(9000),
        );

        assert!(config.track_liveness);
        assert!(config.detect_doppelgangers);
    }

    #[test]
    fn cli_scalar_overrides_args_file() {
        let config =
            try_config_from_args_and_file(["--discovery-port", "7000"], "discovery-port: 8888")
                .expect("a command-line scalar should override the args file");

        assert_eq!(
            config
                .network_config
                .listen_addrs()
                .v4()
                .map(|addr| addr.disc_port),
            Some(7000),
        );
    }

    #[test]
    fn cli_list_overrides_args_file_list() {
        let config = try_config_from_args_and_file(
            ["--eth1-rpc-urls", "http://cli:8545"],
            "
            eth1-rpc-urls:
              - http://file:8545
            ",
        )
        .expect("a command-line list should override the args file list");

        itertools::assert_equal(
            config.eth1_rpc_urls.iter().map(RedactingUrl::to_string),
            ["http://cli:8545/"],
        );
    }

    #[test]
    fn args_file_list_used_when_cli_absent() {
        let config = try_config_from_args_and_file(
            [],
            "
            eth1-rpc-urls:
              - http://file:8545
            ",
        )
        .expect("the args file list should be used when the command line omits it");

        itertools::assert_equal(
            config.eth1_rpc_urls.iter().map(RedactingUrl::to_string),
            ["http://file:8545/"],
        );
    }

    #[test]
    fn args_file_preserves_cli_subcommand() {
        let config = try_config_from_args_and_file(
            ["export", "--from", "0", "--to", "20"],
            "back-sync: true",
        )
        .expect("a subcommand should survive args file merging");

        assert_eq!(
            config.command,
            Some(GrandineCommand::Export {
                from: 0,
                to: 20,
                output_dir: None,
            }),
        );

        assert!(config.back_sync_enabled);
    }

    fn config_from_args<'a>(arguments: impl IntoIterator<Item = &'a str>) -> GrandineConfig {
        try_config_from_args(arguments)
            .expect("GrandineArgs should be successfully parsed from arguments")
    }

    fn try_config_from_args_file(yaml: &str) -> Result<GrandineConfig> {
        try_config_from_args_and_file([], yaml)
    }

    /// Parse the given command-line `arguments` together with a `--args-file`
    /// pointing at a temporary file containing `yaml`.
    fn try_config_from_args_and_file<'a>(
        arguments: impl IntoIterator<Item = &'a str>,
        yaml: &str,
    ) -> Result<GrandineConfig> {
        let mut file = NamedTempFile::new().expect("temporary file should be created");
        write!(file, "{yaml}").expect("writing YAML should succeed");

        let path = file
            .path()
            .to_str()
            .expect("temporary path should be UTF-8")
            .to_owned();

        let mut argv = vec!["--args-file".to_owned(), path];
        argv.extend(arguments.into_iter().map(str::to_owned));

        try_config_from_args(argv.iter().map(String::as_str))
    }

    fn try_config_from_args<'a>(
        arguments: impl IntoIterator<Item = &'a str>,
    ) -> Result<GrandineConfig> {
        let args = core::iter::once(APPLICATION_NAME)
            .chain(arguments)
            .map(OsString::from);

        GrandineArgs::parse_and_merge_args_file(args)?.try_into_config()
    }

    /// Flatten [`yaml_to_arg_groups`] into a single token list, as it is spliced
    /// into the command line.
    fn yaml_to_args(yaml: &str) -> Result<Vec<String>> {
        Ok(yaml_to_arg_groups(yaml)?
            .into_iter()
            .flat_map(|(_, tokens)| tokens)
            .collect())
    }
}
