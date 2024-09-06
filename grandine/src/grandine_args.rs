use core::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::{NonZeroU16, NonZeroU64},
    ops::Not as _,
    time::Duration,
};
use std::{path::PathBuf, sync::Arc};

use anyhow::{ensure, Result};
use bls::PublicKeyBytes;
use builder_api::{
    BuilderConfig, DEFAULT_BUILDER_MAX_SKIPPED_SLOTS, DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH,
};
use bytesize::ByteSize;
use clap::{error::ErrorKind, Args, CommandFactory as _, Error as ClapError, Parser, ValueEnum};
use derive_more::Display;
use directories::Directories;
use educe::Educe;
use enum_iterator::Sequence;
use eth1_api::AuthOptions;
use eth2_libp2p::PeerIdSerialized;
use features::Feature;
use fork_choice_control::DEFAULT_ARCHIVAL_EPOCH_INTERVAL;
use fork_choice_store::StoreConfig;
use grandine_version::{APPLICATION_NAME, APPLICATION_NAME_AND_VERSION, APPLICATION_VERSION};
use http_api::HttpApiConfig;
use itertools::{EitherOrBoth, Itertools as _};
use log::warn;
use metrics::{MetricsServerConfig, MetricsServiceConfig};
use p2p::{Enr, Multiaddr, NetworkConfig};
use prometheus_metrics::{Metrics, METRICS};
use reqwest::{header::HeaderValue, Url};
use runtime::{
    MetricsConfig, StorageConfig, DEFAULT_ETH1_DB_SIZE, DEFAULT_ETH2_DB_SIZE,
    DEFAULT_LIBP2P_IPV4_PORT, DEFAULT_LIBP2P_IPV6_PORT, DEFAULT_LIBP2P_QUIC_IPV4_PORT,
    DEFAULT_LIBP2P_QUIC_IPV6_PORT, DEFAULT_METRICS_PORT, DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_TARGET_PEERS, DEFAULT_TIMEOUT,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use signer::Web3SignerConfig;
use slasher::SlasherConfig;
use slashing_protection::DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT;
use std_ext::ArcExt as _;
use thiserror::Error;
use tower_http::cors::AllowOrigin;
use types::{
    bellatrix::primitives::Difficulty,
    config::Config as ChainConfig,
    nonstandard::Phase,
    phase0::primitives::{
        Epoch, ExecutionAddress, ExecutionBlockHash, ExecutionBlockNumber, Slot, H256,
    },
    preset::PresetName,
};
use validator::{ValidatorApiConfig, ValidatorConfig};

use crate::{
    commands::GrandineCommand,
    config_dir::{
        self, CONFIG_FILE, DEPOSIT_CONTRACT_BLOCK_FILE, GENESIS_STATE_FILE, PLAIN_BOOTNODES_FILE,
    },
    consts::GRANDINE_DONATION_ADDRESS,
    grandine_config::GrandineConfig,
    predefined_network::PredefinedNetwork,
    validators::Validators,
};

/// Grandine Team <info@grandine.io>
/// Fast PoS and Sharding client supporting Ethereum 2.0 networks
#[derive(Parser)]
#[clap(display_name = APPLICATION_NAME, verbatim_doc_comment, version = APPLICATION_VERSION)]
pub struct GrandineArgs {
    #[clap(flatten)]
    chain_options: ChainOptions,

    #[clap(flatten)]
    beacon_node_options: BeaconNodeOptions,

    #[clap(flatten)]
    http_api_options: HttpApiOptions,

    #[clap(flatten)]
    network_config_options: NetworkConfigOptions,

    // TODO(Grandine Team): The slasher is not working properly and should not be used.
    #[allow(dead_code)]
    #[clap(skip)]
    slasher_options: SlasherOptions,

    #[clap(flatten)]
    validator_options: ValidatorOptions,

    #[clap(flatten)]
    validator_api_options: ValidatorApiOptions,

    #[clap(long, value_parser = parse_graffiti, default_value = APPLICATION_NAME_AND_VERSION)]
    graffiti: Vec<H256>,

    /// List of optional runtime features to enable
    #[clap(long, value_delimiter = ',')]
    features: Vec<Feature>,

    #[clap(subcommand)]
    command: Option<GrandineCommand>,
}

#[derive(Args)]
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
    genesis_state_download_url: Option<Url>,
}

#[derive(Args)]
struct HttpApiOptions {
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

    /// Max number of events stored in a single channel for HTTP API /events api call
    #[clap(long, default_value_t = HttpApiConfig::default().max_events)]
    max_events: usize,

    /// HTTP API timeout in milliseconds
    #[clap(long, default_value_t = HttpApiOptions::default_timeout())]
    timeout: u64,
}

impl From<HttpApiOptions> for HttpApiConfig {
    fn from(http_api_options: HttpApiOptions) -> Self {
        let HttpApiOptions {
            http_address,
            http_port,
            http_allowed_origins,
            max_events,
            timeout,
        } = http_api_options;

        let Self {
            address,
            allow_origin,
            ..
        } = Self::with_address(http_address, http_port);

        Self {
            address,
            allow_origin: headers_to_allow_origin(http_allowed_origins).unwrap_or(allow_origin),
            max_events,
            timeout: Some(Duration::from_millis(timeout)),
        }
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

// False positive. The `bool`s are independent.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args)]
struct BeaconNodeOptions {
    #[clap(long, default_value_t = ValidatorConfig::default().max_empty_slots)]
    max_empty_slots: u64,

    /// Beacon node API URL to load recent finalized checkpoint and sync from it
    /// [default: None]
    #[clap(long)]
    checkpoint_sync_url: Option<Url>,

    /// Force checkpoint sync. Requires --checkpoint-sync-url
    /// [default: disabled]
    #[clap(long, requires = "checkpoint_sync_url")]
    force_checkpoint_sync: bool,

    /// List of Eth1 RPC URLs
    #[clap(long, num_args = 1..)]
    eth1_rpc_urls: Vec<Url>,

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

    #[clap(long, default_value_t = DEFAULT_ARCHIVAL_EPOCH_INTERVAL)]
    archival_epoch_interval: NonZeroU64,

    /// Enable prune mode where only single checkpoint state & block are stored in the DB
    /// [default: disabled]
    #[clap(long)]
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

    /// Default global request timeout for various services in milliseconds
    #[clap(long, default_value_t = DEFAULT_REQUEST_TIMEOUT)]
    request_timeout: u64,

    /// State slot
    /// [default: None]
    #[clap(long)]
    state_slot: Option<Slot>,

    /// Disable block signature verification pool
    /// [default: enabled]
    #[clap(long)]
    disable_block_verification_pool: bool,

    /// Subscribe to all subnets
    #[clap(long, default_value_t = true)]
    subscribe_all_subnets: bool,

    /// Subscribe to all data column subnets
    #[clap(long)]
    subscribe_all_data_column_subnets: bool,

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

    /// Enable syncing historical data
    /// [default: disabled]
    #[clap(long)]
    back_sync: bool,

    /// Collect Prometheus metrics
    #[clap(long)]
    metrics: bool,

    /// Metrics address for metrics endpoint
    #[clap(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    metrics_address: IpAddr,

    /// Listen port for metrics endpoint
    #[clap(long, default_value_t = DEFAULT_METRICS_PORT)]
    metrics_port: u16,

    /// Optional remote metrics URL that Grandine will periodically send metrics to
    #[clap(long)]
    remote_metrics_url: Option<Url>,

    /// Enable validator liveness tracking
    /// [default: disabled]
    #[clap(long)]
    track_liveness: bool,

    /// Enable in-memory mode.
    /// No data will be stored in data-dir.
    /// [default: disabled]
    #[clap(long)]
    in_memory: bool,
}

// False positive. The `bool`s are independent.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args)]
struct NetworkConfigOptions {
    /// Listen IPv4 address
    #[clap(long, default_value_t = Ipv4Addr::UNSPECIFIED)]
    listen_address: Ipv4Addr,

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

    /// Disable NAT traversal via UPnP
    /// [default: enabled]
    #[clap(long)]
    disable_upnp: bool,

    /// Disable enr auto update
    /// [default: enabled]
    #[clap(long)]
    disable_enr_auto_update: bool,

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

    /// Target number of network peers
    #[clap(long, default_value_t = DEFAULT_TARGET_PEERS)]
    target_peers: usize,

    /// List of trusted peers
    #[clap(long, value_delimiter = ',')]
    trusted_peers: Vec<PeerIdSerialized>,
}

impl NetworkConfigOptions {
    fn into_config(
        self,
        network: Network,
        network_dir: PathBuf,
        metrics: bool,
        in_memory: bool,
    ) -> NetworkConfig {
        let Self {
            listen_address,
            listen_address_ipv6,
            libp2p_port,
            libp2p_port_ipv6,
            disable_enr_auto_update,
            disable_quic,
            disable_peer_scoring,
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
            target_peers,
            trusted_peers,
        } = self;

        let mut network_config = network
            .predefined_network()
            .map(PredefinedNetwork::network_config)
            .unwrap_or_else(runtime::default_network_config);

        network_config.disable_peer_scoring = disable_peer_scoring;
        network_config.disable_quic_support = disable_quic;
        network_config.discv5_config.enr_update = !disable_enr_auto_update;
        network_config.upnp_enabled = !disable_upnp;
        network_config.network_dir = in_memory.not().then_some(network_dir);
        network_config.metrics_enabled = metrics;
        network_config.target_peers = target_peers;
        network_config.trusted_peers = trusted_peers;

        if let Some(listen_address_ipv6) = listen_address_ipv6 {
            network_config.set_ipv4_ipv6_listening_addresses(
                listen_address,
                libp2p_port.into(),
                discovery_port.into(),
                quic_port.into(),
                listen_address_ipv6,
                libp2p_port_ipv6.into(),
                discovery_port_ipv6.into(),
                quic_port_ipv6.into(),
            );
        } else {
            network_config.set_ipv4_listening_address(
                listen_address,
                libp2p_port.into(),
                discovery_port.into(),
                quic_port.into(),
            );
        }

        network_config.enr_address = (enr_address, enr_address_ipv6);

        // Set ENR fields of `NetworkConfig` only if the value is specified.
        if let Some(enr_tcp_port) = enr_tcp_port {
            network_config.enr_tcp4_port = Some(enr_tcp_port);
        } else {
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
                warn!(
                    "UPnP enabled with manual ENR settings: {}; \
                     manual ENR settings might be overriden by UPnP",
                    manual_options.join(", "),
                );
            }
        }
    }
}

#[derive(Educe, Args)]
#[educe(Default)]
struct SlasherOptions {
    /// Enable slasher
    /// [default: disabled]
    #[clap(long)]
    slashing_enabled: bool,

    /// Number of epochs for slasher to search for violations
    #[clap(long, default_value_t = SlasherConfig::default().slashing_history_limit)]
    slashing_history_limit: u64,
}

#[derive(Args)]
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

    /// [DEPRECATED] External block builder API URL
    #[clap(long)]
    builder_api_url: Option<Url>,

    /// External block builder URL
    #[clap(long)]
    builder_url: Option<Url>,

    /// Always use specified external block builder without checking for circuit breaker conditions
    #[clap(long)]
    builder_disable_checks: bool,

    /// Max allowed consecutive missing blocks to trigger circuit breaker condition and switch to local execution engine for payload construction
    #[clap(long, default_value_t = DEFAULT_BUILDER_MAX_SKIPPED_SLOTS)]
    builder_max_skipped_slots: u64,

    /// Max allowed missing blocks in the last rolling epoch to trigger circuit breaker condition and switch to local execution engine for payload construction
    #[clap(long, default_value_t = DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH)]
    builder_max_skipped_slots_per_epoch: u64,

    /// List of public keys to use from Web3Signer
    #[clap(long, num_args = 1.., value_delimiter = ',')]
    web3signer_public_keys: Vec<PublicKeyBytes>,

    /// Refetches keys from Web3Signer once every epoch. This overwrites changes done via Keymanager API
    #[clap(long)]
    web3signer_refresh_keys_every_epoch: bool,

    /// [DEPRECATED] List of Web3Signer API URLs
    #[clap(long, num_args = 1..)]
    web3signer_api_urls: Vec<Url>,

    /// List of Web3Signer URLs
    #[clap(long, num_args = 1..)]
    web3signer_urls: Vec<Url>,

    /// Use validator key cache for faster startup
    #[clap(long)]
    use_validator_key_cache: bool,

    /// Number of epochs to keep slashing protection data for
    #[clap(long, default_value_t = DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT)]
    slashing_protection_history_limit: u64,
}

#[derive(Args)]
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

#[derive(Clone, Copy, Sequence, ValueEnum)]
enum Network {
    #[cfg(any(feature = "network-mainnet", test))]
    Mainnet,
    #[cfg(any(feature = "network-goerli", test))]
    #[clap(alias = "prater")]
    Goerli,
    #[cfg(any(feature = "network-sepolia", test))]
    Sepolia,
    #[cfg(any(feature = "network-holesky", test))]
    Holesky,
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
            #[cfg(any(feature = "network-goerli", test))]
            Self::Goerli => Some(PredefinedNetwork::Goerli),
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => Some(PredefinedNetwork::Sepolia),
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => Some(PredefinedNetwork::Holesky),
            Self::Custom => None,
        }
    }
}

impl GrandineArgs {
    // This is not a `TryFrom` impl because this has side effects.
    #[allow(clippy::cognitive_complexity)]
    #[allow(clippy::too_many_lines)]
    pub fn try_into_config(self) -> Result<GrandineConfig> {
        let Self {
            chain_options,
            beacon_node_options,
            http_api_options,
            mut network_config_options,
            validator_options,
            validator_api_options,
            graffiti,
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
            verify_configuration_file,
            terminal_total_difficulty_override,
            terminal_block_hash_override,
            terminal_block_hash_activation_epoch_override,
            mut deposit_contract_starting_block,
            mut genesis_state_file,
            genesis_state_download_url,
        } = chain_options;

        let BeaconNodeOptions {
            max_empty_slots,
            checkpoint_sync_url,
            eth1_rpc_urls,
            force_checkpoint_sync,
            data_dir,
            store_directory,
            network_dir,
            database_size,
            eth1_database_size,
            archival_epoch_interval,
            prune_storage,
            unfinalized_states_in_memory,
            request_timeout,
            state_slot,
            disable_block_verification_pool,
            subscribe_all_subnets,
            subscribe_all_data_column_subnets,
            suggested_fee_recipient,
            jwt_id,
            jwt_secret,
            jwt_version,
            back_sync,
            metrics,
            metrics_address,
            metrics_port,
            remote_metrics_url,
            track_liveness,
            in_memory,
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
            builder_api_url,
            builder_url,
            builder_disable_checks,
            builder_max_skipped_slots,
            builder_max_skipped_slots_per_epoch,
            use_validator_key_cache,
            web3signer_public_keys,
            web3signer_refresh_keys_every_epoch,
            web3signer_api_urls,
            web3signer_urls,
            slashing_protection_history_limit,
        } = validator_options;

        if in_memory {
            warn!(
                "running Grandine in in-memory mode; \
                 no data will be stored on disk; \
                 all data will be lost on exit",
            );
        }

        // There's technically nothing wrong with this, but the user may have made a mistake.
        if configuration_file.is_some() && verify_configuration_file.is_some() {
            warn!("both --configuration-file and --verify-configuration-file specified");
        }

        if remote_metrics_url.is_some() && !metrics {
            warn!(
                "Remote metrics enabled without ---metrics. Network metrics will not be available"
            );
        }

        if let Some(directory) = configuration_directory {
            configuration_file = configuration_file
                .inspect(|_| {
                    warn!(
                        "both --configuration-directory and --configuration-file specified; \
                         --configuration-file will take precedence",
                    );
                })
                .or_else(|| Some(directory.join(CONFIG_FILE)));

            deposit_contract_starting_block = match deposit_contract_starting_block {
                Some(number) => {
                    warn!(
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
                    warn!(
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
                warn!(
                    "both --configuration-directory and --boot-nodes specified; \
                     --boot-nodes will take precedence",
                );
            }
        }

        let predefined_network = network.predefined_network();

        if predefined_network.is_none() && eth1_rpc_urls.is_empty() {
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
            warn!(
                "unknown configuration variables: [{:?}]",
                unknown.keys().format(", "),
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
            }
            .set_defaults(&chain_config),
        );

        // enable global feature for easier checking
        if metrics {
            features.push(Feature::PrometheusMetrics);
        }

        // If `--remote-metrics-url` is not specified (for beaconcha.in style metrics) and
        // `--metrics` option (for tracking prometheus metrics) is not enabled and
        // `ServeLeakyEndpoints` (for `GET /system/stats`) is not enabled,
        // there is no need to run the metrics service.
        // However, `ServeLeakyEndpoints` can be enabled after startup through `PATCH /features`.
        let metrics_service_config = (remote_metrics_url.is_some()
            || features.contains(&Feature::PrometheusMetrics)
            || features.contains(&Feature::ServeLeakyEndpoints)
            || features.contains(&Feature::ServeEffectfulEndpoints))
        .then(|| MetricsServiceConfig {
            remote_metrics_url,
            directories: directories.clone_arc(),
        });

        let metrics_server_config = metrics.then_some(MetricsServerConfig {
            metrics_address,
            metrics_port,
            timeout: request_timeout,
            directories: directories.clone_arc(),
        });

        let http_api_config = HttpApiConfig::from(http_api_options);
        let validator_api_config = validator_api_options
            .enable_validator_api
            .then(|| ValidatorApiConfig::from(validator_api_options));

        let mut services = vec![(http_api_config.address, "HTTP API")];

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

        let metrics_enabled = metrics;
        let metrics = if metrics {
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
            .chain(disable_block_verification_pool.then_some(Feature::DisableBlockVerificationPool))
            .chain(subscribe_all_subnets.then_some(Feature::SubscribeToAllAttestationSubnets))
            .chain(subscribe_all_data_column_subnets.then_some(Feature::SubscribeToAllDataColumnSubnets))
            .chain(subscribe_all_subnets.then_some(Feature::SubscribeToAllSyncCommitteeSubnets))
            .collect::<Vec<_>>();

        // enabling these features here, because it being used in below network config conversion
        features.iter().for_each(|f| f.enable());

        let auth_options = AuthOptions {
            secrets_path: jwt_secret,
            id: jwt_id,
            version: jwt_version,
        };

        let builder_url = if builder_url.is_none() && builder_api_url.is_some() {
            warn!("--builder-api-url option is deprecated. Use --builder-url instead.");
            builder_api_url
        } else {
            builder_url
        };

        let builder_config = builder_url.map(|url| BuilderConfig {
            builder_api_url: url,
            builder_disable_checks,
            builder_max_skipped_slots,
            builder_max_skipped_slots_per_epoch,
        });

        let web3signer_urls = if web3signer_urls.is_empty() && !web3signer_api_urls.is_empty() {
            warn!("--web3signer-api-urls option is deprecated. Use --web3signer-urls instead.");
            web3signer_api_urls
        } else {
            web3signer_urls
        };

        let web3signer_config = Web3SignerConfig {
            public_keys: web3signer_public_keys.into_iter().collect(),
            allow_to_reload_keys: web3signer_refresh_keys_every_epoch,
            urls: web3signer_urls,
        };

        let storage_config = StorageConfig {
            in_memory,
            db_size: database_size,
            directories: directories.clone_arc(),
            eth1_db_size: eth1_database_size,
            archival_epoch_interval,
            prune_storage,
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
            back_sync,
            eth1_rpc_urls,
            data_dir: directories.data_dir.clone().unwrap_or_default(),
            validators,
            keystore_storage_password_file,
            graffiti,
            max_empty_slots,
            suggested_fee_recipient: suggested_fee_recipient.unwrap_or(GRANDINE_DONATION_ADDRESS),
            network_config: network_config_options.into_config(
                network,
                directories.network_dir.clone().unwrap_or_default(),
                metrics_enabled,
                in_memory,
            ),
            storage_config,
            unfinalized_states_in_memory,
            request_timeout: Duration::from_millis(request_timeout),
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
        })
    }

    #[must_use]
    pub fn clap_error(message: impl Display) -> ClapError {
        Self::command().error(ErrorKind::ValueValidation, message)
    }
}

#[derive(Debug, Display)]
#[display(fmt = "{variable:?}: expected {expected} but found {actual}")]
struct Difference {
    variable: String,
    expected: Value,
    actual: Value,
}

#[derive(Debug, Error)]
enum Error {
    #[error("graffiti must be no longer than {} bytes", H256::len_bytes())]
    GraffitiTooLong,
    // `clap` cannot check this. `clap::builder::PossibleValue` does not have a `requires` method.
    #[error("--configuration-file must be specified when connecting to custom network")]
    MissingConfigurationFileForCustom,
    #[error(
        "--eth1-rpc-urls must be specified when connecting \
         to custom network without --genesis-state-file"
    )]
    MissingEth1RpcUrlsForCustomWithoutGenesisState,
    #[error(
        "{phase} variables in {preset_name} preset do not match file ({})",
        differences.iter().format(", "),
    )]
    PresetMismatch {
        preset_name: PresetName,
        phase: Phase,
        differences: Vec<Difference>,
    },
    #[error(
        "variables in configuration do not match file ({})",
        differences.iter().format(", "),
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

fn parse_graffiti(string: &str) -> Result<H256> {
    ensure!(string.len() <= H256::len_bytes(), Error::GraffitiTooLong);

    let mut graffiti = H256::zero();
    graffiti[..string.len()].copy_from_slice(string.as_bytes());

    Ok(graffiti)
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
                warn!(
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

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, SocketAddr};

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
        assert_eq!(config.network_config.enr_udp4_port, None,);
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
    fn eth1_rpc_urls_single_value() {
        let config = config_from_args(["--eth1-rpc-urls", "http://localhost:8545"]);

        itertools::assert_equal(
            config.eth1_rpc_urls.iter().map(Url::as_str),
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
            config.eth1_rpc_urls.iter().map(Url::as_str),
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
            config.eth1_rpc_urls.iter().map(Url::as_str),
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
    fn http_port_option() {
        let config = config_from_args(["--http-port", "1234"]);

        assert_eq!(
            config.http_api_config.address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234),
        );
    }

    #[test]
    fn http_allowed_origins_default() {
        let config = config_from_args([]);

        // `Debug` is the only way to inspect the contents of `AllowOrigin`.
        assert_eq!(
            format!("{:?}", config.http_api_config.allow_origin),
            "List([\"http://127.0.0.1:5052\"])",
        );
    }

    #[test]
    fn http_allowed_origins_option_single_occurence() {
        let config = config_from_args(["--http-allowed-origins", "*"]);

        // `Debug` is the only way to inspect the contents of `AllowOrigin`.
        assert_eq!(
            format!("{:?}", config.http_api_config.allow_origin),
            "Const(\"*\")",
        );
    }

    #[test]
    fn http_allowed_origins_option_multiple_occurences() {
        let config = config_from_args([
            "--http-allowed-origins",
            "http://localhost",
            "--http-allowed-origins",
            "http://example.com",
        ]);

        // `Debug` is the only way to inspect the contents of `AllowOrigin`.
        assert_eq!(
            format!("{:?}", config.http_api_config.allow_origin),
            "List([\"http://localhost\", \"http://example.com\"])",
        );
    }

    #[test]
    fn http_allowed_origins_option_multiple_occurences_including_wildcard() {
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
            format!("{:?}", config.http_api_config.allow_origin),
            "Const(\"*\")",
        );
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
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1234)),
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
        try_config_from_args([
            "--graffiti",
            "**test-graffiti*******************************",
        ])
        .expect_err("parse_graffiti should fail");
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

    fn config_from_args<'a>(arguments: impl IntoIterator<Item = &'a str>) -> GrandineConfig {
        try_config_from_args(arguments)
            .expect("GrandineArgs should be successfully parsed from arguments")
    }

    fn try_config_from_args<'a>(
        arguments: impl IntoIterator<Item = &'a str>,
    ) -> Result<GrandineConfig> {
        GrandineArgs::try_parse_from(core::iter::once(APPLICATION_NAME).chain(arguments))?
            .try_into_config()
    }
}
