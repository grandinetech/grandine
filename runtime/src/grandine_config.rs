use core::{net::SocketAddr, time::Duration};
use std::{collections::HashSet, path::PathBuf, sync::Arc};

use binary_utils::TelemetryConfig;
use builder_api::BuilderConfig;
use directories::Directories;
use eth1_api::AuthOptions;
use fork_choice_store::BuilderCircuitBreakerConfig;
use http_api::HttpApiConfig;
use itertools::Itertools as _;
use kzg_utils::KzgBackend;
use p2p::NetworkConfig;
use signer::Web3SignerConfig;
use ssz::Uint256;
use tracing::info;
use types::{
    bellatrix::primitives::Gas,
    config::Config as ChainConfig,
    nonstandard::{CustodyMode, PublishedDuty},
    phase0::primitives::{ExecutionAddress, ExecutionBlockNumber, H256, Slot},
    redacting_url::RedactingUrl,
};
use validator::ValidatorApiConfig;

use crate::{
    MetricsConfig, StorageConfig, commands::GrandineCommand, predefined_network::PredefinedNetwork,
    validators::Validators,
};

#[cfg_attr(test, derive(Debug))]
pub struct GrandineConfig {
    pub predefined_network: Option<PredefinedNetwork>,
    pub chain_config: Arc<ChainConfig>,
    pub genesis_state_file: Option<PathBuf>,
    pub genesis_state_download_url: Option<RedactingUrl>,
    pub data_dir: PathBuf,
    pub directories: Arc<Directories>,
    pub in_memory: bool,
    pub request_timeout: Duration,
    pub command: Option<GrandineCommand>,
    pub metrics_config: MetricsConfig,
    pub disable_blockprint_graffiti: bool,
    pub graffiti: Vec<H256>,
    pub max_empty_slots: u64,
    pub suggested_fee_recipient: Option<ExecutionAddress>,
    pub default_builder_boost_factor: Uint256,
    pub default_gas_limit: Option<Gas>,
    pub disable_wait_for_late_blocks: bool,
    pub builder_config: Option<BuilderConfig>,
    pub built_in_node: Option<BuiltInNodeConfig>,
    pub validator_client: Option<ValidatorClientConfig>,
    pub remote_beacon_nodes: Option<RemoteBeaconNodesConfig>,
}

/// The nodes `vc` performs duties against; the built-in beacon node has none.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct RemoteBeaconNodesConfig {
    pub beacon_node_urls: Vec<RedactingUrl>,
    pub publish_to_every_node: Vec<PublishedDuty>,
}

/// What only the built-in beacon node needs; `vc` has none.
#[expect(
    clippy::struct_excessive_bools,
    reason = "False positive. The `bool`s are independent."
)]
#[cfg_attr(test, derive(Debug))]
pub struct BuiltInNodeConfig {
    pub deposit_contract_starting_block: Option<ExecutionBlockNumber>,
    pub checkpoint_sync_url: Option<RedactingUrl>,
    pub force_checkpoint_sync: bool,
    pub back_sync_enabled: bool,
    pub eth1_rpc_urls: Vec<RedactingUrl>,
    pub auth_options: AuthOptions,
    pub network_config: NetworkConfig,
    pub storage_config: StorageConfig,
    pub unfinalized_states_in_memory: u64,
    pub max_epochs_to_retain_states_in_cache: u64,
    pub state_cache_lock_timeout: Duration,
    pub reconstruction_delay: Duration,
    pub sync_without_reconstruction: bool,
    pub kzg_backend: KzgBackend,
    pub builder_circuit_breaker: BuilderCircuitBreakerConfig,
    pub slashing_enabled: bool,
    pub slashing_history_limit: u64,
    pub state_slot: Option<Slot>,
    pub http_api_config: Option<HttpApiConfig>,
    pub max_events: usize,
    pub telemetry_config: Option<TelemetryConfig>,
    pub track_liveness: bool,
    pub blacklisted_blocks: HashSet<H256>,
    pub backfill_custody_groups: bool,
    pub custody_mode: CustodyMode,
}

/// What only a running validator client needs; `bn` has none.
#[cfg_attr(test, derive(Debug))]
pub struct ValidatorClientConfig {
    pub validators: Option<Validators>,
    pub keystore_storage_password_file: Option<PathBuf>,
    pub web3signer_config: Web3SignerConfig,
    pub detect_doppelgangers: bool,
    pub use_validator_key_cache: bool,
    pub slashing_protection_history_limit: u64,
    pub validator_api_config: Option<ValidatorApiConfig>,
    pub report_validator_performance: bool,
}

impl GrandineConfig {
    pub fn report(&self) {
        let Self {
            predefined_network,
            chain_config,
            data_dir,
            metrics_config,
            disable_blockprint_graffiti,
            graffiti,
            suggested_fee_recipient,
            default_builder_boost_factor,
            builder_config,
            built_in_node,
            validator_client,
            remote_beacon_nodes,
            ..
        } = self;

        match predefined_network {
            Some(network) => info!("network: {network}"),
            None => info!(
                "network: custom with {} preset and {} configuration",
                chain_config.preset_base, chain_config.config_name,
            ),
        }

        info!("data directory: {}", data_dir.display());

        match built_in_node {
            Some(node) => node.report(chain_config),
            None => info!("built-in beacon node disabled"),
        }

        info!("graffiti: {graffiti:?}");

        if *disable_blockprint_graffiti {
            info!("blockprint graffiti disabled");
        }

        if let Some(metrics_server_config) = &metrics_config.metrics_server_config {
            info!(
                "metrics server address: {}",
                SocketAddr::from(metrics_server_config),
            );
        }

        if let Some(metrics_service_config) = &metrics_config.metrics_service_config {
            info!(
                "metrics service configured with {:?} update interval",
                metrics_service_config.metrics_update_interval,
            );
        }

        match validator_client
            .as_ref()
            .map(|config| config.validator_api_config.as_ref())
        {
            Some(Some(validator_api_config)) => {
                info!("validator API address: {}", validator_api_config.address);
            }
            Some(None) => info!("validator API disabled"),
            None => info!("validator client disabled"),
        }

        if let Some(builder_config) = builder_config {
            info!(
                "using external block builder (API URL: {}, format: {}, \
                default_builder_boost_factor: {default_builder_boost_factor})",
                builder_config.builder_api_url, builder_config.builder_api_format,
            );
        }

        if let Some(RemoteBeaconNodesConfig {
            beacon_node_urls,
            publish_to_every_node,
        }) = remote_beacon_nodes
        {
            info!(
                "performing validator duties against remote beacon nodes without the built-in \
                 beacon node: [{}]",
                beacon_node_urls.iter().join(", "),
            );

            if !publish_to_every_node.is_empty() {
                info!(
                    "publishing to every remote beacon node: [{}]",
                    publish_to_every_node.iter().join(", "),
                );
            }
        }

        if let Some(validator_client) = validator_client {
            if !validator_client.web3signer_config.urls.is_empty() {
                info!(
                    "using Web3Signer API to sign validator messages (API URLs: [{}])",
                    validator_client.web3signer_config.urls.keys().join(", "),
                );
            }

            if validator_client.use_validator_key_cache {
                info!("using validator key cache");
            }
        }

        info!("suggested fee recipient: {suggested_fee_recipient:?}");
    }
}

impl BuiltInNodeConfig {
    fn report(&self, chain_config: &ChainConfig) {
        let Self {
            checkpoint_sync_url,
            back_sync_enabled,
            eth1_rpc_urls,
            network_config,
            storage_config,
            sync_without_reconstruction,
            slashing_enabled,
            slashing_history_limit,
            state_slot,
            http_api_config,
            telemetry_config,
            custody_mode,
            ..
        } = self;

        info!("storage mode: {:?}", storage_config.storage_mode);

        storage_config.print_db_sizes();

        info!("Eth1 RPC URLs: [{}]", eth1_rpc_urls.iter().join(", "));

        if let Some(http_api_config) = http_api_config {
            info!("HTTP API address: {}", http_api_config.address);
        } else {
            info!("HTTP API disabled");
        }

        if let Some(config) = telemetry_config {
            info!("telemetry export configured with: {config:?}");
        } else {
            info!("telemetry metrics data export disabled");
        }

        info!(
            "archival interval: {} epochs",
            storage_config.archival_epoch_interval
        );
        info!("slasher enabled: {slashing_enabled}");

        if let Some(client_version) = &network_config.identify_agent_version {
            info!("client version: {client_version}");
        }

        if !network_config.trusted_peers.is_empty() {
            info!("trusted peers: {:?}", network_config.trusted_peers);
        }

        if let Some(slot) = state_slot {
            info!("force state slot: {slot}");
        }

        if let Some(checkpoint_sync_url) = checkpoint_sync_url {
            info!("checkpoint sync url: {checkpoint_sync_url}");
        }

        if *slashing_enabled {
            info!("slasher history limit: {slashing_history_limit}");
        }

        info!("back-sync enabled: {back_sync_enabled}");

        if *sync_without_reconstruction {
            info!("sync with reconstruction disabled");
        }

        if chain_config.is_peerdas_scheduled() {
            info!("custody mode: {custody_mode:?}");
        }
    }
}
