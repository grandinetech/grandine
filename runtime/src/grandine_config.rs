use core::{net::SocketAddr, time::Duration};
use std::{collections::HashSet, path::PathBuf, sync::Arc};

use binary_utils::TelemetryConfig;
use builder_api::BuilderConfig;
use directories::Directories;
use eth1_api::AuthOptions;
use fork_choice_store::StoreConfig;
use http_api::HttpApiConfig;
use itertools::Itertools as _;
use keymanager::{ValidatorDefinitions, ValidatorDefinitionsWithStorage};
use p2p::NetworkConfig;
use signer::Web3SignerConfig;
use slasher::SlasherConfig;
use ssz::Uint256;
use tracing::info;
use types::{
    bellatrix::primitives::Gas,
    config::Config as ChainConfig,
    nonstandard::{CustodyMode, PublishedDuty},
    phase0::primitives::{ExecutionAddress, ExecutionBlockNumber, H256, Slot},
    redacting_url::RedactingUrl,
};
use validator::{ValidatorApiConfig, ValidatorConfig};

use crate::{
    MetricsConfig, StorageConfig, commands::GrandineCommand, predefined_network::PredefinedNetwork,
    validators::Validators,
};

/// Where duties are performed: the built-in beacon node, or under `vc` remote beacon nodes.
#[expect(
    clippy::large_enum_variant,
    reason = "Built once and consumed at once; boxing would only add indirection."
)]
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub enum Mode {
    /// The built-in beacon node, with the validator client unless `bn` was given.
    Local {
        beacon_node_config: BeaconNodeConfig,
        validator_client_config: Option<ValidatorClientConfig>,
        command: Option<GrandineCommand>,
    },
    /// The validator client alone, against the nodes given with `--beacon-node-urls`.
    Remote {
        validator_client_config: ValidatorClientConfig,
        beacon_node_urls: Vec<RedactingUrl>,
        publish_to_every_node: Vec<PublishedDuty>,
        use_builder: bool,
    },
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct GrandineConfig {
    pub predefined_network: Option<PredefinedNetwork>,
    pub chain_config: Arc<ChainConfig>,
    pub genesis_state_file: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub directories: Arc<Directories>,
    pub in_memory: bool,
    pub request_timeout: Duration,
    pub metrics_config: MetricsConfig,
    pub disable_blockprint_graffiti: bool,
    pub graffiti: Vec<H256>,
    pub max_empty_slots: u64,
    pub suggested_fee_recipient: Option<ExecutionAddress>,
    pub default_builder_boost_factor: Uint256,
    pub default_gas_limit: Option<Gas>,
    pub disable_wait_for_late_blocks: bool,
    pub telemetry_config: Option<TelemetryConfig>,
    pub mode: Mode,
}

/// What only the built-in beacon node needs; `vc` has none.
#[expect(
    clippy::struct_excessive_bools,
    reason = "False positive. The `bool`s are independent."
)]
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct BeaconNodeConfig {
    pub deposit_contract_starting_block: Option<ExecutionBlockNumber>,
    pub checkpoint_sync_url: Option<RedactingUrl>,
    pub genesis_state_download_url: Option<RedactingUrl>,
    pub force_checkpoint_sync: bool,
    pub back_sync_enabled: bool,
    pub eth1_rpc_urls: Vec<RedactingUrl>,
    pub auth_options: AuthOptions,
    pub network_config: NetworkConfig,
    pub storage_config: StorageConfig,
    pub store_config: StoreConfig,
    pub reconstruction_delay: Duration,
    pub slasher_config: Option<SlasherConfig>,
    pub state_slot: Option<Slot>,
    pub http_api_config: Option<HttpApiConfig>,
    pub max_events: usize,
    pub track_liveness: bool,
    pub blacklisted_blocks: HashSet<H256>,
    pub backfill_custody_groups: bool,
    pub custody_mode: CustodyMode,
    pub builder_config: Option<BuilderConfig>,
}

/// What only a running validator client needs; `bn` has none.
#[derive(Clone)]
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

impl ValidatorClientConfig {
    #[must_use]
    pub fn expects_keys(&self, validator_definitions: &ValidatorDefinitions) -> bool {
        self.validator_api_config.is_some()
            || self.use_validator_key_cache
            || !self.web3signer_config.is_empty()
            || !validator_definitions.is_empty()
            || self.keystore_storage_password_file.is_some()
    }
}

impl GrandineConfig {
    #[must_use]
    pub const fn beacon_node_config(&self) -> Option<&BeaconNodeConfig> {
        match &self.mode {
            Mode::Local {
                beacon_node_config, ..
            } => Some(beacon_node_config),
            Mode::Remote { .. } => None,
        }
    }

    #[must_use]
    pub const fn beacon_node_config_mut(&mut self) -> Option<&mut BeaconNodeConfig> {
        match &mut self.mode {
            Mode::Local {
                beacon_node_config, ..
            } => Some(beacon_node_config),
            Mode::Remote { .. } => None,
        }
    }

    #[must_use]
    pub const fn validator_client_config(&self) -> Option<&ValidatorClientConfig> {
        match &self.mode {
            Mode::Local {
                validator_client_config,
                ..
            } => validator_client_config.as_ref(),
            Mode::Remote {
                validator_client_config,
                ..
            } => Some(validator_client_config),
        }
    }

    #[must_use]
    pub const fn command(&self) -> Option<&GrandineCommand> {
        match &self.mode {
            Mode::Local { command, .. } => command.as_ref(),
            Mode::Remote { .. } => None,
        }
    }

    #[must_use]
    pub fn validator_config(
        &self,
        validator_definitions: Arc<ValidatorDefinitionsWithStorage>,
    ) -> ValidatorConfig {
        let Self {
            disable_blockprint_graffiti,
            graffiti,
            max_empty_slots,
            suggested_fee_recipient,
            default_builder_boost_factor,
            default_gas_limit,
            disable_wait_for_late_blocks,
            ..
        } = self;

        let custody_mode = self
            .beacon_node_config()
            .map_or_else(CustodyMode::default, |node| node.custody_mode);

        ValidatorConfig {
            disable_blockprint_graffiti: *disable_blockprint_graffiti,
            graffiti: graffiti.clone(),
            max_empty_slots: *max_empty_slots,
            suggested_fee_recipient: *suggested_fee_recipient,
            default_builder_boost_factor: *default_builder_boost_factor,
            default_gas_limit: *default_gas_limit,
            custody_mode,
            disable_wait_for_late_blocks: *disable_wait_for_late_blocks,
            validator_definitions,
        }
    }

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
            telemetry_config,
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

        if let Some(config) = telemetry_config {
            info!("telemetry export configured with: {config:?}");
        }

        match self.beacon_node_config() {
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

        match self
            .validator_client_config()
            .map(|config| config.validator_api_config.as_ref())
        {
            Some(Some(validator_api_config)) => {
                info!("validator API address: {}", validator_api_config.address);
            }
            Some(None) => info!("validator API disabled"),
            None => info!("validator client disabled"),
        }

        if let Some(builder_config) = self
            .beacon_node_config()
            .and_then(|node| node.builder_config.as_ref())
        {
            info!(
                "using external block builder (API URL: {}, format: {}, \
                default_builder_boost_factor: {default_builder_boost_factor})",
                builder_config.builder_api_url, builder_config.builder_api_format,
            );
        }

        if let Mode::Remote {
            beacon_node_urls,
            publish_to_every_node,
            use_builder,
            ..
        } = &self.mode
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

            if *use_builder {
                info!("registering validators with the builder behind the remote beacon nodes");
            }
        }

        if let Some(validator_client) = self.validator_client_config() {
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

impl BeaconNodeConfig {
    fn report(&self, chain_config: &ChainConfig) {
        let Self {
            checkpoint_sync_url,
            back_sync_enabled,
            eth1_rpc_urls,
            network_config,
            storage_config,
            store_config,
            slasher_config,
            state_slot,
            http_api_config,
            track_liveness,
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

        info!(
            "archival interval: {} epochs",
            storage_config.archival_epoch_interval
        );
        info!("slasher enabled: {}", slasher_config.is_some());

        if *track_liveness {
            info!("validator liveness tracking enabled");
        }

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

        if let Some(slasher_config) = slasher_config {
            info!(
                "slasher history limit: {}",
                slasher_config.slashing_history_limit
            );
        }

        info!("back-sync enabled: {back_sync_enabled}");

        if store_config.sync_without_reconstruction {
            info!("sync with reconstruction disabled");
        }

        if chain_config.is_peerdas_scheduled() {
            info!("custody mode: {custody_mode:?}");
        }
    }
}
