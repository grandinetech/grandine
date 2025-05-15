use core::{net::SocketAddr, time::Duration};
use std::{collections::HashSet, path::PathBuf, sync::Arc};

use builder_api::BuilderConfig;
use eth1_api::AuthOptions;
use http_api::HttpApiConfig;
use itertools::Itertools as _;
use kzg_utils::KzgBackend;
use logging::info_with_peers;
use p2p::NetworkConfig;
use signer::Web3SignerConfig;
use ssz::Uint256;
use types::{
    bellatrix::primitives::Gas,
    config::Config as ChainConfig,
    phase0::primitives::{ExecutionAddress, ExecutionBlockNumber, Slot, H256},
    redacting_url::RedactingUrl,
};
use validator::ValidatorApiConfig;

use crate::{
    commands::GrandineCommand, predefined_network::PredefinedNetwork, validators::Validators,
    MetricsConfig, StorageConfig,
};

#[expect(
    clippy::struct_excessive_bools,
    reason = "False positive. The `bool`s are independent."
)]
#[cfg_attr(test, derive(Debug))]
pub struct GrandineConfig {
    pub predefined_network: Option<PredefinedNetwork>,
    pub chain_config: Arc<ChainConfig>,
    pub deposit_contract_starting_block: Option<ExecutionBlockNumber>,
    pub genesis_state_file: Option<PathBuf>,
    pub genesis_state_download_url: Option<RedactingUrl>,
    pub checkpoint_sync_url: Option<RedactingUrl>,
    pub force_checkpoint_sync: bool,
    pub back_sync_enabled: bool,
    pub eth1_rpc_urls: Vec<RedactingUrl>,
    pub data_dir: PathBuf,
    pub validators: Option<Validators>,
    pub keystore_storage_password_file: Option<PathBuf>,
    pub disable_blockprint_graffiti: bool,
    pub graffiti: Vec<H256>,
    pub max_empty_slots: u64,
    pub suggested_fee_recipient: ExecutionAddress,
    pub default_builder_boost_factor: Uint256,
    pub default_gas_limit: Gas,
    pub network_config: NetworkConfig,
    pub storage_config: StorageConfig,
    pub unfinalized_states_in_memory: u64,
    pub request_timeout: Duration,
    pub max_epochs_to_retain_states_in_cache: u64,
    pub state_cache_lock_timeout: Duration,
    pub command: Option<GrandineCommand>,
    pub slashing_enabled: bool,
    pub slashing_history_limit: u64,
    pub state_slot: Option<Slot>,
    pub auth_options: AuthOptions,
    pub builder_config: Option<BuilderConfig>,
    pub web3signer_config: Web3SignerConfig,
    pub http_api_config: HttpApiConfig,
    pub max_events: usize,
    pub metrics_config: MetricsConfig,
    pub track_liveness: bool,
    pub detect_doppelgangers: bool,
    pub use_validator_key_cache: bool,
    pub slashing_protection_history_limit: u64,
    pub in_memory: bool,
    pub validator_api_config: Option<ValidatorApiConfig>,
    pub kzg_backend: KzgBackend,
    pub blacklisted_blocks: HashSet<H256>,
    pub report_validator_performance: bool,
    pub withhold_data_columns_publishing: bool,
    pub backfill_custody_groups: bool,
    pub disable_engine_getblobs: bool,
    pub sync_without_reconstruction: bool,
}

impl GrandineConfig {
    #[expect(clippy::cognitive_complexity)]
    #[expect(clippy::too_many_lines)]
    pub fn report(&self) {
        let Self {
            predefined_network,
            chain_config,
            back_sync_enabled,
            eth1_rpc_urls,
            data_dir,
            disable_blockprint_graffiti,
            graffiti,
            suggested_fee_recipient,
            default_builder_boost_factor,
            network_config,
            storage_config,
            slashing_enabled,
            slashing_history_limit,
            state_slot,
            builder_config,
            web3signer_config,
            http_api_config,
            metrics_config,
            checkpoint_sync_url,
            use_validator_key_cache,
            validator_api_config,
            withhold_data_columns_publishing,
            disable_engine_getblobs,
            sync_without_reconstruction,
            ..
        } = self;

        let StorageConfig {
            archival_epoch_interval,
            ..
        } = storage_config;

        match predefined_network {
            Some(network) => info_with_peers!("network: {network}"),
            None => info_with_peers!(
                "network: custom with {} preset and {} configuration",
                chain_config.preset_base,
                chain_config.config_name,
            ),
        }

        info_with_peers!("storage mode: {:?}", storage_config.storage_mode);
        info_with_peers!("data directory: {}", data_dir.display());

        self.storage_config.print_db_sizes();

        info_with_peers!("Eth1 RPC URLs: [{}]", eth1_rpc_urls.iter().format(", "));
        info_with_peers!("graffiti: {graffiti:?}");

        if *disable_blockprint_graffiti {
            info_with_peers!("blockprint graffiti disabled");
        }

        info_with_peers!("HTTP API address: {}", http_api_config.address);

        if let Some(metrics_server_config) = &metrics_config.metrics_server_config {
            info_with_peers!(
                "metrics server address: {}",
                SocketAddr::from(metrics_server_config),
            );
        }

        if let Some(metrics_service_config) = &metrics_config.metrics_service_config {
            info_with_peers!(
                "metrics service configured with {:?} update interval",
                metrics_service_config.metrics_update_interval,
            );
        }

        if let Some(validator_api_config) = validator_api_config.as_ref() {
            info_with_peers!("validator API address: {}", validator_api_config.address);
        } else {
            info_with_peers!("validator API disabled");
        }

        info_with_peers!("archival interval: {archival_epoch_interval} epochs");
        info_with_peers!("slasher enabled: {slashing_enabled}");

        if let Some(client_version) = &network_config.identify_agent_version {
            info_with_peers!("client version: {client_version}");
        }

        if !network_config.trusted_peers.is_empty() {
            info_with_peers!("trusted peers: {:?}", network_config.trusted_peers);
        }

        if let Some(slot) = state_slot {
            info_with_peers!("force state slot: {slot}");
        }

        if let Some(builder_config) = builder_config {
            info_with_peers!(
                "using external block builder (API URL: {}, format: {}, \
                default_builder_boost_factor: {default_builder_boost_factor})",
                builder_config.builder_api_url,
                builder_config.builder_api_format,
            );
        }

        if let Some(checkpoint_sync_url) = checkpoint_sync_url {
            info_with_peers!("checkpoint sync url: {checkpoint_sync_url}");
        }

        if !web3signer_config.urls.is_empty() {
            info_with_peers!(
                "using Web3Signer API to sign validator messages (API URLs: [{}])",
                web3signer_config.urls.iter().format(", "),
            );
        }

        if *slashing_enabled {
            info_with_peers!("slasher history limit: {slashing_history_limit}");
        }

        info_with_peers!("suggested fee recipient: {suggested_fee_recipient}");
        info_with_peers!("back-sync enabled: {back_sync_enabled}");

        if *use_validator_key_cache {
            info_with_peers!("using validator key cache");
        }

        if *withhold_data_columns_publishing {
            info_with_peers!("withholding data column sidecars publishing");
        }

        if *disable_engine_getblobs {
            info_with_peers!("running without engine_getBlobs integration");
        }

        if *sync_without_reconstruction {
            info_with_peers!("sync with reconstruction disabled");
        }
    }
}
