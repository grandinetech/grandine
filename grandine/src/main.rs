use std::process::ExitCode;

use allocator as _;
use anyhow::Result;
use clap::{Error as ClapError, Parser as _};
use log::error;
use runtime::{Error, GrandineArgs};

// #[cfg(not(any(feature = "preset-any", test, doc)))]
// compile_error! {
//     "at least one preset must be enabled; \
//      pass --features … to Cargo; \
//      see grandine/Cargo.toml for a list of features"
// }

use directories::Directories;
use fork_choice_store::{StoreConfig, DEFAULT_CACHE_LOCK_TIMEOUT_MILLIS};
use grandine_version::APPLICATION_NAME_AND_VERSION;
use http_api::HttpApiConfig;
use runtime::{run, GrandineConfig, MetricsConfig, PredefinedNetwork, StorageConfig, DEFAULT_ETH1_DB_SIZE, DEFAULT_ETH2_DB_SIZE, DEFAULT_REQUEST_TIMEOUT, GRANDINE_DONATION_ADDRESS};
use signer::Web3SignerConfig;
use slasher::SlasherConfig;
use slashing_protection::DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT;
use types::phase0::primitives::H256;
use validator::ValidatorConfig;
use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};
use fork_choice_control::DEFAULT_ARCHIVAL_EPOCH_INTERVAL;
use eth1_api::AuthOptions;
use anyhow::{ensure};
use thiserror::Error;
use reqwest::Url;

#[derive(Debug, Error)]
enum GraffitiError {
    #[error("graffiti must be no longer than {} bytes", H256::len_bytes())]
    GraffitiTooLong,
}

// TODO: do not duplicate this code, move it to general crate (now is copied from grandine_args.rs)
fn parse_graffiti(string: &str) -> Result<H256> {
    ensure!(string.len() <= H256::len_bytes(), GraffitiError::GraffitiTooLong);

    let mut graffiti = H256::zero();
    graffiti[..string.len()].copy_from_slice(string.as_bytes());

    Ok(graffiti)
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

fn try_main() -> Result<()> {
    let config = GrandineArgs::try_parse()?
        .try_into_config()
        .map_err(GrandineArgs::clap_error)?;
    // let chain_config = runtime::PredefinedNetwork::Holesky.chain_config();
    // println!("Paleidime");
    // let dirs = Arc::new(Directories::default().set_defaults(&chain_config));

    // let Ok(graffiti) = parse_graffiti(APPLICATION_NAME_AND_VERSION) else {
    //     return Ok(());
    // };

    // let Some(data_dir) = dirs.data_dir.clone() else {
    //     return Ok(());
    // };

    // println!("Paleidimo configas");
    // let config = GrandineConfig {
    //     predefined_network: Some(
    //         runtime::PredefinedNetwork::Holesky
    //     ),
    //     chain_config: Arc::new(chain_config), // reikia
    //     deposit_contract_starting_block: None,
    //     genesis_state_file: None,
    //     genesis_state_download_url: None,
    //     checkpoint_sync_url: Some(Url::parse("https://holesky-checkpoint-sync.stakely.io/").unwrap()),
    //     force_checkpoint_sync: true,
    //     back_sync: false,
    //     eth1_rpc_urls: vec![
    //         Url::parse("http://localhost:8551").unwrap()
    //     ],
    //     data_dir, // reikia
    //     validators: None,
    //     keystore_storage_password_file: None,
    //     graffiti: vec![graffiti], // reikia
    //     max_empty_slots: ValidatorConfig::default().max_empty_slots,
    //     suggested_fee_recipient: GRANDINE_DONATION_ADDRESS,
    //     network_config: PredefinedNetwork::Holesky.network_config(), // reikia
    //     storage_config: StorageConfig {
    //         in_memory: false,
    //         db_size: DEFAULT_ETH2_DB_SIZE,
    //         eth1_db_size: DEFAULT_ETH1_DB_SIZE,
    //         directories: dirs.clone(),  // same kaip ir dirs
    //         archival_epoch_interval: DEFAULT_ARCHIVAL_EPOCH_INTERVAL,
    //         prune_storage: false,
    //     },
    //     unfinalized_states_in_memory: StoreConfig::default().unfinalized_states_in_memory,
    //     request_timeout: Duration::from_millis(DEFAULT_REQUEST_TIMEOUT),
    //     state_cache_lock_timeout: Duration::from_millis(DEFAULT_CACHE_LOCK_TIMEOUT_MILLIS),
    //     command: None,
    //     slashing_enabled: false,
    //     slashing_history_limit: SlasherConfig::default().slashing_history_limit,
    //     features: Vec::new(),
    //     state_slot: None,
    //     auth_options: AuthOptions {
    //         secrets_path: Some(PathBuf::from("/home/paul/Desktop/blockchain/nether/nethermind/src/Nethermind/Nethermind.Runner/keystore/jwt-secret")),
    //         id: None,
    //         version: None,
    //     },
    //     builder_config: None,
    //     web3signer_config: Web3SignerConfig {
    //         allow_to_reload_keys: false,
    //         urls: Vec::new(),
    //         public_keys: HashSet::new(),
    //     },
    //     http_api_config: HttpApiConfig::default(),
    //     metrics_config: MetricsConfig {
    //         metrics: None,
    //         metrics_server_config: None,
    //         metrics_service_config: None,
    //     },
    //     track_liveness: false,
    //     detect_doppelgangers: false,
    //     use_validator_key_cache: false,
    //     slashing_protection_history_limit: DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT,
    //     in_memory: false,
    //     validator_api_config: None,
    // };
    println!("Po configo");
    match runtime::run(config) {
        Ok(()) => Ok(()),
        Err(error) => {
            if matches!(error.downcast_ref(), Some(Error::ArgumentsError { .. })) {
                println!("Erroras");
                Err(GrandineArgs::clap_error(error).into())
            } else {
                println!("Erroras");
                Err(error)
            }
        }
    }
}
