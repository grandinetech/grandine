use std::path::{Path, PathBuf};

use anyhow::Result;
use types::config::Config;

#[derive(Debug, Default)]
pub struct Directories {
    pub data_dir: Option<PathBuf>,
    pub store_directory: Option<PathBuf>,
    pub network_dir: Option<PathBuf>,
    pub validator_dir: Option<PathBuf>,
}

impl Directories {
    #[must_use]
    pub fn set_defaults(mut self, config: &Config) -> Self {
        assert!(
            !config.config_name.is_empty() && !Path::new(config.config_name.as_ref()).is_absolute(),
            "Config::validate should be called before Directories::set_defaults",
        );

        let Self {
            data_dir,
            store_directory,
            network_dir,
            validator_dir,
        } = &mut self;

        // `~/.grandine` or `.grandine`
        if data_dir.is_none() {
            *data_dir = Some(dirs::home_dir().unwrap_or_default().join(".grandine"));
        }

        // `~/.grandine/NETWORK_NAME`
        if let Some(data_dir) = data_dir.as_mut() {
            data_dir.push(config.config_name.as_ref());
        }

        // `~/.grandine/NETWORK_NAME/beacon`
        if store_directory.is_none() {
            *store_directory = data_dir.as_ref().map(|data_dir| data_dir.join("beacon"));
        }

        // `~/.grandine/NETWORK_NAME/network`
        if network_dir.is_none() {
            *network_dir = data_dir.as_ref().map(|data_dir| data_dir.join("network"));
        }

        // `~/.grandine/NETWORK_NAME/validator`
        if validator_dir.is_none() {
            *validator_dir = data_dir.as_ref().map(|data_dir| data_dir.join("validator"));
        }

        self
    }

    // TODO: This does not include validator_dir and other files outside store and network directories
    pub fn disk_usage(&self) -> Result<u64> {
        let dir_usage =
            |dir: Option<&PathBuf>| dir.as_ref().map(fs_extra::dir::get_size).transpose();

        let store_usage = dir_usage(self.store_directory.as_ref())?.unwrap_or_default();
        let network_usage = dir_usage(self.network_dir.as_ref())?.unwrap_or_default();

        Ok(store_usage + network_usage)
    }
}
