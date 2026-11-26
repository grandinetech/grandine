use std::path::{Path, PathBuf};

use anyhow::Result;
use types::config::Config;

const BLOBS_DATABASE_DIR_NAME: &str = "blobs";

#[derive(Debug, Default)]
pub struct Directories {
    pub data_dir: Option<PathBuf>,
    pub store_directory: Option<PathBuf>,
    pub blobs_dir: Option<PathBuf>,
    pub network_dir: Option<PathBuf>,
    pub validator_dir: Option<PathBuf>,
    pub secrets_dir: Option<PathBuf>,
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
            blobs_dir,
            network_dir,
            validator_dir,
            secrets_dir,
        } = &mut self;

        // `~/.grandine` or `.grandine`
        *data_dir = Some(data_directory(data_dir.as_ref()));

        // `~/.grandine/NETWORK_NAME`
        if let Some(data_dir) = data_dir.as_mut() {
            data_dir.push(config.config_name.as_ref());
        }

        // `~/.grandine/NETWORK_NAME/beacon`
        if store_directory.is_none() {
            *store_directory = data_dir.as_ref().map(|data_dir| data_dir.join("beacon"));
        }

        // `~/.grandine/NETWORK_NAME/beacon`
        // The blobs database is in the `blobs` subdirectory, next to the other beacon databases.
        if blobs_dir.is_none() {
            blobs_dir.clone_from(store_directory);
        }

        // `~/.grandine/NETWORK_NAME/network`
        if network_dir.is_none() {
            *network_dir = data_dir.as_ref().map(|data_dir| data_dir.join("network"));
        }

        // `~/.grandine/NETWORK_NAME/validator`
        if validator_dir.is_none() {
            *validator_dir = data_dir.as_ref().map(|data_dir| data_dir.join("validator"));
        }

        // `~/.grandine/NETWORK_NAME/secrets`
        if secrets_dir.is_none() {
            *secrets_dir = data_dir.as_ref().map(|data_dir| data_dir.join("secrets"));
        }

        self
    }

    // The blobs database is stored in a fixed subdirectory of `blobs_dir`,
    // so that resetting it never deletes other files in a user-supplied directory.
    #[must_use]
    pub fn blobs_database_dir(&self) -> Option<PathBuf> {
        self.blobs_dir
            .as_ref()
            .map(|blobs_dir| blobs_dir.join(BLOBS_DATABASE_DIR_NAME))
    }

    // TODO: This does not include files outside the store, blobs, network and validator directories
    pub fn disk_usage(&self) -> Result<u64> {
        // The validator client never creates the store, blobs and network directories.
        let dir_usage = |dir: Option<&PathBuf>| {
            dir.filter(|dir| dir.exists())
                .map(fs_extra::dir::get_size)
                .transpose()
        };

        let store_usage = dir_usage(self.store_directory.as_ref())?.unwrap_or_default();
        // The blobs database is already counted if it is inside the store directory.
        let blobs_database_dir = self.blobs_database_dir().filter(|blobs_database_dir| {
            self.store_directory
                .as_ref()
                .is_none_or(|store_directory| !blobs_database_dir.starts_with(store_directory))
        });

        let blobs_usage = dir_usage(blobs_database_dir.as_ref())?.unwrap_or_default();
        let network_usage = dir_usage(self.network_dir.as_ref())?.unwrap_or_default();
        let validator_usage = dir_usage(self.validator_dir.as_ref())?.unwrap_or_default();

        Ok(store_usage
            .saturating_add(blobs_usage)
            .saturating_add(network_usage)
            .saturating_add(validator_usage))
    }
}

#[must_use]
pub fn data_directory(data_dir: Option<&PathBuf>) -> PathBuf {
    data_dir
        .cloned()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".grandine"))
}

#[cfg(test)]
mod tests {
    use fs_err as fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn disk_usage_counts_blobs_database_inside_store_directory_once() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store_directory = temp_dir.path().join("beacon");
        let blobs_database_dir = store_directory.join("blobs");

        fs::create_dir_all(&blobs_database_dir)?;
        fs::write(store_directory.join("store"), [0; 10])?;
        fs::write(blobs_database_dir.join("mdbx.dat"), [0; 5])?;

        let directories = Directories {
            store_directory: Some(store_directory.clone()),
            blobs_dir: Some(store_directory),
            ..Directories::default()
        };

        assert_eq!(directories.disk_usage()?, 15);

        Ok(())
    }

    #[test]
    fn disk_usage_counts_only_blobs_database_in_separate_blobs_dir() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store_directory = temp_dir.path().join("beacon");
        let blobs_dir = temp_dir.path().join("shared");

        fs::create_dir_all(&store_directory)?;
        fs::create_dir_all(blobs_dir.join("blobs"))?;
        fs::write(store_directory.join("store"), [0; 10])?;
        fs::write(blobs_dir.join("blobs").join("mdbx.dat"), [0; 5])?;
        fs::write(blobs_dir.join("unrelated"), [0; 100])?;

        let directories = Directories {
            store_directory: Some(store_directory),
            blobs_dir: Some(blobs_dir),
            ..Directories::default()
        };

        assert_eq!(directories.disk_usage()?, 15);

        Ok(())
    }

    #[test]
    fn blobs_dir_defaults_to_store_directory() {
        let directories = Directories {
            data_dir: Some("/data".into()),
            store_directory: Some("/store".into()),
            ..Directories::default()
        }
        .set_defaults(&Config::mainnet());

        assert_eq!(directories.blobs_dir, Some("/store".into()));
        assert_eq!(
            directories.blobs_database_dir(),
            Some("/store/blobs".into()),
        );
    }
}
