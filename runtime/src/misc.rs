use core::num::NonZeroU64;
use std::{path::PathBuf, sync::Arc};

use anyhow::{ensure, Result};
use bytesize::ByteSize;
use database::Database;
use directories::Directories;
use fs_err::PathExt as _;
use log::info;
use metrics::{MetricsServerConfig, MetricsServiceConfig};
use prometheus_metrics::Metrics;

#[derive(Clone, Debug)]
pub struct MetricsConfig {
    pub metrics: Option<Arc<Metrics>>,
    pub metrics_server_config: Option<MetricsServerConfig>,
    pub metrics_service_config: Option<MetricsServiceConfig>,
}

#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub in_memory: bool,
    pub db_size: ByteSize,
    pub directories: Arc<Directories>,
    pub eth1_db_size: ByteSize,
    pub archival_epoch_interval: NonZeroU64,
    pub prune_storage: bool,
}

impl StorageConfig {
    pub fn eth1_database(&self) -> Result<Database> {
        Database::persistent(
            "eth1",
            self.directories
                .store_directory
                .clone()
                .unwrap_or_default()
                .join("eth1_cache"),
            self.eth1_db_size,
            false,
        )
    }

    pub fn beacon_fork_choice_database(
        &self,
        custom_path: Option<PathBuf>,
        read_only: bool,
    ) -> Result<Database> {
        let path = custom_path.unwrap_or_else(|| {
            self.directories
                .store_directory
                .clone()
                .unwrap_or_default()
                .join("beacon_fork_choice")
        });

        if read_only {
            ensure!(
                path.fs_err_try_exists()?,
                "beacon_fork_choice database path does not exist: {path:?}",
            );
        }

        Database::persistent("beacon_fork_choice", path, self.db_size, read_only)
    }

    pub fn sync_database(&self) -> Result<Database> {
        Database::persistent(
            "sync",
            self.directories
                .store_directory
                .clone()
                .unwrap_or_default()
                .join("sync"),
            self.db_size,
            false,
        )
    }

    #[must_use]
    pub fn with_increased_db_sizes(self, modifier: u64) -> Self {
        let Self {
            in_memory,
            db_size,
            directories,
            eth1_db_size,
            archival_epoch_interval,
            prune_storage,
        } = self;

        let new_db_size = ByteSize::b(
            db_size
                .as_u64()
                .checked_mul(modifier)
                .unwrap_or(db_size.as_u64()),
        );

        let new_eth1_db_size = ByteSize::b(
            eth1_db_size
                .as_u64()
                .checked_mul(modifier)
                .unwrap_or(eth1_db_size.as_u64()),
        );

        Self {
            in_memory,
            db_size: new_db_size,
            directories,
            eth1_db_size: new_eth1_db_size,
            archival_epoch_interval,
            prune_storage,
        }
    }

    pub fn print_db_sizes(&self) {
        info!(
            "Eth2 database upper limit: {}",
            self.db_size.to_string_as(true)
        );

        info!(
            "Eth1 database upper limit: {}",
            self.eth1_db_size.to_string_as(true),
        );
    }
}

#[cfg(test)]
mod tests {
    use nonzero_ext::nonzero;

    use super::*;

    #[test]
    fn increase_storage_config_db_sizes_test() {
        let storage_config = StorageConfig {
            in_memory: true,
            db_size: ByteSize::gb(6),
            directories: Arc::new(Directories::default()),
            eth1_db_size: ByteSize::gb(2),
            archival_epoch_interval: nonzero!(1_u64),
            prune_storage: true,
        };

        let StorageConfig {
            db_size,
            eth1_db_size,
            ..
        } = storage_config.with_increased_db_sizes(2);

        assert_eq!(db_size, ByteSize::gb(12));
        assert_eq!(eth1_db_size, ByteSize::gb(4));
    }

    #[test]
    fn increase_storage_config_db_sizes_extreme_test() {
        let storage_config = StorageConfig {
            in_memory: true,
            db_size: ByteSize::b(u64::MAX),
            directories: Arc::new(Directories::default()),
            eth1_db_size: ByteSize::b(u64::MAX),
            archival_epoch_interval: nonzero!(1_u64),
            prune_storage: true,
        };

        assert_eq!(storage_config.db_size, ByteSize::b(u64::MAX));
        assert_eq!(storage_config.eth1_db_size, ByteSize::b(u64::MAX));

        let StorageConfig {
            db_size,
            eth1_db_size,
            ..
        } = storage_config.with_increased_db_sizes(2);

        assert_eq!(db_size, ByteSize::b(u64::MAX));
        assert_eq!(eth1_db_size, ByteSize::b(u64::MAX));
    }
}
