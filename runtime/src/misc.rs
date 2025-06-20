use core::num::NonZeroU64;
use std::{path::PathBuf, sync::Arc};

use anyhow::{ensure, Result};
use bytesize::ByteSize;
use database::{Database, DatabaseMode, RestartMessage};
use directories::Directories;
use fork_choice_control::StorageMode;
use fs_err::PathExt as _;
use futures::channel::mpsc::UnboundedSender;
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
    pub storage_mode: StorageMode,
}

impl StorageConfig {
    pub fn eth1_database(&self, restart_tx: UnboundedSender<RestartMessage>) -> Result<Database> {
        Database::persistent(
            "eth1",
            self.directories
                .store_directory
                .clone()
                .unwrap_or_default()
                .join("eth1_cache"),
            self.eth1_db_size,
            DatabaseMode::ReadWrite,
            Some(restart_tx),
        )
    }

    pub fn beacon_fork_choice_database(
        &self,
        custom_path: Option<PathBuf>,
        mode: DatabaseMode,
        restart_tx: Option<UnboundedSender<RestartMessage>>,
    ) -> Result<Database> {
        let path = custom_path.unwrap_or_else(|| {
            self.directories
                .store_directory
                .clone()
                .unwrap_or_default()
                .join("beacon_fork_choice")
        });

        if mode.is_read_only() {
            ensure!(
                path.fs_err_try_exists()?,
                "beacon_fork_choice database path does not exist: {path:?}",
            );
        }

        Database::persistent("beacon_fork_choice", path, self.db_size, mode, restart_tx)
    }

    pub fn pubkey_cache_database(
        &self,
        custom_path: Option<PathBuf>,
        mode: DatabaseMode,
        restart_tx: Option<UnboundedSender<RestartMessage>>,
    ) -> Result<Database> {
        let path = custom_path.unwrap_or_else(|| {
            self.directories
                .store_directory
                .clone()
                .unwrap_or_default()
                .join("pubkey_cache")
        });

        if mode.is_read_only() {
            ensure!(
                path.fs_err_try_exists()?,
                "pubkey_cache database path does not exist: {path:?}",
            );
        }

        Database::persistent("pubkey_cache", path, self.db_size, mode, restart_tx)
    }

    pub fn sync_database(
        &self,
        custom_path: Option<PathBuf>,
        mode: DatabaseMode,
    ) -> Result<Database> {
        let path = custom_path.unwrap_or_else(|| {
            self.directories
                .store_directory
                .clone()
                .unwrap_or_default()
                .join("sync")
        });

        if mode.is_read_only() {
            ensure!(
                path.fs_err_try_exists()?,
                "sync database path does not exist: {path:?}",
            );
        }

        Database::persistent("sync", path, self.db_size, mode, None)
    }

    #[must_use]
    pub fn with_increased_db_sizes(self, modifier: u64) -> Self {
        let Self {
            in_memory,
            db_size,
            directories,
            eth1_db_size,
            archival_epoch_interval,
            storage_mode,
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
            storage_mode,
        }
    }

    pub fn print_db_sizes(&self) {
        info!("Eth2 database upper limit: {}", self.db_size.display().si());
        info!(
            "Eth1 database upper limit: {}",
            self.eth1_db_size.display().si(),
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
            storage_mode: StorageMode::Standard,
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
            storage_mode: StorageMode::Standard,
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
