use std::path::PathBuf;

use anyhow::Result;
use database::DatabaseMode;

use crate::commands::AppDatabase;
use crate::StorageConfig;
pub fn print(
    storage_config: &StorageConfig,
    database: AppDatabase,
    custom_path: Option<PathBuf>,
) -> Result<()> {
    match database {
        AppDatabase::Sync => {
            let database = storage_config.sync_database(custom_path, DatabaseMode::ReadOnly)?;
            p2p::print_sync_database_info(&database)?;
        }
    }

    Ok(())
}
