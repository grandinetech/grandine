use std::{io::ErrorKind, path::Path};

use anyhow::{bail, ensure, Result};
use grandine_version::APPLICATION_NAME;
use log::info;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// We store metadata in a JSON file directly in the data directory. TOML was considered but rejected
// because the `toml` crate cannot serialize struct-like enum variants, which we may need in the
// future. RocksDB was rejected because it would complicate backward compatibility.
const META_FILE_NAME: &str = "meta.json";

// # Schema version history
//
// ## 0.1.0
//
// First public release. It used the following RocksDB databases:
// - `*/beacon/beacon_fork_choice`
// - `*/beacon/eth1_cache`
// - `*/beacon/slasher_attestation_votes_*_db`
// - `*/beacon/slasher_blocks_*_db`
// - `*/beacon/slasher_indexed_attestations_*_db`
// - `*/beacon/slasher_max_targets_*_db`
// - `*/beacon/slasher_min_targets_*_db`
//
// The names of the databases were the same as their full paths in the filesystem.
// This was unintentional and was fixed in version 0.2.1.
//
// ## 0.2.0
//
// RocksDB was replaced with libmdbx. The files that the two use do not seem to overlap,
// but we treated this as a breaking change to be safe.
//
// ## 0.2.1
//
// - Added database `slashing_protection_meta`.
// - Renamed database `*/beacon/beacon_fork_choice`                to `beacon_fork_choice`.
// - Renamed database `*/beacon/eth1_cache`                        to `eth1`.
// - Renamed database `*/beacon/slasher_attestation_votes_*_db`    to `SLASHER_ATTESTATION_VOTES`.
// - Renamed database `*/beacon/slasher_blocks_*_db`               to `SLASHER_BLOCKS`.
// - Renamed database `*/beacon/slasher_indexed_attestations_*_db` to `SLASHER_INDEXED_ATTESTATIONS`.
// - Renamed database `*/beacon/slasher_max_targets_*_db`          to `SLASHER_MAX_TARGETS`.
// - Renamed database `*/beacon/slasher_min_targets_*_db`          to `SLASHER_MIN_TARGETS`.
//
// The renamed databases are stored in the same directories as before the rename.
// The old databases are used if available.
//
// ## 0.2.2
//
// Persist checkpoint state on each finalized epoch.
//
// ## 0.2.3
//
// Added state_root to slot indexing to storage to enable loading archived states by state root.
const SCHEMA_VERSION: &str = "0.2.3";

// Semantic Versioning by itself only achieves forward compatibility.
// Backward compatibility is achieved using a version requirement separate from the schema version.
const VERSION_REQUIREMENT: &str = "0.2.0";

#[derive(Deserialize, Serialize)]
struct Meta<'bytes> {
    application: &'bytes str,
    schema_version: &'bytes str,
}

#[derive(Debug, Error)]
enum Error {
    #[error("expected application name {APPLICATION_NAME:?}, found {actual:?}")]
    ApplicationNameMismatch { actual: String },
    #[error("expected schema version compatible with {VERSION_REQUIREMENT}, found {version}")]
    IncompatibleVersion { version: Version },
}

pub fn initialize(data_directory: impl AsRef<Path>) -> Result<()> {
    let meta_file_path = data_directory.as_ref().join(META_FILE_NAME);

    match fs_err::read(meta_file_path.as_path()) {
        Ok(bytes) => {
            let Meta {
                application,
                schema_version,
            } = serde_json::from_slice(bytes.as_slice())?;

            ensure!(
                application == APPLICATION_NAME,
                Error::ApplicationNameMismatch {
                    actual: application.to_owned(),
                },
            );

            let version = schema_version.parse()?;

            // 0.2.0 version requirement does not strictly require any actions from users.
            // And as this version requirement was introduced separately from rocks_db -> libmdbx migration,
            // some users may have switched to libmdbx and resynced without updating their schema version to 0.2.0.
            // So we skip this requirement check in order not to force users to unnecessary resync their libmdbx database.
            if VERSION_REQUIREMENT != "0.2.0" {
                ensure!(
                    VersionReq::parse(VERSION_REQUIREMENT)
                        .expect("constant contains valid Semantic Versioning requirement")
                        .matches(&version),
                    Error::IncompatibleVersion { version },
                );
            }

            // Set the schema version to the current one even if it's older.
            // The application can only write data conforming to the current schema.
            if schema_version != SCHEMA_VERSION {
                write_meta(data_directory)?;

                info!("using schema version {SCHEMA_VERSION} for new data");
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            write_meta(data_directory)?;

            info!("initialized data directory with schema version {SCHEMA_VERSION}");
        }
        Err(error) => bail!(error),
    }

    Ok(())
}

fn write_meta(data_directory: impl AsRef<Path>) -> Result<()> {
    let meta_file_path = data_directory.as_ref().join(META_FILE_NAME);

    let meta = Meta {
        application: APPLICATION_NAME,
        schema_version: SCHEMA_VERSION,
    };

    let mut string = serde_json::to_string_pretty(&meta)?;
    string.push('\n');

    fs_err::create_dir_all(data_directory)?;
    fs_err::write(meta_file_path, string)?;

    Ok(())
}
