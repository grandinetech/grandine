use std::path::PathBuf;

use clap::Subcommand;
use strum::EnumString;
use types::phase0::primitives::Slot;

#[derive(Copy, Clone, Debug, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum AppDatabase {
    Sync,
}

#[derive(Clone, Subcommand)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum GrandineCommand {
    /// Show information about database records
    /// (example: grandine db-info --database sync)
    DbInfo {
        /// Type of the database
        #[clap(short, long)]
        database: AppDatabase,
        /// Path to a custom directory where database files are stored
        /// (example: grandine --network holesky db-info -d sync -p ~/.grandine/holesky/beacon/sync)
        #[clap(short, long)]
        path: Option<PathBuf>,
    },

    /// Show `beacon_fork_choice` database element sizes
    /// (example: grandine db-stats)
    DbStats {
        /// Path to a custom directory where `beacon_fork_choice` database files are stored
        #[expect(clippy::doc_markdown)]
        /// (example: grandine --network holesky db-stats -p ~/.grandine/holesky/beacon/beacon_fork_choice)
        #[clap(short, long)]
        path: Option<PathBuf>,
    },

    /// Export blocks and state to ssz files within slot range for debugging
    /// (example: grandine export --from 0 --to 5)
    Export {
        /// First slot to export (inclusive)
        #[clap(short, long, value_name = "SLOT")]
        from: Slot,
        /// Last slot to export (inclusive)
        #[clap(short, long, value_name = "SLOT")]
        to: Slot,
        /// Output directory (defaults to current directory)
        #[clap(short, long)]
        output_dir: Option<PathBuf>,
    },

    /// Replay blocks within slot range
    /// (example: grandine replay --from 0 --to 5)
    Replay {
        /// Replay start slot (inclusive)
        #[clap(short, long, value_name = "SLOT")]
        from: Slot,

        /// Replay end slot (inclusive)
        #[clap(short, long, value_name = "SLOT")]
        to: Slot,

        /// Input directory (defaults to current directory)
        #[clap(short, long)]
        input_dir: Option<PathBuf>,
    },

    /// Import/export slashing protection interchange file
    /// (example: grandine interchange import file.json)
    #[clap(subcommand)]
    Interchange(InterchangeCommand),
}

#[derive(Clone, Subcommand)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum InterchangeCommand {
    /// Import slashing protection interchange file
    /// (example: grandine interchange import file.json)
    Import { file_path: PathBuf },
    /// Export slashing protection interchange file
    /// (example: grandine interchange export file.json)
    Export { file_path: PathBuf },
}
