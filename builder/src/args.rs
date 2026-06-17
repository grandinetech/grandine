use std::path::PathBuf;

use clap::{Args, Parser};
use types::{phase0::primitives::ExecutionAddress, redacting_url::RedactingUrl};

#[derive(Debug, Parser)]
#[command(name = "grandine-builder", version, about = "Grandine builder client")]
pub struct BuilderArgs {
    #[clap(flatten)]
    pub beacon_node: BeaconNodeOptions,

    #[clap(flatten)]
    pub execution: ExecutionOptions,

    #[clap(flatten)]
    pub keystore: KeystoreOptions,

    #[clap(flatten)]
    pub builder: BuilderOptions,
}

#[derive(Debug, Args)]
pub struct BeaconNodeOptions {
    /// Beacon node REST API endpoint (e.g. http://localhost:5052).
    #[clap(long)]
    pub beacon_node: RedactingUrl,

    /// Optional bearer token for beacon nodes whose REST API requires authentication.
    #[clap(long)]
    pub beacon_node_auth: Option<String>,
}

#[derive(Debug, Args)]
pub struct ExecutionOptions {
    /// Execution engine JSON-RPC endpoint (engine API).
    #[clap(long)]
    pub execution_engine: RedactingUrl,

    /// Path to file containing the JWT secret shared with the execution client.
    #[clap(long)]
    pub jwt_secret: PathBuf,

    /// Optional CL unique identifier to send to the EL in the JWT token claim.
    #[clap(long)]
    pub jwt_id: Option<String>,

    /// Optional CL node type/version to send to the EL in the JWT token claim.
    #[clap(long)]
    pub jwt_version: Option<String>,
}

#[derive(Debug, Args)]
pub struct KeystoreOptions {
    /// Directory containing EIP-2335 builder keystore files.
    #[clap(long, requires("builder_keystore_password_file"))]
    pub builder_keystore_dir: PathBuf,

    /// File containing the password used to decrypt every keystore in the dir.
    #[clap(long, conflicts_with("builder_keystore_password_dir"))]
    pub builder_keystore_password_file: Option<PathBuf>,

    /// Directory containing per-keystore password files (matched by name).
    #[clap(long, conflicts_with("builder_keystore_password_file"))]
    pub builder_keystore_password_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct BuilderOptions {
    /// Fee recipient (execution layer address) for built payloads.
    #[clap(long)]
    pub builder_fee_recipient: ExecutionAddress,

    /// Maximum number of slots the beacon head may lag behind the current slot
    /// before the builder refuses to bid.
    #[clap(long, default_value_t = 32)]
    pub max_empty_slots: u64,
}
