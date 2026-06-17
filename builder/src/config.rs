use std::path::PathBuf;

use types::{phase0::primitives::ExecutionAddress, redacting_url::RedactingUrl};

use crate::args::BuilderArgs;

#[derive(Debug, Clone)]
pub struct BuilderConfig {
    pub beacon_node: RedactingUrl,
    pub beacon_node_auth: Option<String>,

    pub execution_engine: RedactingUrl,
    pub jwt_secret_path: PathBuf,
    pub jwt_id: Option<String>,
    pub jwt_version: Option<String>,

    pub builder_keystore_dir: PathBuf,
    pub builder_keystore_password_file: Option<PathBuf>,
    pub builder_keystore_password_dir: Option<PathBuf>,

    pub builder_fee_recipient: ExecutionAddress,
    pub max_empty_slots: u64,
}

impl From<BuilderArgs> for BuilderConfig {
    fn from(args: BuilderArgs) -> Self {
        let BuilderArgs {
            beacon_node,
            execution,
            keystore,
            builder,
        } = args;

        Self {
            beacon_node: beacon_node.beacon_node,
            beacon_node_auth: beacon_node.beacon_node_auth,
            execution_engine: execution.execution_engine,
            jwt_secret_path: execution.jwt_secret,
            jwt_id: execution.jwt_id,
            jwt_version: execution.jwt_version,
            builder_keystore_dir: keystore.builder_keystore_dir,
            builder_keystore_password_file: keystore.builder_keystore_password_file,
            builder_keystore_password_dir: keystore.builder_keystore_password_dir,
            builder_fee_recipient: builder.builder_fee_recipient,
            max_empty_slots: builder.max_empty_slots,
        }
    }
}
