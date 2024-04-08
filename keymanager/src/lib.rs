pub use keystores::{load_key_storage, load_key_storage_password, ValidatingPubkey};
pub use misc::OperationStatus as KeymanagerOperationStatus;
pub use remote_keys::{ListedRemoteKey, RemoteKey};

pub use crate::proposer_configs::ProposerConfigs;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use futures::lock::Mutex;
use signer::Signer;
use slashing_protection::SlashingProtector;
use std_ext::ArcExt as _;
use types::phase0::primitives::{ExecutionAddress, H256};

use crate::{keystores::KeystoreManager, remote_keys::RemoteKeyManager};

mod keystores;
mod misc;
mod proposer_configs;
mod remote_keys;

pub struct KeyManager {
    proposer_configs: Arc<ProposerConfigs>,
    keystores: KeystoreManager,
    remote_keys: RemoteKeyManager,
}

impl KeyManager {
    pub fn new_in_memory(
        signer: Arc<Signer>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
        genesis_validators_root: H256,
        default_fee_recipient: ExecutionAddress,
        default_graffiti: H256,
    ) -> Self {
        let proposer_configs = Arc::new(ProposerConfigs::new_in_memory(
            default_fee_recipient,
            default_graffiti,
        ));

        let keystore_manager = KeystoreManager::new_in_memory(
            signer.clone_arc(),
            slashing_protector.clone_arc(),
            genesis_validators_root,
        );

        let remote_keys_manager = RemoteKeyManager::new(signer, slashing_protector);

        Self {
            proposer_configs,
            keystores: keystore_manager,
            remote_keys: remote_keys_manager,
        }
    }

    pub fn new_persistent(
        signer: Arc<Signer>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
        genesis_validators_root: H256,
        validator_directory: PathBuf,
        keystore_storage_password_path: Option<&Path>,
        default_fee_recipient: ExecutionAddress,
        default_graffiti: H256,
    ) -> Result<Self> {
        let proposer_configs = Arc::new(ProposerConfigs::new_persistent(
            &validator_directory,
            default_fee_recipient,
            default_graffiti,
        )?);

        let keystore_manager = KeystoreManager::new_persistent(
            signer.clone_arc(),
            slashing_protector.clone_arc(),
            genesis_validators_root,
            validator_directory,
            keystore_storage_password_path,
        )?;

        let remote_keys_manager = RemoteKeyManager::new(signer, slashing_protector);

        Ok(Self {
            proposer_configs,
            keystores: keystore_manager,
            remote_keys: remote_keys_manager,
        })
    }

    #[must_use]
    pub const fn proposer_configs(&self) -> &Arc<ProposerConfigs> {
        &self.proposer_configs
    }

    #[must_use]
    pub const fn keystores(&self) -> &KeystoreManager {
        &self.keystores
    }

    #[must_use]
    pub const fn remote_keys(&self) -> &RemoteKeyManager {
        &self.remote_keys
    }
}
