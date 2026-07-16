use std::{
    collections::HashMap,
    io::{ErrorKind, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Result, bail, ensure};
use bls::{PublicKeyBytes, SecretKey, traits::SecretKey as _};
use eip_2335::Keystore;
use futures::lock::{MappedMutexGuard, Mutex, MutexGuard};
use itertools::Itertools as _;
use logging::{info_with_peers, warn_with_peers};
use serde::Serialize;
use signer::{KeyOrigin, Signer};
use slashing_protection::{SlashingProtector, interchange_format::InterchangeFormat};
use std_ext::ArcExt as _;
use tap::{Pipe as _, TryConv as _};
use types::phase0::primitives::H256;
use uuid::Uuid;
use validator_key_cache::ValidatorKeyCache;
use zeroize::Zeroizing;

use crate::{
    misc::{Error, OperationStatus, Status},
    validator_definitions::{SigningMethod, ValidatorDefinitionsWithStorage},
};

const KEYSTORE_STORAGE_FILE: &str = "keystores.json";
const KEYSTORE_FILE: &str = "keystore.json";

enum PersistenceConfig {
    FileSystem {
        validator_directory: PathBuf,
        secrets_directory: PathBuf,
        storage_password: Option<Zeroizing<String>>,
    },
    InMemory,
}

impl PersistenceConfig {
    fn validate_storage_password_presence(&self) -> Result<()> {
        match self {
            Self::FileSystem {
                storage_password, ..
            } => {
                storage_password
                    .as_ref()
                    .ok_or(Error::StoragePasswordNotProvided)?;
                Ok(())
            }
            Self::InMemory => Ok(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ValidatingPubkey {
    pub validating_pubkey: PublicKeyBytes,
    pub readonly: bool,
}

pub struct KeystoreManager {
    signer: Arc<Signer>,
    slashing_protector: Arc<Mutex<SlashingProtector>>,
    genesis_validators_root: H256,
    storage: Mutex<Option<ValidatorKeyCache>>,
    persistence_config: PersistenceConfig,
    validator_definitions: Arc<ValidatorDefinitionsWithStorage>,
}

impl KeystoreManager {
    #[must_use]
    pub const fn new_in_memory(
        signer: Arc<Signer>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
        genesis_validators_root: H256,
        validator_definitions: Arc<ValidatorDefinitionsWithStorage>,
    ) -> Self {
        Self {
            signer,
            slashing_protector,
            genesis_validators_root,
            storage: Mutex::new(None),
            persistence_config: PersistenceConfig::InMemory,
            validator_definitions,
        }
    }

    pub fn new_persistent(
        signer: Arc<Signer>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
        genesis_validators_root: H256,
        validator_directory: PathBuf,
        secrets_directory: PathBuf,
        keystore_storage_password_path: Option<&Path>,
        validator_definitions: Arc<ValidatorDefinitionsWithStorage>,
    ) -> Result<Self> {
        let storage_password = keystore_storage_password_path
            .map(load_key_storage_password)
            .transpose()?;

        let persistence_config = PersistenceConfig::FileSystem {
            validator_directory,
            secrets_directory,
            storage_password,
        };

        Ok(Self {
            signer,
            slashing_protector,
            genesis_validators_root,
            storage: Mutex::new(None),
            persistence_config,
            validator_definitions,
        })
    }

    pub async fn delete(
        &self,
        pubkeys: Vec<PublicKeyBytes>,
    ) -> Result<(Vec<OperationStatus>, String)> {
        let contains_storage_keys = {
            let validator_definitions = self.validator_definitions.read();

            pubkeys.iter().any(|pubkey| {
                matches!(
                    validator_definitions
                        .get(*pubkey)
                        .map(|definition| &definition.signing_method),
                    Some(SigningMethod::KeystoreStorage),
                )
            })
        };

        if contains_storage_keys {
            self.persistence_config
                .validate_storage_password_presence()?;
        }

        let mut deleted_keys = vec![];
        let mut delete_results = vec![];

        self.signer.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();
            let signer_keys = snapshot.keys_with_origin().collect::<HashMap<_, _>>();

            deleted_keys.clear();
            delete_results.clear();

            for pubkey in pubkeys.iter().copied() {
                let result: OperationStatus = match signer_keys.get(&pubkey) {
                    Some(origin) => match origin {
                        KeyOrigin::Internal => {
                            snapshot.delete_key(pubkey);
                            deleted_keys.push(pubkey);
                            Status::Deleted.into()
                        }
                        KeyOrigin::External | KeyOrigin::Web3Signer => Error::ReadOnly.into(),
                    },
                    None => Status::NotFound.into(),
                };

                delete_results.push(result);
            }

            snapshot
        });

        if !deleted_keys.is_empty() {
            let mut keystore_files = vec![];
            let mut storage_keys = vec![];

            {
                let validator_definitions = self.validator_definitions.read();

                for pubkey in deleted_keys.iter().copied() {
                    match validator_definitions.get(pubkey).map(|d| &d.signing_method) {
                        Some(SigningMethod::LocalKeystore {
                            keystore_path,
                            keystore_password_path,
                            ..
                        }) => {
                            keystore_files
                                .push((keystore_path.clone(), keystore_password_path.clone()));
                        }
                        Some(SigningMethod::KeystoreStorage) => storage_keys.push(pubkey),
                        Some(SigningMethod::Web3Signer { .. }) | None => {}
                    }
                }
            }

            if !storage_keys.is_empty() {
                self.remove_from_key_storage(storage_keys).await?;
            }

            self.validator_definitions.update(|validator_definitions| {
                validator_definitions.remove(deleted_keys.iter().copied());
            })?;

            for (keystore_path, password_path) in keystore_files {
                delete_keystore_files(&keystore_path, password_path.as_deref());
            }
        }

        let slashing_protection = self
            .slashing_protector
            .lock()
            .await
            .build_interchange_data_for_validators(
                self.genesis_validators_root,
                pubkeys.iter().copied(),
            )?;

        // A key we don't hold but with slashing-protection history reports not_active rather than not_found.
        for (pubkey, result) in pubkeys.iter().zip(&mut delete_results) {
            if result.status == Status::NotFound
                && slashing_protection
                    .data
                    .iter()
                    .any(|data| data.pubkey == *pubkey)
            {
                result.status = Status::NotActive;
            }
        }

        Ok((delete_results, serde_json::to_string(&slashing_protection)?))
    }

    #[expect(clippy::too_many_lines)]
    pub async fn import(
        &self,
        keystores: Vec<String>,
        passwords: Vec<Zeroizing<String>>,
        slashing_protection: Option<String>,
    ) -> Result<Vec<OperationStatus>> {
        ensure!(
            keystores.len() == passwords.len(),
            Error::PasswordCountMismatch,
        );

        match slashing_protection {
            Some(slashing_protection) => match serde_json::from_str(&slashing_protection) {
                Ok(data) => {
                    self.import_slashing_protection_data(data).await?;
                }
                Err(error) => {
                    bail!("failed to deserialize slashing protection data: {error}");
                }
            },
            None => {
                warn_with_peers!("keystore import: slashing protection data is not provided!");
            }
        }

        let mut imported_keys = vec![];
        let mut new_keystore_files: Vec<(PublicKeyBytes, PathBuf, PathBuf)> = vec![];
        let mut pruned_storage_keys = vec![];

        let decrypt_results = tokio::task::spawn_blocking(|| {
            keystores
                .into_iter()
                .zip(passwords)
                .map(decrypt)
                .collect_vec()
        })
        .await?;

        let mut new_storage_keys = vec![];

        let statuses = decrypt_results
            .into_iter()
            .map(|result| {
                let decrypted = match result {
                    Ok(decrypted) => decrypted,
                    Err(error) => return error.into(),
                };

                let DecryptedKeystore {
                    keystore_json,
                    password,
                    uuid,
                    public_key,
                    secret_key,
                } = decrypted;

                // Match the entry by the keystore's public key, not the file it arrived in.
                let (signs_remotely, already_enabled, is_legacy_storage) = self
                    .validator_definitions
                    .read()
                    .get(public_key)
                    .map_or((false, false, false), |definition| {
                        (
                            !definition.has_local_key(),
                            definition.enabled,
                            matches!(definition.signing_method, SigningMethod::KeystoreStorage),
                        )
                    });

                if signs_remotely {
                    // Mirrors the refusal in `RemoteKeyManager::import`.
                    return Error::RemoteKeyPresent.into();
                }

                // Entries are written after this loop, so catch an in-request duplicate here.
                if imported_keys
                    .iter()
                    .any(|(imported, _)| *imported == public_key)
                {
                    return Status::Duplicate.into();
                }

                // Upgrades a blob-backed validator to a keystore file (blob copy pruned below).
                let upgrading_storage = is_legacy_storage
                    && matches!(
                        self.persistence_config,
                        PersistenceConfig::FileSystem { .. }
                    );

                if already_enabled && !upgrading_storage {
                    return Status::Duplicate.into();
                }

                match &self.persistence_config {
                    PersistenceConfig::FileSystem {
                        validator_directory,
                        secrets_directory,
                        ..
                    } => match write_keystore_files(
                        validator_directory,
                        secrets_directory,
                        public_key,
                        &keystore_json,
                        &password,
                    ) {
                        Ok((keystore_path, password_path)) => {
                            if is_legacy_storage {
                                pruned_storage_keys.push(public_key);
                            }

                            new_keystore_files.push((public_key, keystore_path, password_path));
                        }
                        Err(error) => return error.into(),
                    },
                    PersistenceConfig::InMemory => {
                        new_storage_keys.push((uuid, public_key, secret_key.clone_arc()));
                    }
                }

                imported_keys.push((public_key, secret_key));
                Status::Imported.into()
            })
            .collect_vec();

        if !new_storage_keys.is_empty() {
            let mut key_storage = self.key_storage_mut().await?;

            for (uuid, public_key, secret_key) in new_storage_keys {
                key_storage.add(uuid, public_key, secret_key);
            }
        }

        if !imported_keys.is_empty() {
            self.slashing_protector
                .lock()
                .await
                .register_validators(imported_keys.iter().map(|(pubkey, _)| *pubkey))?;

            // Record in `validators.yml` before going live, or an imported key is dropped on restart.
            self.validator_definitions.update(|validator_definitions| {
                match &self.persistence_config {
                    PersistenceConfig::FileSystem { .. } => {
                        for (pubkey, keystore_path, password_path) in &new_keystore_files {
                            validator_definitions.import_local_keystore(
                                *pubkey,
                                keystore_path.clone(),
                                password_path.clone(),
                            );
                        }
                    }
                    // In-memory runs keep imported keys in the ephemeral key storage.
                    PersistenceConfig::InMemory => {
                        for (pubkey, _) in &imported_keys {
                            validator_definitions.import_storage_keystore(*pubkey);
                        }
                    }
                }
            })?;

            // The upgraded validators' blob copies are now redundant; pruning is best effort.
            if !pruned_storage_keys.is_empty()
                && let Err(error) = self.remove_from_key_storage(pruned_storage_keys).await
            {
                warn_with_peers!(
                    "unable to prune upgraded keys from the keystores.json blob: {error}",
                );
            }

            self.signer.update(|snapshot| {
                let mut snapshot = snapshot.as_ref().clone();

                snapshot.append_keys(imported_keys.clone());

                snapshot
            });
        }

        Ok(statuses)
    }

    async fn key_storage_mut(
        &self,
    ) -> Result<MappedMutexGuard<'_, Option<ValidatorKeyCache>, ValidatorKeyCache>> {
        let storage_guard = self.storage.lock().await;

        let loaded_or_default_storage = match &self.persistence_config {
            PersistenceConfig::FileSystem {
                validator_directory,
                storage_password,
                ..
            } => {
                if storage_guard.is_none() {
                    let storage_password = storage_password
                        .as_ref()
                        .ok_or(Error::StoragePasswordNotProvided)?;

                    load_key_storage(storage_password, validator_directory.clone())?
                } else {
                    ValidatorKeyCache::default()
                }
            }
            PersistenceConfig::InMemory => ValidatorKeyCache::default(),
        };

        let storage = MutexGuard::map(storage_guard, |storage_opt| match storage_opt {
            Some(storage) => storage,
            None => storage_opt.get_or_insert(loaded_or_default_storage),
        });

        Ok(storage)
    }

    /// Write the key storage back to the `keystores.json` blob, deleting it once empty. A no-op in memory.
    async fn persist_key_storage(&self, key_storage: &ValidatorKeyCache) -> Result<()> {
        let (validator_directory, storage_password) = match &self.persistence_config {
            PersistenceConfig::FileSystem {
                validator_directory,
                storage_password,
                ..
            } => (
                validator_directory.clone(),
                storage_password
                    .as_ref()
                    .ok_or(Error::StoragePasswordNotProvided)?
                    .clone(),
            ),
            PersistenceConfig::InMemory => return Ok(()),
        };

        let key_storage = key_storage.clone();

        tokio::task::spawn_blocking(move || {
            if key_storage.keypairs().next().is_none() {
                match fs_err::remove_file(validator_directory.join(KEYSTORE_STORAGE_FILE)) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error.into()),
                }
            } else {
                key_storage.save_to_file(&storage_password, KEYSTORE_STORAGE_FILE)
            }
        })
        .await?
    }

    async fn remove_from_key_storage(
        &self,
        pubkeys: impl IntoIterator<Item = PublicKeyBytes>,
    ) -> Result<()> {
        let mut key_storage = self.key_storage_mut().await?;
        key_storage.delete_keys(pubkeys);
        self.persist_key_storage(&key_storage).await
    }

    async fn import_slashing_protection_data(
        &self,
        slashing_protection: InterchangeFormat,
    ) -> Result<()> {
        slashing_protection.validate(self.genesis_validators_root)?;

        let import_report = self
            .slashing_protector
            .lock()
            .await
            .import(slashing_protection)?;

        info_with_peers!(
            "slashing protection data imported (imported records: {}, failed records: {})",
            import_report.imported_records(),
            import_report.failed_records(),
        );

        Ok(())
    }

    pub fn list_validating_pubkeys(&self) -> Vec<ValidatingPubkey> {
        self.signer
            .load()
            .keys_with_origin()
            .map(|(pubkey, origin)| ValidatingPubkey {
                validating_pubkey: pubkey,
                readonly: match origin {
                    KeyOrigin::Internal => false,
                    KeyOrigin::External | KeyOrigin::Web3Signer => true,
                },
            })
            .collect()
    }
}

/// A decrypted keystore plus the material an import needs to run and re-persist the key.
struct DecryptedKeystore {
    keystore_json: String,
    password: Zeroizing<String>,
    uuid: Uuid,
    public_key: PublicKeyBytes,
    secret_key: Arc<SecretKey>,
}

fn decrypt(pair: (String, Zeroizing<String>)) -> Result<DecryptedKeystore> {
    let (keystore_json, password) = pair;

    let keystore: Keystore = match serde_json::from_str(&keystore_json) {
        Ok(keystore) => keystore,
        Err(error) => {
            bail!("failed to deserialize keystore: {error}");
        }
    };

    let uuid = keystore.uuid();
    let normalized_password = eip_2335::normalize_password(password.as_bytes())?;
    let secret_key = keystore
        .decrypt(&normalized_password)?
        .try_conv::<SecretKey>()?
        .pipe(Arc::new);
    let public_key = secret_key.to_public_key().into();

    Ok(DecryptedKeystore {
        keystore_json,
        password,
        uuid,
        public_key,
        secret_key,
    })
}

/// Write an imported keystore and its password to files, returning their paths:
/// `<validator_directory>/0x<pubkey>/keystore.json` and `<secrets_directory>/0x<pubkey>`.
fn write_keystore_files(
    validator_directory: &Path,
    secrets_directory: &Path,
    public_key: PublicKeyBytes,
    keystore_json: &str,
    password: &str,
) -> Result<(PathBuf, PathBuf)> {
    let name = format!("0x{public_key:x}");
    let keystore_dir = validator_directory.join(&name);
    let keystore_path = keystore_dir.join(KEYSTORE_FILE);
    let password_path = secrets_directory.join(&name);

    fs_err::create_dir_all(&keystore_dir)?;

    if !keystore_path.exists() {
        // The keystore is ciphertext, so it keeps default permissions; only the password is restricted.
        fs_err::write(&keystore_path, keystore_json)?;
    }

    fs_err::create_dir_all(secrets_directory)?;

    if !password_path.exists() {
        write_password_file(&password_path, password.as_bytes())?;
    }

    Ok((keystore_path, password_path))
}

/// Delete a validator's keystore and password files, and the per-validator directory once empty.
fn delete_keystore_files(keystore_path: &Path, password_path: Option<&Path>) {
    remove_file_if_present(keystore_path);

    if let Some(password_path) = password_path {
        remove_file_if_present(password_path);
    }

    // Each keystore has its own directory; one still holding other files is left alone.
    if let Some(directory) = keystore_path.parent() {
        match fs_err::remove_dir(directory) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty,
                ) => {}
            Err(error) => warn_with_peers!("unable to delete {}: {error}", directory.display()),
        }
    }
}

fn remove_file_if_present(path: &Path) {
    match fs_err::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => warn_with_peers!("unable to delete {}: {error}", path.display()),
    }
}

/// Write `bytes` to a new file readable only by its owner.
fn write_password_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs_err::OpenOptions::new();

    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    options.open(path)?.write_all(bytes).map_err(Into::into)
}

pub fn load_key_storage(
    storage_password: &Zeroizing<String>,
    validator_directory: PathBuf,
) -> Result<ValidatorKeyCache> {
    let mut key_storage = ValidatorKeyCache::new(validator_directory);

    key_storage.load_from_file(storage_password, KEYSTORE_STORAGE_FILE)?;

    Ok(key_storage)
}

pub fn load_key_storage_password(
    keystore_storage_password_path: &Path,
) -> Result<Zeroizing<String>> {
    let password = match fs_err::read(keystore_storage_password_path) {
        Ok(password) => Zeroizing::new(password),
        Err(error) => bail!(Error::CannotLoadPassword {
            error: error.into()
        }),
    };

    eip_2335::normalize_password(password.as_slice())
        .map_err(|error| Error::CannotDecryptPassword { error })
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use hex_literal::hex;
    use reqwest::Client;
    use signer::Web3SignerConfig;
    use slashing_protection::DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT;
    use tempfile::Builder;

    use super::*;
    use crate::validator_definitions::{
        DefinitionsStorage, ValidatorDefinition, ValidatorDefinitions,
    };

    const GENESIS_VALIDATORS_ROOT: H256 = H256(hex!(
        "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    ));
    const DELETE_RESPONSE_INTERCHANGE_DATA: &str = r#"
        {
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
            },
            "data": [
                {
                    "pubkey": "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                    "signed_blocks": [
                        {
                            "slot": "81951"
                        },
                        {
                            "slot": "81952",
                            "signing_root": "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
                        }
                    ],
                    "signed_attestations": [
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3007",
                            "signing_root": "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
                        },
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3008"
                        }
                    ]
                },
                {
                    "pubkey": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "signed_blocks": [
                        {
                            "slot": "81951",
                            "signing_root": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        },
                        {
                            "slot": "81952"
                        }
                    ],
                    "signed_attestations": [
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3007",
                            "signing_root": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        },
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3008"
                        }
                    ]
                }
            ]
        }
    "#;
    const IMPORT_INTERCHANGE_DATA: &str = r#"
        {
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
            },
            "data": [
                {
                    "pubkey": "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                    "signed_blocks": [
                        {
                            "slot": "81951"
                        },
                        {
                            "slot": "81952",
                            "signing_root": "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
                        }
                    ],
                    "signed_attestations": [
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3007",
                            "signing_root": "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
                        },
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3008"
                        }
                    ]
                },
                {
                    "pubkey": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "signed_blocks": [
                        {
                            "slot": "81951",
                            "signing_root": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        },
                        {
                            "slot": "81952"
                        }
                    ],
                    "signed_attestations": [
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3007",
                            "signing_root": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        },
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3008"
                        }
                    ]
                },
                {
                    "pubkey": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "signed_blocks": [
                        {
                            "slot": "81951",
                            "signing_root": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                        },
                        {
                            "slot": "81952"
                        }
                    ],
                    "signed_attestations": [
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3007",
                            "signing_root": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                        },
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3008"
                        }
                    ]
                }
            ]
        }
    "#;
    // Taken from eip_2335 crate
    const KEYSTORE_JSON: &str = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
            "version": 4
        }
    "#;
    const KEYSTORE_PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
    const PUBKEY_BYTES: [u8; 48] = hex!(
        "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07"
    );

    fn build_keystore_manager(
        storage_dir: Option<PathBuf>,
    ) -> Result<(
        KeystoreManager,
        Arc<Signer>,
        Arc<ValidatorDefinitionsWithStorage>,
    )> {
        let signer = Arc::new(Signer::new(
            vec![],
            Client::new(),
            Client::new(),
            Web3SignerConfig::default(),
            None,
        ));
        let slashing_protector = Arc::new(Mutex::new(SlashingProtector::in_memory(
            DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT,
        )?));

        let storage = match &storage_dir {
            Some(storage_dir) => {
                DefinitionsStorage::Persistent(ValidatorDefinitions::file_path(storage_dir))
            }
            None => DefinitionsStorage::InMemory,
        };

        let validator_definitions = Arc::new(ValidatorDefinitionsWithStorage::new(
            Arc::new(RwLock::new(ValidatorDefinitions::default())),
            storage,
        ));

        let manager = match storage_dir {
            Some(storage_dir) => {
                let secrets_dir = storage_dir.join("secrets");

                // Needed to prune a blob-backed validator when it is upgraded to a keystore file.
                let password_file_path = storage_dir.join("password.txt");
                fs_err::write(&password_file_path, KEYSTORE_PASSWORD)?;

                KeystoreManager::new_persistent(
                    signer.clone_arc(),
                    slashing_protector,
                    GENESIS_VALIDATORS_ROOT,
                    storage_dir,
                    secrets_dir,
                    Some(&password_file_path),
                    validator_definitions.clone_arc(),
                )?
            }
            None => KeystoreManager::new_in_memory(
                signer.clone_arc(),
                slashing_protector,
                GENESIS_VALIDATORS_ROOT,
                validator_definitions.clone_arc(),
            ),
        };

        Ok((manager, signer, validator_definitions))
    }

    #[expect(clippy::too_many_lines)]
    #[tokio::test]
    async fn test_keystore_import_load_and_delete_with_persistent_storage() -> Result<()> {
        let storage_tempdir = Builder::new()
            .prefix("keystores")
            .rand_bytes(10)
            .tempdir()?;
        let (manager, signer, validator_definitions) =
            build_keystore_manager(Some(storage_tempdir.path().to_path_buf()))?;

        assert!(manager.list_validating_pubkeys().is_empty());

        let normalized_password = eip_2335::normalize_password(KEYSTORE_PASSWORD)?;
        let expected_pubkey = PublicKeyBytes::from(PUBKEY_BYTES);

        // Test successful import

        let import_statuses = manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![normalized_password.clone()],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        assert_eq!(
            import_statuses,
            vec![OperationStatus {
                status: Status::Imported,
                message: None
            }],
        );

        assert_eq!(
            manager.list_validating_pubkeys(),
            vec![ValidatingPubkey {
                validating_pubkey: expected_pubkey,
                readonly: false
            }],
        );

        assert_eq!(
            signer.load().keys().copied().collect_vec(),
            vec![expected_pubkey],
        );

        // The import must be recorded in `validators.yml`, both in memory and on disk.
        assert!(validator_definitions.read().has_local_key(expected_pubkey));

        let persisted =
            ValidatorDefinitions::load(&ValidatorDefinitions::file_path(storage_tempdir.path()))?;

        assert!(persisted.has_local_key(expected_pubkey));

        let name = format!("0x{expected_pubkey:x}");

        assert!(
            storage_tempdir
                .path()
                .join(&name)
                .join(KEYSTORE_FILE)
                .exists()
        );
        assert!(storage_tempdir.path().join("secrets").join(&name).exists());
        assert!(!storage_tempdir.path().join(KEYSTORE_STORAGE_FILE).exists());

        // The password file must be readable only by its owner.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let password_path = storage_tempdir.path().join("secrets").join(&name);

            assert_eq!(
                fs_err::metadata(&password_path)?.permissions().mode() & 0o777,
                0o600,
                "{} must be readable only by its owner",
                password_path.display(),
            );
        }

        // Test duplicate import

        let import_statuses = manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![normalized_password.clone()],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        assert_eq!(
            import_statuses,
            vec![OperationStatus {
                status: Status::Duplicate,
                message: None,
            }],
        );

        assert_eq!(
            manager.list_validating_pubkeys(),
            vec![ValidatingPubkey {
                validating_pubkey: expected_pubkey,
                readonly: false
            }],
        );

        // Test invalid password

        let import_statuses = manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![eip_2335::normalize_password("secret")?],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        assert_eq!(
            import_statuses,
            vec![OperationStatus {
                status: Status::Error,
                message: Some("derived key does not match checksum".into()),
            }],
        );

        // Test successful delete

        let pubkey_2 = PublicKeyBytes::from(hex!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));

        let (delete_statuses, exported_interchange) =
            manager.delete(vec![expected_pubkey, pubkey_2]).await?;

        assert_eq!(
            delete_statuses,
            vec![
                OperationStatus {
                    status: Status::Deleted,
                    message: None,
                },
                // pubkey_2 was never live, but its interchange history makes the status not_active rather than not_found.
                OperationStatus {
                    status: Status::NotActive,
                    message: None,
                },
            ],
        );

        let exported_interchange =
            serde_json::from_str::<InterchangeFormat>(&exported_interchange)?;
        let expected_interchange =
            serde_json::from_str::<InterchangeFormat>(DELETE_RESPONSE_INTERCHANGE_DATA)?;

        assert_eq!(exported_interchange.metadata, expected_interchange.metadata);
        assert_eq!(
            exported_interchange.data.iter().sorted().collect_vec(),
            expected_interchange.data.iter().sorted().collect_vec(),
        );

        // A keymanager-written keystore is deleted outright: key, files and entry all removed.
        assert!(!signer.load().keys().copied().contains(&expected_pubkey));
        assert!(!validator_definitions.read().contains(expected_pubkey));

        let persisted =
            ValidatorDefinitions::load(&ValidatorDefinitions::file_path(storage_tempdir.path()))?;

        assert!(!persisted.contains(expected_pubkey));

        let name = format!("0x{expected_pubkey:x}");

        assert!(!storage_tempdir.path().join(&name).exists());
        assert!(!storage_tempdir.path().join("secrets").join(&name).exists());

        Ok(())
    }

    /// Deleting an already-deleted key finds its retained history, so reports `not_active` per spec.
    #[tokio::test]
    async fn test_keystore_delete_of_inactive_key_reports_not_active() -> Result<()> {
        let (manager, _signer, _definitions) = build_keystore_manager(None)?;
        let expected_pubkey = PublicKeyBytes::from(PUBKEY_BYTES);
        let normalized_password = eip_2335::normalize_password(KEYSTORE_PASSWORD)?;

        manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![normalized_password],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        let (first_delete, _) = manager.delete(vec![expected_pubkey]).await?;

        assert_eq!(
            first_delete,
            vec![OperationStatus {
                status: Status::Deleted,
                message: None,
            }],
        );

        // Key gone but history remains, so a second delete reports not_active rather than not_found, and still exports.
        let (second_delete, exported_interchange) = manager.delete(vec![expected_pubkey]).await?;

        assert_eq!(
            second_delete,
            vec![OperationStatus {
                status: Status::NotActive,
                message: None,
            }],
        );

        let exported_interchange =
            serde_json::from_str::<InterchangeFormat>(&exported_interchange)?;

        assert!(
            exported_interchange
                .data
                .iter()
                .any(|data| data.pubkey == expected_pubkey)
        );

        Ok(())
    }

    /// A `--keystore-dir` key is read-only: its delete is refused, leaving key and entry untouched.
    #[tokio::test]
    async fn test_keystore_delete_refuses_keystore_dir_keys() -> Result<()> {
        let expected_pubkey = PublicKeyBytes::from(PUBKEY_BYTES);
        let decrypted = decrypt((
            KEYSTORE_JSON.to_owned(),
            Zeroizing::new(KEYSTORE_PASSWORD.to_owned()),
        ))?;

        // A signer whose key was loaded from the file system on startup, as discovery loads it.
        let signer = Arc::new(Signer::new(
            vec![(
                expected_pubkey,
                decrypted.secret_key.clone_arc(),
                KeyOrigin::External,
            )],
            Client::new(),
            Client::new(),
            Web3SignerConfig::default(),
            None,
        ));

        let validator_definitions = Arc::new(ValidatorDefinitionsWithStorage::new(
            Arc::new(RwLock::new(ValidatorDefinitions::default())),
            DefinitionsStorage::InMemory,
        ));

        validator_definitions.update(|validator_definitions| {
            validator_definitions.push(ValidatorDefinition::new(
                expected_pubkey,
                SigningMethod::LocalKeystore {
                    keystore_path: "keystore.json".into(),
                    keystore_password_path: Some("password.txt".into()),
                    keystore_password: None,
                },
            ));
        })?;

        let slashing_protector = Arc::new(Mutex::new(SlashingProtector::in_memory(
            DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT,
        )?));

        let manager = KeystoreManager::new_in_memory(
            signer.clone_arc(),
            slashing_protector,
            GENESIS_VALIDATORS_ROOT,
            validator_definitions.clone_arc(),
        );

        assert_eq!(
            manager.list_validating_pubkeys(),
            vec![ValidatingPubkey {
                validating_pubkey: expected_pubkey,
                readonly: true,
            }],
        );

        let (delete_statuses, _) = manager.delete(vec![expected_pubkey]).await?;

        assert_eq!(
            delete_statuses,
            vec![OperationStatus {
                status: Status::Error,
                message: Some("key is read-only".into()),
            }],
        );

        // The key stays loaded and the entry stays enabled.
        assert!(signer.load().keys().copied().contains(&expected_pubkey));
        assert!(
            validator_definitions
                .read()
                .get(expected_pubkey)
                .is_some_and(|definition| definition.enabled)
        );

        Ok(())
    }

    /// Importing a keystore for a blob-backed validator upgrades it to a file and prunes the blob.
    #[tokio::test]
    async fn test_keystore_import_upgrades_a_blob_validator_to_a_file() -> Result<()> {
        let storage_tempdir = Builder::new()
            .prefix("keystores")
            .rand_bytes(10)
            .tempdir()?;
        let storage_dir = storage_tempdir.path().to_path_buf();
        let (manager, signer, validator_definitions) =
            build_keystore_manager(Some(storage_dir.clone()))?;

        let expected_pubkey = PublicKeyBytes::from(PUBKEY_BYTES);
        let normalized_password = eip_2335::normalize_password(KEYSTORE_PASSWORD)?;

        // Seed a `keystores.json` blob plus a matching enabled `keystore_storage` entry: the state
        // after loading a legacy blob on startup, encrypted with `build_keystore_manager`'s password.
        let decrypted = decrypt((
            KEYSTORE_JSON.to_owned(),
            Zeroizing::new(KEYSTORE_PASSWORD.to_owned()),
        ))?;

        let mut blob = ValidatorKeyCache::new(storage_dir.clone());
        blob.add(
            decrypted.uuid,
            decrypted.public_key,
            decrypted.secret_key.clone_arc(),
        );
        blob.save_to_file(&normalized_password, KEYSTORE_STORAGE_FILE)?;

        validator_definitions.update(|validator_definitions| {
            validator_definitions.import_storage_keystore(expected_pubkey);
        })?;

        assert!(storage_dir.join(KEYSTORE_STORAGE_FILE).exists());

        // Re-import the same keystore.
        let import_statuses = manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![normalized_password],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        assert_eq!(
            import_statuses,
            vec![OperationStatus {
                status: Status::Imported,
                message: None,
            }],
        );

        // The entry is now a keystore file, not a blob entry, and the key is live.
        let definitions = validator_definitions.read();
        let definition = definitions
            .get(expected_pubkey)
            .expect("the upgraded entry must exist");

        assert!(matches!(
            definition.signing_method,
            SigningMethod::LocalKeystore { .. },
        ));
        drop(definitions);

        assert!(signer.load().keys().copied().contains(&expected_pubkey));

        // The keystore and password files were written, and the now-empty blob was removed.
        let name = format!("0x{expected_pubkey:x}");

        assert!(storage_dir.join(&name).join(KEYSTORE_FILE).exists());
        assert!(storage_dir.join("secrets").join(&name).exists());
        assert!(!storage_dir.join(KEYSTORE_STORAGE_FILE).exists());

        Ok(())
    }

    /// A keystore must not take a validator away from its Web3Signer (mirrors `RemoteKeyManager::import`).
    #[tokio::test]
    async fn test_keystore_import_refuses_remote_signer_validator() -> Result<()> {
        let (manager, signer, validator_definitions) = build_keystore_manager(None)?;
        let expected_pubkey = PublicKeyBytes::from(PUBKEY_BYTES);

        validator_definitions.update(|validator_definitions| {
            validator_definitions
                .import_web3signer(expected_pubkey, "https://www.example.com/".to_owned());
        })?;

        let import_statuses = manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![eip_2335::normalize_password(KEYSTORE_PASSWORD)?],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        assert_eq!(
            import_statuses,
            vec![OperationStatus {
                status: Status::Error,
                message: Some("key already exists as a remote signer validator".into()),
            }],
        );

        // The entry must still point at the Web3Signer, and the key must not have gone live.
        assert!(
            validator_definitions
                .read()
                .web3signer_pubkeys()
                .contains(&expected_pubkey)
        );
        assert!(signer.load().keys().copied().collect_vec().is_empty());

        Ok(())
    }

    /// The same validator arriving in a different keystore file is still the same validator.
    #[tokio::test]
    async fn test_keystore_import_duplicate_pubkey_from_another_file() -> Result<()> {
        let (manager, _signer, _validator_definitions) = build_keystore_manager(None)?;
        let normalized_password = eip_2335::normalize_password(KEYSTORE_PASSWORD)?;

        manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![normalized_password.clone()],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        // Same secret key, same password, different `uuid`, which the blob is keyed by.
        let other_file = KEYSTORE_JSON.replace(
            "64625def-3331-4eea-ab6f-782f3ed16a83",
            "00000000-0000-4000-8000-000000000000",
        );

        let import_statuses = manager
            .import(
                vec![other_file],
                vec![normalized_password],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        assert_eq!(
            import_statuses,
            vec![OperationStatus {
                status: Status::Duplicate,
                message: None,
            }],
        );

        Ok(())
    }

    /// Importing a hand-disabled validator re-enables it: the answer is `imported`, not `duplicate`.
    #[tokio::test]
    async fn test_keystore_import_reenables_a_disabled_validator() -> Result<()> {
        let (manager, signer, validator_definitions) = build_keystore_manager(None)?;
        let expected_pubkey = PublicKeyBytes::from(PUBKEY_BYTES);
        let normalized_password = eip_2335::normalize_password(KEYSTORE_PASSWORD)?;

        manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![normalized_password.clone()],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        validator_definitions.update(|validator_definitions| {
            validator_definitions
                .get_mut(expected_pubkey)
                .expect("the imported validator has an entry")
                .enabled = false;
        })?;

        assert!(
            !validator_definitions
                .read()
                .loads_from_storage(expected_pubkey)
        );

        let import_statuses = manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![normalized_password],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        assert_eq!(
            import_statuses,
            vec![OperationStatus {
                status: Status::Imported,
                message: None,
            }],
        );

        assert!(
            validator_definitions
                .read()
                .loads_from_storage(expected_pubkey)
        );
        assert_eq!(
            signer.load().keys().copied().collect_vec(),
            vec![expected_pubkey],
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_keystore_import_load_and_delete_with_in_memory_storage() -> Result<()> {
        let (manager, signer, _definitions) = build_keystore_manager(None)?;

        assert!(manager.list_validating_pubkeys().is_empty());

        let normalized_password = eip_2335::normalize_password(KEYSTORE_PASSWORD)?;
        let expected_pubkey = PublicKeyBytes::from(PUBKEY_BYTES);

        // Test successful import

        let import_statuses = manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![normalized_password.clone()],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        assert_eq!(
            import_statuses,
            vec![OperationStatus {
                status: Status::Imported,
                message: None
            }],
        );

        assert_eq!(
            manager.list_validating_pubkeys(),
            vec![ValidatingPubkey {
                validating_pubkey: expected_pubkey,
                readonly: false
            }],
        );

        assert_eq!(
            signer.load().keys().copied().collect_vec(),
            vec![expected_pubkey],
        );

        // Test duplicate import

        let import_statuses = manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![normalized_password.clone()],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        assert_eq!(
            import_statuses,
            vec![OperationStatus {
                status: Status::Duplicate,
                message: None,
            }],
        );

        assert_eq!(
            manager.list_validating_pubkeys(),
            vec![ValidatingPubkey {
                validating_pubkey: expected_pubkey,
                readonly: false
            }],
        );

        // Test invalid password

        let import_statuses = manager
            .import(
                vec![KEYSTORE_JSON.into()],
                vec![eip_2335::normalize_password("secret")?],
                Some(IMPORT_INTERCHANGE_DATA.into()),
            )
            .await?;

        assert_eq!(
            import_statuses,
            vec![OperationStatus {
                status: Status::Error,
                message: Some("derived key does not match checksum".into()),
            }],
        );

        // Test successful delete

        let pubkey_2 = PublicKeyBytes::from(hex!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));

        let (delete_statuses, exported_interchange) =
            manager.delete(vec![expected_pubkey, pubkey_2]).await?;

        assert_eq!(
            delete_statuses,
            vec![
                OperationStatus {
                    status: Status::Deleted,
                    message: None,
                },
                // pubkey_2 was never live, but its interchange history makes the status not_active rather than not_found.
                OperationStatus {
                    status: Status::NotActive,
                    message: None,
                },
            ],
        );

        let exported_interchange =
            serde_json::from_str::<InterchangeFormat>(&exported_interchange)?;
        let expected_interchange =
            serde_json::from_str::<InterchangeFormat>(DELETE_RESPONSE_INTERCHANGE_DATA)?;

        assert_eq!(exported_interchange.metadata, expected_interchange.metadata);
        assert_eq!(
            exported_interchange.data.iter().sorted().collect_vec(),
            expected_interchange.data.iter().sorted().collect_vec(),
        );

        Ok(())
    }
}
