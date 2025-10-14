use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, ensure, Result};
use bls::{traits::SecretKey as _, PublicKeyBytes, SecretKey};
use eip_2335::Keystore;
use futures::lock::{MappedMutexGuard, Mutex, MutexGuard};
use itertools::Itertools as _;
use logging::{info_with_peers, warn_with_peers};
use serde::Serialize;
use signer::{KeyOrigin, Signer};
use slashing_protection::{interchange_format::InterchangeFormat, SlashingProtector};
use std_ext::ArcExt as _;
use tap::{Pipe as _, TryConv as _};
use types::phase0::primitives::H256;
use uuid::Uuid;
use validator_key_cache::ValidatorKeyCache;
use zeroize::Zeroizing;

use crate::misc::{Error, OperationStatus, Status};

const KEYSTORE_STORAGE_FILE: &str = "keystores.json";

enum PersistenceConfig {
    FileSystem {
        validator_directory: PathBuf,
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
}

impl KeystoreManager {
    #[must_use]
    pub fn new_in_memory(
        signer: Arc<Signer>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
        genesis_validators_root: H256,
    ) -> Self {
        Self {
            signer,
            slashing_protector,
            genesis_validators_root,
            storage: Mutex::new(None),
            persistence_config: PersistenceConfig::InMemory,
        }
    }

    pub fn new_persistent(
        signer: Arc<Signer>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
        genesis_validators_root: H256,
        validator_directory: PathBuf,
        keystore_storage_password_path: Option<&Path>,
    ) -> Result<Self> {
        let storage_password = match keystore_storage_password_path {
            Some(password_path) => {
                let password = load_key_storage_password(password_path)?;
                Some(password)
            }
            None => None,
        };

        let persistence_config = PersistenceConfig::FileSystem {
            validator_directory,
            storage_password,
        };

        Ok(Self {
            signer,
            slashing_protector,
            genesis_validators_root,
            storage: Mutex::new(None),
            persistence_config,
        })
    }

    pub async fn delete(
        &self,
        pubkeys: Vec<PublicKeyBytes>,
    ) -> Result<(Vec<OperationStatus>, String)> {
        self.persistence_config
            .validate_storage_password_presence()?;

        let mut deleted_keys = vec![];
        let mut delete_results = vec![];

        self.signer.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();

            let signer_keys = snapshot.keys_with_origin().collect::<HashMap<_, _>>();

            deleted_keys.clear();
            delete_results.clear();

            for pubkey in pubkeys.iter().copied() {
                let result = match signer_keys.get(&pubkey) {
                    Some(origin) => match origin {
                        KeyOrigin::KeymanagerAPI => {
                            snapshot.delete_key(pubkey);
                            deleted_keys.push(pubkey);
                            Status::Deleted.into()
                        }
                        KeyOrigin::LocalFileSystem | KeyOrigin::Web3Signer => {
                            Error::ReadOnly.into()
                        }
                    },
                    None => Error::NotFound.into(),
                };

                delete_results.push(result);
            }

            snapshot
        });

        if !deleted_keys.is_empty() {
            let mut key_storage = self.key_storage_mut().await?;
            key_storage.delete_keys(deleted_keys);
            self.persist_key_storage(&key_storage).await?;
        }

        let slashing_protection = self
            .slashing_protector
            .lock()
            .await
            .build_interchange_data_for_validators(self.genesis_validators_root, pubkeys)?;

        Ok((delete_results, serde_json::to_string(&slashing_protection)?))
    }

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

        self.persistence_config
            .validate_storage_password_presence()?;

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

        let decrypt_results = tokio::task::spawn_blocking(|| {
            keystores
                .into_iter()
                .zip(passwords)
                .map(decrypt)
                .collect_vec()
        })
        .await?;

        let mut key_storage = self.key_storage_mut().await?;

        let statuses = decrypt_results
            .into_iter()
            .map(|result| match result {
                Ok((uuid, public_key, secret_key)) => {
                    if key_storage.contains(uuid) {
                        Error::Duplicate.into()
                    } else {
                        key_storage.add(uuid, public_key, secret_key.clone_arc());
                        imported_keys.push((public_key, secret_key));
                        Status::Imported.into()
                    }
                }
                Err(error) => error.into(),
            })
            .collect_vec();

        if !imported_keys.is_empty() {
            self.persist_key_storage(&key_storage).await?;
            self.slashing_protector
                .lock()
                .await
                .register_validators(imported_keys.iter().map(|(pubkey, _)| *pubkey))?;

            self.signer.update(|snapshot| {
                let mut snapshot = snapshot.as_ref().clone();

                snapshot.append_keys(imported_keys.clone());

                snapshot
            });
        }

        Ok(statuses)
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
                    KeyOrigin::KeymanagerAPI => false,
                    KeyOrigin::LocalFileSystem | KeyOrigin::Web3Signer => true,
                },
            })
            .collect()
    }

    async fn key_storage_mut(
        &self,
    ) -> Result<MappedMutexGuard<Option<ValidatorKeyCache>, ValidatorKeyCache>> {
        let storage_guard = self.storage.lock().await;

        let loaded_or_default_storage = match &self.persistence_config {
            PersistenceConfig::FileSystem {
                validator_directory,
                storage_password,
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

    async fn persist_key_storage(&self, key_storage: &ValidatorKeyCache) -> Result<()> {
        let storage_password = match &self.persistence_config {
            PersistenceConfig::FileSystem {
                storage_password, ..
            } => storage_password
                .as_ref()
                .ok_or(Error::StoragePasswordNotProvided)?
                .clone(),
            PersistenceConfig::InMemory => return Ok(()),
        };

        let key_storage = key_storage.clone();

        tokio::task::spawn_blocking(move || {
            key_storage.save_to_file(&storage_password, KEYSTORE_STORAGE_FILE)
        })
        .await?
    }
}

fn decrypt(pair: (String, Zeroizing<String>)) -> Result<(Uuid, PublicKeyBytes, Arc<SecretKey>)> {
    let (keystore_str, password) = pair;

    let keystore: Keystore = match serde_json::from_str(&keystore_str) {
        Ok(keystore) => keystore,
        Err(error) => {
            bail!("failed to deserialize keystore: {error}");
        }
    };

    let uuid = keystore.uuid();
    let normalized_password = eip_2335::normalize_password(password)?;
    let secret_key = keystore
        .decrypt(&normalized_password)?
        .try_conv::<SecretKey>()?
        .pipe(Arc::new);
    let public_key = secret_key.to_public_key().into();

    Ok((uuid, public_key, secret_key))
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
    use hex_literal::hex;
    use reqwest::Client;
    use signer::Web3SignerConfig;
    use slashing_protection::DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT;
    use tempfile::Builder;

    use super::*;

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
    const PUBKEY_BYTES: [u8; 48] = hex!("9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07");

    fn build_keystore_manager(
        storage_dir: Option<PathBuf>,
    ) -> Result<(KeystoreManager, Arc<Signer>)> {
        let signer = Arc::new(Signer::new(
            vec![],
            Client::new(),
            Web3SignerConfig::default(),
            None,
        ));
        let slashing_protector = Arc::new(Mutex::new(SlashingProtector::in_memory(
            DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT,
        )?));

        let manager = match storage_dir {
            Some(storage_dir) => {
                let password_file_path = storage_dir.join("password.txt");

                fs_err::write(&password_file_path, KEYSTORE_PASSWORD)?;

                KeystoreManager::new_persistent(
                    signer.clone_arc(),
                    slashing_protector,
                    GENESIS_VALIDATORS_ROOT,
                    storage_dir,
                    Some(&password_file_path),
                )?
            }
            None => KeystoreManager::new_in_memory(
                signer.clone_arc(),
                slashing_protector,
                GENESIS_VALIDATORS_ROOT,
            ),
        };

        Ok((manager, signer))
    }

    #[expect(clippy::too_many_lines)]
    #[tokio::test]
    async fn test_keystore_import_load_and_delete_with_persistent_storage() -> Result<()> {
        let storage_tempdir = Builder::new()
            .prefix("keystores")
            .rand_bytes(10)
            .tempdir()?;
        let (manager, signer) = build_keystore_manager(Some(storage_tempdir.path().to_path_buf()))?;

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
                status: Status::Error,
                message: Some("key already exists".into()),
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

        // Test load from storage file

        let storage = load_key_storage(&normalized_password, storage_tempdir.path().to_path_buf())?;

        assert_eq!(
            storage.keypairs().map(|(pubkey, _)| pubkey).collect_vec(),
            vec![expected_pubkey],
        );

        // Test successful delete

        let pubkey_2 = PublicKeyBytes::from(
            hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );

        let (delete_statuses, exported_interchange) =
            manager.delete(vec![expected_pubkey, pubkey_2]).await?;

        assert_eq!(
            delete_statuses,
            vec![
                OperationStatus {
                    status: Status::Deleted,
                    message: None,
                },
                OperationStatus {
                    status: Status::Error,
                    message: Some("key not found".into())
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

        let storage = load_key_storage(&normalized_password, storage_tempdir.path().to_path_buf())?;

        assert!(storage.keypairs().collect_vec().is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_keystore_import_load_and_delete_with_in_memory_storage() -> Result<()> {
        let (manager, signer) = build_keystore_manager(None)?;

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
                status: Status::Error,
                message: Some("key already exists".into()),
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

        let pubkey_2 = PublicKeyBytes::from(
            hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );

        let (delete_statuses, exported_interchange) =
            manager.delete(vec![expected_pubkey, pubkey_2]).await?;

        assert_eq!(
            delete_statuses,
            vec![
                OperationStatus {
                    status: Status::Deleted,
                    message: None,
                },
                OperationStatus {
                    status: Status::Error,
                    message: Some("key not found".into())
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
