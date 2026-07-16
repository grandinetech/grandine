use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, anyhow};
use bls::PublicKeyBytes;
use futures::lock::Mutex;
use serde::{Deserialize, Serialize};
use signer::{KeyOrigin, Signer};
use slashing_protection::SlashingProtector;

use crate::{
    misc::{Error, OperationStatus, Status},
    validator_definitions::ValidatorDefinitionsWithStorage,
};

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ListedRemoteKey {
    pub pubkey: PublicKeyBytes,
    pub url: String,
    pub readonly: bool,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct RemoteKey {
    pub pubkey: PublicKeyBytes,
    pub url: String,
}

pub struct RemoteKeyManager {
    signer: Arc<Signer>,
    slashing_protector: Arc<Mutex<SlashingProtector>>,
    validator_definitions: Arc<ValidatorDefinitionsWithStorage>,
}

impl RemoteKeyManager {
    #[must_use]
    pub const fn new(
        signer: Arc<Signer>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
        validator_definitions: Arc<ValidatorDefinitionsWithStorage>,
    ) -> Self {
        Self {
            signer,
            slashing_protector,
            validator_definitions,
        }
    }

    pub fn delete(&self, pubkeys: &[PublicKeyBytes]) -> Result<Vec<OperationStatus>> {
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
                        KeyOrigin::Internal | KeyOrigin::External => Error::ReadOnly.into(),
                        KeyOrigin::Web3Signer => {
                            snapshot.delete_key(pubkey);
                            deleted_keys.push(pubkey);
                            Status::Deleted.into()
                        }
                    },
                    None => Status::NotFound.into(),
                };

                delete_results.push(result);
            }

            snapshot
        });

        // Drop the entries so the keys are not fetched again. A CLI-configured signer may reload them.
        if !deleted_keys.is_empty() {
            self.validator_definitions.update(|validator_definitions| {
                validator_definitions.remove(deleted_keys.iter().copied())
            })?;
        }

        Ok(delete_results)
    }

    pub async fn import(&self, remote_keys: Vec<RemoteKey>) -> Result<Vec<OperationStatus>> {
        let mut imported_keys = vec![];
        let mut import_results = vec![];

        self.signer.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();
            let validator_definitions = self.validator_definitions.read();

            imported_keys.clear();
            import_results.clear();

            for RemoteKey { pubkey, url } in &remote_keys {
                let result = match url.parse() {
                    Ok(parsed_url) => {
                        if validator_definitions.has_local_key(*pubkey) {
                            Error::LocalKeyPresent.into()
                        } else if snapshot.append_remote_key(*pubkey, parsed_url) {
                            imported_keys.push((*pubkey, url.clone()));
                            Status::Imported.into()
                        } else if snapshot.is_web3signer_key(*pubkey)
                            && !validator_definitions.contains(*pubkey)
                            && !imported_keys.iter().any(|(queued, _)| queued == pubkey)
                        {
                            // Loaded from `--web3signer-urls` but unrecorded: record it so it persists.
                            imported_keys.push((*pubkey, url.clone()));
                            Status::Imported.into()
                        } else {
                            Status::Duplicate.into()
                        }
                    }
                    Err(error) => anyhow!(error).into(),
                };

                import_results.push(result);
            }

            snapshot
        });

        // Record in `validators.yml`, which decides whether they are fetched on the next startup.
        if !imported_keys.is_empty() {
            self.validator_definitions.update(|validator_definitions| {
                for (pubkey, url) in &imported_keys {
                    validator_definitions.import_web3signer(*pubkey, url.clone());
                }
            })?;
        }

        self.slashing_protector
            .lock()
            .await
            .register_validators(imported_keys.iter().map(|(pubkey, _)| *pubkey))?;

        Ok(import_results)
    }

    pub fn list(&self) -> Vec<ListedRemoteKey> {
        self.signer
            .load()
            .web3signer_keys()
            .map(|(pubkey, url)| ListedRemoteKey {
                pubkey,
                url: url.to_string(),
                readonly: false,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use bls::SecretKeyBytes;
    use hex_literal::hex;
    use itertools::Itertools as _;
    use reqwest::Client;
    use signer::Web3SignerConfig;
    use slashing_protection::DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT;
    use std_ext::ArcExt as _;
    use types::redacting_url::RedactingUrl;

    use super::*;
    use crate::validator_definitions::{
        DefinitionsStorage, SigningMethod, ValidatorDefinition, ValidatorDefinitions,
        Web3SignerOptions,
    };

    const PUBKEY_REMOTE: PublicKeyBytes = PublicKeyBytes(hex!(
        "93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
    ));
    const PUBKEY_LOCAL: PublicKeyBytes = PublicKeyBytes(hex!(
        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
    ));
    const SECRET_LOCAL: [u8; 32] =
        hex!("47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138");

    fn build_signer() -> Arc<Signer> {
        Arc::new(Signer::new(
            vec![(
                PUBKEY_LOCAL,
                Arc::new(
                    SecretKeyBytes::from(SECRET_LOCAL)
                        .try_into()
                        .expect("secret key should be valid"),
                ),
                KeyOrigin::External,
            )],
            Client::new(),
            Client::new(),
            Web3SignerConfig::default(),
            None,
        ))
    }

    fn build_slashing_protector() -> Result<Arc<Mutex<SlashingProtector>>> {
        Ok(Arc::new(Mutex::new(SlashingProtector::in_memory(
            DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT,
        )?)))
    }

    /// Definitions matching [`build_signer`]: a `web3signer` entry for [`PUBKEY_REMOTE`] and a
    /// keystore entry for [`PUBKEY_LOCAL`], both enabled — every loaded validator has an entry.
    fn build_validator_definitions() -> Arc<ValidatorDefinitionsWithStorage> {
        let mut validator_definitions = ValidatorDefinitions::default();

        validator_definitions.push(ValidatorDefinition::new(
            PUBKEY_REMOTE,
            SigningMethod::Web3Signer {
                url: "https://www.example.com/".into(),
                options: Web3SignerOptions::default(),
            },
        ));

        validator_definitions.push(ValidatorDefinition::new(
            PUBKEY_LOCAL,
            SigningMethod::LocalKeystore {
                keystore_path: "keystore.json".into(),
                keystore_password_path: None,
                keystore_password: None,
            },
        ));

        Arc::new(ValidatorDefinitionsWithStorage::new(
            Arc::new(RwLock::new(validator_definitions)),
            DefinitionsStorage::InMemory,
        ))
    }

    #[tokio::test]
    async fn test_remote_keys_import() -> Result<()> {
        let signer = build_signer();
        let validator_definitions = build_validator_definitions();
        let manager = RemoteKeyManager::new(
            signer.clone_arc(),
            build_slashing_protector()?,
            validator_definitions.clone_arc(),
        );

        let remote_key_1 = RemoteKey {
            pubkey: PUBKEY_REMOTE,
            url: "https://www.example.com/".into(),
        };

        // A validator whose key we already hold must not be handed to a remote signer.
        let remote_key_2 = RemoteKey {
            pubkey: PUBKEY_LOCAL,
            url: "https://www.example.com/".into(),
        };

        assert_eq!(
            manager.import(vec![remote_key_1, remote_key_2]).await?,
            [
                OperationStatus {
                    status: Status::Imported,
                    message: None,
                },
                OperationStatus {
                    status: Status::Error,
                    message: Some("key already exists in a local keystore".into()),
                },
            ]
        );

        // The import must reach `validators.yml` or it is not fetched after a restart; the local entry stays.
        assert!(
            validator_definitions
                .read()
                .web3signer_pubkeys()
                .contains(&PUBKEY_REMOTE)
        );

        assert!(validator_definitions.read().has_local_key(PUBKEY_LOCAL));
        assert_eq!(
            signer.load().keys().copied().sorted().collect_vec(),
            [PUBKEY_REMOTE, PUBKEY_LOCAL],
        );

        assert_eq!(
            manager.list(),
            [ListedRemoteKey {
                pubkey: PUBKEY_REMOTE,
                url: "https://www.example.com/".into(),
                readonly: false,
            }],
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_remote_keys_delete() -> Result<()> {
        let signer = build_signer();
        let validator_definitions = build_validator_definitions();
        let manager = RemoteKeyManager::new(
            signer.clone_arc(),
            build_slashing_protector()?,
            validator_definitions.clone_arc(),
        );

        let remote_key = RemoteKey {
            pubkey: PUBKEY_REMOTE,
            url: "https://www.example.com/".into(),
        };

        manager.import(vec![remote_key]).await?;

        assert_eq!(manager.list().len(), 1);

        assert_eq!(
            manager.delete(&[PUBKEY_REMOTE, PUBKEY_LOCAL])?,
            [
                OperationStatus {
                    status: Status::Deleted,
                    message: None,
                },
                OperationStatus {
                    status: Status::Error,
                    message: Some("key is read-only".into()),
                },
            ],
        );

        // The entry is dropped, so the key is not fetched back on the next startup.
        assert!(
            !validator_definitions
                .read()
                .web3signer_pubkeys()
                .contains(&PUBKEY_REMOTE)
        );

        assert!(!validator_definitions.read().contains(PUBKEY_REMOTE));
        assert_eq!(signer.load().keys().copied().collect_vec(), [PUBKEY_LOCAL]);
        assert_eq!(manager.list(), []);

        // Re-importing the key records a fresh entry, so the validator runs again.
        manager
            .import(vec![RemoteKey {
                pubkey: PUBKEY_REMOTE,
                url: "https://www.example.com/".into(),
            }])
            .await?;

        assert!(
            validator_definitions
                .read()
                .web3signer_pubkeys()
                .contains(&PUBKEY_REMOTE)
        );

        Ok(())
    }

    /// Importing a key already loaded from `--web3signer-urls` records it, rather than reporting `duplicate`.
    #[tokio::test]
    async fn test_remote_keys_import_records_url_loaded_key() -> Result<()> {
        let signer = Arc::new(Signer::new(
            core::iter::empty(),
            Client::new(),
            Client::new(),
            Web3SignerConfig::default(),
            None,
        ));

        let url = "https://www.example.com/"
            .parse::<RedactingUrl>()
            .expect("url is valid");

        signer.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();
            snapshot.append_remote_key(PUBKEY_REMOTE, url.clone());
            snapshot
        });

        let validator_definitions = Arc::new(ValidatorDefinitionsWithStorage::new(
            Arc::new(RwLock::new(ValidatorDefinitions::default())),
            DefinitionsStorage::InMemory,
        ));

        assert!(!validator_definitions.read().contains(PUBKEY_REMOTE));

        let manager = RemoteKeyManager::new(
            signer.clone_arc(),
            build_slashing_protector()?,
            validator_definitions.clone_arc(),
        );

        let statuses = manager
            .import(vec![RemoteKey {
                pubkey: PUBKEY_REMOTE,
                url: "https://www.example.com/".into(),
            }])
            .await?;

        assert_eq!(
            statuses,
            vec![OperationStatus {
                status: Status::Imported,
                message: None,
            }],
        );

        // The key now has an entry, so it persists and can take per-validator settings.
        assert!(
            validator_definitions
                .read()
                .web3signer_pubkeys()
                .contains(&PUBKEY_REMOTE)
        );

        Ok(())
    }
}
