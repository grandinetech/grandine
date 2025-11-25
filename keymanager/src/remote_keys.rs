use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, anyhow};
use bls::PublicKeyBytes;
use futures::lock::Mutex;
use serde::{Deserialize, Serialize};
use signer::{KeyOrigin, Signer};
use slashing_protection::SlashingProtector;

use crate::misc::{Error, OperationStatus, Status};

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
}

impl RemoteKeyManager {
    #[must_use]
    pub const fn new(
        signer: Arc<Signer>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
    ) -> Self {
        Self {
            signer,
            slashing_protector,
        }
    }

    pub fn delete(&self, pubkeys: &[PublicKeyBytes]) -> Vec<OperationStatus> {
        let mut delete_results = vec![];

        self.signer.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();

            let signer_keys = snapshot.keys_with_origin().collect::<HashMap<_, _>>();

            delete_results.clear();

            for pubkey in pubkeys.iter().copied() {
                let result = match signer_keys.get(&pubkey) {
                    Some(origin) => match origin {
                        KeyOrigin::KeymanagerAPI | KeyOrigin::LocalFileSystem => {
                            Error::ReadOnly.into()
                        }
                        KeyOrigin::Web3Signer => {
                            snapshot.delete_key(pubkey);
                            Status::Deleted.into()
                        }
                    },
                    None => Error::NotFound.into(),
                };

                delete_results.push(result);
            }

            snapshot
        });

        delete_results
    }

    pub async fn import(&self, remote_keys: Vec<RemoteKey>) -> Result<Vec<OperationStatus>> {
        let mut imported_pubkeys = vec![];
        let mut import_results = vec![];

        self.signer.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();

            imported_pubkeys.clear();
            import_results.clear();

            for RemoteKey { pubkey, url } in &remote_keys {
                let result = match url.parse() {
                    Ok(url) => {
                        if snapshot.append_remote_key(*pubkey, url) {
                            imported_pubkeys.push(*pubkey);
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

        self.slashing_protector
            .lock()
            .await
            .register_validators(imported_pubkeys)?;

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
    use bls::SecretKeyBytes;
    use hex_literal::hex;
    use itertools::Itertools as _;
    use reqwest::Client;
    use signer::Web3SignerConfig;
    use slashing_protection::DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT;
    use std_ext::ArcExt as _;

    use super::*;

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
                KeyOrigin::LocalFileSystem,
            )],
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

    #[tokio::test]
    async fn test_remote_keys_import() -> Result<()> {
        let signer = build_signer();
        let manager = RemoteKeyManager::new(signer.clone_arc(), build_slashing_protector()?);

        let remote_key_1 = RemoteKey {
            pubkey: PUBKEY_REMOTE,
            url: "https://www.example.com/".into(),
        };

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
                    status: Status::Duplicate,
                    message: None,
                },
            ]
        );

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
        let manager = RemoteKeyManager::new(signer.clone_arc(), build_slashing_protector()?);

        let remote_key = RemoteKey {
            pubkey: PUBKEY_REMOTE,
            url: "https://www.example.com/".into(),
        };

        manager.import(vec![remote_key]).await?;

        assert_eq!(manager.list().len(), 1);

        assert_eq!(
            manager.delete(&[PUBKEY_REMOTE, PUBKEY_LOCAL]),
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

        assert_eq!(signer.load().keys().copied().collect_vec(), [PUBKEY_LOCAL]);

        assert_eq!(manager.list(), []);

        Ok(())
    }
}
