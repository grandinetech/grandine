use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::{Error, Result};
use bls::{traits::BlsSecretKey, PublicKeyBytes, SecretKey};
use eip_2335::Keystore;
use log::{info, warn};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use signer::KeyOrigin;
use std_ext::ArcExt;
use tap::{Pipe as _, TryConv as _};
use validator_key_cache::ValidatorKeyCache;
use zeroize::Zeroizing;

#[derive(Default)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Validators {
    pub keystore_dir: PathBuf,
    pub keystore_password_file: PathBuf,
}

enum KeystoreExtension {
    Json,
    None,
}

impl Validators {
    fn keymap_from_paths(&self) -> Result<HashMap<PathBuf, PathBuf>> {
        let keystore_dir = self.keystore_dir.as_path();
        let keystore_password_file = self.keystore_password_file.as_path();
        let individual_passwords = keystore_password_file.is_dir();
        let keystore_glob = "*";

        let old_working_directory = std::env::current_dir()?;

        std::env::set_current_dir(keystore_dir)?;

        let keystores = glob::glob(keystore_glob)
            .expect("glob pattern should be valid")
            .flatten()
            .filter_map(|path| {
                // None is a supported extension
                let supported_extension = match path.extension() {
                    None => Some(KeystoreExtension::None),
                    Some(extension) => (extension == "json").then_some(KeystoreExtension::Json),
                };

                if let Some(extension) = supported_extension {
                    let keystore_file = keystore_dir.join(path.as_path());

                    let password_file = if individual_passwords {
                        let file_stem = path
                            .file_stem()
                            .expect("glob patterns above only match paths that have file names");

                        let password_file = keystore_password_file.join(file_stem);

                        match extension {
                            KeystoreExtension::Json => password_file.with_extension("txt"),
                            KeystoreExtension::None => password_file,
                        }
                    } else {
                        keystore_password_file.to_path_buf()
                    };

                    Some((keystore_file, password_file))
                } else {
                    None
                }
            })
            .collect();

        std::env::set_current_dir(old_working_directory)?;

        Ok(keystores)
    }

    pub fn normalize(
        self,
        mut validator_key_cache: Option<&mut ValidatorKeyCache>,
    ) -> Result<Vec<(PublicKeyBytes, Arc<SecretKey>, KeyOrigin)>> {
        // Collect all passwords and keystores first.
        // They may be used to load secret keys from the cache.
        // Secret keys are decrypted later.
        let keystores_with_passwords = self
            .keymap_from_paths()?
            .into_par_iter()
            .map(|(keystore_path, password_path)| {
                let password = Zeroizing::new(fs_err::read(password_path)?);
                let normalized_password = eip_2335::normalize_password(password.as_slice())?;
                let keystore_bytes = Zeroizing::new(fs_err::read(keystore_path)?);
                let keystore = serde_json::from_slice::<Keystore>(keystore_bytes.as_slice())?;
                Ok((keystore, normalized_password))
            })
            .collect::<Result<Vec<_>>>()?;

        // Collect all passwords for decrypting the cache.
        let passwords = keystores_with_passwords
            .iter()
            .map(|(keystore, normalized_password)| (keystore.uuid(), normalized_password.clone()))
            .collect();

        if let Some(cache) = validator_key_cache.as_mut() {
            if let Err(error) = cache.load(passwords) {
                warn!(
                    "Unable to load validator key cache: {error:?}; \
                     Validator key cache will be reset",
                );
            }
        }

        let keypairs = keystores_with_passwords
            .into_par_iter()
            .map(|(keystore, normalized_password)| {
                let uuid = keystore.uuid();

                let keypair = validator_key_cache
                    .as_ref()
                    .and_then(|cache| cache.get(uuid))
                    .map(Ok::<_, Error>)
                    .unwrap_or_else(|| {
                        let secret_key = keystore
                            .decrypt(normalized_password.as_str())?
                            .try_conv::<SecretKey>()?
                            .pipe(Arc::new);

                        let public_key = secret_key.to_public_key().into();

                        info!("decrypted validator key {public_key:?}");

                        Ok((public_key, secret_key))
                    })?;

                Ok((uuid, normalized_password, keypair))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|(uuid, normalized_password, (public_key, secret_key))| {
                if let Some(cache) = validator_key_cache.as_mut() {
                    cache.add_with_password(
                        normalized_password,
                        uuid,
                        public_key,
                        secret_key.clone_arc(),
                    );
                }

                (public_key, secret_key, KeyOrigin::LocalFileSystem)
            })
            .collect();

        Ok(keypairs)
    }
}
