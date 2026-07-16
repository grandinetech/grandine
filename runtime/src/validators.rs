use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Error, Result, ensure};
use bls::{PublicKeyBytes, SecretKey, traits::SecretKey as _};
use eip_2335::Keystore;
use keymanager::{SigningMethod, ValidatorDefinition, ValidatorDefinitions};
use logging::{info_with_peers, warn_with_peers};
use rayon::iter::{IntoParallelIterator as _, IntoParallelRefIterator as _, ParallelIterator as _};
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

    /// Auto-discover keystores, appending an entry for each whose pubkey is not already in `definitions`.
    ///
    /// Additive only. A keystore without a declared `pubkey` field is skipped.
    pub fn discover(&self, definitions: &mut ValidatorDefinitions) -> Result<()> {
        for (keystore_path, password_path) in self.keymap_from_paths()? {
            let keystore = match parse_keystore(&keystore_path) {
                Ok(keystore) => keystore,
                Err(error) => {
                    // A keystore directory may contain unrelated files (e.g. `deposit_data*`).
                    if keystore_path.file_name().is_some_and(|filename| {
                        filename.to_string_lossy().starts_with("deposit_data")
                    }) {
                        warn_with_peers!(
                            "Ignoring loading {} file because it's not a valid keystore file. \
                            Keystore can only contain valid keystore files. \
                            Please make sure that keystore dir does not contain deposit_data* file",
                            keystore_path.display()
                        );

                        continue;
                    }

                    return Err(error);
                }
            };

            let Some(pubkey) = keystore.pubkey() else {
                warn_with_peers!(
                    "keystore {} has no public key field; skipping auto-discovery",
                    keystore_path.display(),
                );

                continue;
            };

            if definitions.contains(pubkey) {
                continue;
            }

            definitions.push(ValidatorDefinition::new(
                pubkey,
                SigningMethod::LocalKeystore {
                    keystore_path,
                    keystore_password_path: Some(password_path),
                    keystore_password: None,
                },
            ));
        }

        Ok(())
    }
}

/// Read and parse a keystore file, without decrypting it.
fn parse_keystore(keystore_path: &Path) -> Result<Keystore> {
    let keystore_bytes = Zeroizing::new(fs_err::read(keystore_path)?);

    serde_json::from_slice::<Keystore>(keystore_bytes.as_slice()).map_err(|error| {
        Error::new(error).context(format!(
            "Failed to load a keystore from file {}",
            keystore_path.display(),
        ))
    })
}

/// Decrypt the keystores of all enabled validator definitions into signing keys.
///
/// Sources keystores and passwords from `validators.yml`; settings-only entries are skipped.
pub fn normalize_definitions(
    definitions: &ValidatorDefinitions,
    validator_directory: Option<&Path>,
    mut validator_key_cache: Option<&mut ValidatorKeyCache>,
) -> Result<Vec<(PublicKeyBytes, Arc<SecretKey>, KeyOrigin)>> {
    let key_definitions = definitions.enabled_keystores().collect::<Vec<_>>();

    // Collect keystores and passwords first; keys are loaded from the cache or decrypted below.
    let keystores_with_passwords = key_definitions
        .par_iter()
        .map(|definition| {
            let keystore_path = definition
                .keystore_file()
                .expect("enabled_keystores yields only file-backed entries");

            let password = definition
                .keystore_password()?
                .expect("enabled_keystores yields only file-backed entries");

            let normalized_password = eip_2335::normalize_password(password.as_str().as_bytes())?;
            let keystore = parse_keystore(keystore_path)?;

            Ok((keystore, normalized_password))
        })
        .collect::<Result<Vec<_>>>()?;

    // Collect all passwords for decrypting the cache.
    let passwords = keystores_with_passwords
        .iter()
        .map(|(keystore, normalized_password)| (keystore.uuid(), normalized_password.clone()))
        .collect();

    if let Some(cache) = validator_key_cache.as_mut()
        && let Err(error) = cache.load(passwords)
    {
        warn_with_peers!(
            "Unable to load validator key cache: {error:?}; \
                 Validator key cache will be reset",
        );
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

                    info_with_peers!("decrypted validator key {public_key:?}");

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

            (public_key, secret_key)
        })
        .collect::<Vec<_>>();

    // Order is preserved, so verify each decrypted key against its declared pubkey and tag its origin.
    key_definitions
        .iter()
        .zip(keypairs)
        .map(|(definition, (public_key, secret_key))| {
            ensure!(
                public_key == definition.pubkey,
                "keystore {:?} contains key {public_key:?} but validators.yml declares pubkey {:?}",
                definition.keystore_file(),
                definition.pubkey,
            );

            let keystore_path = definition
                .keystore_file()
                .expect("enabled_keystores yields only file-backed entries");

            Ok((
                public_key,
                secret_key,
                keystore_origin(validator_directory, keystore_path),
            ))
        })
        .collect()
}

/// A keystore's origin by location: under the validator directory it is `Internal` (API-deletable),
/// elsewhere it is an operator's `--keystore-dir` keystore, `External` (read-only). Stable across restarts.
fn keystore_origin(validator_directory: Option<&Path>, keystore_path: &Path) -> KeyOrigin {
    match validator_directory {
        Some(directory) if keystore_path.starts_with(directory) => KeyOrigin::Internal,
        _ => KeyOrigin::External,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A keystore under the validator directory is `Internal`; one outside it is `External`.
    #[test]
    fn test_keystore_origin_is_by_location() {
        let validator_directory = Path::new("/data/validator");
        let api_keystore = validator_directory.join("0xabc").join("keystore.json");
        let external_keystore = Path::new("/keys/voting-keystore.json");

        assert!(matches!(
            keystore_origin(Some(validator_directory), &api_keystore),
            KeyOrigin::Internal,
        ));

        assert!(matches!(
            keystore_origin(Some(validator_directory), external_keystore),
            KeyOrigin::External,
        ));

        // With no validator directory, no keystore can be under it, so every keystore is external.
        assert!(matches!(
            keystore_origin(None, &api_keystore),
            KeyOrigin::External,
        ));
    }
}
