use core::fmt::{Debug, Formatter, Result as FmtResult};
use std::{
    collections::HashSet,
    io::{ErrorKind, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, RwLock, RwLockReadGuard},
};

use anyhow::{Context as _, Result, bail, ensure};
use bls::PublicKeyBytes;
use helper_functions::misc;
use serde::{Deserialize, Serialize};
use types::{bellatrix::primitives::Gas, phase0::primitives::ExecutionAddress};
use zeroize::Zeroizing;

const VALIDATORS_FILE_NAME: &str = "validators.yml";

const fn default_enabled() -> bool {
    true
}

#[derive(Clone, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct KeystorePassword(Zeroizing<String>);

impl Debug for KeystorePassword {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("[redacted]")
    }
}

impl From<Zeroizing<String>> for KeystorePassword {
    fn from(password: Zeroizing<String>) -> Self {
        Self(password)
    }
}

impl KeystorePassword {
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl PartialEq for KeystorePassword {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

/// A Web3Signer client's TLS material and request timeout. An empty block uses the default client.
///
/// At most one distinct non-empty configuration is supported; see [`ValidatorDefinitions::web3signer_options`].
#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize)]
pub struct Web3SignerOptions {
    /// Path to a PEM certificate added to the client's trusted roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_certificate_path: Option<PathBuf>,
    /// Per-request timeout, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,
    /// Path to a PKCS#12 file holding the client identity, for mutual TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity_path: Option<PathBuf>,
    /// Password for the PKCS#12 file. An empty password is used if omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity_password: Option<KeystorePassword>,
}

impl Web3SignerOptions {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.root_certificate_path.is_none()
            && self.request_timeout_ms.is_none()
            && self.client_identity_path.is_none()
            && self.client_identity_password.is_none()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SigningMethod {
    /// A keystore file on disk (auto-discovered from `--keystore-dir` or listed explicitly).
    LocalKeystore {
        keystore_path: PathBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        keystore_password_path: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        keystore_password: Option<KeystorePassword>,
    },
    /// The key lives in the legacy `keystores.json` storage blob.
    KeystoreStorage,
    /// Signing is delegated to a remote Web3Signer at `url`, via a client built from `options`.
    #[serde(rename = "web3signer")]
    Web3Signer {
        url: String,
        #[serde(flatten)]
        options: Web3SignerOptions,
    },
}

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ValidatorDefinitions(Vec<ValidatorDefinition>);

/// Per-validator builder (MEV-Boost) preferences.
#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct BuilderOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_proposals: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_boost_factor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_builder_proposals: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidatorDefinition {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub pubkey: PublicKeyBytes,
    #[serde(flatten)]
    pub signing_method: SigningMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_recipient: Option<ExecutionAddress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<Gas>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<String>,
    #[serde(flatten)]
    pub builder_options: BuilderOptions,
}

impl ValidatorDefinition {
    #[must_use]
    pub fn new(pubkey: PublicKeyBytes, signing_method: SigningMethod) -> Self {
        Self {
            enabled: default_enabled(),
            pubkey,
            signing_method,
            description: None,
            fee_recipient: None,
            gas_limit: None,
            graffiti: None,
            builder_options: BuilderOptions::default(),
        }
    }

    #[must_use]
    pub fn keystore_file(&self) -> Option<&Path> {
        match &self.signing_method {
            SigningMethod::LocalKeystore { keystore_path, .. } => Some(keystore_path),
            _ => None,
        }
    }

    pub fn keystore_password(&self) -> Result<Option<KeystorePassword>> {
        match &self.signing_method {
            SigningMethod::LocalKeystore {
                keystore_password: Some(password),
                ..
            } => Ok(Some(password.clone())),
            SigningMethod::LocalKeystore {
                keystore_password_path: Some(path),
                ..
            } => fs_err::read_to_string(path)
                .map(|password| Some(Zeroizing::new(password).into()))
                .map_err(Into::into),
            SigningMethod::LocalKeystore { .. } => bail!(
                "validator {:?} declares neither keystore_password nor keystore_password_path",
                self.pubkey,
            ),
            SigningMethod::KeystoreStorage | SigningMethod::Web3Signer { .. } => Ok(None),
        }
    }

    /// Whether the secret key is held locally rather than delegated to a signer.
    #[must_use]
    pub const fn has_local_key(&self) -> bool {
        matches!(
            self.signing_method,
            SigningMethod::LocalKeystore { .. } | SigningMethod::KeystoreStorage,
        )
    }
}

impl ValidatorDefinitions {
    #[must_use]
    pub fn file_path(validator_directory: &Path) -> PathBuf {
        validator_directory.join(VALIDATORS_FILE_NAME)
    }

    pub fn load_or_default(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::default())
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let file = fs_err::File::open(path)?;
        let definitions: Self = serde_yaml::from_reader(file)?;

        definitions
            .validate()
            .with_context(|| format!("invalid validators file {}", path.display()))?;

        Ok(definitions)
    }

    /// Reject a hand-edited file the node could not run: a duplicate pubkey or an oversized graffiti.
    fn validate(&self) -> Result<()> {
        let mut seen = HashSet::new();

        for definition in &self.0 {
            ensure!(
                seen.insert(definition.pubkey),
                "duplicate entry for validator {:?}",
                definition.pubkey,
            );

            if let Some(graffiti) = &definition.graffiti {
                misc::parse_graffiti(graffiti).with_context(|| {
                    format!("invalid graffiti for validator {:?}", definition.pubkey)
                })?;
            }
        }

        Ok(())
    }

    /// Atomically write the definitions: serialize to a sibling temp file, then rename over `path`.
    ///
    /// A new file is owner-readable only; an existing one is copied first so its permissions carry over.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs_err::create_dir_all(parent)?;
        }

        let mut temp = path.as_os_str().to_os_string();
        temp.push(".tmp");
        let temp_path = PathBuf::from(temp);

        let mut bytes = Zeroizing::new(vec![]);
        serde_yaml::to_writer(&mut *bytes, self)?;

        // Never write through a leftover temp file: it could keep wider permissions.
        match fs_err::remove_file(&temp_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        if path.exists() {
            fs_err::copy(path, &temp_path)?;
            fs_err::write(&temp_path, &*bytes)?;
        } else {
            write_owner_only(&temp_path, &bytes)?;
        }

        fs_err::rename(&temp_path, path)?;

        Ok(())
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn contains(&self, pubkey: PublicKeyBytes) -> bool {
        self.0.iter().any(|definition| definition.pubkey == pubkey)
    }

    #[must_use]
    pub fn get(&self, pubkey: PublicKeyBytes) -> Option<&ValidatorDefinition> {
        self.0.iter().find(|definition| definition.pubkey == pubkey)
    }

    pub fn get_mut(&mut self, pubkey: PublicKeyBytes) -> Option<&mut ValidatorDefinition> {
        self.0
            .iter_mut()
            .find(|definition| definition.pubkey == pubkey)
    }

    /// Enabled entries backed by a keystore file.
    pub fn enabled_keystores(&self) -> impl Iterator<Item = &ValidatorDefinition> {
        self.0
            .iter()
            .filter(|definition| definition.enabled && definition.keystore_file().is_some())
    }

    pub fn disabled_pubkeys(&self) -> impl Iterator<Item = PublicKeyBytes> + '_ {
        self.0
            .iter()
            .filter(|definition| !definition.enabled)
            .map(|definition| definition.pubkey)
    }

    /// The `(url, pubkey)` of every enabled `web3signer` entry.
    pub fn web3signer_definitions(&self) -> impl Iterator<Item = (&str, PublicKeyBytes)> {
        self.0
            .iter()
            .filter_map(|definition| match &definition.signing_method {
                SigningMethod::Web3Signer { url, .. } if definition.enabled => {
                    Some((url.as_str(), definition.pubkey))
                }
                _ => None,
            })
    }

    /// The single distinct non-empty Web3Signer client configuration across enabled entries, if any.
    ///
    /// More than one is a hard error; option-less entries are ignored and use the resulting client.
    pub fn web3signer_options(&self) -> Result<Option<Web3SignerOptions>> {
        let mut chosen: Option<&Web3SignerOptions> = None;

        for definition in self.0.iter().filter(|definition| definition.enabled) {
            let SigningMethod::Web3Signer { options, .. } = &definition.signing_method else {
                continue;
            };

            if options.is_empty() {
                continue;
            }

            match chosen {
                None => chosen = Some(options),
                Some(existing) if existing == options => {}
                Some(_) => bail!(
                    "validators.yml declares more than one Web3Signer client configuration; \
                     Grandine supports only a single one (differing certificates or timeouts)",
                ),
            }
        }

        Ok(chosen.cloned())
    }

    pub fn web3signer_pubkeys(&self) -> impl Iterator<Item = PublicKeyBytes> + '_ {
        self.0
            .iter()
            .filter_map(|definition| match &definition.signing_method {
                SigningMethod::Web3Signer { .. } if definition.enabled => Some(definition.pubkey),
                _ => None,
            })
    }

    #[must_use]
    pub fn loads_from_storage(&self, pubkey: PublicKeyBytes) -> bool {
        self.get(pubkey).is_some_and(|definition| {
            definition.enabled
                && matches!(definition.signing_method, SigningMethod::KeystoreStorage)
        })
    }

    pub fn add_storage_keystores(&mut self, pubkeys: impl IntoIterator<Item = PublicKeyBytes>) {
        for pubkey in pubkeys {
            if !self.contains(pubkey) {
                self.push(ValidatorDefinition::new(
                    pubkey,
                    SigningMethod::KeystoreStorage,
                ));
            }
        }
    }

    /// Whether `pubkey`'s secret key is held locally, enabled or not (so it is never sent to a signer).
    #[must_use]
    pub fn has_local_key(&self, pubkey: PublicKeyBytes) -> bool {
        self.get(pubkey)
            .is_some_and(ValidatorDefinition::has_local_key)
    }

    /// Record a validator imported into the `keystores.json` blob.
    pub fn import_storage_keystore(&mut self, pubkey: PublicKeyBytes) {
        self.import(pubkey, SigningMethod::KeystoreStorage);
    }

    /// Record a validator imported through the remote-key API, signed at `url`.
    pub fn import_web3signer(&mut self, pubkey: PublicKeyBytes, url: String) {
        // The remote-key API carries no TLS options, so it uses the node's single Web3Signer client.
        self.import(
            pubkey,
            SigningMethod::Web3Signer {
                url,
                options: Web3SignerOptions::default(),
            },
        );
    }

    /// Record a validator imported through the keystore API.
    pub fn import_local_keystore(
        &mut self,
        pubkey: PublicKeyBytes,
        keystore_path: PathBuf,
        password_path: PathBuf,
    ) {
        self.import(
            pubkey,
            SigningMethod::LocalKeystore {
                keystore_path,
                keystore_password_path: Some(password_path),
                keystore_password: None,
            },
        );
    }

    /// Point `pubkey`'s entry at `signing_method` and enable it, adding the entry if it is new.
    fn import(&mut self, pubkey: PublicKeyBytes, signing_method: SigningMethod) {
        match self.get_mut(pubkey) {
            Some(definition) => {
                definition.signing_method = signing_method;
                definition.enabled = true;
            }
            None => self.push(ValidatorDefinition::new(pubkey, signing_method)),
        }
    }

    /// Drop the entries for `pubkeys`, discarding their proposer settings.
    ///
    /// Only for validators whose key source is gone; one still on disk would be re-added on restart.
    pub fn remove(&mut self, pubkeys: impl IntoIterator<Item = PublicKeyBytes>) {
        let pubkeys = pubkeys.into_iter().collect::<HashSet<_>>();

        self.0
            .retain(|definition| !pubkeys.contains(&definition.pubkey));
    }

    pub fn push(&mut self, definition: ValidatorDefinition) {
        self.0.push(definition);
    }
}

/// Write `bytes` to a new file readable only by its owner, with the mode set at creation.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs_err::OpenOptions::new();

    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;

    file.write_all(bytes)?;

    Ok(())
}

/// Where [`ValidatorDefinitions`] are written back to, if at all.
#[derive(Default, Debug)]
pub enum DefinitionsStorage {
    Persistent(PathBuf),
    #[default]
    InMemory,
}

/// Shared handle to the `validators.yml` definitions: the copy the node reads from, and where to
/// write it back. Built once and shared, so a change through one holder is seen by all.
#[derive(Default, Debug)]
pub struct ValidatorDefinitionsWithStorage {
    validator_definitions: Arc<RwLock<ValidatorDefinitions>>,
    storage: DefinitionsStorage,
}

impl ValidatorDefinitionsWithStorage {
    #[must_use]
    pub const fn new(
        validator_definitions: Arc<RwLock<ValidatorDefinitions>>,
        storage: DefinitionsStorage,
    ) -> Self {
        Self {
            validator_definitions,
            storage,
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, ValidatorDefinitions> {
        self.validator_definitions
            .read()
            .expect("validator definitions lock is poisoned")
    }

    pub fn update<R>(&self, mutation: impl FnOnce(&mut ValidatorDefinitions) -> R) -> Result<R> {
        let mut validator_definitions = self
            .validator_definitions
            .write()
            .expect("validator definitions lock is poisoned");

        let result = mutation(&mut validator_definitions);

        match &self.storage {
            DefinitionsStorage::Persistent(path) => validator_definitions.save(path)?,
            DefinitionsStorage::InMemory => {}
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::Builder;

    use super::*;

    const PUBKEY: PublicKeyBytes = PublicKeyBytes::repeat_byte(1);

    fn keystore(
        keystore_password_path: Option<PathBuf>,
        keystore_password: Option<&str>,
    ) -> ValidatorDefinition {
        ValidatorDefinition::new(
            PUBKEY,
            SigningMethod::LocalKeystore {
                keystore_path: "keystore.json".into(),
                keystore_password_path,
                keystore_password: keystore_password
                    .map(|password| Zeroizing::new(password.to_owned()).into()),
            },
        )
    }

    fn password_of(definition: &ValidatorDefinition) -> Result<Option<String>> {
        Ok(definition
            .keystore_password()?
            .map(|password| password.as_str().to_owned()))
    }

    fn web3signer(pubkey_byte: u8, options: Web3SignerOptions) -> ValidatorDefinition {
        ValidatorDefinition::new(
            PublicKeyBytes::repeat_byte(pubkey_byte),
            SigningMethod::Web3Signer {
                url: "https://signer.example/".to_owned(),
                options,
            },
        )
    }

    fn root_certificate(path: &str) -> Web3SignerOptions {
        Web3SignerOptions {
            root_certificate_path: Some(path.into()),
            ..Web3SignerOptions::default()
        }
    }

    #[test]
    fn test_web3signer_options_none_when_all_empty() -> Result<()> {
        let mut definitions = ValidatorDefinitions::default();
        definitions.push(web3signer(1, Web3SignerOptions::default()));
        definitions.push(web3signer(2, Web3SignerOptions::default()));

        assert_eq!(definitions.web3signer_options()?, None);

        Ok(())
    }

    #[test]
    fn test_web3signer_options_returns_the_single_group() -> Result<()> {
        let mut definitions = ValidatorDefinitions::default();
        definitions.push(web3signer(1, root_certificate("/ca.pem")));
        definitions.push(web3signer(2, Web3SignerOptions::default()));

        assert_eq!(
            definitions.web3signer_options()?,
            Some(root_certificate("/ca.pem")),
        );

        Ok(())
    }

    #[test]
    fn test_web3signer_options_allows_identical_groups() -> Result<()> {
        let mut definitions = ValidatorDefinitions::default();
        definitions.push(web3signer(1, root_certificate("/ca.pem")));
        definitions.push(web3signer(2, root_certificate("/ca.pem")));

        assert_eq!(
            definitions.web3signer_options()?,
            Some(root_certificate("/ca.pem")),
        );

        Ok(())
    }

    #[test]
    fn test_web3signer_options_rejects_conflicting_groups() {
        let mut definitions = ValidatorDefinitions::default();
        definitions.push(web3signer(1, root_certificate("/ca.pem")));
        definitions.push(web3signer(2, root_certificate("/other.pem")));

        definitions
            .web3signer_options()
            .expect_err("conflicting Web3Signer configurations must be rejected");
    }

    #[test]
    fn test_web3signer_options_ignores_disabled_entries() -> Result<()> {
        let mut definitions = ValidatorDefinitions::default();
        definitions.push(web3signer(1, root_certificate("/ca.pem")));

        let mut disabled = web3signer(2, root_certificate("/other.pem"));
        disabled.enabled = false;
        definitions.push(disabled);

        assert_eq!(
            definitions.web3signer_options()?,
            Some(root_certificate("/ca.pem")),
        );

        Ok(())
    }

    #[test]
    fn test_inline_keystore_password_is_used() -> Result<()> {
        let definition = keystore(None, Some("inline"));

        assert_eq!(password_of(&definition)?.as_deref(), Some("inline"));

        Ok(())
    }

    #[test]
    fn test_keystore_password_is_read_from_its_file() -> Result<()> {
        let tempdir = Builder::new().prefix("secrets").rand_bytes(10).tempdir()?;
        let path = tempdir.path().join("password.txt");

        fs_err::write(&path, "from-file")?;

        let definition = keystore(Some(path), None);

        assert_eq!(password_of(&definition)?.as_deref(), Some("from-file"));

        Ok(())
    }

    #[test]
    fn test_inline_keystore_password_wins_over_the_file() -> Result<()> {
        let definition = keystore(Some("/nonexistent".into()), Some("inline"));
        assert_eq!(password_of(&definition)?.as_deref(), Some("inline"));
        Ok(())
    }

    #[test]
    fn test_keystore_without_a_password_is_an_error() {
        keystore(None, None)
            .keystore_password()
            .expect_err("a keystore with no password anywhere cannot be decrypted");
    }

    #[test]
    fn test_validators_without_a_keystore_have_no_password() -> Result<()> {
        let blob = ValidatorDefinition::new(PUBKEY, SigningMethod::KeystoreStorage);

        assert!(blob.keystore_password()?.is_none());

        Ok(())
    }

    #[test]
    fn test_inline_keystore_password_is_redacted_when_printed() {
        let definition = keystore(None, Some("hunter2"));

        assert!(!format!("{definition:?}").contains("hunter2"));
    }

    #[test]
    fn test_load_or_default_does_not_create_the_file() -> Result<()> {
        let tempdir = Builder::new()
            .prefix("validators")
            .rand_bytes(10)
            .tempdir()?;
        let path = ValidatorDefinitions::file_path(tempdir.path());

        let validator_definitions = ValidatorDefinitions::load_or_default(&path)?;

        assert!(validator_definitions.is_empty());
        assert!(!path.exists());

        Ok(())
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> Result<u32> {
        use std::os::unix::fs::PermissionsExt as _;

        Ok(fs_err::metadata(path)?.permissions().mode() & 0o777)
    }

    #[cfg(unix)]
    #[test]
    fn test_save_creates_the_file_readable_only_by_its_owner() -> Result<()> {
        let tempdir = Builder::new()
            .prefix("validators")
            .rand_bytes(10)
            .tempdir()?;
        let path = ValidatorDefinitions::file_path(tempdir.path());

        ValidatorDefinitions::default().save(&path)?;

        assert_eq!(mode_of(&path)?, 0o600);

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_save_preserves_the_permissions_of_an_existing_file() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let tempdir = Builder::new()
            .prefix("validators")
            .rand_bytes(10)
            .tempdir()?;
        let path = ValidatorDefinitions::file_path(tempdir.path());

        ValidatorDefinitions::default().save(&path)?;
        fs_err::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;

        let mut validator_definitions = ValidatorDefinitions::load(&path)?;
        validator_definitions.push(ValidatorDefinition::new(
            PUBKEY,
            SigningMethod::KeystoreStorage,
        ));
        validator_definitions.save(&path)?;

        assert_eq!(mode_of(&path)?, 0o640);
        assert!(ValidatorDefinitions::load(&path)?.contains(PUBKEY));

        Ok(())
    }

    #[test]
    fn test_load_rejects_duplicate_pubkeys() -> Result<()> {
        let tempdir = Builder::new()
            .prefix("validators")
            .rand_bytes(10)
            .tempdir()?;
        let path = ValidatorDefinitions::file_path(tempdir.path());

        let mut validator_definitions = ValidatorDefinitions::default();
        validator_definitions.push(ValidatorDefinition::new(
            PUBKEY,
            SigningMethod::KeystoreStorage,
        ));
        validator_definitions.push(ValidatorDefinition::new(
            PUBKEY,
            SigningMethod::KeystoreStorage,
        ));
        validator_definitions.save(&path)?;

        ValidatorDefinitions::load(&path)
            .expect_err("a file with duplicate pubkeys must be refused");

        Ok(())
    }

    #[test]
    fn test_load_rejects_oversized_graffiti() -> Result<()> {
        let tempdir = Builder::new()
            .prefix("validators")
            .rand_bytes(10)
            .tempdir()?;
        let path = ValidatorDefinitions::file_path(tempdir.path());

        let mut definition = ValidatorDefinition::new(PUBKEY, SigningMethod::KeystoreStorage);
        definition.graffiti =
            Some("graffiti longer than the thirty-two bytes a block holds".into());

        let mut validator_definitions = ValidatorDefinitions::default();
        validator_definitions.push(definition);
        validator_definitions.save(&path)?;

        ValidatorDefinitions::load(&path)
            .expect_err("a file with an oversized graffiti must be refused");

        Ok(())
    }
}
