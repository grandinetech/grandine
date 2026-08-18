use std::{io::ErrorKind, path::Path, str, sync::Arc};

use anyhow::Result;
use bls::PublicKeyBytes;
use bytesize::ByteSize;
use database::{Database, DatabaseMode};
use derive_more::Display;
use helper_functions::misc;
use serde::de::DeserializeOwned;
use types::{
    bellatrix::primitives::Gas,
    phase0::primitives::{ExecutionAddress, H256},
};

use crate::{
    misc::Error,
    validator_definitions::{ValidatorDefinitions, ValidatorDefinitionsWithStorage},
};

const DB_MAX_SIZE: ByteSize = ByteSize::gib(1);

pub struct ProposerConfigs {
    default_fee_recipient: ExecutionAddress,
    default_gas_limit: Option<Gas>,
    default_graffiti: H256,
    validator_definitions: Arc<ValidatorDefinitionsWithStorage>,
}

impl ProposerConfigs {
    #[must_use]
    pub const fn new(
        default_fee_recipient: ExecutionAddress,
        default_gas_limit: Option<Gas>,
        default_graffiti: H256,
        validator_definitions: Arc<ValidatorDefinitionsWithStorage>,
    ) -> Self {
        Self {
            default_fee_recipient,
            default_gas_limit,
            default_graffiti,
            validator_definitions,
        }
    }

    #[must_use]
    pub fn fee_recipient(&self, pubkey: PublicKeyBytes) -> ExecutionAddress {
        self.validator_definitions
            .read()
            .get(pubkey)
            .and_then(|definition| definition.fee_recipient)
            .unwrap_or(self.default_fee_recipient)
    }

    pub fn set_fee_recipient(
        &self,
        pubkey: PublicKeyBytes,
        fee_recipient: ExecutionAddress,
    ) -> Result<()> {
        self.validator_definitions.update(|validator_definitions| {
            let definition = validator_definitions
                .get_mut(pubkey)
                .ok_or(Error::NotFound)?;

            definition.fee_recipient = Some(fee_recipient);

            Ok(())
        })?
    }

    pub fn delete_fee_recipient(&self, pubkey: PublicKeyBytes) -> Result<()> {
        self.validator_definitions.update(|validator_definitions| {
            let definition = validator_definitions
                .get_mut(pubkey)
                .ok_or(Error::NotFound)?;

            definition.fee_recipient = None;

            Ok(())
        })?
    }

    /// Returns the gas limit configured for `pubkey`, if any.
    #[must_use]
    pub fn gas_limit(&self, pubkey: PublicKeyBytes) -> Option<Gas> {
        self.validator_definitions
            .read()
            .get(pubkey)
            .and_then(|definition| definition.gas_limit)
            .or(self.default_gas_limit)
    }

    pub fn set_gas_limit(&self, pubkey: PublicKeyBytes, gas_limit: Gas) -> Result<()> {
        self.validator_definitions.update(|validator_definitions| {
            let definition = validator_definitions
                .get_mut(pubkey)
                .ok_or(Error::NotFound)?;

            definition.gas_limit = Some(gas_limit);

            Ok(())
        })?
    }

    pub fn delete_gas_limit(&self, pubkey: PublicKeyBytes) -> Result<()> {
        self.validator_definitions.update(|validator_definitions| {
            let definition = validator_definitions
                .get_mut(pubkey)
                .ok_or(Error::NotFound)?;

            definition.gas_limit = None;

            Ok(())
        })?
    }

    pub fn graffiti_bytes(&self, pubkey: PublicKeyBytes) -> Result<Option<H256>> {
        self.validator_definitions
            .read()
            .get(pubkey)
            .and_then(|definition| definition.graffiti.as_deref())
            .map(misc::parse_graffiti)
            .transpose()
    }

    pub fn graffiti(&self, pubkey: PublicKeyBytes) -> Result<String> {
        let graffiti_bytes = self
            .graffiti_bytes(pubkey)?
            .unwrap_or(self.default_graffiti);

        Ok(str::from_utf8(graffiti_bytes.as_bytes())?
            .trim_end_matches('\0')
            .into())
    }

    pub fn set_graffiti(&self, pubkey: PublicKeyBytes, graffiti: &str) -> Result<()> {
        // Validate before storing so an unparsable graffiti never reaches the file.
        misc::parse_graffiti(graffiti)?;

        self.validator_definitions.update(|validator_definitions| {
            let definition = validator_definitions
                .get_mut(pubkey)
                .ok_or(Error::NotFound)?;

            definition.graffiti = Some(graffiti.to_owned());

            Ok(())
        })?
    }

    pub fn delete_graffiti(&self, pubkey: PublicKeyBytes) -> Result<()> {
        self.validator_definitions.update(|validator_definitions| {
            let definition = validator_definitions
                .get_mut(pubkey)
                .ok_or(Error::NotFound)?;

            definition.graffiti = None;

            Ok(())
        })?
    }
}

/// Legacy `proposer-configs` validators, split by whether they had a definition to attach to.
#[derive(Debug)]
pub struct LegacyMigration {
    /// Migrated into the definitions; [`prune_legacy_database`] removes their rows.
    pub migrated: Vec<PublicKeyBytes>,
    /// No entry; their rows stay in the database for a later run.
    pub skipped: Vec<PublicKeyBytes>,
}

/// Fold the legacy `proposer-configs` database into `validator_definitions`, or `None` if absent.
///
/// Existing settings win. Read-only: rows are deleted by [`prune_legacy_database`] after a save.
pub fn migrate_legacy_database(
    validator_definitions: &mut ValidatorDefinitions,
    validator_directory: &Path,
) -> Result<Option<LegacyMigration>> {
    if !validator_directory.join("mdbx.dat").exists() {
        return Ok(None);
    }

    let database = Database::persistent(
        "proposer-configs",
        validator_directory,
        DB_MAX_SIZE,
        DatabaseMode::ReadOnly,
        None,
    )?;

    // The named database is absent until a setting was stored; opening it then fails: nothing to migrate.
    let Ok(iterator) = database.iterator_ascending(Vec::<u8>::new()..) else {
        return Ok(Some(LegacyMigration {
            migrated: vec![],
            skipped: vec![],
        }));
    };

    // Keys are a one-byte setting prefix plus the hex public key; collect the distinct validators.
    let mut pubkeys = Vec::new();

    for result in iterator {
        let (key, _) = result?;

        let Some((_, pubkey_hex)) = key.split_first() else {
            continue;
        };

        let pubkey = str::from_utf8(pubkey_hex)?.parse::<PublicKeyBytes>()?;

        if !pubkeys.contains(&pubkey) {
            pubkeys.push(pubkey);
        }
    }

    let mut migrated = vec![];
    let mut skipped = vec![];

    for pubkey in pubkeys {
        // Only attach settings to validators that have an entry; others keep their rows.
        let Some(definition) = validator_definitions.get_mut(pubkey) else {
            skipped.push(pubkey);
            continue;
        };

        migrated.push(pubkey);

        // Existing settings win.
        if definition.fee_recipient.is_none() {
            definition.fee_recipient = db_get(&database, FeeRecipientByPubkey(pubkey))?;
        }

        if definition.gas_limit.is_none() {
            definition.gas_limit = db_get(&database, GasLimitByPubkey(pubkey))?;
        }

        if definition.graffiti.is_none()
            && let Some(graffiti) = db_get::<H256>(&database, GraffitiByPubkey(pubkey))?
        {
            definition.graffiti = Some(graffiti_to_string(graffiti));
        }
    }

    Ok(Some(LegacyMigration { migrated, skipped }))
}

/// Delete the migrated validators' rows from the legacy `proposer-configs` database, and the
/// database files themselves once it holds nothing more. Returns whether the database was removed.
pub fn prune_legacy_database(
    validator_directory: &Path,
    migrated: &[PublicKeyBytes],
) -> Result<bool> {
    let database = Database::persistent(
        "proposer-configs",
        validator_directory,
        DB_MAX_SIZE,
        DatabaseMode::ReadWrite,
        None,
    )?;

    for pubkey in migrated.iter().copied() {
        database.delete(FeeRecipientByPubkey(pubkey).to_string())?;
        database.delete(GasLimitByPubkey(pubkey).to_string())?;
        database.delete(GraffitiByPubkey(pubkey).to_string())?;
    }

    let is_empty = match database.iterator_ascending(Vec::<u8>::new()..) {
        Ok(mut iterator) => iterator.next().is_none(),
        // The named database is absent until a setting is stored; nothing is left to keep.
        Err(_) => true,
    };

    drop(database);

    if is_empty {
        remove_legacy_database(validator_directory)?;
    }

    Ok(is_empty)
}

/// Remove the legacy `proposer-configs` database from the validator directory.
fn remove_legacy_database(validator_directory: &Path) -> Result<()> {
    for name in ["mdbx.dat", "mdbx.lck"] {
        let path = validator_directory.join(name);

        match fs_err::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

/// Convert a raw graffiti value into text, trimming trailing null padding (inverse of `parse_graffiti`).
///
/// Non-UTF-8 graffiti falls back to a lossy conversion so migration never fails.
fn graffiti_to_string(graffiti: H256) -> String {
    String::from_utf8_lossy(graffiti.as_bytes())
        .trim_end_matches('\0')
        .to_owned()
}

/// Read and JSON-decode a single value from the legacy database, if the key is present.
fn db_get<V: DeserializeOwned>(
    database: &Database,
    key: impl core::fmt::Display,
) -> Result<Option<V>> {
    database
        .get(key.to_string())?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()
        .map_err(Into::into)
}

/// Keys of the legacy `proposer-configs` database: a one-byte setting prefix plus the lower-hex pubkey.
#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
struct FeeRecipientByPubkey(PublicKeyBytes);

impl FeeRecipientByPubkey {
    const PREFIX: &'static str = "f";
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
struct GasLimitByPubkey(PublicKeyBytes);

impl GasLimitByPubkey {
    const PREFIX: &'static str = "g";
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
struct GraffitiByPubkey(PublicKeyBytes);

impl GraffitiByPubkey {
    const PREFIX: &'static str = "r";
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use tempfile::Builder;

    use super::*;
    use crate::validator_definitions::{
        DefinitionsStorage, SigningMethod, ValidatorDefinition, ValidatorDefinitions,
    };

    /// Definitions seeded with an entry for [`PUBKEY`]; setters only mutate existing entries.
    fn definitions_with_pubkey() -> ValidatorDefinitions {
        let mut validator_definitions = ValidatorDefinitions::default();
        validator_definitions.push(ValidatorDefinition::new(
            PUBKEY,
            SigningMethod::KeystoreStorage,
        ));
        validator_definitions
    }

    const DEFAULT_GRAFFITI: &str = "Grandine";
    const DEFAULT_FEE_RECIPIENT: ExecutionAddress = ExecutionAddress::repeat_byte(1);
    const DEFAULT_GAS_LIMIT: Gas = 60_000_000;
    const TEST_FEE_RECIPIENT: ExecutionAddress = ExecutionAddress::repeat_byte(2);
    const PUBKEY: PublicKeyBytes = PublicKeyBytes::repeat_byte(1);

    fn in_memory() -> Result<ProposerConfigs> {
        let graffiti_bytes = misc::parse_graffiti(DEFAULT_GRAFFITI)?;

        let validator_definitions = Arc::new(ValidatorDefinitionsWithStorage::new(
            Arc::new(RwLock::new(definitions_with_pubkey())),
            DefinitionsStorage::InMemory,
        ));

        Ok(ProposerConfigs::new(
            DEFAULT_FEE_RECIPIENT,
            Some(DEFAULT_GAS_LIMIT),
            graffiti_bytes,
            validator_definitions,
        ))
    }

    #[test]
    fn test_get_fee_recipient_when_recipient_is_not_set() -> Result<()> {
        let proposer_configs = in_memory()?;

        assert_eq!(
            proposer_configs.fee_recipient(PUBKEY),
            DEFAULT_FEE_RECIPIENT
        );

        Ok(())
    }

    #[test]
    fn test_set_and_get_fee_recipient() -> Result<()> {
        let proposer_configs = in_memory()?;

        proposer_configs.set_fee_recipient(PUBKEY, TEST_FEE_RECIPIENT)?;

        assert_eq!(proposer_configs.fee_recipient(PUBKEY), TEST_FEE_RECIPIENT);

        Ok(())
    }

    #[test]
    fn test_delete_fee_recipient() -> Result<()> {
        let proposer_configs = in_memory()?;

        proposer_configs.set_fee_recipient(PUBKEY, TEST_FEE_RECIPIENT)?;
        proposer_configs.delete_fee_recipient(PUBKEY)?;

        assert_eq!(
            proposer_configs.fee_recipient(PUBKEY),
            DEFAULT_FEE_RECIPIENT
        );

        Ok(())
    }

    #[test]
    fn test_get_gas_limit_when_gas_limit_is_not_set() -> Result<()> {
        let proposer_configs = in_memory()?;

        assert_eq!(proposer_configs.gas_limit(PUBKEY), Some(DEFAULT_GAS_LIMIT));

        Ok(())
    }

    #[test]
    fn test_set_and_get_gas_limit() -> Result<()> {
        let proposer_configs = in_memory()?;

        proposer_configs.set_gas_limit(PUBKEY, 12345)?;

        assert_eq!(proposer_configs.gas_limit(PUBKEY), Some(12345));

        Ok(())
    }

    #[test]
    fn test_delete_gas_limit() -> Result<()> {
        let proposer_configs = in_memory()?;

        proposer_configs.set_gas_limit(PUBKEY, 12345)?;
        proposer_configs.delete_gas_limit(PUBKEY)?;

        assert_eq!(proposer_configs.gas_limit(PUBKEY), Some(DEFAULT_GAS_LIMIT));

        Ok(())
    }

    #[test]
    fn test_get_graffiti_when_graffiti_is_not_set() -> Result<()> {
        let proposer_configs = in_memory()?;

        assert_eq!(proposer_configs.graffiti(PUBKEY)?, DEFAULT_GRAFFITI);

        Ok(())
    }

    #[test]
    fn test_set_and_get_graffiti() -> Result<()> {
        let proposer_configs = in_memory()?;

        proposer_configs.set_graffiti(PUBKEY, "Hello, world!")?;

        assert_eq!(proposer_configs.graffiti(PUBKEY)?, "Hello, world!");

        Ok(())
    }

    /// A setting for a validator with no entry must be refused, not silently dropped.
    #[test]
    fn test_settings_for_an_unknown_validator_are_refused() -> Result<()> {
        const UNKNOWN_PUBKEY: PublicKeyBytes = PublicKeyBytes::repeat_byte(9);

        let proposer_configs = in_memory()?;

        proposer_configs
            .set_fee_recipient(UNKNOWN_PUBKEY, TEST_FEE_RECIPIENT)
            .expect_err("setting a fee recipient for an unknown validator must fail");
        proposer_configs
            .set_gas_limit(UNKNOWN_PUBKEY, 12345)
            .expect_err("setting a gas limit for an unknown validator must fail");
        proposer_configs
            .set_graffiti(UNKNOWN_PUBKEY, "graffiti")
            .expect_err("setting a graffiti for an unknown validator must fail");
        proposer_configs
            .delete_fee_recipient(UNKNOWN_PUBKEY)
            .expect_err("deleting a fee recipient for an unknown validator must fail");

        assert!(
            !proposer_configs
                .validator_definitions
                .read()
                .contains(UNKNOWN_PUBKEY)
        );

        Ok(())
    }

    #[test]
    fn test_delete_graffiti() -> Result<()> {
        let proposer_configs = in_memory()?;

        proposer_configs.set_graffiti(PUBKEY, "Hello, world!")?;
        proposer_configs.delete_graffiti(PUBKEY)?;

        assert_eq!(proposer_configs.graffiti(PUBKEY)?, DEFAULT_GRAFFITI);

        Ok(())
    }

    #[test]
    fn test_settings_persist_across_reload() -> Result<()> {
        let tempdir = Builder::new()
            .prefix("validators")
            .rand_bytes(10)
            .tempdir()?;

        let path = ValidatorDefinitions::file_path(tempdir.path());
        let graffiti_bytes = misc::parse_graffiti(DEFAULT_GRAFFITI)?;
        let mut loaded = ValidatorDefinitions::load_or_default(&path)?;

        loaded.push(ValidatorDefinition::new(
            PUBKEY,
            SigningMethod::KeystoreStorage,
        ));

        let validator_definitions = Arc::new(ValidatorDefinitionsWithStorage::new(
            Arc::new(RwLock::new(loaded)),
            DefinitionsStorage::Persistent(path.clone()),
        ));

        let proposer_configs = ProposerConfigs::new(
            DEFAULT_FEE_RECIPIENT,
            Some(DEFAULT_GAS_LIMIT),
            graffiti_bytes,
            validator_definitions,
        );

        proposer_configs.set_gas_limit(PUBKEY, 12345)?;
        proposer_configs.set_fee_recipient(PUBKEY, TEST_FEE_RECIPIENT)?;

        // A freshly loaded instance must observe the previously persisted settings.
        let reloaded_definitions = Arc::new(ValidatorDefinitionsWithStorage::new(
            Arc::new(RwLock::new(ValidatorDefinitions::load(&path)?)),
            DefinitionsStorage::Persistent(path),
        ));

        let reloaded = ProposerConfigs::new(
            DEFAULT_FEE_RECIPIENT,
            Some(DEFAULT_GAS_LIMIT),
            graffiti_bytes,
            reloaded_definitions,
        );

        assert_eq!(reloaded.gas_limit(PUBKEY), Some(12345));
        assert_eq!(reloaded.fee_recipient(PUBKEY), TEST_FEE_RECIPIENT);

        Ok(())
    }

    /// Settings for entryless validators survive in the legacy database until they gain an entry.
    #[test]
    fn test_legacy_database_migration_keeps_homeless_settings() -> Result<()> {
        const OTHER_PUBKEY: PublicKeyBytes = PublicKeyBytes::repeat_byte(2);

        let tempdir = Builder::new()
            .prefix("proposer-configs")
            .rand_bytes(10)
            .tempdir()?;
        let validator_directory = tempdir.path();

        let database = Database::persistent(
            "proposer-configs",
            validator_directory,
            DB_MAX_SIZE,
            DatabaseMode::ReadWrite,
            None,
        )?;

        for pubkey in [PUBKEY, OTHER_PUBKEY] {
            database.put(
                FeeRecipientByPubkey(pubkey).to_string(),
                serde_json::to_string(&TEST_FEE_RECIPIENT)?,
            )?;
        }

        drop(database);

        // Only `PUBKEY` has an entry, so only its row is migrated and pruned.
        let mut validator_definitions = definitions_with_pubkey();

        let migration = migrate_legacy_database(&mut validator_definitions, validator_directory)?
            .expect("the legacy database exists");

        assert_eq!(migration.migrated, vec![PUBKEY]);
        assert_eq!(migration.skipped, vec![OTHER_PUBKEY]);
        assert_eq!(
            validator_definitions
                .get(PUBKEY)
                .and_then(|definition| definition.fee_recipient),
            Some(TEST_FEE_RECIPIENT),
        );

        assert!(!prune_legacy_database(
            validator_directory,
            &migration.migrated
        )?);
        assert!(validator_directory.join("mdbx.dat").exists());

        // Once the validator gains an entry, a later run migrates it and removes the empty database.
        validator_definitions.push(ValidatorDefinition::new(
            OTHER_PUBKEY,
            SigningMethod::KeystoreStorage,
        ));

        let migration = migrate_legacy_database(&mut validator_definitions, validator_directory)?
            .expect("the legacy database still exists");

        assert_eq!(migration.migrated, vec![OTHER_PUBKEY]);
        assert_eq!(migration.skipped, vec![]);
        assert_eq!(
            validator_definitions
                .get(OTHER_PUBKEY)
                .and_then(|definition| definition.fee_recipient),
            Some(TEST_FEE_RECIPIENT),
        );

        assert!(prune_legacy_database(
            validator_directory,
            &migration.migrated
        )?);
        assert!(!validator_directory.join("mdbx.dat").exists());

        Ok(())
    }
}
