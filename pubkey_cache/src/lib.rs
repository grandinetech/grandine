use std::sync::Arc;

use anyhow::Result;
use bls::{traits::PublicKey as _, PublicKey, PublicKeyBytes, COMPRESSED_SIZE, DECOMPRESSED_SIZE};
use core::ops::RangeFrom;
use dashmap::{DashMap, DashSet};
use database::{Database, InMemoryMap, PrefixableKey};
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
#[cfg(not(target_os = "zkvm"))]
use prometheus_metrics::Metrics;
use ssz::{ContiguousList, Size, Ssz, SszRead, SszSize, SszWrite};
use std_ext::ArcExt;
use typenum::U65536;
use types::{combined::BeaconState, preset::Preset, traits::BeaconState as _};

type CachedKeys = DashMap<PublicKeyBytes, Arc<PublicKey>>;

#[derive(Default)]
pub struct PubkeyCache {
    database: Option<Database>,
    keys: CachedKeys,
    unpersisted: DashSet<PublicKeyBytes>,
}

impl SszSize for PubkeyCache {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

#[derive(Ssz)]
struct CacheKeyPair {
    key: ContiguousList<u8, U65536>,
    value: ContiguousList<u8, U65536>,
}

impl<C> SszRead<C> for PubkeyCache {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> core::result::Result<Self, ssz::ReadError> {
        let vals: ContiguousList<CacheKeyPair, U65536> = ContiguousList::from_ssz(context, bytes)?;

        let map: InMemoryMap = vals
            .as_ref()
            .iter()
            .map(|v| {
                let key: Arc<[u8]> = v.key.as_ref().into();
                let value: Arc<[u8]> = v.value.as_ref().into();
                (key, value)
            })
            .collect();

        Ok(Self::load(Database::from(map)))
    }
}

impl SszWrite for PubkeyCache {
    fn to_ssz(&self) -> core::result::Result<Vec<u8>, ssz::WriteError> {
        let Some(ref database) = self.database else {
            return Ok(Vec::new());
        };

        let vals: ContiguousList<CacheKeyPair, U65536> = database
            .iterator_ascending(RangeFrom { start: [] })
            .map_err(|_| ssz::WriteError::Custom {
                message: "failed to read database entries",
            })?
            .map(|v| {
                v.and_then(|(key, value)| {
                    Ok(CacheKeyPair {
                        key: key.to_vec().try_into()?,
                        value: value.try_into()?,
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ssz::WriteError::Custom {
                message: "failed to serialize cache key pairs",
            })?
            .try_into()
            .map_err(|_| ssz::WriteError::Custom {
                message: "failed to convert vector",
            })?;

        vals.to_ssz()
    }
}

impl PubkeyCache {
    pub fn load(database: Database) -> Self {
        let keys = Self::load_all_keys_from_db(&database)
            .inspect_err(|error| {
                warn_with_peers!("failed to load cached public keys from database: {error}")
            })
            .unwrap_or_default();

        Self {
            database: Some(database),
            keys,
            unpersisted: DashSet::default(),
        }
    }

    // Intended for use with anchor state during startup:
    // - Inserts any missing pubkeys from anchor state into the cache
    // - Persists unpersisted pubkeys to disk, making persist task on finalization faster
    pub fn load_and_persist_state_keys<P: Preset>(&self, state: &BeaconState<P>) -> Result<()> {
        info_with_peers!(
            "decompressing new validator keys for state at slot: {}",
            state.slot()
        );

        let mut batch = vec![];

        for validator in state.validators() {
            let decompressed = self.get_or_insert(validator.pubkey)?;

            if let Some(pubkey) = self.unpersisted.remove(&validator.pubkey) {
                batch.push(serialize(&PublicKeyDbKey(pubkey), &decompressed));
            }
        }

        if let Some(database) = self.database.as_ref() {
            let entries = batch.len();
            database.put_batch(batch)?;
            debug_with_peers!("persisted {entries} validator pubkeys to pubkey cache db");
        }

        info_with_peers!(
            "finished decompressing new validator keys for state at slot: {}",
            state.slot()
        );

        Ok(())
    }

    pub fn persist<P: Preset>(&self, state: &BeaconState<P>) -> Result<()> {
        let Some(database) = self.database.as_ref() else {
            return Ok(());
        };

        let mut batch = vec![];

        // persist decompressed bytes to disk only for finalized validators,
        // avoiding storage of validator pubkeys from invalid deposits.
        for validator in state.validators() {
            if let Some(pubkey) = self.unpersisted.remove(&validator.pubkey) {
                if let Some(decompressed) = self.keys.get(&pubkey) {
                    batch.push(serialize(&PublicKeyDbKey(pubkey), &decompressed));
                }
            }
        }

        let entries = batch.len();
        database.put_batch(batch)?;

        for pubkey in self.unpersisted.iter() {
            debug_with_peers!("pubkey {:?} unpersisted: removing from cache", *pubkey);
            self.keys.remove(&*pubkey);
        }

        self.unpersisted.clear();

        debug_with_peers!("persisted {entries} validator pubkeys to pubkey cache db");

        Ok(())
    }

    pub fn get_or_insert(&self, public_key_bytes: PublicKeyBytes) -> Result<Arc<PublicKey>> {
        if let Some(pubkey) = self.keys.get(&public_key_bytes) {
            return Ok(pubkey.clone_arc());
        }

        let pubkey: Arc<PublicKey> = Arc::new(public_key_bytes.try_into()?);

        self.keys.insert(public_key_bytes, pubkey.clone_arc());
        self.unpersisted.insert(public_key_bytes);

        Ok(pubkey)
    }

    #[cfg(not(target_os = "zkvm"))]
    pub fn track_collection_metrics(&self, metrics: &Arc<Metrics>) {
        let type_name = tynm::type_name::<Self>();

        metrics.set_collection_length(module_path!(), &type_name, "keys", self.keys.len());

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "unpersisted",
            self.unpersisted.len(),
        );
    }

    fn load_all_keys_from_db(database: &Database) -> Result<CachedKeys> {
        let map = DashMap::new();
        let results = database
            .iterator_ascending(serialize_key(&PublicKeyDbKey(PublicKeyBytes::zero()))..)?;

        for result in results {
            let (key_bytes, value_bytes) = result?;

            if !PublicKeyDbKey::has_prefix(&key_bytes) {
                break;
            }

            let pubkey_bytes = PublicKeyBytes::from_slice(&key_bytes[PREFIX_LEN..]);
            let pubkey = Arc::new(PublicKey::deserialize_from_decompressed_bytes(
                &value_bytes,
            )?);

            map.insert(pubkey_bytes, pubkey);
        }

        debug_with_peers!("loaded {} cached public keys from the database", map.len());

        Ok(map)
    }
}

pub struct PublicKeyDbKey(PublicKeyBytes);

impl PrefixableKey for PublicKeyDbKey {
    const PREFIX: &'static str = "p";
}

const PREFIX_LEN: usize = PublicKeyDbKey::PREFIX.len();
const KEY_LEN: usize = PREFIX_LEN + COMPRESSED_SIZE;

fn serialize_key(key: &PublicKeyDbKey) -> [u8; KEY_LEN] {
    let mut result = [0u8; KEY_LEN];
    result[..PREFIX_LEN].copy_from_slice(PublicKeyDbKey::PREFIX.as_bytes());
    result[PREFIX_LEN..].copy_from_slice(key.0.as_fixed_bytes());
    result
}

fn serialize_value(value: &PublicKey) -> [u8; DECOMPRESSED_SIZE] {
    value.serialize_to_decompressed_bytes()
}

#[must_use]
pub fn serialize(
    key: &PublicKeyDbKey,
    value: &PublicKey,
) -> ([u8; KEY_LEN], [u8; DECOMPRESSED_SIZE]) {
    (serialize_key(key), serialize_value(value))
}

#[cfg(test)]
#[cfg(feature = "eth2-cache")]
mod tests {
    use super::*;

    use bytesize::ByteSize;
    use database::DatabaseMode;
    use hex_literal::hex;
    use tempfile::TempDir;

    #[test]
    fn test_validator_pubkey_cache() -> Result<()> {
        let database = build_persistent_database()?;
        let pubkey_cache = PubkeyCache::load(database);

        assert_eq!(pubkey_cache.keys.len(), 0);

        let pubkey_bytes = PublicKeyBytes::from(hex!(
            "b6f4de08c2c1401c9f0fd4f1f366e1ec8704f58ebb69d4b218cc290d7ecd63103718ff69d9f725da1f4427a8328b86be"
        ));

        let pubkey: PublicKey = pubkey_bytes
            .try_into()
            .expect("mainnet validator 0 has a valid pubkey");

        let pubkey = Arc::new(pubkey);

        assert_eq!(pubkey_cache.get_or_insert(pubkey_bytes)?, pubkey);
        assert_eq!(pubkey_cache.keys.len(), 1);
        assert_eq!(pubkey_cache.unpersisted.len(), 1);

        let genesis_state = eth2_cache_utils::mainnet::GENESIS_BEACON_STATE
            .force()
            .clone_arc();

        pubkey_cache.load_and_persist_state_keys(&genesis_state)?;

        assert_eq!(pubkey_cache.keys.len(), 21_063);
        assert_eq!(pubkey_cache.unpersisted.len(), 0);

        assert_eq!(pubkey_cache.get_or_insert(pubkey_bytes)?, pubkey);
        assert_eq!(pubkey_cache.unpersisted.len(), 0);

        let map = PubkeyCache::load_all_keys_from_db(
            pubkey_cache.database.as_ref().expect("database is present"),
        )?;

        assert_eq!(map.len(), 21_063);
        assert_eq!(map.get(&pubkey_bytes).map(|value| **value), Some(*pubkey));

        Ok(())
    }

    #[test]
    fn test_validator_pubkey_cache_persist() -> Result<()> {
        let database = build_persistent_database()?;
        let pubkey_cache = PubkeyCache::load(database);

        assert_eq!(pubkey_cache.keys.len(), 0);

        let genesis_state = eth2_cache_utils::mainnet::GENESIS_BEACON_STATE
            .force()
            .clone_arc();

        for validator in genesis_state.validators() {
            pubkey_cache.get_or_insert(validator.pubkey)?;
        }

        assert_eq!(pubkey_cache.keys.len(), 21_063);
        assert_eq!(pubkey_cache.unpersisted.len(), 21_063);

        pubkey_cache.persist(&genesis_state)?;

        assert_eq!(pubkey_cache.keys.len(), 21_063);
        assert_eq!(pubkey_cache.unpersisted.len(), 0);

        let map = PubkeyCache::load_all_keys_from_db(
            pubkey_cache.database.as_ref().expect("database is present"),
        )?;

        assert_eq!(map.len(), 21_063);

        Ok(())
    }

    fn build_persistent_database() -> Result<Database> {
        Database::persistent(
            "test_db",
            TempDir::new()?,
            ByteSize::mib(5),
            DatabaseMode::ReadWrite,
            None,
        )
    }
}
