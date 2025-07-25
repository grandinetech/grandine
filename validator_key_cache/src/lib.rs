use core::ops::Deref;
use std::{
    collections::{BTreeMap, HashSet},
    io::ErrorKind,
    path::PathBuf,
    sync::Arc,
};

use anyhow::{bail, Result};
use bls::{traits::SecretKey as _, PublicKeyBytes, SecretKey, SecretKeyBytes};
use eip_2335::Crypto;
use log::info;
use sha2::{Digest as _, Sha256};
use ssz::{ContiguousList, Ssz, SszReadDefault as _, SszWrite as _};
use tap::Pipe as _;
use try_from_iterator::TryFromIterator as _;
use typenum::U65536;
use uuid::Uuid;
use zeroize::Zeroizing;

type ValidatorKeyCacheMap = ContiguousList<ValidatorKeyCacheRecord, U65536>;

#[derive(Ssz)]
#[ssz(derive_hash = false, derive_unify = false)]
struct ValidatorKeyCacheRecord {
    uuid: u128,
    public_key: PublicKeyBytes,
    secret_key: SecretKeyBytes,
}

#[derive(Default, Clone)]
pub struct ValidatorKeyCache {
    keys: BTreeMap<Uuid, (PublicKeyBytes, Arc<SecretKey>)>,
    passwords: BTreeMap<Uuid, Zeroizing<String>>,
    validator_directory: PathBuf,
}

impl ValidatorKeyCache {
    #[must_use]
    pub const fn new(validator_directory: PathBuf) -> Self {
        Self {
            keys: BTreeMap::new(),
            passwords: BTreeMap::new(),
            validator_directory,
        }
    }

    pub fn delete_keys(&mut self, public_keys: impl IntoIterator<Item = PublicKeyBytes>) {
        let pubkeys = public_keys.into_iter().collect::<HashSet<_>>();

        self.keys.retain(|_, (pubkey, _)| !pubkeys.contains(pubkey));
    }

    pub fn keypairs(&self) -> impl Iterator<Item = (PublicKeyBytes, Arc<SecretKey>)> + '_ {
        self.keys.values().cloned()
    }

    pub fn load(&mut self, passwords: BTreeMap<Uuid, Zeroizing<String>>) -> Result<()> {
        self.passwords = passwords;

        self.load_from_file(&self.concatenate_passwords(), &self.file_name())?;

        info!("validator key cache loaded");

        Ok(())
    }

    pub fn load_from_file(&mut self, password: &Zeroizing<String>, file_name: &str) -> Result<()> {
        let file_path = self.validator_directory.join(file_name);
        let crypto_bytes = match fs_err::read(file_path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                info!("validator key cache not found");
                return Ok(());
            }
            Err(error) => bail!(error),
        };

        let crypto = serde_json::from_slice::<Crypto<Vec<u8>>>(crypto_bytes.as_slice())?;
        let map_bytes = Zeroizing::new(crypto.decrypt(password.as_str())?);
        let map = ValidatorKeyCacheMap::from_ssz_default(map_bytes.as_slice())?;

        self.keys = map
            .into_iter()
            .map(|record| {
                let ValidatorKeyCacheRecord {
                    uuid,
                    public_key,
                    secret_key,
                } = record;

                let uuid = Uuid::from_u128(uuid);
                let secret_key = Arc::new(secret_key.try_into()?);

                Ok((uuid, (public_key, secret_key)))
            })
            .collect::<Result<_>>()?;

        Ok(())
    }

    pub fn add(&mut self, uuid: Uuid, public_key: PublicKeyBytes, secret_key: Arc<SecretKey>) {
        self.keys.insert(uuid, (public_key, secret_key));
    }

    pub fn add_with_password(
        &mut self,
        password: Zeroizing<String>,
        uuid: Uuid,
        public_key: PublicKeyBytes,
        secret_key: Arc<SecretKey>,
    ) {
        self.add(uuid, public_key, secret_key);
        self.passwords.insert(uuid, password);
    }

    #[must_use]
    pub fn contains(&self, uuid: Uuid) -> bool {
        self.keys.contains_key(&uuid)
    }

    #[must_use]
    pub fn get(&self, uuid: Uuid) -> Option<(PublicKeyBytes, Arc<SecretKey>)> {
        self.keys.get(&uuid).cloned()
    }

    pub fn save(&self) -> Result<()> {
        self.save_to_file(&self.concatenate_passwords(), &self.file_name())?;

        info!("validator key cache saved");

        Ok(())
    }

    pub fn save_to_file(&self, password: &Zeroizing<String>, file_name: &str) -> Result<()> {
        let map = self
            .keys
            .iter()
            .map(|(key, (public_key, secret_key))| ValidatorKeyCacheRecord {
                uuid: key.as_u128(),
                public_key: *public_key,
                secret_key: secret_key.to_bytes(),
            })
            .pipe(ValidatorKeyCacheMap::try_from_iter)?;

        let map_bytes = Zeroizing::new(map.to_ssz()?);
        let crypto = Crypto::encrypt(map_bytes, password.as_str())?;

        fs_err::create_dir_all(self.validator_directory.as_path())?;
        fs_err::write(
            self.validator_directory.join(file_name),
            serde_json::to_string_pretty(&crypto)?,
        )?;

        Ok(())
    }

    fn concatenate_passwords(&self) -> Zeroizing<String> {
        let passwords = self.passwords.values().map(Deref::deref).map(Deref::deref);
        let concatenated_length = passwords.clone().map(str::len).sum();
        let mut concatenated = Zeroizing::new(String::with_capacity(concatenated_length));
        concatenated.extend(passwords);
        assert_eq!(concatenated.len(), concatenated_length);
        concatenated
    }

    fn file_name(&self) -> String {
        let mut hasher = Sha256::new();

        for uuid in self.passwords.keys() {
            hasher.update(uuid.as_bytes());
        }

        let uuid_hash = hasher.finalize();

        format!("validator_key_cache_0x{uuid_hash:x}.json")
    }
}
