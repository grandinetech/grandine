use std::{path::Path, str};

use anyhow::{ensure, Result};
use bls::PublicKeyBytes;
use bytesize::ByteSize;
use database::{Database, DatabaseMode};
use derive_more::Display;
use serde::{de::DeserializeOwned, Serialize};
use types::{
    bellatrix::primitives::Gas,
    phase0::primitives::{ExecutionAddress, H256},
};

use crate::misc::Error;

const DB_MAX_SIZE: ByteSize = ByteSize::gib(1);

pub struct ProposerConfigs {
    database: Database,
    default_fee_recipient: ExecutionAddress,
    default_gas_limit: Gas,
    default_graffiti: H256,
}

impl ProposerConfigs {
    #[must_use]
    pub fn new_in_memory(
        default_fee_recipient: ExecutionAddress,
        default_gas_limit: Gas,
        default_graffiti: H256,
    ) -> Self {
        let database = Database::in_memory();

        Self {
            database,
            default_fee_recipient,
            default_gas_limit,
            default_graffiti,
        }
    }

    pub fn new_persistent(
        validator_directory: &Path,
        default_fee_recipient: ExecutionAddress,
        default_gas_limit: Gas,
        default_graffiti: H256,
    ) -> Result<Self> {
        let database = Database::persistent(
            "proposer-configs",
            validator_directory,
            DB_MAX_SIZE,
            DatabaseMode::ReadWrite,
        )?;

        Ok(Self {
            database,
            default_fee_recipient,
            default_gas_limit,
            default_graffiti,
        })
    }

    pub fn fee_recipient(&self, pubkey: PublicKeyBytes) -> Result<ExecutionAddress> {
        let fee_recipient = self.db_get(FeeRecipientByPubkey(pubkey))?;

        Ok(fee_recipient.unwrap_or(self.default_fee_recipient))
    }

    pub fn set_fee_recipient(
        &self,
        pubkey: PublicKeyBytes,
        fee_recipient: ExecutionAddress,
    ) -> Result<()> {
        self.db_put(FeeRecipientByPubkey(pubkey), &fee_recipient)
    }

    pub fn delete_fee_recipient(&self, pubkey: PublicKeyBytes) -> Result<()> {
        self.db_remove(FeeRecipientByPubkey(pubkey))
    }

    pub fn gas_limit(&self, pubkey: PublicKeyBytes) -> Result<Gas> {
        let gas_limit = self.db_get(GasLimitByPubkey(pubkey))?;

        Ok(gas_limit.unwrap_or(self.default_gas_limit))
    }

    pub fn set_gas_limit(&self, pubkey: PublicKeyBytes, gas_limit: Gas) -> Result<()> {
        self.db_put(GasLimitByPubkey(pubkey), &gas_limit)
    }

    pub fn delete_gas_limit(&self, pubkey: PublicKeyBytes) -> Result<()> {
        self.db_remove(GasLimitByPubkey(pubkey))
    }

    pub fn graffiti_bytes(&self, pubkey: PublicKeyBytes) -> Result<Option<H256>> {
        self.db_get(GraffitiByPubkey(pubkey))
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
        self.db_put(GraffitiByPubkey(pubkey), &parse_graffiti(graffiti)?)
    }

    pub fn delete_graffiti(&self, pubkey: PublicKeyBytes) -> Result<()> {
        self.db_remove(GraffitiByPubkey(pubkey))
    }

    fn db_get<V: DeserializeOwned>(&self, key: impl Display) -> Result<Option<V>> {
        let key_string = key.to_string();

        if let Some(value_bytes) = self.database.get(key_string)? {
            let value = serde_json::from_slice(&value_bytes)?;
            return Ok(Some(value));
        }

        Ok(None)
    }

    fn db_put(&self, key: impl Display, value: &impl Serialize) -> Result<()> {
        self.database
            .put(key.to_string(), serde_json::to_string(value)?)
    }

    fn db_remove(&self, key: impl Display) -> Result<()> {
        self.database.delete(key.to_string())
    }
}

fn parse_graffiti(string: &str) -> Result<H256> {
    ensure!(string.len() <= H256::len_bytes(), Error::GraffitiTooLong);

    let mut graffiti = H256::zero();
    graffiti[..string.len()].copy_from_slice(string.as_bytes());

    Ok(graffiti)
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
pub struct FeeRecipientByPubkey(pub PublicKeyBytes);

impl FeeRecipientByPubkey {
    const PREFIX: &'static str = "f";
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
pub struct GasLimitByPubkey(pub PublicKeyBytes);

impl GasLimitByPubkey {
    const PREFIX: &'static str = "g";
}

#[derive(Display)]
#[display("{}{_0:x}", Self::PREFIX)]
pub struct GraffitiByPubkey(pub PublicKeyBytes);

impl GraffitiByPubkey {
    const PREFIX: &'static str = "r";
}

#[cfg(test)]
mod tests {
    use tempfile::Builder;

    use super::*;

    const DEFAULT_GRAFFITI: &str = "Grandine";
    const DEFAULT_FEE_RECIPIENT: ExecutionAddress = ExecutionAddress::repeat_byte(1);
    const DEFAULT_GAS_LIMIT: Gas = 36_000_000;
    const TEST_FEE_RECIPIENT: ExecutionAddress = ExecutionAddress::repeat_byte(2);
    const PUBKEY: PublicKeyBytes = PublicKeyBytes::repeat_byte(1);

    fn build_proposer_configs(validator_dir: Option<&Path>) -> Result<ProposerConfigs> {
        let graffiti_bytes = parse_graffiti(DEFAULT_GRAFFITI)?;

        match validator_dir {
            Some(dir) => ProposerConfigs::new_persistent(
                dir,
                DEFAULT_FEE_RECIPIENT,
                DEFAULT_GAS_LIMIT,
                graffiti_bytes,
            ),
            None => Ok(ProposerConfigs::new_in_memory(
                DEFAULT_FEE_RECIPIENT,
                DEFAULT_GAS_LIMIT,
                graffiti_bytes,
            )),
        }
    }

    #[test]
    fn test_get_fee_recipient_when_recipient_is_not_set() -> Result<()> {
        let proposer_configs = build_proposer_configs(None)?;

        let fee_recipient = proposer_configs.fee_recipient(PUBKEY)?;

        assert_eq!(fee_recipient, DEFAULT_FEE_RECIPIENT);

        Ok(())
    }

    #[test]
    fn test_set_and_get_fee_recipient() -> Result<()> {
        let proposer_configs = build_proposer_configs(None)?;

        proposer_configs.set_fee_recipient(PUBKEY, TEST_FEE_RECIPIENT)?;

        let fee_recipient = proposer_configs.fee_recipient(PUBKEY)?;

        assert_eq!(fee_recipient, TEST_FEE_RECIPIENT);

        Ok(())
    }

    #[test]
    fn test_delete_fee_recipient() -> Result<()> {
        let proposer_configs = build_proposer_configs(None)?;

        proposer_configs.set_fee_recipient(PUBKEY, TEST_FEE_RECIPIENT)?;
        proposer_configs.delete_fee_recipient(PUBKEY)?;

        let fee_recipient = proposer_configs.fee_recipient(PUBKEY)?;

        assert_eq!(fee_recipient, DEFAULT_FEE_RECIPIENT);

        Ok(())
    }

    #[test]
    fn test_get_gas_limit_when_gas_limit_is_not_set() -> Result<()> {
        let proposer_configs = build_proposer_configs(None)?;

        let gas_limit = proposer_configs.gas_limit(PUBKEY)?;

        assert_eq!(gas_limit, DEFAULT_GAS_LIMIT);

        Ok(())
    }

    #[test]
    fn test_set_and_get_gas_limit() -> Result<()> {
        let proposer_configs = build_proposer_configs(None)?;

        proposer_configs.set_gas_limit(PUBKEY, 12345)?;

        let gas_limit = proposer_configs.gas_limit(PUBKEY)?;

        assert_eq!(gas_limit, 12345);

        Ok(())
    }

    #[test]
    fn test_delete_gas_limit() -> Result<()> {
        let proposer_configs = build_proposer_configs(None)?;

        proposer_configs.set_gas_limit(PUBKEY, 12345)?;
        proposer_configs.delete_gas_limit(PUBKEY)?;

        let gas_limit = proposer_configs.gas_limit(PUBKEY)?;

        assert_eq!(gas_limit, DEFAULT_GAS_LIMIT);

        Ok(())
    }

    #[test]
    fn test_get_graffiti_when_graffiti_is_not_set() -> Result<()> {
        let proposer_configs = build_proposer_configs(None)?;

        let graffiti = proposer_configs.graffiti(PUBKEY)?;

        assert_eq!(graffiti, DEFAULT_GRAFFITI);

        Ok(())
    }

    #[test]
    fn test_set_and_get_graffiti() -> Result<()> {
        let proposer_configs = build_proposer_configs(None)?;

        proposer_configs.set_graffiti(PUBKEY, "Hello, world!")?;

        let graffiti = proposer_configs.graffiti(PUBKEY)?;

        assert_eq!(graffiti, "Hello, world!");

        Ok(())
    }

    #[test]
    fn test_delete_graffiti() -> Result<()> {
        let proposer_configs = build_proposer_configs(None)?;

        proposer_configs.set_graffiti(PUBKEY, "Hello, world!")?;
        proposer_configs.delete_graffiti(PUBKEY)?;

        let graffiti = proposer_configs.graffiti(PUBKEY)?;

        assert_eq!(graffiti, DEFAULT_GRAFFITI);

        Ok(())
    }

    #[test]
    fn test_proposer_configs_with_persistent_db() -> Result<()> {
        let tempdir = Builder::new()
            .prefix("proposer-configs")
            .rand_bytes(10)
            .tempdir()?;

        let proposer_configs = build_proposer_configs(Some(&tempdir.into_path()))?;

        proposer_configs.set_gas_limit(PUBKEY, 12345)?;

        let gas_limit = proposer_configs.gas_limit(PUBKEY)?;

        assert_eq!(gas_limit, 12345);

        Ok(())
    }
}
