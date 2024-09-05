use core::marker::PhantomData;

use anyhow::Result;
use database::Database;
use types::{
    phase0::{
        containers::{AttestationData, IndexedAttestation},
        primitives::{Epoch, ValidatorIndex},
    },
    preset::Preset,
};

const VALIDATOR_INDEX_SIZE: usize = size_of::<ValidatorIndex>();
const TARGET_KEY_LENGTH: usize = VALIDATOR_INDEX_SIZE;
// Weaks Subjectivity period from https://hackmd.io/@sproul/min-max-slasher
pub const TARGETS_LENGTH: u64 = 54000;

type TargetKey = [u8; TARGET_KEY_LENGTH];

pub struct Targets<P: Preset> {
    min_targets_db: Database,
    max_targets_db: Database,
    phantom: PhantomData<P>,
}

impl<P: Preset> Targets<P> {
    pub const fn new(min_targets_db: Database, max_targets_db: Database) -> Self {
        Self {
            min_targets_db,
            max_targets_db,
            phantom: PhantomData,
        }
    }

    const fn key(validator_index: ValidatorIndex) -> TargetKey {
        validator_index.to_le_bytes()
    }

    pub fn check_for_surrounding_entry(
        &self,
        validator_index: ValidatorIndex,
        attestation: &IndexedAttestation<P>,
    ) -> Result<Option<Epoch>> {
        let source_epoch = attestation.data.source.epoch;
        let target_epoch = attestation.data.target.epoch;
        let index = usize::try_from(source_epoch % TARGETS_LENGTH)?;
        let min_targets = self.find_min_targets(validator_index)?;
        let min_target = min_targets[index].into();

        if target_epoch.saturating_sub(source_epoch) % TARGETS_LENGTH > min_target {
            return Ok(Some(min_target + source_epoch));
        }

        Ok(None)
    }

    pub fn check_for_surrounded_entry(
        &self,
        validator_index: ValidatorIndex,
        attestation: &IndexedAttestation<P>,
    ) -> Result<Option<Epoch>> {
        let source_epoch = attestation.data.source.epoch;
        let target_epoch = attestation.data.target.epoch;
        let index = usize::try_from(source_epoch % TARGETS_LENGTH)?;
        let max_targets = self.find_max_targets(validator_index)?;
        let max_target = max_targets[index].into();

        if target_epoch.saturating_sub(source_epoch) % TARGETS_LENGTH < max_target {
            return Ok(Some(max_target + source_epoch));
        }

        Ok(None)
    }

    pub fn update(
        &self,
        validator_index: ValidatorIndex,
        attestation: &IndexedAttestation<P>,
        current_epoch: Epoch,
    ) -> Result<()> {
        // maintain min/max targets
        self.update_min_targets(validator_index, &attestation.data, current_epoch)?;
        self.update_max_targets(validator_index, &attestation.data, current_epoch)?;

        Ok(())
    }

    fn find_min_targets(&self, validator_index: ValidatorIndex) -> Result<Vec<u16>> {
        let key = Self::key(validator_index);

        Ok(match self.min_targets_db.get(key)? {
            Some(bytes) => bincode::deserialize(&bytes)?,
            None => vec![u16::MAX; usize::try_from(TARGETS_LENGTH)?],
        })
    }

    fn find_max_targets(&self, validator_index: ValidatorIndex) -> Result<Vec<u16>> {
        let key = Self::key(validator_index);

        Ok(match self.max_targets_db.get(key)? {
            Some(bytes) => bincode::deserialize(&bytes)?,
            None => vec![0; usize::try_from(TARGETS_LENGTH)?],
        })
    }

    fn update_min_targets(
        &self,
        validator_index: ValidatorIndex,
        attestation: &AttestationData,
        current_epoch: Epoch,
    ) -> Result<()> {
        let key = Self::key(validator_index);
        let mut min_targets = self.find_min_targets(validator_index)?;
        let mut epoch = attestation.source.epoch;
        let target_epoch = attestation.target.epoch;
        let min_epoch = current_epoch.saturating_sub(TARGETS_LENGTH);

        while epoch > min_epoch {
            epoch -= 1;
            let index = usize::try_from(epoch % TARGETS_LENGTH)?;

            if target_epoch < min_targets[index].into() {
                min_targets[index] = u16::try_from(target_epoch.saturating_sub(epoch))?;
            } else {
                break;
            }
        }

        self.min_targets_db
            .put(key, bincode::serialize(&min_targets)?)?;

        Ok(())
    }

    fn update_max_targets(
        &self,
        validator_index: ValidatorIndex,
        attestation: &AttestationData,
        current_epoch: Epoch,
    ) -> Result<()> {
        let key = Self::key(validator_index);
        let mut max_targets = self.find_max_targets(validator_index)?;
        let mut epoch = attestation.source.epoch + 1;
        let target_epoch = attestation.target.epoch;

        while epoch <= current_epoch {
            let index = usize::try_from(epoch % TARGETS_LENGTH)?;
            if target_epoch > max_targets[index].into() {
                max_targets[index] = u16::try_from(target_epoch.saturating_sub(epoch))?;
                epoch += 1;
            } else {
                break;
            }
        }

        self.max_targets_db
            .put(key, bincode::serialize(&max_targets)?)?;

        Ok(())
    }
}
