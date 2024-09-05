use anyhow::Result;
use database::Database;
use derive_more::Constructor;
use ssz::SszHash as _;
use types::phase0::{
    containers::AttestationData,
    primitives::{Epoch, ValidatorIndex, H256},
};

const EPOCH_SIZE: usize = size_of::<Epoch>();
const VALIDATOR_INDEX_SIZE: usize = size_of::<ValidatorIndex>();
const ATTESTATION_VOTE_KEY_LENGTH: usize = EPOCH_SIZE + VALIDATOR_INDEX_SIZE;

// TargetEpoch,ValidatorIndex -> AttestationDataRoot
type AttestationVoteKey = [u8; ATTESTATION_VOTE_KEY_LENGTH];

#[derive(Constructor)]
pub struct AttestationVotes {
    db: Database,
}

impl AttestationVotes {
    fn key(target_epoch: Epoch, validator_index: ValidatorIndex) -> AttestationVoteKey {
        let mut key = [0; ATTESTATION_VOTE_KEY_LENGTH];
        key[..EPOCH_SIZE].copy_from_slice(&target_epoch.to_le_bytes());
        key[EPOCH_SIZE..].copy_from_slice(&validator_index.to_le_bytes());
        key
    }

    pub fn find(
        &self,
        validator_index: ValidatorIndex,
        target_epoch: Epoch,
    ) -> Result<Option<H256>> {
        let key = Self::key(target_epoch, validator_index);
        let bytes = self.db.get(key)?;

        if let Some(bytes) = bytes {
            return Ok(Some(H256::from_slice(&bytes)));
        }

        Ok(None)
    }

    pub fn insert(
        &self,
        validator_index: ValidatorIndex,
        target_epoch: Epoch,
        attestation_data: AttestationData,
    ) -> Result<()> {
        let key = Self::key(target_epoch, validator_index);
        self.db.put(key, attestation_data.hash_tree_root())?;
        Ok(())
    }

    pub fn cleanup(&self, current_epoch: Epoch, epochs_to_keep: u64) -> Result<()> {
        let to_epoch = current_epoch.saturating_sub(epochs_to_keep + 1);
        let from_epoch = to_epoch.saturating_sub(epochs_to_keep);

        let first_key = Self::key(from_epoch, 1);
        let last_key = Self::key(to_epoch, ValidatorIndex::MAX);

        self.db.delete_range(&first_key..&last_key)?;

        Ok(())
    }
}
