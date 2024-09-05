use core::marker::PhantomData;

use anyhow::Result;
use database::Database;
use ssz::SszHash as _;
use types::{
    phase0::{
        containers::IndexedAttestation,
        primitives::{Epoch, H256},
    },
    preset::Preset,
};

const EPOCH_SIZE: usize = size_of::<Epoch>();
const H256_SIZE: usize = size_of::<H256>();
const INDEXED_ATTESTATION_KEY_LENGTH: usize = EPOCH_SIZE + H256_SIZE;

type IndexedAttestationKey = [u8; INDEXED_ATTESTATION_KEY_LENGTH];

// TargetEpoch,AttestationDataHash -> IndexedAttestation (TODO: store without attestation data as its duplicate data)
pub struct IndexedAttestations<P: Preset> {
    db: Database,
    phantom: PhantomData<P>,
}

impl<P: Preset> IndexedAttestations<P> {
    pub const fn new(db: Database) -> Self {
        Self {
            db,
            phantom: PhantomData,
        }
    }

    fn key(target_epoch: Epoch, attestation_data_hash: H256) -> IndexedAttestationKey {
        let mut key = [0; INDEXED_ATTESTATION_KEY_LENGTH];
        key[..EPOCH_SIZE].copy_from_slice(&target_epoch.to_le_bytes());
        key[EPOCH_SIZE..].copy_from_slice(attestation_data_hash.as_bytes());
        key
    }

    pub fn find(
        &self,
        attestation_data_root: H256,
        target_epoch: Epoch,
    ) -> Result<Option<IndexedAttestation<P>>> {
        let key = Self::key(target_epoch, attestation_data_root);
        let bytes = self.db.get(key)?;

        if let Some(bytes) = bytes {
            return Ok(Some(bincode::deserialize(&bytes)?));
        }

        Ok(None)
    }

    pub fn insert(
        &self,
        target_epoch: Epoch,
        indexed_attestation: &IndexedAttestation<P>,
    ) -> Result<()> {
        let attestation_data_root = indexed_attestation.data.hash_tree_root();
        let key = Self::key(target_epoch, attestation_data_root);

        self.db
            .put(key, bincode::serialize(&indexed_attestation)?)?;
        Ok(())
    }

    pub fn cleanup(&self, current_epoch: Epoch, epochs_to_keep: u64) -> Result<()> {
        let to_epoch = current_epoch.saturating_sub(epochs_to_keep + 1);
        let from_epoch = to_epoch.saturating_sub(epochs_to_keep);

        let first_key = Self::key(from_epoch, H256::zero());
        let last_key = Self::key(to_epoch, H256::repeat_byte(255_u8));

        self.db.delete_range(&first_key..&last_key)?;

        Ok(())
    }
}
