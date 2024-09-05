use anyhow::Result;
use bls::SignatureBytes;
use database::Database;
use derive_more::Constructor;
use helper_functions::misc;
use serde::{Deserialize, Serialize};
use types::{
    combined::SignedBeaconBlock,
    phase0::{
        containers::{BeaconBlockHeader, ProposerSlashing},
        primitives::{Epoch, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::{
    slasher_config::SlasherConfig,
    status::{ExplainedProposerSlashing, ProposerSlashingReason},
};

const VALIDATOR_INDEX_SIZE: usize = size_of::<ValidatorIndex>();
const SLOT_SIZE: usize = size_of::<Slot>();
const BLOCK_RECORD_KEY_LENGTH: usize = SLOT_SIZE + VALIDATOR_INDEX_SIZE;

type BlockRecordKey = [u8; BLOCK_RECORD_KEY_LENGTH];

// Slot,ValidatorIndex-> BlockRecord
fn build_block_record_key(proposer_index: ValidatorIndex, slot: Slot) -> BlockRecordKey {
    let mut key = [0; BLOCK_RECORD_KEY_LENGTH];
    key[..SLOT_SIZE].copy_from_slice(&slot.to_le_bytes());
    key[SLOT_SIZE..].copy_from_slice(&proposer_index.to_le_bytes());
    key
}

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug))]
struct BlockRecord {
    signature: SignatureBytes,
    parent_root: H256,
    state_root: H256,
    body_root: H256,
}

#[derive(Constructor)]
pub struct Blocks {
    config: SlasherConfig,
    blocks_db: Database,
}

impl Blocks {
    pub fn find_slashing<P: Preset>(
        &self,
        block: &SignedBeaconBlock<P>,
    ) -> Result<Option<ExplainedProposerSlashing>> {
        let proposer_index = block.message().proposer_index();
        let slot = block.message().slot();

        if let Some(existing_block_record) = self.find_block_record(proposer_index, slot)? {
            let block_record = BlockRecord {
                signature: block.signature(),
                parent_root: block.message().parent_root(),
                state_root: block.message().state_root(),
                body_root: block.message().body().hash_tree_root(),
            };

            if existing_block_record != block_record {
                let BlockRecord {
                    signature,
                    parent_root,
                    state_root,
                    body_root,
                } = existing_block_record;

                let existing_header = BeaconBlockHeader {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body_root,
                }
                .with_signature(signature);

                let slashing = ProposerSlashing {
                    signed_header_1: existing_header,
                    signed_header_2: block.to_header(),
                };

                return Ok(Some(ExplainedProposerSlashing {
                    slashing,
                    reason: ProposerSlashingReason::DoubleVote,
                }));
            }
        }

        Ok(None)
    }

    pub fn update<P: Preset>(&self, block: &SignedBeaconBlock<P>) -> Result<()> {
        let key = build_block_record_key(block.message().proposer_index(), block.message().slot());
        let block_record = BlockRecord {
            signature: block.signature(),
            parent_root: block.message().parent_root(),
            state_root: block.message().state_root(),
            body_root: block.message().body().hash_tree_root(),
        };

        self.blocks_db
            .put(key, bincode::serialize(&block_record)?)?;

        Ok(())
    }

    pub fn cleanup<P: Preset>(&self, current_epoch: Epoch) -> Result<()> {
        let epochs_to_keep = self.config.slashing_history_limit;

        if epochs_to_keep >= current_epoch {
            return Ok(());
        }

        let to_epoch = current_epoch.saturating_sub(epochs_to_keep);
        let from_epoch = to_epoch.saturating_sub(epochs_to_keep);

        let from_slot = misc::compute_start_slot_at_epoch::<P>(from_epoch);
        let to_slot = misc::compute_start_slot_at_epoch::<P>(to_epoch).saturating_sub(1);

        let first_key = build_block_record_key(1, from_slot);
        let last_key = build_block_record_key(ValidatorIndex::MAX, to_slot);

        self.blocks_db.delete_range(&first_key..&last_key)?;

        Ok(())
    }

    fn find_block_record(
        &self,
        proposer_index: ValidatorIndex,
        slot: Slot,
    ) -> Result<Option<BlockRecord>> {
        let key = build_block_record_key(proposer_index, slot);
        let bytes = self.blocks_db.get(key)?;

        if let Some(bytes) = bytes {
            return Ok(Some(bincode::deserialize(&bytes)?));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use types::{
        combined::BeaconBlock, phase0::containers::BeaconBlock as Phase0BeaconBlock,
        preset::Mainnet,
    };
    use unwrap_none::UnwrapNone as _;

    use super::*;

    fn build_block<P: Preset>(
        proposer_index: ValidatorIndex,
        slot: Slot,
        parent_root: H256,
    ) -> SignedBeaconBlock<P> {
        BeaconBlock::from(Phase0BeaconBlock {
            slot,
            proposer_index,
            parent_root,
            ..Phase0BeaconBlock::default()
        })
        .with_zero_signature()
    }

    fn build_blocks() -> Blocks {
        let config = SlasherConfig {
            slashing_history_limit: 1,
        };

        Blocks::new(config, Database::in_memory())
    }

    #[test]
    fn slasher_blocks_test() -> Result<()> {
        let blocks = build_blocks();

        let block_1 = build_block::<Mainnet>(2, 1, H256::zero());
        let block_2 = build_block::<Mainnet>(2, 1, H256::repeat_byte(1));

        blocks.find_slashing(&block_1)?.unwrap_none();
        blocks.find_slashing(&block_2)?.unwrap_none();

        blocks.update::<Mainnet>(&block_1)?;

        blocks.find_slashing(&block_1)?.unwrap_none();

        let explained_slashing = blocks
            .find_slashing(&block_2)?
            .expect("Double vote slashing must be found");

        assert_eq!(
            explained_slashing.reason,
            ProposerSlashingReason::DoubleVote,
        );

        let signed_header_1 = block_1.to_header();
        let signed_header_2 = block_2.to_header();

        assert_eq!(explained_slashing.slashing.signed_header_1, signed_header_1);
        assert_eq!(explained_slashing.slashing.signed_header_2, signed_header_2);

        Ok(())
    }

    #[test]
    fn slasher_blocks_db_cleanup_test() -> Result<()> {
        let blocks = build_blocks();

        let data = [(1, 1), (1, 3), (1, 31), (4, 32), (1, 70), (3, 70)];

        for (proposer_index, slot) in data {
            blocks.update::<Mainnet>(&build_block::<Mainnet>(
                proposer_index,
                slot,
                H256::zero(),
            ))?;
            assert!(blocks.find_block_record(proposer_index, slot)?.is_some());
        }

        blocks.cleanup::<Mainnet>(2)?;

        // we keep data of current_epoch and slashing_history_limit epochs in the past
        // Epoch 0
        blocks.find_block_record(1, 1)?.unwrap_none();
        blocks.find_block_record(3, 1)?.unwrap_none();
        blocks.find_block_record(1, 31)?.unwrap_none();

        // Epoch 1
        assert!(blocks.find_block_record(4, 32)?.is_some());

        // Epoch 2
        assert!(blocks.find_block_record(1, 70)?.is_some());
        assert!(blocks.find_block_record(3, 70)?.is_some());

        Ok(())
    }
}
