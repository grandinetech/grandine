use bls::PublicKeyBytes;
use types::phase0::primitives::{
    CommitteeIndex, Epoch, ExecutionAddress, Gwei, H256, Slot, UnixSeconds, ValidatorIndex,
};

#[derive(Clone, Copy, Debug)]
pub struct GenesisData {
    pub genesis_time: UnixSeconds,
    pub genesis_validators_root: H256,
    pub genesis_fork_version: [u8; 4],
}

#[derive(Clone, Copy, Debug)]
pub struct SyncingStatus {
    pub head_slot: Slot,
    pub sync_distance: Slot,
    pub is_syncing: bool,
    pub is_optimistic: bool,
    pub el_offline: bool,
}

impl SyncingStatus {
    #[must_use]
    pub const fn is_synced(&self) -> bool {
        !self.is_syncing && !self.is_optimistic && !self.el_offline
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BlockHeaderSummary {
    pub slot: Slot,
    pub block_root: H256,
    pub parent_root: H256,
    pub state_root: H256,
    pub proposer_index: ValidatorIndex,
}

#[derive(Clone, Debug)]
pub struct DutiesResponse<T> {
    pub dependent_root: H256,
    pub execution_optimistic: bool,
    pub data: T,
}

#[derive(Clone, Copy, Debug)]
pub struct AttesterDuty {
    pub pubkey: PublicKeyBytes,
    pub validator_index: ValidatorIndex,
    pub committee_index: CommitteeIndex,
    pub committee_length: usize,
    pub committees_at_slot: u64,
    pub validator_committee_index: usize,
    pub slot: Slot,
}

#[derive(Clone, Copy, Debug)]
pub struct ProposerDuty {
    pub pubkey: PublicKeyBytes,
    pub validator_index: ValidatorIndex,
    pub slot: Slot,
}

#[derive(Clone, Debug)]
pub struct SyncCommitteeDuty {
    pub pubkey: PublicKeyBytes,
    pub validator_index: ValidatorIndex,
    pub validator_sync_committee_indices: Vec<usize>,
}

#[derive(Clone, Copy, Debug)]
pub struct ValidatorLiveness {
    pub index: ValidatorIndex,
    pub is_live: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ProposerPreparation {
    pub validator_index: ValidatorIndex,
    pub fee_recipient: ExecutionAddress,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlockEncoding {
    #[default]
    Json,
    Ssz,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BroadcastValidation {
    #[default]
    Gossip,
    Consensus,
    ConsensusAndEquivocation,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockProductionOptions {
    pub graffiti: Option<H256>,
    pub skip_randao_verification: bool,
    pub builder_boost_factor: Option<u64>,
    pub disable_blockprint_graffiti: bool,
}

pub type OwnSyncMessageAggregates = ();

#[derive(Clone, Copy, Debug)]
pub struct ProposerGasLimit {
    pub validator_index: ValidatorIndex,
    pub gas_limit: Gwei,
}

#[derive(Clone, Copy, Debug)]
pub struct CommitteeIndexAndSlot {
    pub committee_index: CommitteeIndex,
    pub slot: Slot,
}

#[derive(Clone, Copy, Debug)]
pub struct ProposerRegistrationStatus {
    pub validator_index: ValidatorIndex,
    pub epoch: Epoch,
}
