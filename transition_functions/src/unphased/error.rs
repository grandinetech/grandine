use thiserror::Error;
use types::{
    capella::containers::Withdrawal,
    combined::Attestation,
    phase0::{
        containers::{AttestationData, BeaconBlockHeader, Checkpoint, Deposit, Validator},
        primitives::{Epoch, Slot, UnixSeconds, ValidatorIndex, H256},
    },
    preset::Preset,
};

#[derive(Debug, Error)]
pub enum Error<P: Preset> {
    #[error("attestation data is not slashable (data_1: {data_1:?}, data_2: {data_2:?})")]
    AttestationDataNotSlashable {
        data_1: AttestationData,
        data_2: AttestationData,
    },
    #[error(
        "attestation in slot {attestation_slot} is outside \
         inclusion range for state at slot {state_slot}"
    )]
    AttestationOutsideInclusionRange {
        state_slot: Slot,
        attestation_slot: Slot,
    },
    #[error(
        "attestation source does not match justified checkpoint \
         (in_state: {in_state:?}, in_block: {in_block:?})"
    )]
    AttestationSourceMismatch {
        in_state: Checkpoint,
        in_block: Checkpoint,
    },
    #[error("attestation votes for a checkpoint in the wrong epoch: {attestation:?}")]
    AttestationTargetsWrongEpoch { attestation: Attestation<P> },
    #[error("post-Electra attestation with invalid (non-zero) committee index: {attestation:?}")]
    AttestationWithNonZeroCommitteeIndex { attestation: Attestation<P> },
    #[error("block is not newer than latest block header ({block_slot} <= {block_header_slot})")]
    BlockNotNewerThanLatestBlockHeader {
        block_slot: Slot,
        block_header_slot: Slot,
    },
    #[error("deposit count is incorrect (computed: {computed}, in_block: {in_block})")]
    DepositCountMismatch { computed: u64, in_block: u64 },
    #[error("deposit proof is invalid: {deposit:?}")]
    DepositProofInvalid {
        // Boxed to pass `clippy::large_enum_variant`.
        deposit: Box<Deposit>,
    },
    #[error(
        "parent hash in execution payload ({in_block:?}) \
         does not match latest execution payload header ({in_state:?})"
    )]
    ExecutionPayloadParentHashMismatch { in_state: H256, in_block: H256 },
    #[error(
        "previous RANDAO mix in execution payload is incorrect \
         (in_state: {in_state:?}, in_block: {in_block:?})"
    )]
    ExecutionPayloadPrevRandaoMismatch { in_state: H256, in_block: H256 },
    #[error(
        "timestamp in execution payload is incorrect \
         (computed: {computed}, in_block: {in_block})"
    )]
    ExecutionPayloadTimestampMismatch {
        computed: UnixSeconds,
        in_block: UnixSeconds,
    },
    #[error("no attesters slashed")]
    NoAttestersSlashed,
    #[error("block parent root ({in_block:?}) does not match latest block header ({computed:?})")]
    ParentRootMismatch { computed: H256, in_block: H256 },
    #[error("proposer (validator {index}) is slashed")]
    ProposerSlashed { index: ValidatorIndex },
    #[error("proposer index is incorrect (in_block: {in_block}, computed: {computed})")]
    ProposerIndexMismatch {
        computed: ValidatorIndex,
        in_block: ValidatorIndex,
    },
    #[error("proposer (validator {index}) is not slashable: {proposer:?}")]
    ProposerNotSlashable {
        index: ValidatorIndex,
        proposer: Validator,
    },
    #[error("block headers in proposer slashing are identical: {header:?}")]
    ProposerSlashingHeadersIdentical { header: BeaconBlockHeader },
    #[error(
        "proposer indices in proposer slashing do not match \
         ({proposer_index_1} != {proposer_index_2})"
    )]
    ProposerSlashingProposerMismatch {
        proposer_index_1: ValidatorIndex,
        proposer_index_2: ValidatorIndex,
    },
    #[error("slots in proposer slashing do not match ({slot_1} != {slot_2})")]
    ProposerSlashingSlotMismatch { slot_1: Slot, slot_2: Slot },
    #[error("block slot ({block_slot}) does not match state slot ({state_slot})")]
    SlotMismatch { state_slot: Slot, block_slot: Slot },
    #[error("target slot ({target}) is not later than current slot ({current})")]
    SlotNotLater { current: Slot, target: Slot },
    #[error("state root in block ({in_block:?}) does not match state ({computed:?})")]
    StateRootMismatch { computed: H256, in_block: H256 },
    #[error("too many blob KZG commitments (maximum: {maximum}, in_block: {in_block})")]
    TooManyBlockKzgCommitments { maximum: usize, in_block: usize },
    #[error("validator {index} exited in epoch {exit_epoch}")]
    ValidatorAlreadyExited {
        index: ValidatorIndex,
        exit_epoch: Epoch,
    },
    #[error(
        "validator {index} has not been active long enough \
         (activation_epoch: {activation_epoch}, current_epoch: {current_epoch})"
    )]
    ValidatorHasNotBeenActiveLongEnough {
        index: ValidatorIndex,
        activation_epoch: Epoch,
        current_epoch: Epoch,
    },
    #[error("validator index overflowed")]
    ValidatorIndexOverflow,
    #[error("validator {index} is not active in epoch {current_epoch}: {validator:?}")]
    ValidatorNotActive {
        index: ValidatorIndex,
        validator: Validator,
        current_epoch: Epoch,
    },
    #[error("voluntary exit is expired (epoch: {epoch}, current_epoch: {current_epoch})")]
    VoluntaryExitIsExpired { epoch: Epoch, current_epoch: Epoch },
    #[error("cannot exit validator because it has pending withdrawals in the queue")]
    VoluntaryExitWithPendingWithdrawals,
    #[error("withdrawal count is incorrect (computed: {computed}, in_block: {in_block})")]
    WithdrawalCountMismatch { computed: usize, in_block: usize },
    #[error("withdrawal is incorrect (computed: {computed:?}, in_block: {in_block:?})")]
    WithdrawalMismatch {
        computed: Withdrawal,
        in_block: Withdrawal,
    },
    #[error("withdrawal root is incorrect (computed: {computed:?}, in_block: {in_block:?})")]
    WithdrawalRootMismatch { computed: H256, in_block: H256 },
    #[error(
        "withdrawal credentials computed from block do not match state \
         (in_state: {in_state:?}, in_block: {in_block:?})"
    )]
    WithdrawalCredentialsMismatch { in_state: H256, in_block: H256 },
    #[error("withdrawal index overflowed")]
    WithdrawalIndexOverflow,
}
