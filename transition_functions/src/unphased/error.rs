use thiserror::Error;
use types::{
    bellatrix::primitives::Gas,
    capella::containers::Withdrawal,
    combined::Attestation,
    phase0::{
        containers::{AttestationData, BeaconBlockHeader, Checkpoint, Deposit, Validator},
        primitives::{Epoch, ExecutionBlockHash, Gwei, Slot, UnixSeconds, ValidatorIndex, H256},
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
    #[error("post-Gloas attestation for current slot with payload presence: {attestation:?}")]
    AttestationForCurrentSlotWithPayloadPresence { attestation: Attestation<P> },
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
    #[error("post-Gloas attestation with invalid payload status: {attestation:?}")]
    AttestationWithInvalidPayloadStatus { attestation: Attestation<P> },
    #[error("post-Electra attestation with invalid (non-zero) committee index: {attestation:?}")]
    AttestationWithNonZeroCommitteeIndex { attestation: Attestation<P> },
    #[error("bid slot ({in_bid}) does not match block slot ({in_block})")]
    BidSlotMismatch { in_bid: Slot, in_block: Slot },
    #[error("bid parent block hash ({in_bid}) does not match in state ({in_state})")]
    BidParentBlockHashMismatch {
        in_bid: ExecutionBlockHash,
        in_state: ExecutionBlockHash,
    },
    #[error("bid parent block root ({in_bid:?}) does not match in block ({in_block:?})")]
    BidParentBlockRootMismatch { in_bid: H256, in_block: H256 },
    #[error("bid prev randao ({in_bid:?}) does not match in state ({in_state:?})")]
    BidPrevRandaoMismatch { in_bid: H256, in_state: H256 },
    #[error("block is not newer than latest block header ({block_slot} <= {block_header_slot})")]
    BlockNotNewerThanLatestBlockHeader {
        block_slot: Slot,
        block_header_slot: Slot,
    },
    #[error("builder balance is not sufficient (balance: {balance}, payments: {payments})")]
    BuilderBalanceNotSufficient { balance: Gwei, payments: Gwei },
    #[error("deposit count is incorrect (computed: {computed}, in_block: {in_block})")]
    DepositCountMismatch { computed: u64, in_block: u64 },
    #[error("deposit proof is invalid: {deposit:?}")]
    DepositProofInvalid {
        // Boxed to pass `clippy::large_enum_variant`.
        deposit: Box<Deposit>,
    },
    #[error(
        "blob commitments root in envelope ({in_envelope:?}) does not match in committed bid ({in_state:?})"
    )]
    EnvelopeBlobCommitmentsMismatch { in_envelope: H256, in_state: H256 },
    #[error(
        "builder index in envelope ({in_envelope}) does not match in committed bid ({in_state})"
    )]
    EnvelopeBuilderMismatch {
        in_envelope: ValidatorIndex,
        in_state: ValidatorIndex,
    },
    #[error("block root in envelope ({in_envelope:?}) does not match in state ({in_state:?})")]
    EnvelopeBlockRootMismatch { in_envelope: H256, in_state: H256 },
    #[error("slot in envelope ({in_envelope}) does not match in state ({in_state})")]
    EnvelopeSlotMismatch { in_envelope: Slot, in_state: Slot },
    #[error("the execution payload bid is not from builder")]
    ExecutionPayloadBidNotBuilder,
    #[error("execution payload bid's signature is invalid")]
    ExecutionPayloadBidSignatureInvalid,
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
    #[error("non zero bid value for self-build block")]
    NoneZeroBidValue,
    #[error("block parent root ({in_block:?}) does not match latest block header ({computed:?})")]
    ParentRootMismatch { computed: H256, in_block: H256 },
    #[error(
        "payload attestation block root ({in_attestation:?}) does not match \
        parent block root in latest block header ({in_header:?})"
    )]
    PayloadAttestationBlockRootMismatch {
        in_header: H256,
        in_attestation: H256,
    },
    #[error(
        "payload attestation slot ({in_attestation}) is not the previous slot (state_slot: {state_slot:?})"
    )]
    PayloadAttestationNotForPreviousSlot {
        in_attestation: Slot,
        state_slot: Slot,
    },
    #[error(
        "block hash in payload ({in_payload:?}) does not match in committed bid ({in_state:?})"
    )]
    PayloadBlockHashMismatch {
        in_payload: ExecutionBlockHash,
        in_state: ExecutionBlockHash,
    },
    #[error("gas limit in payload ({in_payload}) does not match in committed bid ({in_state})")]
    PayloadGasLimitMismatch { in_payload: Gas, in_state: Gas },
    #[error("withdrawals root in payload ({in_payload:?}) does not match in state ({in_state:?})")]
    PayloadWithdrawalsMismatch { in_payload: H256, in_state: H256 },
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
    #[error("validator {index} is already slashed")]
    ValidatorAlreadySlashed { index: ValidatorIndex },
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
