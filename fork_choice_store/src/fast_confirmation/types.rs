//! Types and constants consumed by the Fast Confirmation Rule.

use types::phase0::{
    containers::Checkpoint,
    primitives::{Epoch, Gwei, H256},
};

/// Per-mille value added to committee weight estimates for ranges not covering a full epoch,
/// to ensure safety with high probability.
///
/// See <https://gist.github.com/saltiniroberto/9ee53d29c33878d79417abb2b4468c20>.
pub const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

/// Pre-computed per-block data built during FCR chain construction.
#[derive(Debug, Clone)]
pub struct ChainInfo {
    pub block_root: H256,
    /// Epoch of this block's slot.
    pub epoch: Epoch,
    /// Voting source epoch: `unrealized_justified_checkpoint.epoch` for prev-epoch blocks,
    /// `store.justified_checkpoint.epoch` for current-epoch blocks.
    pub voting_source_epoch: Epoch,
    /// Whether `previous_slot_head` has this block as an ancestor.
    pub seen_by_prev_head: bool,
    /// Total active balance of validators whose latest message is a descendant of this block
    /// (the attestation score).
    pub support: Gwei,
    /// Total balance of equivocating validators assigned to committees in the adversarial slot
    /// range for this block (the equivocation score).
    pub adversarial: Gwei,
    /// Maximum possible committee weight from `parent_slot + 1` to `current_slot - 1`.
    /// Used as `maximum_support` in `compute_safety_threshold`.
    pub committee_weight: Gwei,
    /// Maximum possible committee weight for the adversarial slot range
    /// (`adv_start` to `current_slot - 1`). Used in `compute_adversarial_weight`.
    pub adv_committee_weight: Gwei,
    /// Proposer boost weight for this block.
    pub proposer_score: Gwei,
    /// Empty-slot support discount for this block; pre-computed because it needs
    /// `get_block_support_between_slots` for the parent across empty slots.
    pub support_discount: Gwei,
    /// `false` if this block's payload status is not VALID (i.e. optimistic).
    /// `is_one_confirmed` MUST return `false` for non-VALID blocks per the optimistic sync spec.
    pub is_valid: bool,
    /// Value of `Config::confirmation_byzantine_threshold` (percent) at the time the chain was built.
    pub byzantine_threshold: u64,
}

/// FFG-related state built during FCR per-slot pre-computation.
#[derive(Debug, Clone)]
pub struct FcrFfgData {
    /// Cached minimum honest FFG support for the current epoch target.
    pub honest_ffg_support: Gwei,
    /// Cached total active balance from the current balance source.
    pub total_active_balance: Gwei,
    /// The store's current `unrealized_justified_checkpoint` (for the spec shortcut).
    pub unrealized_justified_checkpoint: Checkpoint,
    /// Ancestor of the current head at the current epoch start slot.
    pub current_target: Option<Checkpoint>,
    /// Pre-computed current-target FFG support score. Computed during pre-computation
    /// because it requires `latest_messages` and `ancestor()`.
    pub current_target_score: Gwei,
    /// Committee weight from epoch start to `current_slot - 1` (used by
    /// `compute_honest_ffg_support_for_current_target`).
    pub ffg_weight_till_now: Gwei,
    /// Adversarial weight from epoch start to `current_slot - 1`.
    pub adversarial_this_epoch: Gwei,
    /// Value of `Config::confirmation_byzantine_threshold` (percent) at the time the data was built.
    pub byzantine_threshold: u64,
}
