//! Pure-math helpers used by the Fast Confirmation Rule.
//!
//! Every function here operates on pre-computed `ChainInfo` / `FcrFfgData` inputs and does not
//! touch the fork-choice `Store`. The per-slot pre-computation that builds those inputs lives
//! on `FastConfirmationStore`.

use arithmetic::NonZeroExt as _;
use helper_functions::misc;
use typenum::Unsigned as _;
use types::{
    phase0::primitives::{Epoch, Gwei, H256, Slot},
    preset::Preset,
};

use super::types::{COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR, ChainInfo, FcrFfgData};

/// Returns an estimate of the total committee weight between two slots (inclusive of both).
///
/// Roughly corresponds to [`estimate_committee_weight_between_slots`] from the Fast Confirmation specification.
///
/// [`estimate_committee_weight_between_slots`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#estimate_committee_weight_between_slots
pub fn estimate_committee_weight_between_slots<P: Preset>(
    total_active_balance: Gwei,
    start_slot: Slot,
    end_slot: Slot,
) -> Gwei {
    if start_slot > end_slot {
        return 0;
    }

    // is_full_validator_set_covered: does the range contain a complete epoch?
    let spe = P::SlotsPerEpoch::U64;
    let start_full_epoch = misc::compute_epoch_at_slot::<P>(start_slot.saturating_add(spe - 1));
    let end_full_epoch = misc::compute_epoch_at_slot::<P>(end_slot.saturating_add(1));
    if start_full_epoch < end_full_epoch {
        return total_active_balance;
    }

    let start_epoch = misc::compute_epoch_at_slot::<P>(start_slot);
    let end_epoch = misc::compute_epoch_at_slot::<P>(end_slot);
    let committee_weight = total_active_balance / P::SlotsPerEpoch::non_zero();

    if start_epoch == end_epoch {
        committee_weight * (end_slot - start_slot + 1)
    } else {
        // Spans epoch boundary but doesn't cover a full epoch — pro-rata calculation
        let num_slots_in_end_epoch = misc::slots_since_epoch_start::<P>(end_slot) + 1;
        let remaining_slots_in_end_epoch = spe - num_slots_in_end_epoch;
        let num_slots_in_start_epoch = spe - misc::slots_since_epoch_start::<P>(start_slot);

        let start_epoch_weight = committee_weight * num_slots_in_start_epoch;
        let end_epoch_weight = committee_weight * num_slots_in_end_epoch;

        let start_epoch_weight_pro_rated = start_epoch_weight / spe * remaining_slots_in_end_epoch;

        let raw_estimate = start_epoch_weight_pro_rated + end_epoch_weight;

        // adjust_committee_weight_estimate_to_ensure_safety:
        // ceil(estimate / 1000) * (1000 + ADJUSTMENT_FACTOR)
        raw_estimate.div_ceil(1000) * (1000 + COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR)
    }
}

/// Returns the proposer boost weight derived from total active balance.
///
/// Roughly corresponds to [`compute_proposer_score`] from the Fork Choice specification.
///
/// [`compute_proposer_score`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fork-choice.md#compute_proposer_score
pub fn compute_proposer_score<P: Preset>(
    total_active_balance: Gwei,
    proposer_score_boost: u64,
) -> Gwei {
    let committee_weight = total_active_balance / P::SlotsPerEpoch::non_zero();
    committee_weight * proposer_score_boost / 100
}

/// Returns the maximum adversarial weight bounded by `byzantine_threshold` (percent), discounted by already-equivocating validators.
///
/// Roughly corresponds to [`compute_adversarial_weight`] from the Fast Confirmation specification.
///
/// [`compute_adversarial_weight`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#compute_adversarial_weight
pub const fn compute_adversarial_weight(
    adv_committee_weight: Gwei,
    equivocation_score: Gwei,
    byzantine_threshold: u64,
) -> Gwei {
    let max_adversarial = adv_committee_weight / 100 * byzantine_threshold;
    max_adversarial.saturating_sub(equivocation_score)
}

/// Returns the empty-slot support discount for a block. The value is pre-computed and exposed here for spec traceability.
///
/// Roughly corresponds to [`compute_empty_slot_support_discount`] from the Fast Confirmation specification.
///
/// [`compute_empty_slot_support_discount`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#compute_empty_slot_support_discount
#[inline]
pub const fn compute_empty_slot_support_discount(info: &ChainInfo) -> Gwei {
    info.support_discount
}

/// Computes the LMD-GHOST safety threshold: `(maximum_support + proposer_score + 2 * adversarial_weight - support_discount) / 2`.
///
/// Roughly corresponds to [`compute_safety_threshold`] from the Fast Confirmation specification.
///
/// [`compute_safety_threshold`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#compute_safety_threshold
pub const fn compute_safety_threshold(info: &ChainInfo) -> Gwei {
    let adversarial_weight = compute_adversarial_weight(
        info.adv_committee_weight,
        info.adversarial,
        info.byzantine_threshold,
    );
    let support_discount = compute_empty_slot_support_discount(info);

    let lhs = info
        .committee_weight
        .saturating_add(info.proposer_score)
        .saturating_add(2 * adversarial_weight);

    if support_discount < lhs {
        (lhs - support_discount) / 2
    } else {
        0
    }
}

/// Returns `true` iff the block is LMD-GHOST safe. Returns `false` if the block's payload status is not VALID, per the optimistic sync specification.
///
/// Roughly corresponds to [`is_one_confirmed`] from the Fast Confirmation specification.
///
/// [`is_one_confirmed`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#is_one_confirmed
pub const fn is_one_confirmed(info: &ChainInfo) -> bool {
    if !info.is_valid {
        return false;
    }
    info.support > compute_safety_threshold(info)
}

/// Returns the voting source epoch for a block.
///
/// Roughly corresponds to [`get_voting_source`] from the Fork Choice specification.
///
/// [`get_voting_source`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fork-choice.md#get_voting_source
pub const fn get_voting_source_epoch(
    block_epoch: Epoch,
    current_epoch: Epoch,
    unrealized_justified_epoch: Epoch,
    store_justified_epoch: Epoch,
) -> Epoch {
    if block_epoch < current_epoch {
        unrealized_justified_epoch
    } else {
        store_justified_epoch
    }
}

/// Computes the minimum honest FFG support for the current epoch target.
///
/// Roughly corresponds to [`compute_honest_ffg_support_for_current_target`] from the Fast Confirmation specification.
///
/// [`compute_honest_ffg_support_for_current_target`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#compute_honest_ffg_support_for_current_target
pub fn compute_honest_ffg_support_for_current_target(ffg: &FcrFfgData) -> Gwei {
    let remaining_ffg_weight = ffg
        .total_active_balance
        .saturating_sub(ffg.ffg_weight_till_now);

    let remaining_honest_ffg_weight = remaining_ffg_weight / 100 * (100 - ffg.byzantine_threshold);

    let min_honest_ffg_support = ffg
        .current_target_score
        .saturating_sub(ffg.adversarial_this_epoch.min(ffg.current_target_score));

    min_honest_ffg_support + remaining_honest_ffg_weight
}

/// Returns `true` iff no checkpoint conflicting with the current target can ever be justified.
///
/// Roughly corresponds to [`will_no_conflicting_checkpoint_be_justified`] from the Fast Confirmation specification.
///
/// [`will_no_conflicting_checkpoint_be_justified`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#will_no_conflicting_checkpoint_be_justified
pub fn will_no_conflicting_checkpoint_be_justified(ffg: &FcrFfgData) -> bool {
    // Spec shortcut: if current target IS the unrealized justified, no conflict is possible
    if let Some(current_target) = ffg.current_target
        && current_target == ffg.unrealized_justified_checkpoint
    {
        return true;
    }

    if ffg.total_active_balance == 0 {
        return false;
    }
    3 * ffg.honest_ffg_support > ffg.total_active_balance
}

/// Returns `true` iff the current target will eventually be justified.
///
/// Roughly corresponds to [`will_current_target_be_justified`] from the Fast Confirmation specification.
///
/// [`will_current_target_be_justified`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#will_current_target_be_justified
pub const fn will_current_target_be_justified(ffg: &FcrFfgData) -> bool {
    if ffg.total_active_balance == 0 {
        return false;
    }
    3 * ffg.honest_ffg_support >= 2 * ffg.total_active_balance
}

/// Returns `true` iff every block in the confirmed chain passes `is_one_confirmed`. The `chain` argument must be built with the previous epoch balance source.
///
/// Roughly corresponds to [`is_confirmed_chain_safe`] from the Fast Confirmation specification.
///
/// [`is_confirmed_chain_safe`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#is_confirmed_chain_safe
pub fn is_confirmed_chain_safe(chain: &[ChainInfo]) -> bool {
    chain.iter().all(is_one_confirmed)
}

/// Returns the most recent confirmed block in the canonical chain suffix starting from `confirmed_root`.
///
/// Roughly corresponds to [`find_latest_confirmed_descendant`] from the Fast Confirmation specification.
///
/// Parameters:
/// - `chain`: blocks from `confirmed_root` (exclusive) toward head (inclusive), oldest-first.
/// - `confirmed_epoch`: epoch of the initial `confirmed_root`.
/// - `current_slot_is_epoch_start`: `misc::is_epoch_start(current_slot)`.
/// - `prev_head_voting_source_epoch`: `ChainInfo.voting_source_epoch` of `previous_slot_head`.
/// - `prev_head_unrealized_justified_epoch`: unrealized justified epoch of `previous_slot_head`.
/// - `head_unrealized_justified_epoch`: unrealized justified epoch of the current head.
///
/// [`find_latest_confirmed_descendant`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#find_latest_confirmed_descendant
#[expect(
    clippy::too_many_arguments,
    reason = "This is a pure-math helper translated directly from the spec. Bundling the scalar \
              `prev_head_*` and `head_*` parameters into a struct would obscure the 1:1 \
              correspondence with `find_latest_confirmed_descendant` in `fast-confirmation.md`."
)]
pub fn find_latest_confirmed_descendant(
    chain: &[ChainInfo],
    confirmed_root: H256,
    confirmed_epoch: Epoch,
    current_epoch: Epoch,
    current_slot_is_epoch_start: bool,
    ffg: &FcrFfgData,
    prev_head_voting_source_epoch: Epoch,
    prev_head_unrealized_justified_epoch: Epoch,
    head_unrealized_justified_epoch: Epoch,
) -> H256 {
    let mut confirmed_root = confirmed_root;
    let mut confirmed_epoch = confirmed_epoch;

    // Loop 1 guard: advance through previous-epoch blocks when
    //   - confirmed is from previous epoch
    //   - previous_slot_head's voting source is recent (epoch+2 >= current)
    //   - FFG condition: epoch start OR (no conflicting justification can happen AND
    //     either the previous head or current head unrealized-justifies the previous epoch)
    let loop1_guard = confirmed_epoch + 1 == current_epoch
        && prev_head_voting_source_epoch + 2 >= current_epoch
        && (current_slot_is_epoch_start
            || (will_no_conflicting_checkpoint_be_justified(ffg)
                && (prev_head_unrealized_justified_epoch + 1 >= current_epoch
                    || head_unrealized_justified_epoch + 1 >= current_epoch)));

    if loop1_guard {
        for info in chain {
            if info.epoch == current_epoch {
                break;
            }
            if !info.seen_by_prev_head {
                break;
            }
            if !is_one_confirmed(info) {
                break;
            }
            confirmed_root = info.block_root;
            confirmed_epoch = info.epoch;
        }
    }

    // Loop 2 guard: advance through current-epoch blocks when
    //   - it's the epoch start, OR
    //   - the head's unrealized justification covers the previous epoch
    let loop2_guard =
        current_slot_is_epoch_start || head_unrealized_justified_epoch + 1 >= current_epoch;

    if loop2_guard {
        // Start from after the block Loop 1 advanced to (or from beginning if no advancement)
        let loop2_start = chain
            .iter()
            .position(|c| c.block_root == confirmed_root)
            .map(|i| i + 1)
            .unwrap_or(0);

        let mut tentative_root = confirmed_root;
        let mut tentative_epoch = confirmed_epoch;

        for info in &chain[loop2_start..] {
            // Spec: any time the loop advances to a strictly later epoch, the FFG guarantee
            // must hold. (Comment in spec notes this can only be true the first time the
            // algorithm advances to a current-epoch block, but the *condition* is just
            // `block_epoch > tentative_confirmed_epoch` — not gated on `== current_epoch`.)
            if info.epoch > tentative_epoch && !will_current_target_be_justified(ffg) {
                break;
            }

            if !is_one_confirmed(info) {
                break;
            }

            tentative_root = info.block_root;
            tentative_epoch = info.epoch;
        }

        // Final gate: can we commit to tentative_root?
        let tentative_vs_epoch = chain
            .iter()
            .find(|c| c.block_root == tentative_root)
            .map(|c| c.voting_source_epoch)
            .unwrap_or(0);

        let can_advance = tentative_epoch == current_epoch
            || (tentative_vs_epoch + 2 >= current_epoch
                && (current_slot_is_epoch_start
                    || will_no_conflicting_checkpoint_be_justified(ffg)));

        if can_advance {
            confirmed_root = tentative_root;
        }
    }

    confirmed_root
}
