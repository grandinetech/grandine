//! FCR-local committee accessor.
//!
//! The Fast Confirmation Rule reconfirmation path can query committees for slots whose epoch
//! is `current_epoch − 2` (spec note on [`compute_empty_slot_support_discount`] and the spec
//! requirement on [`get_slot_committee`] — "MUST support committees of epochs starting from
//! `current_epoch − 2`"). Grandine's `helper_functions::accessors::beacon_committee` routes
//! through `relative_epoch`, which only resolves `Next` / `Current` / `Previous` (i.e. a
//! ±1-epoch window from the state's current epoch) and returns `EpochBeforePrevious` for
//! anything older, silently zeroing the equivocation score / empty-slot discount in the FCR
//! helpers when the lookup reaches `current_epoch − 2`.
//!
//! This helper computes the slot's committee participants directly from `state.randao_mixes`,
//! mirroring pyspec's [`get_beacon_committee`] semantics, so any epoch whose RANDAO mix is
//! still inside the `EPOCHS_PER_HISTORICAL_VECTOR` ring is computable. Scope: the function is
//! used only by `Store::fcr_get_equivocation_score` and `Store::fcr_precompute_support_discount`;
//! the existing `relative_epoch` and `beacon_committee` accessors are not modified.
//!
//! [`get_slot_committee`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#get_slot_committee
//! [`compute_empty_slot_support_discount`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#compute_empty_slot_support_discount
//! [`get_beacon_committee`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/beacon-chain.md#get_beacon_committee

use std::collections::HashSet as StdHashSet;

use helper_functions::{accessors, misc, predicates};
use typenum::Unsigned as _;
use types::{
    combined::BeaconState,
    phase0::{
        consts::DOMAIN_BEACON_ATTESTER,
        primitives::{Slot, ValidatorIndex},
    },
    preset::Preset,
    traits::BeaconState as _,
};

/// Returns the union of validator indices assigned to all committees at `slot`.
///
/// Tries the cached `accessors::beacon_committees` path first (the same accessor every
/// non-FCR caller uses). When that path rejects the lookup with `EpochBeforePrevious`
/// (i.e. the queried slot's epoch is more than `MIN_SEED_LOOKAHEAD + 1` behind the state's
/// current epoch), falls back to a direct shuffling derived from `state.randao_mixes` —
/// mirroring the pyspec sequence `get_active_validator_indices → get_seed → shuffle →
/// slice`. The fallback is only invoked on the FCR reconfirmation path, where the spec
/// requires committees for slots up to `current_epoch − 2`.
pub fn fcr_slot_committee_participants<P: Preset>(
    state: &BeaconState<P>,
    slot: Slot,
) -> StdHashSet<ValidatorIndex> {
    if let Ok(committees) = accessors::beacon_committees::<P>(state, slot) {
        let mut participants = StdHashSet::new();
        for committee in committees {
            for vi in committee {
                participants.insert(vi);
            }
        }
        return participants;
    }

    let epoch = misc::compute_epoch_at_slot::<P>(slot);

    let mut active_indices: Vec<ValidatorIndex> = state
        .validators()
        .into_iter()
        .enumerate()
        .filter_map(|(i, validator)| {
            if predicates::is_active_validator(validator, epoch) {
                ValidatorIndex::try_from(i).ok()
            } else {
                None
            }
        })
        .collect();

    if active_indices.is_empty() {
        return StdHashSet::new();
    }

    // spec `get_seed(state, epoch, DOMAIN_BEACON_ATTESTER)`:
    //   mix = state.randao_mixes[(epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1)
    //                            % EPOCHS_PER_HISTORICAL_VECTOR]
    //   seed = hash(DOMAIN_BEACON_ATTESTER || epoch || mix)
    let mix_epoch = epoch + P::EpochsPerHistoricalVector::U64 - P::MinSeedLookahead::U64 - 1;
    let mix = accessors::get_randao_mix(state, mix_epoch);
    let seed = hashing::hash_32_64_256(DOMAIN_BEACON_ATTESTER.to_fixed_bytes(), epoch, mix);

    shuffling::shuffle_slice::<P, _>(&mut active_indices, seed)
        .expect("active_indices length fits in u64 by Preset's ValidatorRegistryLimit bound");

    // spec `get_beacon_committee(state, slot, index)` slices the shuffled array by
    //     start = validator_count * index_in_epoch       / committees_in_epoch
    //     end   = validator_count * (index_in_epoch + 1) / committees_in_epoch
    // Iterating every committee at this slot and unioning the slices is equivalent to a
    // single contiguous range, because committees at a given slot occupy adjacent
    // sub-ranges of the shuffled list:
    //     committees_per_slot * slot_in_epoch     // committees_in_epoch
    //       = slot_in_epoch / SLOTS_PER_EPOCH (with the validator_count multiplier).
    let validator_count = active_indices.len();
    let spe = usize::try_from(P::SlotsPerEpoch::U64)
        .expect("SLOTS_PER_EPOCH fits in usize on any supported target");
    let slot_in_epoch = usize::try_from(misc::slots_since_epoch_start::<P>(slot))
        .expect("slot-in-epoch is bounded by SLOTS_PER_EPOCH which fits in usize");
    let start = validator_count * slot_in_epoch / spe;
    let end = validator_count * (slot_in_epoch + 1) / spe;

    active_indices[start..end].iter().copied().collect()
}
