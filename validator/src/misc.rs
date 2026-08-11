use core::ops::Range;

use bls::{PublicKeyBytes, SignatureBytes};
use helper_functions::misc::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use ssz::{BitVector, H256};
use typenum::{True, U1, U8, Unsigned as _, assert_type, op};
use types::{
    altair::consts::SyncCommitteeSubnetCount,
    combined::SignedBeaconBlock,
    phase0::primitives::{Epoch, Slot, ValidatorIndex},
    preset::Preset,
};

type ComputeInAdvanceSlots = U8;

#[must_use]
pub const fn slots_to_compute_in_advance(current_slot: Slot) -> Range<Slot> {
    current_slot..current_slot.saturating_add(ComputeInAdvanceSlots::U64)
}

// Yields nothing for an empty range, and never yields an empty one.
pub fn slots_by_epoch<P: Preset>(slots: Range<Slot>) -> impl Iterator<Item = (Epoch, Range<Slot>)> {
    let first = compute_epoch_at_slot::<P>(slots.start);
    let last = compute_epoch_at_slot::<P>(slots.end.saturating_sub(1));

    (first..=last).filter_map(move |epoch| {
        let start = compute_start_slot_at_epoch::<P>(epoch).max(slots.start);
        let end = compute_start_slot_at_epoch::<P>(epoch.saturating_add(1)).min(slots.end);

        (start < end).then_some((epoch, start..end))
    })
}

#[expect(clippy::struct_field_names)]
pub struct Aggregator {
    pub aggregator_index: ValidatorIndex,
    pub position_in_committee: usize,
    pub public_key: PublicKeyBytes,
    pub selection_proof: SignatureBytes,
}

pub struct SyncCommitteeMember {
    pub validator_index: ValidatorIndex,
    pub public_key: PublicKeyBytes,
    pub subnets: BitVector<SyncCommitteeSubnetCount>,
}

pub enum SignedBeaconBlockOrBlockRoot<P: Preset> {
    Block(Box<SignedBeaconBlock<P>>),
    Root(H256),
}

#[cfg(target_pointer_width = "32")]
use typenum::U32;

#[cfg(target_pointer_width = "64")]
use typenum::U64;

#[cfg(target_pointer_width = "32")]
assert_type!(op!(ComputeInAdvanceSlots < U1 << U32));

#[cfg(target_pointer_width = "64")]
assert_type!(op!(ComputeInAdvanceSlots < U1 << U64));

#[cfg(test)]
mod tests {
    use types::preset::Minimal;

    use super::*;

    #[test]
    fn slots_by_epoch_yields_nothing_for_an_empty_range() {
        assert!(grouped(0..0).is_empty());
        assert!(grouped(9..9).is_empty());
    }

    #[test]
    fn slots_by_epoch_keeps_a_range_inside_one_epoch_whole() {
        assert_eq!(grouped(3..7), [(0, 3..7)]);
        assert_eq!(grouped(8..16), [(1, 8..16)]);
    }

    #[test]
    fn slots_by_epoch_splits_a_range_at_epoch_boundaries() {
        assert_eq!(grouped(6..19), [(0, 6..8), (1, 8..16), (2, 16..19)]);
    }

    #[test]
    fn slots_by_epoch_groups_the_slots_computed_in_advance() {
        assert_eq!(
            grouped(slots_to_compute_in_advance(5)),
            [(0, 5..8), (1, 8..13)]
        );
    }

    fn grouped(slots: Range<Slot>) -> Vec<(Epoch, Range<Slot>)> {
        slots_by_epoch::<Minimal>(slots).collect()
    }
}
