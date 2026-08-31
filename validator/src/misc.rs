use core::ops::Range;
use std::sync::Arc;

use anyhow::{Result, ensure};
use arithmetic::UsizeExt as _;
use bls::{PublicKeyBytes, SignatureBytes};
use helper_functions::misc::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use ssz::{BitVector, H256};
use typenum::{True, U1, U8, Unsigned as _, assert_type, op};
use types::{
    altair::consts::SyncCommitteeSubnetCount,
    combined::{BeaconState, SignedBeaconBlock},
    phase0::primitives::{Epoch, Slot, ValidatorIndex},
    preset::{Preset, SyncSubcommitteeSize},
};

use crate::slot_head::SlotHead;

type ComputeInAdvanceSlots = U8;

#[must_use]
pub const fn slots_to_compute_in_advance(current_slot: Slot) -> Range<Slot> {
    current_slot..current_slot.saturating_add(ComputeInAdvanceSlots::U64)
}

pub fn slots_by_epoch<P: Preset>(slots: Range<Slot>) -> impl Iterator<Item = (Epoch, Range<Slot>)> {
    let first = compute_epoch_at_slot::<P>(slots.start);
    let last = compute_epoch_at_slot::<P>(slots.end.saturating_sub(1));

    (first..=last).filter_map(move |epoch| {
        let start = compute_start_slot_at_epoch::<P>(epoch).max(slots.start);
        let end = compute_start_slot_at_epoch::<P>(epoch.saturating_add(1)).min(slots.end);

        (start < end).then_some((epoch, start..end))
    })
}

// Positions come from a remote beacon node and `BitVector::set` panics outside the vector.
pub fn subnets_from_sync_committee_indices<P: Preset>(
    indices: impl IntoIterator<Item = usize>,
) -> Result<BitVector<SyncCommitteeSubnetCount>> {
    let mut subnets = BitVector::default();

    for index in indices {
        ensure!(
            index < P::SyncCommitteeSize::USIZE,
            "beacon node reported sync committee position {index}, \
             which is outside a committee of {}",
            P::SyncCommitteeSize::USIZE,
        );

        subnets.set(index.div_typenum::<SyncSubcommitteeSize<P>>(), true);
    }

    Ok(subnets)
}

/// How the validator performs duties: against the built-in beacon node, the nodes given with
/// `--beacon-node-urls`, or both.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValidatorMode {
    Local,
    LocalWithRemotes,
    RemoteOnly,
}

impl ValidatorMode {
    #[must_use]
    pub const fn new(disable_local_beacon_node: bool, has_remote_nodes: bool) -> Self {
        match (disable_local_beacon_node, has_remote_nodes) {
            (true, _) => Self::RemoteOnly,
            (false, true) => Self::LocalWithRemotes,
            (false, false) => Self::Local,
        }
    }

    /// Whether duties may be performed against the built-in beacon node.
    #[must_use]
    pub const fn uses_local_node(self) -> bool {
        matches!(self, Self::Local | Self::LocalWithRemotes)
    }

    #[must_use]
    pub const fn has_remote_nodes(self) -> bool {
        matches!(self, Self::LocalWithRemotes | Self::RemoteOnly)
    }

    /// Blocks are produced by the built-in beacon node alone.
    #[must_use]
    pub const fn supports_block_production(self) -> bool {
        self.uses_local_node()
    }
}

/// The head duties are performed against in a slot.
///
/// A beacon state accompanies the head only when it came from the built-in beacon node, so a
/// state from a stale node cannot be paired with a remote head.
#[derive(Clone)]
pub enum DutySource<P: Preset> {
    /// The head of the built-in beacon node and the state it holds for it.
    Local {
        slot_head: SlotHead<P>,
        beacon_state: Arc<BeaconState<P>>,
    },
    /// A head reported by a node given with `--beacon-node-urls`.
    Remote { slot_head: SlotHead<P> },
}

impl<P: Preset> DutySource<P> {
    #[must_use]
    pub const fn slot_head(&self) -> &SlotHead<P> {
        match self {
            Self::Local { slot_head, .. } | Self::Remote { slot_head } => slot_head,
        }
    }

    #[must_use]
    pub const fn beacon_state(&self) -> Option<&Arc<BeaconState<P>>> {
        match self {
            Self::Local { beacon_state, .. } => Some(beacon_state),
            Self::Remote { .. } => None,
        }
    }
}

#[expect(clippy::struct_field_names)]
pub struct Aggregator {
    pub aggregator_index: ValidatorIndex,
    pub position_in_committee: usize,
    pub public_key: PublicKeyBytes,
    pub selection_proof: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

    // Under the minimal preset a sync committee holds 32 members across 4 subnets, so each
    // subcommittee spans 8 positions.
    #[test]
    fn a_position_maps_to_the_subnet_of_its_subcommittee() -> Result<()> {
        assert_eq!(subnets(&[0])?, [true, false, false, false]);
        assert_eq!(subnets(&[7])?, [true, false, false, false]);
        assert_eq!(subnets(&[8])?, [false, true, false, false]);
        assert_eq!(subnets(&[31])?, [false, false, false, true]);

        Ok(())
    }

    #[test]
    fn a_validator_in_several_subcommittees_joins_every_subnet() -> Result<()> {
        assert_eq!(subnets(&[3, 3])?, [true, false, false, false]);
        assert_eq!(subnets(&[3, 24])?, [true, false, false, true]);

        Ok(())
    }

    #[test]
    fn no_position_means_no_subnet() -> Result<()> {
        assert_eq!(subnets(&[])?, [false, false, false, false]);

        Ok(())
    }

    #[test]
    fn a_position_outside_the_committee_is_rejected() {
        subnets(&[32]).expect_err("position 32 is outside a committee of 32");
        subnets(&[usize::MAX]).expect_err("position usize::MAX is outside a committee of 32");
    }

    fn subnets(indices: &[usize]) -> Result<Vec<bool>> {
        subnets_from_sync_committee_indices::<Minimal>(indices.iter().copied())
            .map(|subnets| subnets.into_iter().collect())
    }

    fn grouped(slots: Range<Slot>) -> Vec<(Epoch, Range<Slot>)> {
        slots_by_epoch::<Minimal>(slots).collect()
    }
}
