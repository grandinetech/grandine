use std::sync::Arc;

use derivative::Derivative;
use once_cell::sync::OnceCell;

use crate::phase0::primitives::{Epoch, Slot, ValidatorIndex};

/// Equivalence function for `ptc_positions` that ignores trailing `None` entries.
/// Will be used in tests.
fn compare_ptc_positions(xs: &Vec<Option<usize>>, ys: &Vec<Option<usize>>) -> bool {
    use std::cmp::Ordering;

    let (shorter, longer) = match xs.len().cmp(&ys.len()) {
        Ordering::Equal => {
            return xs == ys;
        }
        Ordering::Less => (xs, ys),
        Ordering::Greater => (ys, xs),
    };

    shorter == &longer[..shorter.len()]
        && longer[shorter.len()..].iter().all(|new| new.is_none())
}

/// Cache for Payload Timeliness Committee (PTC) assignments for an entire epoch.
#[derive(Clone, Debug, Default, Derivative)]
#[derivative(PartialEq)]
pub struct PTCCache {
    /// The epoch this cache was initialized for
    pub initialized_epoch: Option<Epoch>,
    /// Flat shuffling for all slots in epoch
    pub ptc_shuffling: Vec<ValidatorIndex>,
    /// Reverse index: validator_index → position in ptc_shuffling
    #[derivative(PartialEq(compare_with = "compare_ptc_positions"))]
    pub ptc_positions: Vec<Option<usize>>,
    /// PTC size per slot
    pub ptc_size: usize,
    /// Slots per epoch
    pub slots_per_epoch: u64,
}

impl PTCCache {
    /// Creates a new PTCCache from the provided data.
    /// Called from helper_functions after computing the epoch-wide PTC.
    pub fn from_parts(
        epoch: Epoch,
        ptc_shuffling: Vec<ValidatorIndex>,
        ptc_positions: Vec<Option<usize>>,
        ptc_size: usize,
        slots_per_epoch: u64,
    ) -> Self {
        Self {
            initialized_epoch: Some(epoch),
            ptc_shuffling,
            ptc_positions,
            ptc_size,
            slots_per_epoch,
        }
    }

    pub fn get_ptc(&self, slot: Slot, slots_per_epoch: u64, ptc_size: usize) -> anyhow::Result<&[ValidatorIndex]> {
        use anyhow::{anyhow, ensure};

        let epoch = self.initialized_epoch.ok_or_else(|| anyhow!("PTCCache uninitialized"))?;

        let slot_offset = slot.checked_sub(epoch * slots_per_epoch)
            .ok_or_else(|| anyhow!("slot before epoch"))?;

        ensure!(slot_offset < slots_per_epoch, "slot not in epoch");

        let start = (slot_offset as usize) * ptc_size;
        let end = start + ptc_size;

        self.ptc_shuffling.get(start..end).ok_or_else(|| anyhow!("PTC index out of bounds"))
    }

    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        self.initialized_epoch == Some(epoch)
    }

    /// Returns the slot where the validator is assigned to PTC, if any.
    /// Uses reverse index lookup.
    pub fn get_validator_ptc_slot(&self, validator_index: ValidatorIndex) -> Option<Slot> {
        let epoch = self.initialized_epoch?;

        // Lookup: get position in shuffling
        let position = self.ptc_positions.get(validator_index as usize).and_then(|&pos| pos)?;

        // Calculate which slot this position belongs to
        let slot_offset = (position / self.ptc_size) as u64;
        let slot = epoch * self.slots_per_epoch + slot_offset;

        Some(slot)
    }
}

/// Type alias for PTC caches stored in BeaconState
/// Stores caches for Previous, Current, Next epochs
pub type PtcCaches = enum_map::EnumMap<crate::nonstandard::RelativeEpoch, OnceCell<Arc<PTCCache>>>;

/// Advance PTC caches to the next epoch (rotate Previous <- Current <- Next)
pub fn advance_ptc_caches(caches: &mut PtcCaches) {
    use crate::nonstandard::RelativeEpoch;

    // Rotate: Previous <- Current <- Next
    caches[RelativeEpoch::Previous] = core::mem::take(&mut caches[RelativeEpoch::Current]);
    caches[RelativeEpoch::Current] = core::mem::take(&mut caches[RelativeEpoch::Next]);
    // Next epoch cache will be lazily initialized when needed
}
