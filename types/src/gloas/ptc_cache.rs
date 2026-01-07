use std::sync::Arc;

use once_cell::sync::OnceCell;

use crate::phase0::primitives::{Epoch, Slot, ValidatorIndex};

/// Cache for Payload Timeliness Committee (PTC) assignments for an entire epoch.
///
/// PTC member selection uses `balance_weighted_selection`, which iterates through all
/// eligible validators and samples based on their effective balances. Without caching,
/// this operation runs every time PTC members are needed:
/// - Fork Choice Store: `validate_payload_attestation`
/// - Validator: `compute_members_at_slot`
/// - Operation Pool: `get_or_init_ptc_at_slot`
///
/// - The cache is cleared at epoch boundaries because effective balances change
///
/// Stores the forward index (slot -> validators) as a flat array.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PTCCache {
    /// The epoch this cache was initialized for
    pub initialized_epoch: Option<Epoch>,
    /// Flat shuffling for all slots in epoch: [slot0_ptc..., slot1_ptc..., ...]
    pub ptc_shuffling: Vec<ValidatorIndex>,
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
        ptc_size: usize,
        slots_per_epoch: u64,
    ) -> Self {
        Self {
            initialized_epoch: Some(epoch),
            ptc_shuffling,
            ptc_size,
            slots_per_epoch,
        }
    }

    /// Get PTC members for a specific slot (forward lookup).
    pub fn get_ptc(
        &self,
        slot: Slot,
        slots_per_epoch: u64,
        ptc_size: usize,
    ) -> anyhow::Result<&[ValidatorIndex]> {
        use anyhow::{anyhow, ensure};

        let epoch = self
            .initialized_epoch
            .ok_or_else(|| anyhow!("PTCCache uninitialized"))?;

        let slot_offset = slot
            .checked_sub(epoch * slots_per_epoch)
            .ok_or_else(|| anyhow!("slot before epoch"))?;

        ensure!(slot_offset < slots_per_epoch, "slot not in epoch");

        let start = (slot_offset as usize) * ptc_size;
        let end = start + ptc_size;

        self.ptc_shuffling
            .get(start..end)
            .ok_or_else(|| anyhow!("PTC index out of bounds"))
    }

    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        self.initialized_epoch == Some(epoch)
    }
}

/// Type alias for PTC cache stored in BeaconState
/// Only stores Current epoch cache (balances change every epoch, invalidating future caches)
pub type PtcCache = OnceCell<Arc<PTCCache>>;

/// Clear PTC cache on epoch transition
/// Unlike committee cache, PTC uses balance-weighted selection which changes every epoch
pub fn clear_ptc_cache(cache: &mut PtcCache) {
    // Clear the cache - balances have changed, making cached selection probabilities invalid
    *cache = OnceCell::new();
}
