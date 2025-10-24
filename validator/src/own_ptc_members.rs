use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use bls::PublicKeyBytes;
use helper_functions::accessors;
use logging::warn_with_peers;
use std_ext::ArcExt as _;
use tap::{Conv as _, Pipe as _};
use tokio::sync::Mutex;
use typenum::{assert_type, op, True, Unsigned as _, U1, U8};
use types::{
    combined::BeaconState,
    phase0::primitives::{Slot, ValidatorIndex},
    preset::Preset,
};

type ComputeInAdvanceSlots = U8;

#[expect(clippy::declare_interior_mutable_const)]
const NONE_MUTEX: Mutex<Option<PTCMembers>> = Mutex::const_new(None);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PTCMember {
    pub public_key: PublicKeyBytes,
    pub validator_index: ValidatorIndex,
    pub position_in_committee: usize,
}

#[derive(Debug)]
struct PTCMembers {
    slot: Slot,
    members: Arc<[PTCMember]>,
}

pub struct OwnPTCMembers {
    slots: [Mutex<Option<PTCMembers>>; ComputeInAdvanceSlots::USIZE],
}

impl OwnPTCMembers {
    pub const fn new() -> Self {
        Self {
            slots: [NONE_MUTEX; ComputeInAdvanceSlots::USIZE],
        }
    }

    pub async fn get_at_slot(&self, slot: Slot) -> Option<Arc<[PTCMember]>> {
        let slot_index = slot_index_from_slot(slot);
        let slot_members_opt = self.slots[slot_index].lock().await;

        slot_members_opt.as_ref().and_then(|slot_members| {
            (slot_members.slot == slot).then_some(slot_members.members.clone_arc())
        })
    }

    pub async fn init_at_slot<P: Preset>(
        &self,
        state: &BeaconState<P>,
        slot: Slot,
        own_public_keys: &HashSet<PublicKeyBytes>,
    ) {
        let slot_index = slot_index_from_slot(slot);
        let mut slot_members_opt = self.slots[slot_index].lock().await;

        *slot_members_opt = match self
            .compute_members_at_slot(state, slot, own_public_keys)
            .await
        {
            Ok(members) => members.map(|members| PTCMembers { slot, members }),
            Err(error) => {
                warn_with_peers!("failed to compute own ptc members at slot {slot}: {error:?}");
                None
            }
        };
    }

    pub async fn needs_to_compute_members_at_slot(&self, slot: Slot) -> bool {
        let slot_index = slot_index_from_slot(slot);

        if let Some(slot_members) = self.slots[slot_index].lock().await.as_ref() {
            if slot_members.slot == slot {
                return false;
            }
        }

        true
    }

    pub fn slots_to_compute_in_advance(current_slot: Slot) -> impl Iterator<Item = Slot> {
        current_slot..current_slot + ComputeInAdvanceSlots::U64
    }

    async fn compute_members_at_slot<P: Preset>(
        &self,
        state: &BeaconState<P>,
        slot: Slot,
        own_public_keys: &HashSet<PublicKeyBytes>,
    ) -> Result<Option<Arc<[PTCMember]>>> {
        if own_public_keys.is_empty() {
            return Ok(None);
        }

        let own_validator_indices = own_public_keys
            .iter()
            .filter_map(|public_key| {
                let validator_index = accessors::index_of_public_key(state, &public_key)?;
                Some((validator_index, public_key))
            })
            .collect::<HashMap<_, _>>();

        accessors::ptc_for_slot(state, slot)?
            .into_iter()
            .zip(0..)
            .filter_map(|(validator_index, position_in_committee)| {
                own_validator_indices
                    .get(&validator_index)
                    .copied()
                    .map(|public_key| PTCMember {
                        public_key: *public_key,
                        validator_index,
                        position_in_committee,
                    })
            })
            .collect::<Vec<_>>()
            .conv::<Arc<[_]>>()
            .pipe(Some)
            .pipe(Ok)
    }
}

#[cfg(target_pointer_width = "32")]
use typenum::U32;

#[cfg(target_pointer_width = "64")]
use typenum::U64;

#[cfg(target_pointer_width = "32")]
assert_type!(op!(ComputeInAdvanceSlots < U1 << U32));

#[cfg(target_pointer_width = "64")]
assert_type!(op!(ComputeInAdvanceSlots < U1 << U64));

fn slot_index_from_slot(slot: Slot) -> usize {
    usize::try_from(slot % ComputeInAdvanceSlots::U64).expect(
        "ComputeInAdvanceSlots should always fit in usize due to compile-time assertions above",
    )
}
