use std::collections::{BTreeMap, HashMap};

use helper_functions::accessors;
use serde::Serialize;
use typenum::Unsigned as _;
use types::{
    altair::containers::SyncAggregate,
    combined::{BeaconState, SignedBeaconBlock},
    nonstandard::UsizeVec,
    phase0::primitives::{Slot, ValidatorIndex, H256},
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

#[derive(Default, Debug, Serialize)]
pub struct SyncCommitteeAssignment {
    pub positions: UsizeVec,
}

#[derive(Debug, Serialize)]
pub struct SyncCommitteePerformance {
    pub positions: BTreeMap<usize, bool>,
    pub beacon_block_root: H256,
}

// A function that does the same for the previous epoch may be impossible.
// The Altair Honest Validator specification states:
// > *Note*: The data required to compute a given committee is not cached in the `BeaconState` after
// > committees are calculated at the period boundaries.
pub fn current_epoch_sync_committee_assignments<P: Preset>(
    state: &BeaconState<P>,
) -> HashMap<ValidatorIndex, SyncCommitteeAssignment> {
    let Some(state) = state.post_altair() else {
        return HashMap::new();
    };

    let mut sync_committee_assignments =
        HashMap::<_, SyncCommitteeAssignment>::with_capacity(P::SyncCommitteeSize::USIZE);

    for (position, pubkey) in state.current_sync_committee().pubkeys.iter().enumerate() {
        let validator_index = accessors::index_of_public_key(state, pubkey)
            .expect("public keys in state.current_sync_committee are taken from state.validators");

        sync_committee_assignments
            .entry(validator_index)
            .or_default()
            .positions
            .push(position);
    }

    sync_committee_assignments
}

pub fn sync_aggregate_with_root<P: Preset>(
    block: &SignedBeaconBlock<P>,
) -> Option<(SyncAggregate<P>, H256)> {
    let sync_aggregate = block
        .message()
        .body()
        .with_sync_aggregate()?
        .sync_aggregate();
    let parent_root = block.message().parent_root();
    Some((sync_aggregate, parent_root))
}

#[must_use]
pub fn sync_committee_performance(
    assignment: Option<&SyncCommitteeAssignment>,
    sync_aggregates_with_roots: &HashMap<Slot, (SyncAggregate<impl Preset>, H256)>,
) -> BTreeMap<Slot, SyncCommitteePerformance> {
    assignment
        .iter()
        .flat_map(|assignment| {
            sync_aggregates_with_roots.iter().map(
                move |(slot, (sync_aggregate, beacon_block_root))| {
                    let positions = assignment
                        .positions
                        .iter()
                        .copied()
                        .map(|position| (position, sync_aggregate.sync_committee_bits[position]))
                        .collect();

                    let performance = SyncCommitteePerformance {
                        positions,
                        beacon_block_root: *beacon_block_root,
                    };

                    (*slot, performance)
                },
            )
        })
        .collect()
}
