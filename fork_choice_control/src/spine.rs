use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use ssz::H256;
use std_ext::ArcExt as _;
use types::{combined::BeaconState, config::Config, phase0::primitives::Slot, preset::Preset};

use crate::{hierarchy::Hierarchy, storage::StateByBlockRoot};

struct Entry<P: Preset> {
    slot: Slot,
    key: StateByBlockRoot,
    state: Arc<BeaconState<P>>,
}

/// Hierarchy ancestors of the state persisted last, kept in memory to
/// delta-encode the states that follow against, instead of reconstructing them
/// from disk.
///
/// Holds at most one state per hierarchy layer, indexed the same way
/// [`crate::frame_cache::FrameCache`] indexes layers: 0 is the snapshot at the
/// top of the hierarchy, `hierarchy.depth() - 1` is a leaf. Writing a layer
/// supersedes it, so no eviction logic is needed - an entry no later state
/// depends on is simply a slot nobody queries.
pub struct Spine<P: Preset> {
    config: Arc<Config>,
    hierarchy: Hierarchy,
    anchor_slot: Arc<AtomicU64>,
    layers: Vec<ArcSwapOption<Entry<P>>>,
}

impl<P: Preset> Spine<P> {
    pub fn new(config: Arc<Config>, hierarchy: Hierarchy, anchor_slot: Arc<AtomicU64>) -> Self {
        let layers = core::iter::repeat_with(ArcSwapOption::empty)
            .take(hierarchy.depth())
            .collect();

        Self {
            config,
            hierarchy,
            anchor_slot,
            layers,
        }
    }

    pub fn get(&self, slot: Slot) -> Option<(StateByBlockRoot, Arc<BeaconState<P>>)> {
        self.entries()
            .find(|entry| entry.slot == slot)
            .map(|entry| (entry.key.clone(), entry.state.clone_arc()))
    }

    pub fn get_by_block_root(&self, block_root: H256) -> Option<Arc<BeaconState<P>>> {
        self.entries()
            .find(|entry| entry.key.block_root == block_root)
            .map(|entry| entry.state.clone_arc())
    }

    /// Track a persisted state, superseding the one previously tracked in the
    /// same hierarchy layer.
    pub fn insert(&self, slot: Slot, key: StateByBlockRoot, state: Arc<BeaconState<P>>) {
        let anchor_slot = self.anchor_slot.load(Ordering::SeqCst);

        // The number of hierarchy ancestors above a slot is its layer index.
        let layer = self
            .hierarchy
            .spine::<P>(&self.config, anchor_slot, slot)
            .len();

        if let Some(entry) = self.layers.get(layer) {
            entry.store(Some(Arc::new(Entry { slot, key, state })));
        }
    }

    /// Copy every tracked state into `other`, as if it had been inserted there.
    pub fn copy_into(&self, other: &Self) {
        for entry in self.entries() {
            other.insert(entry.slot, entry.key.clone(), entry.state.clone_arc());
        }
    }

    /// Forget the states that pruning deleted - those at or below
    /// `pruned_up_to_slot` that it did not retain. Everything else is still on
    /// disk and stays usable as a delta parent.
    pub fn remove_pruned(&self, pruned_up_to_slot: Slot, retained_slots: &[Slot]) {
        for layer in &self.layers {
            let Some(entry) = layer.load_full() else {
                continue;
            };

            if entry.slot <= pruned_up_to_slot && !retained_slots.contains(&entry.slot) {
                layer.store(None);
            }
        }
    }

    #[cfg(test)]
    pub fn clear(&self) {
        for layer in &self.layers {
            layer.store(None);
        }
    }

    fn entries(&self) -> impl Iterator<Item = Arc<Entry<P>>> {
        self.layers.iter().filter_map(ArcSwapOption::load_full)
    }
}

#[cfg(test)]
mod tests {
    use types::{
        phase0::beacon_state::BeaconState as Phase0BeaconState, preset::Mainnet,
        traits::BeaconState as _,
    };

    use super::*;

    fn spine(anchor_slot: Slot) -> Spine<Mainnet> {
        let hierarchy = Hierarchy::new([11, 9, 5]).expect("exponents in tests are valid");

        Spine::new(
            Arc::new(Config::mainnet()),
            hierarchy,
            Arc::new(AtomicU64::new(anchor_slot)),
        )
    }

    fn state(slot: Slot) -> Arc<BeaconState<Mainnet>> {
        Arc::new(BeaconState::Phase0(
            Phase0BeaconState {
                slot,
                ..Phase0BeaconState::default()
            }
            .into(),
        ))
    }

    fn key(byte: u8) -> StateByBlockRoot {
        StateByBlockRoot::snapshot(H256::repeat_byte(byte))
    }

    fn insert(spine: &Spine<Mainnet>, slot: Slot) {
        // One distinct byte per hierarchy node, so keys are comparable.
        let byte = u8::try_from(slot / 32 % 256).expect("remainder fits in u8");

        spine.insert(slot, key(byte), state(slot));
    }

    fn tracked(spine: &Spine<Mainnet>) -> Vec<Option<Slot>> {
        spine
            .layers
            .iter()
            .map(|layer| layer.load_full().map(|entry| entry.slot))
            .collect()
    }

    #[test]
    fn get_returns_an_inserted_state_with_its_key() {
        let spine = spine(0);

        insert(&spine, 0);
        insert(&spine, 512);

        let (key, state) = spine.get(512).expect("slot 512 was just inserted");

        assert_eq!(key.to_string(), self::key(16).to_string());
        assert_eq!(state.slot(), 512);

        assert!(spine.get(0).is_some());
        assert!(spine.get(544).is_none());
    }

    #[test]
    fn get_by_block_root_finds_a_state_regardless_of_its_layer() {
        let spine = spine(0);

        insert(&spine, 0);
        insert(&spine, 544);

        assert_eq!(
            spine
                .get_by_block_root(H256::repeat_byte(17))
                .map(|state| state.slot()),
            Some(544),
        );

        assert_eq!(
            spine
                .get_by_block_root(H256::repeat_byte(0))
                .map(|state| state.slot()),
            Some(0),
        );

        assert!(spine.get_by_block_root(H256::repeat_byte(16)).is_none());
    }

    #[test]
    fn insert_places_a_state_in_the_layer_matching_its_depth() {
        let spine = spine(0);

        // The anchor is a snapshot, 512 is delta-encoded against it and 544
        // against 512, which is exactly how deep each of them sits.
        insert(&spine, 0);
        assert_eq!(tracked(&spine), vec![Some(0), None, None]);

        insert(&spine, 512);
        assert_eq!(tracked(&spine), vec![Some(0), Some(512), None]);

        insert(&spine, 544);
        assert_eq!(tracked(&spine), vec![Some(0), Some(512), Some(544)]);
    }

    #[test]
    fn insert_supersedes_the_state_in_the_same_layer() {
        let spine = spine(0);

        insert(&spine, 0);
        insert(&spine, 512);
        insert(&spine, 544);

        assert_eq!(tracked(&spine), vec![Some(0), Some(512), Some(544)]);

        // 576 is a sibling of 544, so it takes over the layer.
        insert(&spine, 576);

        assert_eq!(tracked(&spine), vec![Some(0), Some(512), Some(576)]);
        assert!(spine.get(544).is_none());

        // 1024's only ancestor is the anchor, so it supersedes 512. The leaf
        // below 512 is left in place: no later state resolves it as a delta
        // parent, so there is nothing to evict.
        insert(&spine, 1024);

        assert_eq!(tracked(&spine), vec![Some(0), Some(1024), Some(576)]);
    }

    #[test]
    fn insert_is_anchor_relative() {
        let spine = spine(96);

        insert(&spine, 96);
        insert(&spine, 128);

        // Relative to the anchor, 128 is a leaf hanging directly off the
        // anchor. Against an anchor of 0 it would sit below a mid-level node.
        assert_eq!(tracked(&spine), vec![Some(96), Some(128), None]);

        // Relative 512 also hangs off the anchor, so it takes over the layer.
        insert(&spine, 608);

        assert_eq!(tracked(&spine), vec![Some(96), Some(608), None]);
    }

    #[test]
    fn remove_pruned_forgets_only_the_states_pruning_deleted() {
        let spine = spine(0);

        insert(&spine, 0);
        insert(&spine, 512);
        insert(&spine, 544);

        // 0 is below the boundary but retained, 512 is below it and deleted,
        // 544 is above it.
        spine.remove_pruned(520, &[0]);

        assert_eq!(tracked(&spine), vec![Some(0), None, Some(544)]);
    }

    #[test]
    fn remove_pruned_keeps_everything_above_the_boundary() {
        let spine = spine(0);

        insert(&spine, 512);
        insert(&spine, 544);

        spine.remove_pruned(0, &[]);

        assert_eq!(tracked(&spine), vec![None, Some(512), Some(544)]);
    }

    #[test]
    fn copy_into_reproduces_every_tracked_state_in_the_target() {
        let source = spine(0);

        insert(&source, 0);
        insert(&source, 512);

        let target = spine(0);

        insert(&target, 1024);

        source.copy_into(&target);

        // 1024 sits in the same layer as 512, so the copy supersedes it.
        assert_eq!(tracked(&target), vec![Some(0), Some(512), None]);
        assert!(target.get(512).is_some());
    }
}
