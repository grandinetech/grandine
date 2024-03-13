use std::sync::Arc;

use im::{HashMap, OrdMap};
use types::{
    combined::BeaconState,
    phase0::primitives::{Slot, H256},
    preset::Preset,
    traits::BeaconState as _,
};

#[derive(Clone, Default)]
pub struct StateCache<P: Preset> {
    states: HashMap<H256, OrdMap<Slot, Arc<BeaconState<P>>>>,
}

impl<P: Preset> StateCache<P> {
    #[must_use]
    pub fn len(&self) -> usize {
        self.states.values().map(OrdMap::len).sum()
    }

    #[must_use]
    pub fn before_or_at_slot(&self, block_root: H256, slot: Slot) -> Option<&Arc<BeaconState<P>>> {
        self.states
            .get(&block_root)
            .and_then(|states| states.get_prev(&slot))
            .map(|(_, state)| state)
    }

    pub fn insert(&mut self, block_root: H256, state: Arc<BeaconState<P>>) {
        self.states
            .entry(block_root)
            .or_default()
            .insert(state.slot(), state);
    }

    pub fn prune(&mut self, last_pruned_slot: Slot) {
        for (_, states) in self.states.iter_mut() {
            let (_, retained) = states.split(&last_pruned_slot);
            *states = retained;
        }

        self.states.retain(|_, states| !states.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use types::{phase0::beacon_state::BeaconState as Phase0BeaconState, preset::Minimal};

    use super::*;

    const ROOT_1: H256 = H256::repeat_byte(1);
    const ROOT_2: H256 = H256::repeat_byte(2);
    const ROOT_3: H256 = H256::repeat_byte(3);

    #[test]
    fn test_state_cache_len() {
        let cache = new_test_cache();

        assert_eq!(cache.len(), 4);
    }

    #[test]
    fn test_state_cache_before_or_at_slot() {
        let cache = new_test_cache();

        assert_eq!(cache.before_or_at_slot(ROOT_2, 1), None);
        assert_eq!(cache.before_or_at_slot(ROOT_2, 3), Some(&state_at_slot(3)));
        assert_eq!(cache.before_or_at_slot(ROOT_2, 4), Some(&state_at_slot(3)));
        assert_eq!(cache.before_or_at_slot(ROOT_2, 9), Some(&state_at_slot(5)));
        assert_eq!(cache.before_or_at_slot(ROOT_3, 9), None);
    }

    #[test]
    fn test_state_cache_prune() {
        let mut cache = new_test_cache();

        cache.prune(2);

        assert_eq!(cache.before_or_at_slot(ROOT_1, 1), None);
        assert_eq!(cache.before_or_at_slot(ROOT_2, 2), None);
        assert_eq!(cache.before_or_at_slot(ROOT_2, 3), Some(&state_at_slot(3)));
        assert_eq!(cache.before_or_at_slot(ROOT_2, 5), Some(&state_at_slot(5)));

        assert_eq!(cache.len(), 2);
    }

    fn new_test_cache() -> StateCache<Minimal> {
        let mut cache = StateCache::default();

        cache.insert(ROOT_1, state_at_slot(1));
        cache.insert(ROOT_2, state_at_slot(2));
        cache.insert(ROOT_2, state_at_slot(3));
        cache.insert(ROOT_2, state_at_slot(5));

        cache
    }

    fn state_at_slot(slot: Slot) -> Arc<BeaconState<Minimal>> {
        Arc::new(
            Phase0BeaconState {
                slot,
                ..Phase0BeaconState::default()
            }
            .into(),
        )
    }
}
