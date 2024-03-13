use ssz::SszHash as _;
use types::{
    preset::Preset,
    traits::{BeaconBlock, BeaconState},
};

pub enum ProcessSlots {
    Always,
    IfNeeded,
    Never,
}

impl ProcessSlots {
    pub fn should_process<P: Preset>(
        self,
        state: &impl BeaconState<P>,
        block: &(impl BeaconBlock<P> + ?Sized),
    ) -> bool {
        match self {
            Self::Always => true,
            // The test for equality is intentional. It ensures that blocks attempting to "rewind"
            // the state are rejected early by `slot_processing::process_slots`.
            // `state.slot < block.slot` would also work, but the block would be rejected as invalid
            // later, while verifying the state root.
            Self::IfNeeded => state.slot() != block.slot(),
            Self::Never => false,
        }
    }
}

pub fn process_slot<P: Preset>(state: &mut impl BeaconState<P>) {
    let slot = state.slot();

    // > Cache state root
    let previous_state_root = state.hash_tree_root();
    *state.state_roots_mut().mod_index_mut(slot) = previous_state_root;

    // > Cache latest block header state root
    if state.latest_block_header().state_root.is_zero() {
        state.latest_block_header_mut().state_root = previous_state_root;
    }

    // > Cache block root
    let previous_block_root = state.latest_block_header().hash_tree_root();
    *state.block_roots_mut().mod_index_mut(slot) = previous_block_root;

    state.cache_mut().advance_slot();
}
