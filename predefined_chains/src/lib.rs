//! Functions for loading [`BeaconState`]s included in a binary.

use std::sync::Arc;

use genesis::AnchorCheckpointProvider;
use hex_literal::hex;
use ssz::SszRead as _;
use types::{
    combined::BeaconState,
    config::Config,
    nonstandard::{FinalizedCheckpoint, WithOrigin},
    phase0::primitives::H256,
    preset::Preset,
};

// TODO(Grandine Team): Try refactoring `grandine` to make the type parameter hack unnecessary.
// The type parameter is needed to make `PredefinedNetwork::anchor_checkpoint_provider` in `grandine` work.
// Ultimately this is because Medalla uses a different preset.
// Calling this function with the wrong `Preset` will produce an invalid state.
// This should not happen as long as all built-in `Config`s have correct values in `preset_base`.
#[must_use]
pub fn mainnet<P: Preset>() -> AnchorCheckpointProvider<P> {
    let state = state_from_ssz(
        &Config::mainnet(),
        include_bytes!("../assets/mainnet_genesis_state.ssz"),
    );

    let block = Arc::new(genesis::beacon_block(&state));

    AnchorCheckpointProvider::Predefined(
        WithOrigin::new_from_genesis(FinalizedCheckpoint { block, state }),
        H256(hex!(
            "7e76880eb67bbdc86250aa578958e9d0675e64e714337855204fb5abaaf82c2b"
        )),
    )
}

// Deserialize to the combined `BeaconState` to support testnets that start in later phases.
fn state_from_ssz<P: Preset>(config: &Config, bytes: &[u8]) -> Arc<BeaconState<P>> {
    Arc::from_ssz(config, bytes).expect("bytes should encode a valid BeaconState")
}

#[cfg(test)]
mod tests {
    use ssz::SszHash as _;
    use std_ext::DefaultExt as _;
    use test_case::test_case;
    use types::{phase0::consts::GENESIS_SLOT, preset::Mainnet, traits::BeaconState as _};

    use super::*;

    #[test_case(&mainnet::<Mainnet>())]
    fn genesis_state_is_valid(anchor_checkpoint_provider: &AnchorCheckpointProvider<impl Preset>) {
        let state_root = anchor_checkpoint_provider.state_root();
        let state = anchor_checkpoint_provider.checkpoint().value.state;

        assert_eq!(state.slot(), GENESIS_SLOT);

        assert!(state.block_roots().is_default());
        assert!(state.state_roots().is_default());
        assert!(state.historical_roots().is_default());

        assert!(state.eth1_data_votes().is_default());

        assert!(state.slashings().is_default());

        assert!(state.justification_bits().is_default());
        assert!(state.previous_justified_checkpoint().is_default());
        assert!(state.current_justified_checkpoint().is_default());
        assert!(state.finalized_checkpoint().is_default());

        assert_eq!(state.hash_tree_root(), state_root);
    }
}
