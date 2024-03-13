//! Functions for loading [`BeaconState`]s included in a binary.

use std::sync::{Arc, OnceLock};

use genesis::GenesisProvider;
use hex_literal::hex;
use ssz::SszRead as _;
use types::{
    combined::BeaconState,
    config::Config,
    phase0::{consts::GENESIS_SLOT, primitives::H256},
    preset::Preset,
};

// TODO(Grandine Team): Try refactoring `grandine` to make the type parameter hack unnecessary.
// The type parameter is needed to make `PredefinedNetwork::genesis_provider` in `grandine` work.
// Ultimately this is because Medalla uses a different preset.
// Calling this function with the wrong `Preset` will produce an invalid state.
// This should not happen as long as all built-in `Config`s have correct values in `preset_base`.
#[must_use]
pub fn mainnet<P: Preset>() -> GenesisProvider<P> {
    GenesisProvider::Predefined(
        Arc::new(OnceLock::new()),
        || {
            state_from_ssz(
                &Config::mainnet(),
                include_bytes!("../assets/mainnet_genesis_state.ssz"),
            )
        },
        Config::mainnet().phase_at_slot::<P>(GENESIS_SLOT),
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
    use types::{preset::Mainnet, traits::BeaconState as _};

    use super::*;

    #[test_case(mainnet::<Mainnet>())]
    fn genesis_state_is_valid(genesis_provider: GenesisProvider<impl Preset>) {
        let state_root = genesis_provider.state_root();
        let state = genesis_provider.state();

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
