//! Functions for loading [`BeaconState`]s included in a binary.

use std::sync::{Arc, OnceLock};

use duplicate::duplicate_item;
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
// Calling one of the generated functions with the wrong `Preset` will produce an invalid state.
// This should not happen as long as all built-in `Config`s have correct values in `preset_base`.
#[duplicate_item(
    config                  genesis_state_bytes_path                                            genesis_state_root_hex;
    [mainnet]               ["../../eth2-cache/mainnet/genesis_beacon_state.ssz"]               ["7e76880eb67bbdc86250aa578958e9d0675e64e714337855204fb5abaaf82c2b"];
    [medalla]               ["../../eth2-cache/medalla/genesis_beacon_state.ssz"]               ["af6aafa94dcc22a5cf0253c4f5dd886397900034bf7c149c54635b537f34f64e"];
    [pyrmont]               ["../../eth2-cache/pyrmont/genesis_beacon_state.ssz"]               ["2bb257ca66d05a047a65fe43a5f457b674de445d917cca029efb09b3ba4758c4"];
    [goerli]                ["../../eth2-cache/prater/genesis_beacon_state.ssz"]                ["895390e92edc03df7096e9f51e51896e8dbe6e7e838180dadbfd869fdd77a659"];
    [kintsugi]              ["../../eth2-cache/kintsugi/genesis_beacon_state.ssz"]              ["01e136a24f58dfa0c8735afdc1ccada58d286ae4e15cb26327d97f040fd8f36b"];
    [kiln]                  ["../../eth2-cache/kiln/genesis_beacon_state.ssz"]                  ["449335c404bfc66660a7a89a924dd0dc07cec5b23ff095ac76c1eba776a97094"];
    [ropsten]               ["../../eth2-cache/ropsten_beacon_chain/genesis_beacon_state.ssz"]  ["75b3f63942f47f1b17a1ca4a61bf5ca37ffb5e2a9ef9129f9c80cc13d6c67f03"];
    [sepolia]               ["../../eth2-cache/sepolia/genesis_beacon_state.ssz"]               ["fb9afe32150fa39f4b346be2519a67e2a4f5efcd50a1dc192c3f6b3d013d2798"];
    [withdrawal_devnet_3]   ["../../eth2-cache/withdrawals_devnet_3/genesis_beacon_state.ssz"]  ["015704b987a1a9966e4a8194b8078a3920e3d9da6a40b81b4fbb84f72952ccc4"];
    [withdrawal_devnet_4]   ["../../eth2-cache/withdrawals_devnet_4/genesis_beacon_state.ssz"]  ["c4c7e9732c9b8045fdcf1cf8e4db22fbbc81c2cf5c678f5a4b3494d333381358"];
)]
#[must_use]
pub fn config<P: Preset>() -> GenesisProvider<P> {
    GenesisProvider::Predefined(
        Arc::new(OnceLock::new()),
        || state_from_ssz(&Config::config(), include_bytes!(genesis_state_bytes_path)),
        Config::config().phase_at_slot::<P>(GENESIS_SLOT),
        H256(hex!(genesis_state_root_hex)),
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
    use types::{
        preset::{Mainnet, Medalla},
        traits::BeaconState as _,
    };

    use super::*;

    #[test_case(mainnet::<Mainnet>())]
    // Notice that `medalla` must be called with a different `Preset`.
    #[test_case(medalla::<Medalla>())]
    #[test_case(pyrmont::<Mainnet>())]
    #[test_case(goerli::<Mainnet>())]
    #[test_case(kintsugi::<Mainnet>())]
    #[test_case(kiln::<Mainnet>())]
    #[test_case(ropsten::<Mainnet>())]
    #[test_case(sepolia::<Mainnet>())]
    #[test_case(withdrawal_devnet_3::<Mainnet>())]
    #[test_case(withdrawal_devnet_4::<Mainnet>())]
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
