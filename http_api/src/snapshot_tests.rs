use snapshot_test_utils::Case;
use test_generator::test_resources;

use crate::context::{self, Context};

// TODO(feature/deneb): Update snapshot tests just like for Capella.

#[test]
fn update_responses_should_not_be_permanently_enabled() {
    assert!(
        !context::should_update_responses(),
        "UPDATE_RESPONSES should not be permanently enabled",
    );
}

#[test_resources("grandine-snapshot-tests/mainnet/mainnet/genesis/none/*")]
fn mainnet_genesis_none(case: Case) {
    Context::mainnet_genesis_none().run_case(case)
}

#[test_resources("grandine-snapshot-tests/mainnet/mainnet/genesis/128-slots/*")]
#[cfg(feature = "eth2-cache")]
fn mainnet_genesis_128_slots(case: Case) {
    Context::mainnet_genesis_128_slots().run_case(case)
}

#[test_resources("grandine-snapshot-tests/mainnet/mainnet/epoch-96214/128-slots/*")]
#[cfg(feature = "eth2-cache")]
fn mainnet_epoch_96214_128_slots(case: Case) {
    Context::mainnet_epoch_96214_128_slots().run_case(case)
}

#[test_resources("grandine-snapshot-tests/mainnet/mainnet/epoch-244816/128-slots/*")]
#[cfg(feature = "eth2-cache")]
fn mainnet_epoch_244816_128_slots(case: Case) {
    Context::mainnet_epoch_244816_128_slots().run_case(case)
}

#[test_resources("grandine-snapshot-tests/minimal/minimal/quick-start/all-keys/*")]
fn minimal_minimal_all_keys(case: Case) {
    Context::minimal_minimal_all_keys().run_case(case)
}

#[test_resources("grandine-snapshot-tests/minimal/minimal/quick-start/4-epochs/*")]
fn minimal_minimal_4_epochs(case: Case) {
    Context::minimal_minimal_4_epochs().run_case(case)
}

#[test_resources("grandine-snapshot-tests/minimal/rapid-upgrade/quick-start/none/*")]
fn minimal_rapid_upgrade_none(case: Case) {
    Context::minimal_rapid_upgrade_none().run_case(case)
}

#[test_resources("grandine-snapshot-tests/minimal/rapid-upgrade/quick-start/all-keys/*")]
fn minimal_rapid_upgrade_all_keys(case: Case) {
    Context::minimal_rapid_upgrade_all_keys().run_case(case)
}

#[test_resources("grandine-snapshot-tests/minimal/rapid-upgrade/quick-start/all-phases-all-keys/*")]
fn minimal_rapid_upgrade_all_phases_all_keys(case: Case) {
    Context::minimal_rapid_upgrade_all_phases_all_keys().run_case(case)
}
