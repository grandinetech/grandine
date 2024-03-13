use core::ops::Mul as _;

use educe::Educe;
use types::config::Config as ChainConfig;

#[derive(Clone, Copy, Educe)]
#[educe(Default)]
pub struct StoreConfig {
    #[educe(Default = 32)]
    pub max_empty_slots: u64,
    #[educe(Default = 128)]
    pub unfinalized_states_in_memory: u64,
}

impl StoreConfig {
    #[must_use]
    pub fn minimal(chain_config: &ChainConfig) -> Self {
        let minimum = Self::min_unfinalized_states_in_memory(chain_config);

        Self {
            unfinalized_states_in_memory: minimum,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn min_unfinalized_states_in_memory(chain_config: &ChainConfig) -> u64 {
        // The minimum was chosen arbitrarily to protect users from bugs based on the intuition
        // that blocks older than 2 epochs should rarely be needed in well-behaved networks.
        // We did find a bug in `ChainLink::unload_old_states` while implementing in-memory mode.
        chain_config
            .preset_base
            .phase0_preset()
            .slots_per_epoch()
            .get()
            .mul(2)
    }
}
