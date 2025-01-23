use core::{ops::Mul as _, time::Duration};

use derivative::Derivative;
use kzg_utils::{KzgBackend, DEFAULT_KZG_BACKEND};
use types::config::Config as ChainConfig;

pub const DEFAULT_CACHE_LOCK_TIMEOUT_MILLIS: u64 = 1500;

#[derive(Clone, Copy, Derivative)]
#[derivative(Default)]
pub struct StoreConfig {
    #[derivative(Default(value = "32"))]
    pub max_empty_slots: u64,
    #[derivative(Default(value = "8"))]
    pub max_epochs_to_retain_states_in_cache: u64,
    #[derivative(Default(value = "Duration::from_millis(DEFAULT_CACHE_LOCK_TIMEOUT_MILLIS)"))]
    pub state_cache_lock_timeout: Duration,
    #[derivative(Default(value = "128"))]
    pub unfinalized_states_in_memory: u64,
    #[derivative(Default(value = "DEFAULT_KZG_BACKEND"))]
    pub kzg_backend: KzgBackend,
}

impl StoreConfig {
    /// Returns a configuration more likely to trigger bugs.
    ///
    /// Intended for use in tests.
    #[must_use]
    pub fn aggressive(chain_config: &ChainConfig) -> Self {
        Self {
            unfinalized_states_in_memory: Self::min_unfinalized_states_in_memory(chain_config),
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
