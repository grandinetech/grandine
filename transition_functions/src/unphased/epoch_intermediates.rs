use types::phase0::{containers::Validator, primitives::Gwei};

#[cfg(test)]
use ::{
    ssz::{ContiguousList, Ssz},
    types::preset::{Mainnet, Preset},
};

pub trait ValidatorSummary {
    fn update_from(&mut self, validator: &Validator);
}

pub trait EpochDeltas: Copy {
    fn combined_reward(self) -> Gwei;
    fn combined_penalty(self) -> Gwei;
}

#[cfg(test)]
#[derive(Ssz)]
#[ssz(derive_hash = false, derive_unify = false, derive_write = false)]
pub struct TestDeltas {
    rewards: ContiguousList<Gwei, <Mainnet as Preset>::ValidatorRegistryLimit>,
    penalties: ContiguousList<Gwei, <Mainnet as Preset>::ValidatorRegistryLimit>,
}

#[cfg(test)]
impl TestDeltas {
    pub fn assert_equal(
        actual_rewards: impl IntoIterator<Item = Gwei>,
        actual_penalties: impl IntoIterator<Item = Gwei>,
        expected_deltas: Self,
    ) {
        itertools::assert_equal(actual_rewards, expected_deltas.rewards);
        itertools::assert_equal(actual_penalties, expected_deltas.penalties);
    }
}
