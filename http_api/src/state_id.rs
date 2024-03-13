use std::sync::Arc;

use eth1_api::ApiController;
use fork_choice_control::Wait;
use genesis::GenesisProvider;
use parse_display::FromStr;
use types::{
    combined::BeaconState,
    nonstandard::WithStatus,
    phase0::primitives::{Slot, H256},
    preset::Preset,
};

use crate::error::Error;

#[cfg(test)]
use parse_display::Display;

#[derive(FromStr)]
#[display(style = "lowercase")]
#[cfg_attr(test, derive(Clone, Copy, PartialEq, Eq, Debug, Display))]
pub enum StateId {
    Head,
    Genesis,
    Finalized,
    Justified,
    #[display("{0}")]
    Slot(Slot),
    #[display("{0:?}")]
    Root(H256),
}

impl StateId {
    pub fn state<P: Preset, W: Wait>(
        self,
        controller: &ApiController<P, W>,
        genesis_provider: GenesisProvider<P>,
    ) -> Result<WithStatus<Arc<BeaconState<P>>>, Error> {
        match self {
            Self::Head => Some(controller.head_state()),
            Self::Genesis => Some(WithStatus::valid_and_finalized(genesis_provider.state())),
            Self::Finalized => Some(controller.last_finalized_state()),
            Self::Justified => Some(controller.justified_state()?),
            Self::Slot(slot) => controller.state_at_slot(slot)?,
            Self::Root(root) => controller.state_by_state_root(root)?,
        }
        .ok_or(Error::StateNotFound)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use test_case::test_case;

    use super::*;

    #[test_case("head", StateId::Head)]
    #[test_case("genesis", StateId::Genesis)]
    #[test_case("finalized", StateId::Finalized)]
    #[test_case("justified", StateId::Justified)]
    #[test_case("12", StateId::Slot(12))]
    #[test_case(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        StateId::Root(H256::zero())
    )]
    #[test_case(
        "0x286a9f59df6017029975682ba803d67efbb9daec7a012c193025a8e6e1e8f22e",
        StateId::Root(H256(hex!("286a9f59df6017029975682ba803d67efbb9daec7a012c193025a8e6e1e8f22e")))
    )]
    fn state_id_string_round_trip(string: &str, state_id: StateId) {
        assert_eq!(string.parse(), Ok(state_id));
        assert_eq!(state_id.to_string(), string);
    }
}
