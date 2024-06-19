use parse_display::{Display, FromStr};
use types::phase0::primitives::{Slot, H256};

#[derive(Display, FromStr)]
#[display(style = "lowercase")]
#[cfg_attr(test, derive(Clone, Copy, PartialEq, Eq, Debug))]
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
