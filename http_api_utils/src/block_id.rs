use parse_display::{Display, FromStr};
use types::phase0::primitives::{H256, Slot};

#[derive(Clone, Copy, Display, FromStr)]
#[display(style = "lowercase")]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum BlockId {
    Head,
    Genesis,
    Finalized,
    #[display("{0}")]
    Slot(Slot),
    #[display("{0:?}")]
    Root(H256),
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case("head", BlockId::Head)]
    #[test_case("genesis", BlockId::Genesis)]
    #[test_case("finalized", BlockId::Finalized)]
    #[test_case("12", BlockId::Slot(12))]
    #[test_case(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        BlockId::Root(H256::zero())
    )]
    fn block_id_string_round_trip(string: &str, block_id: BlockId) {
        assert_eq!(string.parse(), Ok(block_id));
        assert_eq!(block_id.to_string(), string);
    }
}
