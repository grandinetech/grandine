use anyhow::{Error, Result};
use itertools::Itertools as _;
use p2p::Enr;

pub const CONFIG_FILE: &str = "config.yaml";
pub const DEPOSIT_CONTRACT_BLOCK_FILE: &str = "deposit_contract_block.txt";
pub const GENESIS_STATE_FILE: &str = "genesis.ssz";
pub const PLAIN_BOOTNODES_FILE: &str = "bootstrap_nodes.txt";

pub fn parse_plain_bootnodes(string: &str) -> Result<Vec<Enr>> {
    string
        .lines()
        .map(|line| {
            line.split_once('#')
                .map(|(before_comment, _)| before_comment)
                .unwrap_or(line)
        })
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::parse)
        .try_collect()
        .map_err(Error::msg)
}

#[allow(clippy::needless_pass_by_value)]
#[cfg(test)]
mod tests {
    use test_case::test_case;

    use crate::predefined_network::PredefinedNetwork;

    use super::*;

    const ENR_1: &str = PredefinedNetwork::MAINNET_BOOTNODES[2];
    const ENR_2: &str = PredefinedNetwork::MAINNET_BOOTNODES[5];

    #[test_case(format!("{ENR_1}\n{ENR_2}"); "minimal")]
    #[test_case(
        format!("
            # bootnode 1
            {ENR_1}

            {ENR_2} # bootnode 2
        ");
        "empty lines, leading whitespace, trailing whitespace, comments"
    )]
    fn parse_plain_bootnodes_successfully_parses(string: String) -> Result<()> {
        let expected = [
            ENR_1.parse().map_err(Error::msg)?,
            ENR_2.parse().map_err(Error::msg)?,
        ];

        let actual = parse_plain_bootnodes(string.as_str())?;

        assert_eq!(actual, expected);

        Ok(())
    }
}
