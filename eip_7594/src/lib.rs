use num_traits::One as _;
use sha2::{Digest as _, Sha256};
use ssz::Uint256;
use typenum::Unsigned as _;
use types::{
    eip7594::{CustodyIndex, NumberOfColumns, NUMBER_OF_CUSTODY_GROUPS},
    phase0::primitives::NodeId,
};

#[must_use]
pub fn get_custody_groups(node_id: NodeId, custody_group_count: u64) -> Vec<CustodyIndex> {
    assert!(custody_group_count <= NUMBER_OF_CUSTODY_GROUPS);

    let mut custody_groups = vec![];
    let mut current_id = node_id;

    while (custody_groups.len() as u64) < custody_group_count {
        let mut hasher = Sha256::new();
        let mut bytes: [u8; 32] = [0; 32];

        current_id.into_raw().to_little_endian(&mut bytes);

        hasher.update(bytes);
        bytes = hasher.finalize().into();

        let output_prefix = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];

        let output_prefix_u64 = u64::from_le_bytes(output_prefix);
        let custody_group = output_prefix_u64 % NUMBER_OF_CUSTODY_GROUPS;

        if !custody_groups.contains(&custody_group) {
            custody_groups.push(custody_group);
        }

        if current_id == Uint256::MAX {
            current_id = Uint256::ZERO;
        }

        current_id = current_id + Uint256::one();
    }

    let columns_per_custody_group = NumberOfColumns::U64 / NUMBER_OF_CUSTODY_GROUPS;
    let mut result = Vec::new();
    for i in 0..columns_per_custody_group {
        for &custody_group in &custody_groups {
            result.push(NUMBER_OF_CUSTODY_GROUPS * i + custody_group);
        }
    }

    result.sort_unstable();
    result
}

#[cfg(test)]
mod tests {
    use duplicate::duplicate_item;
    use serde::Deserialize;
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::{
        eip7594::CustodyIndex,
        phase0::primitives::NodeId,
        preset::{Mainnet, Minimal, Preset},
    };

    use crate::get_custody_groups;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Meta {
        description: Option<String>,
        node_id: NodeId,
        custody_group_count: u64,
        result: Vec<CustodyIndex>,
    }

    #[duplicate_item(
        glob                                                                              function_name                 preset;
        ["consensus-spec-tests/tests/mainnet/fulu/networking/get_custody_groups/*/*"] [get_custody_groups_mainnet] [Mainnet];
        ["consensus-spec-tests/tests/minimal/fulu/networking/get_custody_groups/*/*"] [get_custody_groups_minimal] [Minimal];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_case::<preset>(case);
    }

    #[expect(clippy::extra_unused_type_parameters)]
    fn run_case<P: Preset>(case: Case) {
        let Meta {
            description: _description,
            node_id,
            custody_group_count,
            result,
        } = case.yaml::<Meta>("meta");

        assert_eq!(get_custody_groups(node_id, custody_group_count), result);
    }
}
