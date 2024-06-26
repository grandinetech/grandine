use num_traits::One as _;
use sha2::{Digest as _, Sha256};
use ssz::Uint256;
use typenum::Unsigned as _;
use types::{
    eip7594::{ColumnIndex, NumberOfColumns, DATA_COLUMN_SIDECAR_SUBNET_COUNT},
    phase0::primitives::NodeId,
};

#[must_use]
pub fn get_custody_columns(node_id: NodeId, custody_subnet_count: u64) -> Vec<ColumnIndex> {
    assert!(custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT);

    let mut subnet_ids = vec![];
    let mut current_id = node_id;

    while (subnet_ids.len() as u64) < custody_subnet_count {
        let mut hasher = Sha256::new();
        let mut bytes: [u8; 32] = [0; 32];

        current_id.into_raw().to_little_endian(&mut bytes);

        hasher.update(bytes);
        bytes = hasher.finalize().into();

        let output_prefix = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];

        let output_prefix_u64 = u64::from_le_bytes(output_prefix);
        let subnet_id = output_prefix_u64 % DATA_COLUMN_SIDECAR_SUBNET_COUNT;

        if !subnet_ids.contains(&subnet_id) {
            subnet_ids.push(subnet_id);
        }

        if current_id == Uint256::MAX {
            current_id = Uint256::ZERO;
        }

        current_id = current_id + Uint256::one();
    }

    let columns_per_subnet = NumberOfColumns::U64 / DATA_COLUMN_SIDECAR_SUBNET_COUNT;
    let mut result = Vec::new();
    for i in 0..columns_per_subnet {
        for &subnet_id in &subnet_ids {
            result.push(DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnet_id);
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
        phase0::primitives::NodeId,
        preset::{Mainnet, Minimal, Preset},
    };

    use crate::{get_custody_columns, ColumnIndex};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Meta {
        description: Option<String>,
        node_id: NodeId,
        custody_subnet_count: u64,
        result: Vec<ColumnIndex>,
    }

    #[duplicate_item(
        glob                                                                              function_name                 preset;
        ["consensus-spec-tests/tests/mainnet/eip7594/networking/get_custody_columns/*/*"] [get_custody_columns_mainnet] [Mainnet];
        ["consensus-spec-tests/tests/minimal/eip7594/networking/get_custody_columns/*/*"] [get_custody_columns_minimal] [Minimal];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_case::<preset>(case);
    }

    #[allow(clippy::extra_unused_type_parameters)]
    fn run_case<P: Preset>(case: Case) {
        let Meta {
            description: _description,
            node_id,
            custody_subnet_count,
            result,
        } = case.yaml::<Meta>("meta");

        assert_eq!(get_custody_columns(node_id, custody_subnet_count), result);
    }
}
