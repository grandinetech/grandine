use std::collections::HashSet;

use duplicate::duplicate_item;
use serde::Deserialize;
use spec_test_utils::Case;
use test_generator::test_resources;
use types::{
    fulu::primitives::{ColumnIndex, CustodyIndex},
    nonstandard::Phase,
    phase0::primitives::NodeId,
    preset::{Mainnet, Minimal, Preset},
};

use crate::{compute_columns_for_custody_group, get_custody_groups};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetCustodyGroupsMeta {
    node_id: NodeId,
    custody_group_count: u64,
    result: HashSet<CustodyIndex>,
}

#[duplicate_item(
    glob                                                                           function_name                preset;
    ["consensus-spec-tests/tests/mainnet/fulu/networking/get_custody_groups/*/*"] [get_custody_groups_mainnet] [Mainnet];
    ["consensus-spec-tests/tests/minimal/fulu/networking/get_custody_groups/*/*"] [get_custody_groups_minimal] [Minimal];
)]
#[test_resources(glob)]
fn function_name(case: Case) {
    run_get_custody_groups_case::<preset>(case);
}

fn run_get_custody_groups_case<P: Preset>(case: Case) {
    let GetCustodyGroupsMeta {
        node_id,
        custody_group_count,
        result,
    } = case.yaml("meta");

    let config = P::default_config().start_and_stay_in(Phase::Fulu);
    let mut raw_node_id = [0u8; 32];
    node_id.into_raw().to_big_endian(&mut raw_node_id);

    let custody_groups = get_custody_groups(raw_node_id, custody_group_count, &config)
        .expect("custody groups must be valid");

    assert_eq!(custody_groups, result);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputeColumnsForCustodyGroup {
    custody_group: CustodyIndex,
    result: Vec<ColumnIndex>,
}

#[duplicate_item(
    glob                                                                                         function_name                               preset;
    ["consensus-spec-tests/tests/mainnet/fulu/networking/compute_columns_for_custody_group/*/*"] [compute_columns_for_custody_group_mainnet] [Mainnet];
    ["consensus-spec-tests/tests/minimal/fulu/networking/compute_columns_for_custody_group/*/*"] [compute_columns_for_custody_group_minimal] [Minimal];
)]
#[test_resources(glob)]
fn function_name(case: Case) {
    run_compute_columns_for_custody_group::<preset>(case);
}

fn run_compute_columns_for_custody_group<P: Preset>(case: Case) {
    let ComputeColumnsForCustodyGroup {
        custody_group,
        result,
    } = case.yaml("meta");

    let config = P::default_config().start_and_stay_in(Phase::Fulu);
    let columns = compute_columns_for_custody_group::<P>(custody_group, &config)
        .expect("custody group must be valid");

    assert_eq!(columns.collect::<Vec<_>>(), result);
}
