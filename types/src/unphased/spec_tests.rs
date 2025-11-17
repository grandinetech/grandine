use core::fmt::Debug;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use spec_test_utils::Case;
use ssz::{SszHash, SszReadDefault, SszWrite};

use crate::phase0::primitives::H256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Roots {
    root: H256,
}

// This is nearly the same as `ssz::spec_tests::run_valid_case`, but reuse isn't worth the trouble.
pub fn run_spec_test_case<T>(case: Case)
where
    T: SszReadDefault + SszWrite + SszHash + DeserializeOwned + Serialize + PartialEq + Debug,
{
    let expected_ssz_bytes = case.bytes("serialized.ssz_snappy");
    let yaml_value = case.yaml::<T>("value");
    let Roots { root } = case.yaml("roots");

    assert_matches_consensus_specs(expected_ssz_bytes.as_slice(), &yaml_value, root);
    serde_utils::assert_json_contains_no_numbers(&yaml_value);
    assert_survives_bincode_round_trip(&yaml_value);
}

fn assert_matches_consensus_specs<T>(expected_ssz_bytes: &[u8], yaml_value: &T, root: H256)
where
    T: SszReadDefault + SszWrite + SszHash + PartialEq + Debug,
{
    let actual_ssz_bytes = yaml_value.to_ssz().expect("SSZ encoding should succeed");
    let ssz_value = T::from_ssz_default(expected_ssz_bytes).expect("SSZ decoding should succeed");

    assert_eq!(actual_ssz_bytes, expected_ssz_bytes);
    assert_eq!(&ssz_value, yaml_value);
    assert_eq!(yaml_value.hash_tree_root(), root);
}

fn assert_survives_bincode_round_trip<T>(input: &T)
where
    T: DeserializeOwned + Serialize + PartialEq + Debug,
{
    let bincode_bytes = bincode::serialize(input).expect("serialization to Bincode should succeed");
    let output = bincode::deserialize::<T>(bincode_bytes.as_slice())
        .expect("deserialization from Bincode should succeed");

    assert_eq!(&output, input);
}
