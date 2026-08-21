use core::fmt::Debug;
use std::collections::HashMap;

use duplicate::duplicate_item;
use serde_json::Value;
use spec_test_utils::Case;
use ssz_derive::Ssz;
use static_assertions::assert_not_impl_any;
use test_generator::test_resources;
use typenum::{
    Prod, U0, U1, U3, U4, U7, U8, U9, U16, U32, U52, U64, U255, U256, U257, U512, U1024, U2048,
};

use crate::{
    bit_list::BitList,
    bit_vector::BitVector,
    byte_list::ByteList,
    byte_vector::ByteVector,
    contiguous_list::ContiguousList,
    contiguous_vector::ContiguousVector,
    error::{ReadError, WriteError},
    merkle_tree,
    porcelain::{SszHash, SszRead, SszReadDefault, SszSize, SszWrite},
    progressive_bit_list::ProgressiveBitList,
    progressive_list::ProgressiveList,
    size::Size,
    uint256::Uint256,
};

type U524288 = Prod<U512, U1024>;

// --- Progressive container types matching ssz-spec-tests fixtures ---

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [1]))]
struct SampleOneField {
    a: u16,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [1, 0, 1]))]
struct SampleSquare {
    side: u16,
    color: u8,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [0, 1, 1]))]
struct SampleCircle {
    radius: u16,
    color: u8,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [0, 0, 1]))]
struct SampleLeadingGaps {
    c: u32,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [1, 0, 0, 1, 0, 1]))]
struct SampleMultipleGaps {
    a: u8,
    b: u16,
    c: u32,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [1, 1, 1]))]
struct SampleProgressiveFields {
    head: u64,
    numbers: ProgressiveList<u64>,
    flags: ProgressiveBitList<U2048>,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]))]
struct SampleLevelBoundary {
    first: u16,
    last: u8,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]))]
struct SampleWidestLayout {
    tail: u8,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [1, 0, 1]))]
struct SampleBoundedListField {
    head: u64,
    body: ContiguousList<u16, U4>,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [1, 0, 1]))]
struct SampleInnerShape {
    x: u16,
    y: u8,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [1, 0, 1]))]
struct SampleOuterShape {
    head: u8,
    inner: SampleInnerShape,
}

// --- Container types ---

#[derive(Debug, Ssz)]
#[ssz(internal)]
struct SampleShapeContainer {
    tag: u8,
    shape: SampleSquare,
}

#[derive(Debug, Ssz)]
#[ssz(internal)]
struct SampleContainerWithProgressiveList {
    a: u16,
    b: ProgressiveList<u64>,
    c: u8,
}

// --- Compatible union types ---

#[derive(Debug)]
enum SampleUnionShape {
    Square1(SampleSquare),
    Circle(SampleCircle),
    Square127(SampleSquare),
}

impl SszSize for SampleUnionShape {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl<C> SszRead<C> for SampleUnionShape {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let (&selector, payload) = bytes.split_first().ok_or(ReadError::Custom {
            message: "empty union",
        })?;

        match selector {
            1 => Ok(Self::Square1(SampleSquare::from_ssz(context, payload)?)),
            2 => Ok(Self::Circle(SampleCircle::from_ssz(context, payload)?)),
            127 => Ok(Self::Square127(SampleSquare::from_ssz(context, payload)?)),
            _ => Err(ReadError::Custom {
                message: "invalid union selector",
            }),
        }
    }
}

impl SszWrite for SampleUnionShape {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        let (selector, encoded) = match self {
            Self::Square1(v) => (1, v.to_ssz()?),
            Self::Circle(v) => (2, v.to_ssz()?),
            Self::Square127(v) => (127, v.to_ssz()?),
        };
        bytes.push(selector);
        bytes.extend(encoded);
        Ok(())
    }
}

impl SszHash for SampleUnionShape {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> crate::H256 {
        let (selector, root) = match self {
            Self::Square1(v) => (1, v.hash_tree_root()),
            Self::Circle(v) => (2, v.hash_tree_root()),
            Self::Square127(v) => (127, v.hash_tree_root()),
        };
        merkle_tree::mix_in_length(root, selector)
    }
}

#[derive(Debug)]
enum SampleNestedUnionShape {
    Shape(SampleUnionShape),
}

impl SszSize for SampleNestedUnionShape {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl<C> SszRead<C> for SampleNestedUnionShape {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let (&selector, payload) = bytes.split_first().ok_or(ReadError::Custom {
            message: "empty union",
        })?;

        match selector {
            1 => Ok(Self::Shape(SampleUnionShape::from_ssz(context, payload)?)),
            _ => Err(ReadError::Custom {
                message: "invalid union selector",
            }),
        }
    }
}

impl SszWrite for SampleNestedUnionShape {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        let Self::Shape(v) = self;
        bytes.push(1);
        v.write_variable(bytes)?;
        Ok(())
    }
}

impl SszHash for SampleNestedUnionShape {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> crate::H256 {
        let Self::Shape(v) = self;
        merkle_tree::mix_in_length(v.hash_tree_root(), 1)
    }
}

#[derive(Debug)]
enum SampleNumbers {
    V1(ContiguousList<u16, U16>),
    V2(ContiguousList<u16, U16>),
}

impl SszSize for SampleNumbers {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl<C> SszRead<C> for SampleNumbers {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let (&selector, payload) = bytes.split_first().ok_or(ReadError::Custom {
            message: "empty union",
        })?;

        match selector {
            1 => Ok(Self::V1(ContiguousList::from_ssz(context, payload)?)),
            2 => Ok(Self::V2(ContiguousList::from_ssz(context, payload)?)),
            _ => Err(ReadError::Custom {
                message: "invalid union selector",
            }),
        }
    }
}

impl SszWrite for SampleNumbers {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::V1(v) => {
                bytes.push(1);
                v.write_variable(bytes)?;
            }
            Self::V2(v) => {
                bytes.push(2);
                v.write_variable(bytes)?;
            }
        }
        Ok(())
    }
}

impl SszHash for SampleNumbers {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> crate::H256 {
        let (selector, root) = match self {
            Self::V1(v) => (1, v.hash_tree_root()),
            Self::V2(v) => (2, v.hash_tree_root()),
        };
        merkle_tree::mix_in_length(root, selector)
    }
}

#[derive(Debug)]
enum SampleEmptyProne {
    V1(ProgressiveList<u16>),
    V2(ProgressiveList<u8>),
}

impl SszSize for SampleEmptyProne {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl<C> SszRead<C> for SampleEmptyProne {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let (&selector, payload) = bytes.split_first().ok_or(ReadError::Custom {
            message: "empty union",
        })?;

        match selector {
            1 => Ok(Self::V1(ProgressiveList::from_ssz(context, payload)?)),
            2 => Ok(Self::V2(ProgressiveList::from_ssz(context, payload)?)),
            _ => Err(ReadError::Custom {
                message: "invalid union selector",
            }),
        }
    }
}

impl SszWrite for SampleEmptyProne {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::V1(v) => {
                bytes.push(1);
                v.write_variable(bytes)?;
            }
            Self::V2(v) => {
                bytes.push(2);
                v.write_variable(bytes)?;
            }
        }
        Ok(())
    }
}

impl SszHash for SampleEmptyProne {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> crate::H256 {
        let (selector, root) = match self {
            Self::V1(v) => (1, v.hash_tree_root()),
            Self::V2(v) => (2, v.hash_tree_root()),
        };
        merkle_tree::mix_in_length(root, selector)
    }
}

#[derive(Debug, Ssz)]
#[ssz(internal)]
struct SampleUnionShapeContainer {
    tag: u64,
    body: SampleUnionShape,
}

#[derive(Debug, Ssz)]
#[ssz(internal, stable(active = [1, 0, 1]))]
struct SampleUnionShapeProgressiveContainer {
    tag: u64,
    body: SampleUnionShape,
}

// --- Fixture parsing ---

struct SszFixture {
    serialized: Vec<u8>,
    root: crate::H256,
    raw_bytes: Option<Vec<u8>>,
    has_rejection: bool,
}

fn decode_hex(hex_str: &str) -> Vec<u8> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if stripped.is_empty() {
        return Vec::new();
    }
    hex::decode(stripped).expect("valid hex string")
}

fn load_fixture(case: Case) -> SszFixture {
    let file_bytes = case.read_file();
    let json: HashMap<String, Value> =
        serde_json::from_slice(&file_bytes).expect("valid JSON fixture");

    let fixture = json
        .into_values()
        .next()
        .expect("fixture should have at least one test case");

    let serialized_hex = fixture["serialized"]
        .as_str()
        .expect("serialized should be a string");
    let root_hex = fixture["root"].as_str().expect("root should be a string");

    let serialized = decode_hex(serialized_hex);

    let root = if root_hex.is_empty() {
        crate::H256::zero()
    } else {
        let root_bytes = decode_hex(root_hex);
        crate::H256::from_slice(&root_bytes)
    };

    let has_rejection = fixture.get("rejectionReason").is_some_and(Value::is_string);

    let raw_bytes = fixture
        .get("rawBytes")
        .and_then(Value::as_str)
        .map(decode_hex);

    SszFixture {
        serialized,
        root,
        raw_bytes,
        has_rejection,
    }
}

fn run_valid<T: SszReadDefault + SszWrite + SszHash + Debug>(fixture: &SszFixture) {
    let decoded = T::from_ssz_default(&fixture.serialized).expect("SSZ decoding should succeed");
    let re_encoded = decoded.to_ssz().expect("SSZ encoding should succeed");

    assert_eq!(re_encoded, fixture.serialized, "SSZ round-trip mismatch");
    assert_eq!(
        decoded.hash_tree_root(),
        fixture.root,
        "hash tree root mismatch"
    );
}

fn run_invalid<T: SszReadDefault + Debug>(fixture: &SszFixture) {
    let bytes = fixture.raw_bytes.as_ref().unwrap_or(&fixture.serialized);
    T::from_ssz_default(bytes).expect_err("SSZ decoding should fail");
}

fn run_fixture<T: SszReadDefault + SszWrite + SszHash + Debug>(case: Case) {
    let fixture = load_fixture(case);
    if fixture.has_rejection {
        run_invalid::<T>(&fixture);
    } else {
        run_valid::<T>(&fixture);
    }
}

// --- Tests ---

// Each entry maps a glob pattern to a Rust type. The test function auto-detects
// valid vs. invalid cases based on the presence of `rejectionReason` in the fixture.
#[duplicate_item(
    glob                                                                                                                           function_name                                  ssz_type;
    // === test_basic_types ===
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_boolean_*.json"]                                                       [boolean]                                      [bool];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_uint8_*.json"]                                                         [uint8]                                        [u8];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_uint16_[moz]*.json"]                                                   [uint16]                                       [u16];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_uint32_[moz]*.json"]                                                   [uint32]                                       [u32];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_uint64_[moz]*.json"]                                                   [uint64]                                       [u64];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_uint128_*.json"]                                                       [uint128]                                      [u128];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_uint256_*.json"]                                                       [uint256]                                      [Uint256];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_bytes4_*.json"]                                                        [bytes4]                                       [ByteVector<U4>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_bytes32_[itz]*.json"]                                                  [bytes32]                                      [ByteVector<U32>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_bytes52_*.json"]                                                       [bytes52]                                      [ByteVector<U52>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_bytes64_*.json"]                                                       [bytes64]                                      [ByteVector<U64>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_bytelist_*.json"]                                                      [bytelist]                                     [ByteList<U524288>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_bitlist_*.json"]                                                       [bitlist_16]                                   [BitList<U16>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_bitvector8_*.json"]                                                    [bitvector_8]                                  [BitVector<U8>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_bitvector64_*.json"]                                                   [bitvector_64]                                 [BitVector<U64>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_uint16_vector3_*.json"]                                                [uint16_vector3]                               [ContiguousVector<u16, U3>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_uint64_vector4_*.json"]                                                [uint64_vector4]                               [ContiguousVector<u64, U4>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_uint32_list_*.json"]                                                   [uint32_list_16]                               [ContiguousList<u32, U16>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_basic_types/test_bytes32_list_*.json"]                                                  [bytes32_list_8]                               [ContiguousList<ByteVector<U32>, U8>];
    // === test_merkleization_boundaries ===
    ["ssz-spec-tests/fixtures/ssz/ssz/test_merkleization_boundaries/test_bitvector_length_one_all_set.json"]                       [boundary_bitvector_1]                         [BitVector<U1>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_merkleization_boundaries/test_bitvector_length_seven_all_set.json"]                     [boundary_bitvector_7]                         [BitVector<U7>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_merkleization_boundaries/test_bitvector_length_nine_all_set.json"]                      [boundary_bitvector_9]                         [BitVector<U9>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_merkleization_boundaries/test_bitvector_length_255_all_set.json"]                       [boundary_bitvector_255]                       [BitVector<U255>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_merkleization_boundaries/test_bitvector_length_256_all_set.json"]                       [boundary_bitvector_256]                       [BitVector<U256>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_merkleization_boundaries/test_bitvector_length_257_all_set.json"]                       [boundary_bitvector_257]                       [BitVector<U257>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_merkleization_boundaries/test_bitlist_filled_to_chunk_boundary_limit.json"]             [boundary_bitlist_256]                         [BitList<U256>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_merkleization_boundaries/test_uint64_list_with_misaligned_chunk_count.json"]            [boundary_uint64_list_32]                      [ContiguousList<u64, U32>];
    // === test_decode_failure_smoke ===
    ["ssz-spec-tests/fixtures/ssz/ssz/test_decode_failure_smoke/test_ssz_decode_failure_bitlist_exceeds_limit.json"]               [decode_failure_bitlist_exceeds_limit]         [BitList<U8>];
    // === test_progressive_types ===
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_types/test_progressive_bitlist_*.json"]                                     [progressive_bitlist]                          [ProgressiveBitList<U2048>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_types/test_progressive_list_[efs]*.json"]                                   [progressive_list_uint64]                      [ProgressiveList<u64>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_types/test_progressive_list_opens_*.json"]                                  [progressive_list_uint64_opens]                [ProgressiveList<u64>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_types/test_progressive_list_of_composites_*.json"]                          [progressive_list_bytes32]                     [ProgressiveList<ByteVector<U32>>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_types/test_progressive_list_of_variable_size_elements.json"]                [progressive_list_nested]                      [ProgressiveList<ProgressiveList<u16>>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_types/test_container_with_*progressive_list_field.json"]                    [container_with_progressive_list]              [SampleContainerWithProgressiveList];
    // === test_progressive_containers ===
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_single_field.json"]                   [progressive_container_single_field]           [SampleOneField];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_square.json"]                         [progressive_container_square]                 [SampleSquare];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_decode_failure_trailing_byte.json"]   [progressive_container_trailing_byte]          [SampleSquare];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_circle.json"]                         [progressive_container_circle]                 [SampleCircle];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_leading_gaps.json"]                   [progressive_container_leading_gaps]           [SampleLeadingGaps];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_multiple_gaps.json"]                  [progressive_container_multiple_gaps]          [SampleMultipleGaps];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_with_progressive_fields.json"]        [progressive_container_with_fields]            [SampleProgressiveFields];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_opens_the_fourth_level.json"]         [progressive_container_fourth_level]           [SampleLevelBoundary];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_widest_layout.json"]                  [progressive_container_widest_layout]          [SampleWidestLayout];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_with_bounded_list_field.json"]        [progressive_container_bounded_list]           [SampleBoundedListField];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_with_empty_variable_field.json"]      [progressive_container_empty_variable]         [SampleBoundedListField];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_container_decode_failure_first_offset.json"]    [progressive_container_bad_offset]             [SampleBoundedListField];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_nested_progressive_containers.json"]                        [nested_progressive_containers]                [SampleOuterShape];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_progressive_list_of_progressive_containers.json"]           [progressive_list_of_containers]               [ProgressiveList<SampleSquare>];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_progressive_containers/test_container_holding_a_progressive_container.json"]            [container_holding_progressive]                [SampleShapeContainer];
    // === test_compatible_unions ===
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_first_option.json"]                             [union_first_option]                           [SampleUnionShape];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_second_option.json"]                            [union_second_option]                          [SampleUnionShape];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_highest_selector.json"]                         [union_highest_selector]                       [SampleUnionShape];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_decode_failure_empty_input.json"]               [union_decode_failure_empty]                   [SampleUnionShape];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_decode_failure_reserved_zero_selector.json"]    [union_decode_failure_zero_selector]           [SampleUnionShape];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_decode_failure_trailing_byte.json"]             [union_decode_failure_trailing]                [SampleUnionShape];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_decode_failure_truncated_payload.json"]         [union_decode_failure_truncated]               [SampleUnionShape];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_decode_failure_undeclared_selector.json"]       [union_decode_failure_undeclared]              [SampleUnionShape];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_of_unions.json"]                                [union_of_unions]                              [SampleNestedUnionShape];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_variable_size_option.json"]                     [union_variable_size_option]                   [SampleNumbers];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_empty_variable_size_option.json"]               [union_empty_variable_size]                    [SampleNumbers];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_empty_list_options_separated_by_the_selector.json"]  [union_empty_list_sel1]                   [SampleEmptyProne];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_compatible_union_other_empty_list_option.json"]                  [union_empty_list_sel2]                        [SampleEmptyProne];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_container_holding_a_compatible_union.json"]                      [container_holding_union]                      [SampleUnionShapeContainer];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_progressive_container_holding_a_compatible_union.json"]          [progressive_container_holding_union]          [SampleUnionShapeProgressiveContainer];
    ["ssz-spec-tests/fixtures/ssz/ssz/test_compatible_unions/test_progressive_list_of_compatible_unions.json"]                     [progressive_list_of_unions]                   [ProgressiveList<SampleUnionShape>];
)]
#[test_resources(glob)]
fn function_name(case: Case) {
    run_fixture::<ssz_type>(case);
}

// 0-length vectors are invalid SSZ types and must not implement SSZ traits.
assert_not_impl_any!(ContiguousVector<bool, U0>: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(ContiguousVector<u8, U0>: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(ContiguousVector<u16, U0>: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(ContiguousVector<u32, U0>: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(ContiguousVector<u64, U0>: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(ContiguousVector<u128, U0>: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(ContiguousVector<Uint256, U0>: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(BitVector<U0>: SszSize, SszReadDefault, SszWrite, SszHash);
