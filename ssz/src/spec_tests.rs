use core::fmt::Debug;

use duplicate::duplicate_item;
use serde::{de::DeserializeOwned, Deserialize};
use spec_test_utils::Case;
use ssz_derive::Ssz;
use static_assertions::assert_not_impl_any;
use test_generator::test_resources;
use typenum::{U0, U1, U1024, U128, U16, U2, U256, U3, U31, U32, U4, U5, U512, U513, U6, U8, U9};

use crate::{
    bit_list::BitList,
    bit_vector::BitVector,
    byte_list::ByteList,
    contiguous_list::ContiguousList,
    contiguous_vector::ContiguousVector,
    persistent_vector::PersistentVector,
    porcelain::{SszHash, SszReadDefault, SszSize, SszUnify, SszWrite},
    uint256::Uint256,
};

// `u128` values are stored in `value.yaml` files as [single-quoted scalars].
// [`serde_yaml::Deserializer::deserialize_u*`] methods expect a [plain scalar].
// This is surprising, because [`serde_yaml::Deserializer::deserialize_str`] allows plain scalars.
//
// [single-quoted scalars]:                       https://yaml.org/spec/1.2.2/ext/glossary/#single-quoted-scalar
// [plain scalar]:                                https://yaml.org/spec/1.2.2/ext/glossary/#plain-scalar
// [`serde_yaml::Deserializer::deserialize_u*`]:  https://github.com/dtolnay/serde-yaml/blob/1e06dd7fdb4a0f967d96c979666eedf4224b5180/src/de.rs#L1303-L1345
// [`serde_yaml::Deserializer::deserialize_str`]: https://github.com/dtolnay/serde-yaml/blob/1e06dd7fdb4a0f967d96c979666eedf4224b5180/src/de.rs#L1383-L1404
#[derive(PartialEq, Eq, Debug, Deserialize, Ssz)]
#[serde(transparent)]
#[ssz(internal, transparent)]
struct StringyU128 {
    #[serde(with = "serde_utils::string_or_native")]
    value: u128,
}

#[derive(PartialEq, Eq, Debug, Deserialize, Ssz)]
#[serde(deny_unknown_fields, rename_all = "UPPERCASE")]
#[ssz(internal)]
struct SingleFieldTestStruct {
    a: u8,
}

#[derive(PartialEq, Eq, Debug, Deserialize, Ssz)]
#[serde(deny_unknown_fields, rename_all = "UPPERCASE")]
#[ssz(internal)]
struct SmallTestStruct {
    a: u16,
    b: u16,
}

#[derive(PartialEq, Eq, Debug, Deserialize, Ssz)]
#[serde(deny_unknown_fields, rename_all = "UPPERCASE")]
#[ssz(internal)]
struct FixedTestStruct {
    a: u8,
    b: u64,
    c: u32,
}

#[derive(PartialEq, Eq, Debug, Deserialize, Ssz)]
#[serde(deny_unknown_fields, rename_all = "UPPERCASE")]
#[ssz(internal)]
struct VarTestStruct {
    a: u16,
    b: ContiguousList<u16, U1024>,
    c: u8,
}

#[derive(PartialEq, Eq, Debug, Deserialize, Ssz)]
#[serde(deny_unknown_fields, rename_all = "UPPERCASE")]
#[ssz(internal)]
struct ComplexTestStruct {
    a: u16,
    b: ContiguousList<u16, U128>,
    c: u8,
    d: ByteList<U256>,
    e: VarTestStruct,
    f: ContiguousVector<FixedTestStruct, U4>,
    g: ContiguousVector<VarTestStruct, U2>,
}

#[derive(PartialEq, Eq, Debug, Deserialize, Ssz)]
#[serde(deny_unknown_fields, rename_all = "UPPERCASE")]
#[ssz(internal)]
struct BitsStruct {
    a: BitList<U5>,
    b: BitVector<U2>,
    c: BitVector<U1>,
    d: BitList<U6>,
    e: BitVector<U8>,
}

mod valid {
    use super::*;

    #[duplicate_item(
        glob                                                                                          function_name              ssz_type;
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_bool_1_*"]            [basic_vector_bool_1]      [ContiguousVector<bool, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_bool_2_*"]            [basic_vector_bool_2]      [ContiguousVector<bool, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_bool_3_*"]            [basic_vector_bool_3]      [ContiguousVector<bool, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_bool_4_*"]            [basic_vector_bool_4]      [ContiguousVector<bool, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_bool_5_*"]            [basic_vector_bool_5]      [ContiguousVector<bool, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_bool_8_*"]            [basic_vector_bool_8]      [ContiguousVector<bool, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_bool_16_*"]           [basic_vector_bool_16]     [ContiguousVector<bool, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_bool_31_*"]           [basic_vector_bool_31]     [ContiguousVector<bool, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_bool_512_*"]          [basic_vector_bool_512]    [ContiguousVector<bool, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_bool_513_*"]          [basic_vector_bool_513]    [ContiguousVector<bool, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint8_1_*"]           [basic_vector_uint8_1]     [ContiguousVector<u8, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint8_2_*"]           [basic_vector_uint8_2]     [ContiguousVector<u8, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint8_3_*"]           [basic_vector_uint8_3]     [ContiguousVector<u8, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint8_4_*"]           [basic_vector_uint8_4]     [ContiguousVector<u8, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint8_5_*"]           [basic_vector_uint8_5]     [ContiguousVector<u8, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint8_8_*"]           [basic_vector_uint8_8]     [ContiguousVector<u8, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint8_16_*"]          [basic_vector_uint8_16]    [ContiguousVector<u8, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint8_31_*"]          [basic_vector_uint8_31]    [ContiguousVector<u8, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint8_512_*"]         [basic_vector_uint8_512]   [ContiguousVector<u8, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint8_513_*"]         [basic_vector_uint8_513]   [ContiguousVector<u8, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint16_1_*"]          [basic_vector_uint16_1]    [ContiguousVector<u16, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint16_2_*"]          [basic_vector_uint16_2]    [ContiguousVector<u16, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint16_3_*"]          [basic_vector_uint16_3]    [ContiguousVector<u16, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint16_4_*"]          [basic_vector_uint16_4]    [ContiguousVector<u16, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint16_5_*"]          [basic_vector_uint16_5]    [ContiguousVector<u16, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint16_8_*"]          [basic_vector_uint16_8]    [ContiguousVector<u16, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint16_16_*"]         [basic_vector_uint16_16]   [ContiguousVector<u16, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint16_31_*"]         [basic_vector_uint16_31]   [ContiguousVector<u16, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint16_512_*"]        [basic_vector_uint16_512]  [ContiguousVector<u16, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint16_513_*"]        [basic_vector_uint16_513]  [ContiguousVector<u16, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint32_1_*"]          [basic_vector_uint32_1]    [ContiguousVector<u32, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint32_2_*"]          [basic_vector_uint32_2]    [ContiguousVector<u32, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint32_3_*"]          [basic_vector_uint32_3]    [ContiguousVector<u32, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint32_4_*"]          [basic_vector_uint32_4]    [ContiguousVector<u32, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint32_5_*"]          [basic_vector_uint32_5]    [ContiguousVector<u32, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint32_8_*"]          [basic_vector_uint32_8]    [ContiguousVector<u32, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint32_16_*"]         [basic_vector_uint32_16]   [ContiguousVector<u32, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint32_31_*"]         [basic_vector_uint32_31]   [ContiguousVector<u32, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint32_512_*"]        [basic_vector_uint32_512]  [ContiguousVector<u32, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint32_513_*"]        [basic_vector_uint32_513]  [ContiguousVector<u32, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint64_1_*"]          [basic_vector_uint64_1]    [ContiguousVector<u64, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint64_2_*"]          [basic_vector_uint64_2]    [ContiguousVector<u64, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint64_3_*"]          [basic_vector_uint64_3]    [ContiguousVector<u64, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint64_4_*"]          [basic_vector_uint64_4]    [ContiguousVector<u64, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint64_5_*"]          [basic_vector_uint64_5]    [ContiguousVector<u64, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint64_8_*"]          [basic_vector_uint64_8]    [ContiguousVector<u64, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint64_16_*"]         [basic_vector_uint64_16]   [ContiguousVector<u64, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint64_31_*"]         [basic_vector_uint64_31]   [ContiguousVector<u64, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint64_512_*"]        [basic_vector_uint64_512]  [ContiguousVector<u64, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint64_513_*"]        [basic_vector_uint64_513]  [ContiguousVector<u64, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint128_1_*"]         [basic_vector_uint128_1]   [ContiguousVector<StringyU128, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint128_2_*"]         [basic_vector_uint128_2]   [ContiguousVector<StringyU128, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint128_3_*"]         [basic_vector_uint128_3]   [ContiguousVector<StringyU128, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint128_4_*"]         [basic_vector_uint128_4]   [ContiguousVector<StringyU128, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint128_5_*"]         [basic_vector_uint128_5]   [ContiguousVector<StringyU128, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint128_8_*"]         [basic_vector_uint128_8]   [ContiguousVector<StringyU128, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint128_16_*"]        [basic_vector_uint128_16]  [ContiguousVector<StringyU128, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint128_31_*"]        [basic_vector_uint128_31]  [ContiguousVector<StringyU128, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint128_512_*"]       [basic_vector_uint128_512] [ContiguousVector<StringyU128, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint128_513_*"]       [basic_vector_uint128_513] [ContiguousVector<StringyU128, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint256_1_*"]         [basic_vector_uint256_1]   [ContiguousVector<Uint256, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint256_2_*"]         [basic_vector_uint256_2]   [ContiguousVector<Uint256, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint256_3_*"]         [basic_vector_uint256_3]   [ContiguousVector<Uint256, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint256_4_*"]         [basic_vector_uint256_4]   [ContiguousVector<Uint256, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint256_5_*"]         [basic_vector_uint256_5]   [ContiguousVector<Uint256, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint256_8_*"]         [basic_vector_uint256_8]   [ContiguousVector<Uint256, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint256_16_*"]        [basic_vector_uint256_16]  [ContiguousVector<Uint256, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint256_31_*"]        [basic_vector_uint256_31]  [ContiguousVector<Uint256, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint256_512_*"]       [basic_vector_uint256_512] [ContiguousVector<Uint256, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/valid/*_uint256_513_*"]       [basic_vector_uint256_513] [ContiguousVector<Uint256, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/valid/*_1_*"]                      [bitlist_1]                [BitList<U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/valid/*_2_*"]                      [bitlist_2]                [BitList<U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/valid/*_3_*"]                      [bitlist_3]                [BitList<U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/valid/*_4_*"]                      [bitlist_4]                [BitList<U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/valid/*_5_*"]                      [bitlist_5]                [BitList<U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/valid/*_8_*"]                      [bitlist_8]                [BitList<U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/valid/*_16_*"]                     [bitlist_16]               [BitList<U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/valid/*_31_*"]                     [bitlist_31]               [BitList<U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/valid/*_512_*"]                    [bitlist_512]              [BitList<U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/valid/*_513_*"]                    [bitlist_513]              [BitList<U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/valid/*_1_*"]                    [bitvector_1]              [BitVector<U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/valid/*_2_*"]                    [bitvector_2]              [BitVector<U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/valid/*_3_*"]                    [bitvector_3]              [BitVector<U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/valid/*_4_*"]                    [bitvector_4]              [BitVector<U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/valid/*_5_*"]                    [bitvector_5]              [BitVector<U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/valid/*_8_*"]                    [bitvector_8]              [BitVector<U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/valid/*_16_*"]                   [bitvector_16]             [BitVector<U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/valid/*_31_*"]                   [bitvector_31]             [BitVector<U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/valid/*_512_*"]                  [bitvector_512]            [BitVector<U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/valid/*_513_*"]                  [bitvector_513]            [BitVector<U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/boolean/valid/*"]                          [boolean]                  [bool];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/valid/BitsStruct_*"]            [bits_struct]              [BitsStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/valid/ComplexTestStruct_*"]     [complex_test_struct]      [ComplexTestStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/valid/FixedTestStruct_*"]       [fixed_test_struct]        [FixedTestStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/valid/SingleFieldTestStruct_*"] [single_field_test_struct] [SingleFieldTestStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/valid/SmallTestStruct_*"]       [small_test_struct]        [SmallTestStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/valid/VarTestStruct_*"]         [var_test_struct]          [VarTestStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/valid/*_8_*"]                        [uints_8]                  [u8];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/valid/*_16_*"]                       [uints_16]                 [u16];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/valid/*_32_*"]                       [uints_32]                 [u32];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/valid/*_64_*"]                       [uints_64]                 [u64];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/valid/*_128_*"]                      [uints_128]                [StringyU128];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/valid/*_256_*"]                      [uints_256]                [Uint256];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_valid_case::<ssz_type>(case);
    }
}

mod invalid {
    use super::*;

    #[duplicate_item(
        glob                                                                                            function_name              ssz_type;
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_bool_1_*"]            [basic_vector_bool_1]      [ContiguousVector<bool, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_bool_2_*"]            [basic_vector_bool_2]      [ContiguousVector<bool, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_bool_3_*"]            [basic_vector_bool_3]      [ContiguousVector<bool, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_bool_4_*"]            [basic_vector_bool_4]      [ContiguousVector<bool, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_bool_5_*"]            [basic_vector_bool_5]      [ContiguousVector<bool, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_bool_8_*"]            [basic_vector_bool_8]      [ContiguousVector<bool, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_bool_16_*"]           [basic_vector_bool_16]     [ContiguousVector<bool, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_bool_31_*"]           [basic_vector_bool_31]     [ContiguousVector<bool, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_bool_512_*"]          [basic_vector_bool_512]    [ContiguousVector<bool, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_bool_513_*"]          [basic_vector_bool_513]    [ContiguousVector<bool, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint8_1_*"]           [basic_vector_uint8_1]     [ContiguousVector<u8, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint8_2_*"]           [basic_vector_uint8_2]     [ContiguousVector<u8, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint8_3_*"]           [basic_vector_uint8_3]     [ContiguousVector<u8, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint8_4_*"]           [basic_vector_uint8_4]     [ContiguousVector<u8, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint8_5_*"]           [basic_vector_uint8_5]     [ContiguousVector<u8, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint8_8_*"]           [basic_vector_uint8_8]     [ContiguousVector<u8, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint8_16_*"]          [basic_vector_uint8_16]    [ContiguousVector<u8, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint8_31_*"]          [basic_vector_uint8_31]    [ContiguousVector<u8, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint8_512_*"]         [basic_vector_uint8_512]   [ContiguousVector<u8, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint8_513_*"]         [basic_vector_uint8_513]   [ContiguousVector<u8, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint16_1_*"]          [basic_vector_uint16_1]    [ContiguousVector<u16, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint16_2_*"]          [basic_vector_uint16_2]    [ContiguousVector<u16, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint16_3_*"]          [basic_vector_uint16_3]    [ContiguousVector<u16, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint16_4_*"]          [basic_vector_uint16_4]    [ContiguousVector<u16, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint16_5_*"]          [basic_vector_uint16_5]    [ContiguousVector<u16, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint16_8_*"]          [basic_vector_uint16_8]    [ContiguousVector<u16, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint16_16_*"]         [basic_vector_uint16_16]   [ContiguousVector<u16, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint16_31_*"]         [basic_vector_uint16_31]   [ContiguousVector<u16, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint16_512_*"]        [basic_vector_uint16_512]  [ContiguousVector<u16, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint16_513_*"]        [basic_vector_uint16_513]  [ContiguousVector<u16, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint32_1_*"]          [basic_vector_uint32_1]    [ContiguousVector<u32, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint32_2_*"]          [basic_vector_uint32_2]    [ContiguousVector<u32, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint32_3_*"]          [basic_vector_uint32_3]    [ContiguousVector<u32, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint32_4_*"]          [basic_vector_uint32_4]    [ContiguousVector<u32, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint32_5_*"]          [basic_vector_uint32_5]    [ContiguousVector<u32, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint32_8_*"]          [basic_vector_uint32_8]    [ContiguousVector<u32, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint32_16_*"]         [basic_vector_uint32_16]   [ContiguousVector<u32, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint32_31_*"]         [basic_vector_uint32_31]   [ContiguousVector<u32, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint32_512_*"]        [basic_vector_uint32_512]  [ContiguousVector<u32, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint32_513_*"]        [basic_vector_uint32_513]  [ContiguousVector<u32, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint64_1_*"]          [basic_vector_uint64_1]    [ContiguousVector<u64, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint64_2_*"]          [basic_vector_uint64_2]    [ContiguousVector<u64, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint64_3_*"]          [basic_vector_uint64_3]    [ContiguousVector<u64, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint64_4_*"]          [basic_vector_uint64_4]    [ContiguousVector<u64, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint64_5_*"]          [basic_vector_uint64_5]    [ContiguousVector<u64, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint64_8_*"]          [basic_vector_uint64_8]    [ContiguousVector<u64, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint64_16_*"]         [basic_vector_uint64_16]   [ContiguousVector<u64, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint64_31_*"]         [basic_vector_uint64_31]   [ContiguousVector<u64, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint64_512_*"]        [basic_vector_uint64_512]  [ContiguousVector<u64, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint64_513_*"]        [basic_vector_uint64_513]  [ContiguousVector<u64, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint128_1_*"]         [basic_vector_uint128_1]   [ContiguousVector<StringyU128, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint128_2_*"]         [basic_vector_uint128_2]   [ContiguousVector<StringyU128, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint128_3_*"]         [basic_vector_uint128_3]   [ContiguousVector<StringyU128, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint128_4_*"]         [basic_vector_uint128_4]   [ContiguousVector<StringyU128, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint128_5_*"]         [basic_vector_uint128_5]   [ContiguousVector<StringyU128, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint128_8_*"]         [basic_vector_uint128_8]   [ContiguousVector<StringyU128, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint128_16_*"]        [basic_vector_uint128_16]  [ContiguousVector<StringyU128, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint128_31_*"]        [basic_vector_uint128_31]  [ContiguousVector<StringyU128, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint128_512_*"]       [basic_vector_uint128_512] [ContiguousVector<u128, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint128_513_*"]       [basic_vector_uint128_513] [ContiguousVector<StringyU128, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint256_1_*"]         [basic_vector_uint256_1]   [ContiguousVector<Uint256, U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint256_2_*"]         [basic_vector_uint256_2]   [ContiguousVector<Uint256, U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint256_3_*"]         [basic_vector_uint256_3]   [ContiguousVector<Uint256, U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint256_4_*"]         [basic_vector_uint256_4]   [ContiguousVector<Uint256, U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint256_5_*"]         [basic_vector_uint256_5]   [ContiguousVector<Uint256, U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint256_8_*"]         [basic_vector_uint256_8]   [ContiguousVector<Uint256, U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint256_16_*"]        [basic_vector_uint256_16]  [ContiguousVector<Uint256, U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint256_31_*"]        [basic_vector_uint256_31]  [ContiguousVector<Uint256, U31>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint256_512_*"]       [basic_vector_uint256_512] [ContiguousVector<Uint256, U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/*_uint256_513_*"]       [basic_vector_uint256_513] [ContiguousVector<Uint256, U513>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/invalid/*_1_*"]                      [bitlist_1]                [BitList<U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/invalid/*_2_*"]                      [bitlist_2]                [BitList<U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/invalid/*_3_*"]                      [bitlist_3]                [BitList<U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/invalid/*_4_*"]                      [bitlist_4]                [BitList<U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/invalid/*_5_*"]                      [bitlist_5]                [BitList<U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/invalid/*_8_*"]                      [bitlist_8]                [BitList<U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/invalid/*_32_*"]                     [bitlist_32]               [BitList<U32>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/invalid/*_512_*"]                    [bitlist_512]              [BitList<U512>];
        // The longest of the `*_no_delimiter_*` cases is 3 bytes long,
        // so it would have to have a maximum length of at least 16 bits to be valid.
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitlist/invalid/*_no_delimiter_*"]           [bitlist_no_delimiter]     [BitList<U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/*_1_*"]                    [bitvector_1]              [BitVector<U1>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/*_2_*"]                    [bitvector_2]              [BitVector<U2>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/*_3_*"]                    [bitvector_3]              [BitVector<U3>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/*_4_*"]                    [bitvector_4]              [BitVector<U4>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/*_5_*"]                    [bitvector_5]              [BitVector<U5>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/*_8_*"]                    [bitvector_8]              [BitVector<U8>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/*_9_*"]                    [bitvector_9]              [BitVector<U9>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/*_16_*"]                   [bitvector_16]             [BitVector<U16>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/*_32_*"]                   [bitvector_32]             [BitVector<U32>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/*_512_*"]                  [bitvector_512]            [BitVector<U512>];
        ["consensus-spec-tests/tests/general/*/ssz_generic/boolean/invalid/*"]                          [boolean]                  [bool];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/invalid/BitsStruct_*"]            [bits_struct]              [BitsStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/invalid/ComplexTestStruct_*"]     [complex_test_struct]      [ComplexTestStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/invalid/FixedTestStruct_*"]       [fixed_test_struct]        [FixedTestStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/invalid/SingleFieldTestStruct_*"] [single_field_test_struct] [SingleFieldTestStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/invalid/SmallTestStruct_*"]       [small_test_struct]        [SmallTestStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/containers/invalid/VarTestStruct_*"]         [var_test_struct]          [VarTestStruct];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/invalid/*_8_*"]                        [uints_8]                  [u8];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/invalid/*_16_*"]                       [uints_16]                 [u16];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/invalid/*_32_*"]                       [uints_32]                 [u32];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/invalid/*_64_*"]                       [uints_64]                 [u64];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/invalid/*_128_*"]                      [uints_128]                [StringyU128];
        ["consensus-spec-tests/tests/general/*/ssz_generic/uints/invalid/*_256_*"]                      [uints_256]                [Uint256];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_invalid_case::<ssz_type>(case);
    }
}

fn run_valid_case<T>(case: Case)
where
    T: SszReadDefault + SszWrite + SszHash + DeserializeOwned + PartialEq + Debug,
{
    let root = case.meta().root;
    let expected_ssz_bytes = case.bytes("serialized.ssz_snappy");
    let yaml_value = case.yaml::<T>("value");

    let actual_ssz_bytes = yaml_value.to_ssz().expect("SSZ encoding should succeed");
    let ssz_value = T::from_ssz_default(&expected_ssz_bytes).expect("SSZ decoding should succeed");

    // > Encoding: After encoding the given `value` object, the output should match `serialized`.
    assert_eq!(actual_ssz_bytes, expected_ssz_bytes);

    // > Decoding: After decoding the given `serialized` bytes, it should match the `value` object.
    assert_eq!(ssz_value, yaml_value);

    // > Hash-tree-root: the root should match the root declared in the metadata.
    assert_eq!(yaml_value.hash_tree_root(), root);
}

fn run_invalid_case<T>(case: Case)
where
    T: SszReadDefault + Debug,
{
    let bytes = case.bytes("serialized.ssz_snappy");

    // > Unlike the `valid` suite, invalid encodings do not have any `value` or hash tree root.
    // > The `serialized` data should simply not be decoded without raising an error.
    T::from_ssz_default(bytes).expect_err("SSZ decoding should fail");
}

// > Note that for some type declarations in the invalid suite, the type itself may technically be
// > invalid.  This is a valid way of detecting `invalid` data too. E.g. a 0-length basic vector.

// `consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/vec_bool_0`
assert_not_impl_any!(ContiguousVector<bool, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);
assert_not_impl_any!(PersistentVector<bool, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);

// `consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/vec_uint128_0`
assert_not_impl_any!(ContiguousVector<StringyU128, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);
assert_not_impl_any!(PersistentVector<StringyU128, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);

// `consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/vec_uint16_0`
assert_not_impl_any!(ContiguousVector<u16, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);
assert_not_impl_any!(PersistentVector<u16, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);

// `consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/vec_uint256_0`
assert_not_impl_any!(ContiguousVector<Uint256, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);
assert_not_impl_any!(PersistentVector<Uint256, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);

// `consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/vec_uint32_0`
assert_not_impl_any!(ContiguousVector<u32, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);
assert_not_impl_any!(PersistentVector<u32, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);

// `consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/vec_uint64_0`
assert_not_impl_any!(ContiguousVector<u64, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);
assert_not_impl_any!(PersistentVector<u64, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);

// `consensus-spec-tests/tests/general/*/ssz_generic/basic_vector/invalid/vec_uint8_0`
assert_not_impl_any!(ContiguousVector<u8, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);
assert_not_impl_any!(PersistentVector<u8, U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);

// `consensus-spec-tests/tests/general/*/ssz_generic/bitvector/invalid/bitvec_0`
// This is already covered in `ssz::negative`, but there's no harm in having it here as well.
assert_not_impl_any!(BitVector<U0>: SszSize, SszReadDefault, SszWrite, SszHash, SszUnify);
