use core::{
    fmt::{Display, Formatter, LowerHex, Result as FmtResult},
    marker::PhantomData,
};

use num_traits::Num;
use serde::{
    de::{Error as DeserializeError, Visitor},
    Deserializer, Serializer,
};

use crate::shared;

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Num<FromStrRadixErr: Display>,
    D: Deserializer<'de>,
{
    struct HexVisitor<T>(PhantomData<T>);

    impl<'de, T: Num<FromStrRadixErr: Display>> Visitor<'de> for HexVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
            formatter.write_str(shared::expecting_prefixed_hex_or_bytes(true))
        }

        fn visit_str<E: DeserializeError>(self, string: &str) -> Result<Self::Value, E> {
            let digits = shared::strip_hex_prefix(string)?;

            if digits.is_empty() {
                return Err(E::custom("string contains no hexadecimal digits"));
            }

            if digits == "0" {
                return Ok(T::zero());
            }

            // Values of type `QUANTITY` in the Engine API must not have leading zeros after the
            // hexadecimal prefix (except for the number 0). See:
            // <https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/common.md#encoding>
            if digits.starts_with('0') {
                return Err(E::custom(
                    "string contains leading zeros after hexadecimal prefix",
                ));
            }

            T::from_str_radix(digits, 16).map_err(E::custom)
        }
    }

    deserializer.deserialize_str(HexVisitor(PhantomData))
}

pub fn serialize<S: Serializer>(number: impl LowerHex, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{number:#x}"))
}

#[cfg(test)]
mod tests {
    use num_traits::{One as _, Zero as _};
    use serde_json::{value::Serializer, Result, Value};
    use ssz::Uint256;
    use test_case::test_case;

    use super::*;

    #[test_case(Uint256::zero(), "0x0")]
    #[test_case(Uint256::one(), "0x1")]
    #[test_case(Uint256::from_u64(1_000_000_000_000), "0xe8d4a51000")]
    #[test_case(
        Uint256::MAX,
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )]
    fn uint256_string_round_trip(uint: Uint256, string: &str) -> Result<()> {
        let json = Value::from(string);

        assert_eq!(deserialize::<Uint256, _>(json.clone())?, uint);
        assert_eq!(serialize(uint, Serializer)?, json);

        Ok(())
    }

    #[test_case("";         "empty string")]
    #[test_case("0";        "missing hexadecimal prefix")]
    #[test_case("0x";       "missing hexadecimal digits")]
    #[test_case("0x000034"; "leading zeros after hexadecimal prefix")]
    #[test_case(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        "one digit too many for Uint256"
    )]
    fn deserialize_uint256_fails_on(string: &str) {
        let json = Value::from(string);

        deserialize::<Uint256, _>(json).expect_err("deserialization should fail");
    }
}
