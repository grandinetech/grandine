// Various standard APIs require numbers to be represented as strings
// (except for error codes and metadata in the Eth Beacon Node API).
// We also want the serialization code to be compatible with `bincode` for use in `slasher`.
//
// `serde_with::rust::display_fromstr` interacts poorly with `#[serde(untagged)]`,
// which makes parsing `fork_choice_control::spec_tests::Step::Checks` fail.
// This appears to be caused by `serde::de::Content`. `serde_with::rust::display_fromstr` uses
// `deserialize_str`, but by that point `serde_yaml` has already parsed the values into numbers.
//
// `serde_aux::field_attributes::deserialize_number_from_string` uses `deserialize_any`,
// which works with `serde_yaml` but not with `bincode`:
// <https://github.com/bincode-org/bincode/issues/272#issuecomment-603532560>

use core::{
    fmt::{Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    str::FromStr,
};

use serde::{
    de::{Error, IntoDeserializer as _, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'de> + FromStr<Err: Display>,
    D: Deserializer<'de>,
{
    struct AnyVisitor<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de> + FromStr<Err: Display>> Visitor<'de> for AnyVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
            formatter.write_str("a string or integer")
        }

        fn visit_str<E: Error>(self, string: &str) -> Result<Self::Value, E> {
            string.parse().map_err(E::custom)
        }

        fn visit_u64<E: Error>(self, value: u64) -> Result<Self::Value, E> {
            T::deserialize(value.into_deserializer())
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_any(AnyVisitor(PhantomData))
    } else {
        T::deserialize(deserializer)
    }
}

pub fn serialize<S: Serializer>(
    value: impl Serialize + Display,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.collect_str(&value)
    } else {
        value.serialize(serializer)
    }
}
