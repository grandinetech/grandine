// This is used to (de)serialize SSZ collections that contain numbers.
// See the comment in `serde_utils::string_or_native`.

use core::{
    fmt::{Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    str::FromStr,
};

use itertools::Itertools as _;
use serde::{
    de::{Error, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use try_from_iterator::TryFromIterator;

#[derive(Deserialize, Serialize)]
#[serde(bound(
    deserialize = "T: Deserialize<'de> + FromStr<Err: Display>",
    serialize = "T: Serialize + Display",
))]
struct Wrapper<T>(#[serde(with = "crate::string_or_native")] T);

pub fn deserialize<'de, I, T, D>(deserializer: D) -> Result<T, D::Error>
where
    I: Deserialize<'de> + FromStr<Err: Display>,
    T: TryFromIterator<I, Error: Display>,
    D: Deserializer<'de>,
{
    struct AnyVisitor<I, T>(PhantomData<(I, T)>);

    impl<'de, I, T> Visitor<'de> for AnyVisitor<I, T>
    where
        I: Deserialize<'de> + FromStr<Err: Display>,
        T: TryFromIterator<I, Error: Display>,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
            formatter.write_str("a sequence of strings or integers")
        }

        fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
            itertools::process_results(
                core::iter::from_fn(|| seq.next_element().transpose()).map_ok(|Wrapper(item)| item),
                |items| T::try_from_iter(items).map_err(S::Error::custom),
            )?
        }
    }

    deserializer.deserialize_seq(AnyVisitor(PhantomData))
}

pub fn serialize<S: Serializer>(
    items: impl IntoIterator<Item = impl Serialize + Display>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(items.into_iter().map(Wrapper))
}

#[cfg(test)]
mod tests {
    use bincode::{DefaultOptions, Options as _, Result as BincodeResult};
    use serde_json::{json, Result as JsonResult};

    use super::*;

    // `bincode::Deserializer` and `bincode::Serializer` are hard to use directly.
    #[derive(PartialEq, Eq, Debug, Deserialize, Serialize)]
    #[serde(transparent)]
    struct Numbers(#[serde(with = "super")] Vec<u64>);

    #[test]
    fn serializes_to_strings_in_json() -> JsonResult<()> {
        let numbers = Numbers(vec![3, 4, 5]);
        let json = json!(["3", "4", "5"]);

        assert_eq!(serde_json::from_value::<Numbers>(json.clone())?, numbers);
        assert_eq!(serde_json::to_value(numbers)?, json);

        Ok(())
    }

    #[test]
    fn deserialize_also_accepts_numbers_in_json() -> JsonResult<()> {
        let numbers = Numbers(vec![3, 4, 5]);
        let json = json!([3, 4, 5]);

        assert_eq!(serde_json::from_value::<Numbers>(json)?, numbers);

        Ok(())
    }

    #[test]
    fn serializes_to_numbers_in_bincode() -> BincodeResult<()> {
        let options = DefaultOptions::new();
        let numbers = Numbers(vec![3, 4, 5]);
        let bytes = [3, 3, 4, 5];

        assert_eq!(options.deserialize::<Numbers>(&bytes)?, numbers);
        assert_eq!(options.serialize(&numbers)?, bytes);

        Ok(())
    }
}
