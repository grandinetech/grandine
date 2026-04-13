// This is used to (de)serialize SSZ collections of collections that contain numbers.
// See the comments in `serde_utils::string_or_native` and `serde_utils::string_or_native_sequence`.

use core::{
    fmt::{Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    str::FromStr,
};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error, SeqAccess, Visitor},
};
use try_from_iterator::TryFromIterator;

pub fn deserialize<'de, I, T, O, D>(deserializer: D) -> Result<O, D::Error>
where
    I: Deserialize<'de> + FromStr<Err: Display>,
    T: TryFromIterator<I, Error: Display>,
    O: TryFromIterator<T, Error: Display>,
    D: Deserializer<'de>,
{
    struct OuterVisitor<I, T, O>(PhantomData<(I, T, O)>);

    impl<'de, I, T, O> Visitor<'de> for OuterVisitor<I, T, O>
    where
        I: Deserialize<'de> + FromStr<Err: Display>,
        T: TryFromIterator<I, Error: Display>,
        O: TryFromIterator<T, Error: Display>,
    {
        type Value = O;

        fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
            formatter.write_str("a sequence of sequences of strings or integers")
        }

        fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
            itertools::process_results(
                core::iter::from_fn(|| {
                    seq.next_element_seed(InnerSeed::<I, T>(PhantomData))
                        .transpose()
                }),
                |items| O::try_from_iter(items).map_err(S::Error::custom),
            )?
        }
    }

    struct InnerSeed<I, T>(PhantomData<(I, T)>);

    impl<'de, I, T> serde::de::DeserializeSeed<'de> for InnerSeed<I, T>
    where
        I: Deserialize<'de> + FromStr<Err: Display>,
        T: TryFromIterator<I, Error: Display>,
    {
        type Value = T;

        fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<T, D::Error> {
            crate::string_or_native_sequence::deserialize(deserializer)
        }
    }

    deserializer.deserialize_seq(OuterVisitor(PhantomData))
}

pub fn serialize<S, Outer, Inner, Item>(outer: Outer, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    Outer: IntoIterator<Item = Inner>,
    Inner: IntoIterator<Item = Item> + Copy,
    Item: Serialize + Display,
{
    serializer.collect_seq(outer.into_iter().map(InnerSerializer))
}

struct InnerSerializer<Inner>(Inner);

impl<Inner, Item> Serialize for InnerSerializer<Inner>
where
    Inner: IntoIterator<Item = Item> + Copy,
    Item: Serialize + Display,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::string_or_native_sequence::serialize(self.0, serializer)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Result as JsonResult, json};

    use super::*;

    #[derive(PartialEq, Eq, Debug, Deserialize, Serialize)]
    #[serde(transparent)]
    struct NestedNumbers(#[serde(with = "super")] Vec<Vec<u64>>);

    #[test]
    fn serializes_to_strings_in_json() -> JsonResult<()> {
        let numbers = NestedNumbers(vec![vec![1, 2], vec![3, 4, 5]]);
        let json = json!([["1", "2"], ["3", "4", "5"]]);

        assert_eq!(
            serde_json::from_value::<NestedNumbers>(json.clone())?,
            numbers
        );
        assert_eq!(serde_json::to_value(numbers)?, json);

        Ok(())
    }

    #[test]
    fn deserialize_also_accepts_numbers_in_json() -> JsonResult<()> {
        let numbers = NestedNumbers(vec![vec![1, 2], vec![3, 4, 5]]);
        let json = json!([[1, 2], [3, 4, 5]]);

        assert_eq!(serde_json::from_value::<NestedNumbers>(json)?, numbers);

        Ok(())
    }

    #[test]
    fn deserialize_accepts_mixed_strings_and_numbers() -> JsonResult<()> {
        let numbers = NestedNumbers(vec![vec![1, 2], vec![3, 4, 5]]);
        let json = json!([["1", 2], [3, "4", 5]]);

        assert_eq!(serde_json::from_value::<NestedNumbers>(json)?, numbers);

        Ok(())
    }

    #[test]
    fn handles_empty_outer_sequence() -> JsonResult<()> {
        let numbers = NestedNumbers(vec![]);
        let json = json!([]);

        assert_eq!(
            serde_json::from_value::<NestedNumbers>(json.clone())?,
            numbers
        );
        assert_eq!(serde_json::to_value(numbers)?, json);

        Ok(())
    }

    #[test]
    fn handles_empty_inner_sequences() -> JsonResult<()> {
        let numbers = NestedNumbers(vec![vec![], vec![]]);
        let json = json!([[], []]);

        assert_eq!(
            serde_json::from_value::<NestedNumbers>(json.clone())?,
            numbers
        );
        assert_eq!(serde_json::to_value(numbers)?, json);

        Ok(())
    }
}
