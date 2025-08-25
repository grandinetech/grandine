use core::{
    cmp::Ord,
    fmt::{Display, Formatter, Result as FmtResult},
    marker::PhantomData,
};

use serde::{
    de::{Error, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use try_from_iterator::TryFromIterator;

use crate::shared::Sortable;

pub fn serialize<S: Serializer>(
    items: impl IntoIterator<Item = impl Serialize>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(items)
}

pub fn deserialize<'de, I, T, D>(deserializer: D) -> Result<T, D::Error>
where
    I: Deserialize<'de> + Sortable,
    T: TryFromIterator<I, Error: Display>,
    D: Deserializer<'de>,
{
    struct AnyVisitor<I, T>(PhantomData<(I, T)>);

    impl<'de, I, T> Visitor<'de> for AnyVisitor<I, T>
    where
        I: Deserialize<'de> + Sortable,
        T: TryFromIterator<I, Error: Display>,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
            formatter.write_str("a sequence of objects with a sortable key")
        }

        fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
            itertools::process_results(
                core::iter::from_fn(|| seq.next_element().transpose()),
                |iter| {
                    let mut items: Vec<I> = iter.collect();
                    items.sort_by(|a, b| b.key().cmp(&a.key()));
                    T::try_from_iter(items.into_iter()).map_err(S::Error::custom)
                },
            )?
        }
    }

    deserializer.deserialize_seq(AnyVisitor(PhantomData))
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Result as JsonResult};

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Object {
        key: u64,
        value: u64,
    }

    impl Sortable for Object {
        fn key(&self) -> impl Ord {
            self.key
        }
    }

    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    #[serde(transparent)]
    struct Objects(#[serde(with = "super")] Vec<Object>);

    #[test]
    fn deserialize_descending_sorted_objects() -> JsonResult<()> {
        let json = json!([
            {"key": 3, "value": 15},
            {"key": 1, "value": 10},
            {"key": 2, "value": 20},
        ]);
        let sorted_objects = Objects(vec![
            Object { key: 3, value: 15 },
            Object { key: 2, value: 20 },
            Object { key: 1, value: 10 },
        ]);

        assert_eq!(serde_json::from_value::<Objects>(json)?, sorted_objects);

        Ok(())
    }
}
