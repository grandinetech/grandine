// This is used to (de)serialize optional numbers that are represented as strings when present.

use core::{fmt::Display, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Deserialize, Serialize)]
#[serde(bound(
    deserialize = "T: Deserialize<'de> + FromStr<Err: Display>",
    serialize = "T: Serialize + Display",
))]
struct Wrapper<T>(#[serde(with = "crate::string_or_native")] T);

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de> + FromStr<Err: Display>,
    D: Deserializer<'de>,
{
    let wrapper = Option::<Wrapper<T>>::deserialize(deserializer)?;
    Ok(wrapper.map(|Wrapper(value)| value))
}

pub fn serialize<S: Serializer>(
    value: &Option<impl Serialize + Display>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => crate::string_or_native::serialize(value, serializer),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Result, json};

    use super::*;

    #[derive(PartialEq, Eq, Debug, Deserialize, Serialize)]
    #[serde(transparent)]
    struct Number(#[serde(with = "super")] Option<u64>);

    #[test]
    fn serde_some_to_string_in_json() -> Result<()> {
        let number = Number(Some(3));
        let json = json!("3");

        assert_eq!(serde_json::from_value::<Number>(json.clone())?, number);
        assert_eq!(serde_json::to_value(number)?, json);

        Ok(())
    }

    #[test]
    fn serde_none_to_null_in_json() -> Result<()> {
        let number = Number(None);
        let json = json!(null);

        assert_eq!(serde_json::from_value::<Number>(json.clone())?, number);
        assert_eq!(serde_json::to_value(number)?, json);

        Ok(())
    }
}
