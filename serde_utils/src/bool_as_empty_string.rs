use serde::{Deserialize as _, Deserializer, de::Error as _};

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    <&str>::deserialize(deserializer)?
        .is_empty()
        .then_some(true)
        .ok_or_else(|| D::Error::custom("no value allowed"))
}
