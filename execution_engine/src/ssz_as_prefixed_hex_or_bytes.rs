use serde::{de::Error as _, ser::Error as _, Deserializer, Serializer};
use ssz::{SszReadDefault, SszWrite};

pub fn deserialize<'de, T: SszReadDefault, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    let bytes = serde_utils::prefixed_hex_or_bytes_cow::deserialize(deserializer)?;
    T::from_ssz_default(bytes).map_err(D::Error::custom)
}

pub fn serialize<S: Serializer>(value: impl SszWrite, serializer: S) -> Result<S::Ok, S::Error> {
    let bytes = value.to_ssz().map_err(S::Error::custom)?;
    serde_utils::prefixed_hex_or_bytes_slice::serialize(bytes, serializer)
}
