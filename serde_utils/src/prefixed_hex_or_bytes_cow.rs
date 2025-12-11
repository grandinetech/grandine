use std::borrow::Cow;

use serde::{de::Error, Deserializer};

use crate::shared::{deserialize_with_hex_or_bytes, HexOrBytesConvert};

impl<'de> HexOrBytesConvert<'de> for Cow<'de, [u8]> {
    fn from_borrowed_bytes<E: Error>(bytes: &'de [u8]) -> Result<Self, E> {
        Ok(Cow::Borrowed(bytes))
    }

    fn from_byte_buf<E: Error>(bytes: Vec<u8>) -> Result<Self, E> {
        Ok(Cow::Owned(bytes))
    }

    fn from_bytes<E: Error>(bytes: &[u8]) -> Result<Self, E> {
        Ok(Cow::Owned(bytes.to_owned()))
    }

    fn from_hex_digits<E: Error>(digits: &str) -> Result<Self, E> {
        let bytes = const_hex::decode(digits).map_err(E::custom)?;
        Ok(Cow::Owned(bytes))
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Cow<'de, [u8]>, D::Error> {
    deserialize_with_hex_or_bytes(deserializer)
}
