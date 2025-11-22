use serde::{de::Error, Deserializer};

use crate::shared::{deserialize_with_hex_or_bytes, HexOrBytesConvert};

impl<const N: usize> HexOrBytesConvert<'_> for [u8; N] {
    fn from_bytes<E: Error>(bytes: &[u8]) -> Result<Self, E> {
        bytes.try_into().map_err(E::custom)
    }

    fn from_hex_digits<E: Error>(digits: &str) -> Result<Self, E> {
        let mut bytes = [0; N];
        const_hex::decode_to_slice(digits, &mut bytes).map_err(E::custom)?;
        Ok(bytes)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    deserialize_with_hex_or_bytes(deserializer)
}
