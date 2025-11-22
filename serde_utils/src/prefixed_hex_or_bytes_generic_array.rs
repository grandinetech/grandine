use generic_array::{ArrayLength, GenericArray};
use serde::{de::Error, Deserializer};

use crate::shared::{deserialize_with_hex_or_bytes, HexOrBytesConvert};

impl<N: ArrayLength<u8>> HexOrBytesConvert<'_> for GenericArray<u8, N> {
    fn from_bytes<E: Error>(bytes: &[u8]) -> Result<Self, E> {
        let expected = N::USIZE;
        let actual = bytes.len();

            if actual != expected {
                return Err(E::custom(format!(
                    "expected {expected} bytes, found {actual}",
                )));
            }

            Ok(GenericArray::clone_from_slice(bytes))
        }

    fn from_hex_digits<E: Error>(digits: &str) -> Result<Self, E> {
        let mut bytes = GenericArray::default();
        const_hex::decode_to_slice(digits, &mut bytes).map_err(E::custom)?;
        Ok(bytes)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>, N: ArrayLength<u8>>(
    deserializer: D,
) -> Result<GenericArray<u8, N>, D::Error> {
    deserialize_with_hex_or_bytes(deserializer)
}
