use core::fmt::{Formatter, Result as FmtResult};

use serde::{
    de::{Error, Visitor},
    Deserializer,
};

use crate::shared;

pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    struct ArrayVisitor<const N: usize> {
        human_readable: bool,
    }

    impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
            formatter.write_str(shared::expecting_prefixed_hex_or_bytes(self.human_readable))
        }

        fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            bytes.try_into().map_err(E::custom)
        }

        fn visit_str<E: Error>(self, string: &str) -> Result<Self::Value, E> {
            let digits = shared::strip_hex_prefix(string)?;

            let mut bytes = [0; N];
            const_hex::decode_to_slice(digits, &mut bytes).map_err(E::custom)?;

            Ok(bytes)
        }
    }

    let human_readable = deserializer.is_human_readable();
    let visitor = ArrayVisitor { human_readable };

    if human_readable {
        deserializer.deserialize_str(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}
