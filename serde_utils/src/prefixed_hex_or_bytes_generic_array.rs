use core::{
    fmt::{Formatter, Result as FmtResult},
    marker::PhantomData,
};

use generic_array::{ArrayLength, GenericArray};
use serde::{
    de::{Error, Visitor},
    Deserializer,
};

use crate::shared;

pub fn deserialize<'de, D: Deserializer<'de>, N: ArrayLength<u8>>(
    deserializer: D,
) -> Result<GenericArray<u8, N>, D::Error> {
    struct GenericArrayVisitor<N> {
        human_readable: bool,
        phantom: PhantomData<N>,
    }

    impl<'de, N: ArrayLength<u8>> Visitor<'de> for GenericArrayVisitor<N> {
        type Value = GenericArray<u8, N>;

        fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
            formatter.write_str(shared::expecting_prefixed_hex_or_bytes(self.human_readable))
        }

        fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            let expected = N::USIZE;
            let actual = bytes.len();

            if actual != expected {
                return Err(E::custom(format!(
                    "expected {expected} bytes, found {actual}",
                )));
            }

            Ok(GenericArray::clone_from_slice(bytes))
        }

        fn visit_str<E: Error>(self, string: &str) -> Result<Self::Value, E> {
            let digits = shared::strip_hex_prefix(string)?;

            let mut bytes = GenericArray::default();
            hex::decode_to_slice(digits, &mut bytes).map_err(E::custom)?;

            Ok(bytes)
        }
    }

    let human_readable = deserializer.is_human_readable();

    let visitor = GenericArrayVisitor {
        human_readable,
        phantom: PhantomData,
    };

    if human_readable {
        deserializer.deserialize_str(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}
