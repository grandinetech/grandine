use core::fmt::Display;

use hex::{FromHex, ToHex};
use serde::{Deserializer, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

// Neither `serde` nor `serde_with` have a way to map the functions in a `with`-compatible module
// over the contents of an `Option`. `serde_with::hex::Hex` requires the type being deserialized to
// implement `TryFrom<Vec<u8>>` rather than `FromHex`.
pub enum FromHexTrait {}

impl<'de, T: FromHex<Error: Display>> DeserializeAs<'de, T> for FromHexTrait {
    fn deserialize_as<D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
        hex::serde::deserialize(deserializer)
    }
}

impl<T: ToHex> SerializeAs<T> for FromHexTrait {
    fn serialize_as<S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        // `ToHex` is not implemented for references.
        struct Wrapper<'bytes, B>(&'bytes B);

        impl<B: ToHex> ToHex for Wrapper<'_, B> {
            fn encode_hex<T: FromIterator<char>>(&self) -> T {
                self.0.encode_hex()
            }

            fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
                self.0.encode_hex_upper()
            }
        }

        hex::serde::serialize(Wrapper(value), serializer)
    }
}
