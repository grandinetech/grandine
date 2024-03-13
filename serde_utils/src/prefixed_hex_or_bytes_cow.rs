use core::fmt::{Formatter, Result as FmtResult};
use std::borrow::Cow;

use serde::{
    de::{Error, Visitor},
    Deserializer,
};

use crate::shared;

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Cow<'de, [u8]>, D::Error> {
    struct CowVisitor {
        human_readable: bool,
    }

    impl<'de> Visitor<'de> for CowVisitor {
        type Value = Cow<'de, [u8]>;

        fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
            formatter.write_str(shared::expecting_prefixed_hex_or_bytes(self.human_readable))
        }

        fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
            Ok(Cow::Borrowed(bytes))
        }

        fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            Ok(Cow::Owned(bytes))
        }

        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            Ok(Cow::Owned(bytes.to_owned()))
        }

        fn visit_str<E: Error>(self, string: &str) -> Result<Self::Value, E> {
            let digits = shared::strip_hex_prefix(string)?;
            let bytes = hex::decode(digits).map_err(E::custom)?;
            Ok(Cow::Owned(bytes))
        }
    }

    let human_readable = deserializer.is_human_readable();
    let visitor = CowVisitor { human_readable };

    if human_readable {
        deserializer.deserialize_str(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}
