use core::fmt::{Formatter, Result as FmtResult};

use serde::{
    de::{Error, Visitor},
    Deserializer,
};

pub trait Sortable {
    fn key(&self) -> impl Ord;
}

pub(crate) const fn expecting_prefixed_hex_or_bytes(human_readable: bool) -> &'static str {
    if human_readable {
        "a string of hexadecimal digits prefixed with 0x"
    } else {
        "a byte array"
    }
}

pub(crate) fn strip_hex_prefix<E: Error>(string: &str) -> Result<&str, E> {
    string
        .strip_prefix("0x")
        .ok_or_else(|| E::custom("string does not have hexadecimal prefix"))
}

ub(crate) trait HexOrBytesConvert<'de>: Sized {
    fn from_bytes<E: Error>(bytes: &[u8]) -> Result<Self, E>;
    fn from_hex_digits<E: Error>(digits: &str) -> Result<Self, E>;
    
    fn from_borrowed_bytes<E: Error>(bytes: &'de [u8]) -> Result<Self, E> {
        Self::from_bytes(bytes)
    }
    
    fn from_byte_buf<E: Error>(bytes: Vec<u8>) -> Result<Self, E> {
        Self::from_bytes(&bytes)
    }
}

pub(crate) struct HexOrBytesVisitor<'de, T: HexOrBytesConvert<'de>> {
    human_readable: bool,
    _phantom: core::marker::PhantomData<fn() -> &'de T>,
}

impl<'de, T: HexOrBytesConvert<'de>> Visitor<'de> for HexOrBytesVisitor<'de, T> {
    type Value = T;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str(expecting_prefixed_hex_or_bytes(self.human_readable))
    }

    fn visit_borrowed_bytes<E: Error>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
        T::from_borrowed_bytes(bytes)
    }

    fn visit_byte_buf<E: Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
        T::from_byte_buf(bytes)
    }

    fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        T::from_bytes(bytes)
    }

    fn visit_str<E: Error>(self, string: &str) -> Result<Self::Value, E> {
        let digits = strip_hex_prefix(string)?;
        T::from_hex_digits(digits)
    }
}

pub(crate) fn deserialize_with_hex_or_bytes<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: HexOrBytesConvert<'de>,
{
    let human_readable = deserializer.is_human_readable();
    let visitor = HexOrBytesVisitor {
        human_readable,
        _phantom: core::marker::PhantomData,
    };

    if human_readable {
        deserializer.deserialize_str(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}
