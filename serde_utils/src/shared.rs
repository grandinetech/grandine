use serde::de::Error;

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
