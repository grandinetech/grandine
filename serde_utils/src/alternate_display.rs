use core::fmt::Display;

use serde::Serializer;
use serde_with::SerializeAs;

pub enum AlternateDisplay {}

impl<T: Display> SerializeAs<T> for AlternateDisplay {
    fn serialize_as<S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        serialize(value, serializer)
    }
}

pub fn serialize<S: Serializer>(value: impl Display, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{value:#}"))
}
