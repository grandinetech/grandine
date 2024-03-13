/// Trait for types whose [default value](Default::default) is all zeros when serialized to SSZ.
pub trait ZeroDefault: Default {}

impl ZeroDefault for u8 {}

impl ZeroDefault for u64 {}
