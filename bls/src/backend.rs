#[derive(Clone, Copy, Debug, Default)]
pub enum Backend {
    #[cfg(feature = "blst")]
    #[default]
    Blst,
}
