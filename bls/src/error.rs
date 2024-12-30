#[cfg(feature = "blst")]
use blst::BLST_ERROR;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("no public keys to aggregate")]
    NoPublicKeysToAggregate,
    #[error("failed to decompress point")]
    DecompressionFailed,
    #[cfg(feature = "blst")]
    #[error("blst error: {0:?}")]
    Blst(BLST_ERROR),
}

#[cfg(feature = "blst")]
impl From<BLST_ERROR> for Error {
    fn from(err: BLST_ERROR) -> Self {
        Self::Blst(err)
    }
}
