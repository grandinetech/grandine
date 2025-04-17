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
}
