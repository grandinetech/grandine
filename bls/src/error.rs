use blst::BLST_ERROR;
use derive_more::From;
use static_assertions::assert_eq_size;
use thiserror::Error;

#[derive(Debug, From, Error)]
pub enum Error {
    #[error("decompression failed: {0:?}")]
    DecompressionFailed(BLST_ERROR),
    #[error("no public keys to aggregate")]
    NoPublicKeysToAggregate,
}

assert_eq_size!(Error, u32);
