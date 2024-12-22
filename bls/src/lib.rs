mod backends;
pub mod consts;
pub mod error;
pub mod traits;

#[cfg(feature = "blst")]
pub use crate::backends::blst::{
    cached_public_key::CachedPublicKey, public_key::PublicKey, public_key_bytes::PublicKeyBytes,
    secret_key::SecretKey, secret_key_bytes::SecretKeyBytes, signature::Signature,
    signature_bytes::SignatureBytes,
};

pub type AggregatePublicKey = PublicKey;
pub type AggregatePublicKeyBytes = PublicKeyBytes;
pub type AggregateSignature = Signature;
pub type AggregateSignatureBytes = SignatureBytes;
