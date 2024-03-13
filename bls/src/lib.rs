pub use crate::{
    cached_public_key::CachedPublicKey, error::Error, public_key::PublicKey,
    public_key_bytes::PublicKeyBytes, secret_key::SecretKey, secret_key_bytes::SecretKeyBytes,
    signature::Signature, signature_bytes::SignatureBytes,
};

mod cached_public_key;
mod consts;
mod error;
mod public_key;
mod public_key_bytes;
mod secret_key;
mod secret_key_bytes;
mod signature;
mod signature_bytes;

pub type AggregatePublicKey = PublicKey;
pub type AggregatePublicKeyBytes = PublicKeyBytes;
pub type AggregateSignature = Signature;
pub type AggregateSignatureBytes = SignatureBytes;
