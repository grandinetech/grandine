pub mod consts;
pub mod error;

pub use consts::*;
pub use error::*;

mod backend;
mod cached_public_key;
mod public_key;
mod public_key_bytes;
mod secret_key;
mod secret_key_bytes;
mod signature;
mod signature_bytes;

pub use backend::{Backend, set_backend};

pub use cached_public_key::CachedPublicKey;
pub use public_key::{PublicKey, PublicKeyTrait};
pub use public_key_bytes::PublicKeyBytes;
pub use secret_key::{SecretKey, SecretKeyTrait};
pub use secret_key_bytes::SecretKeyBytes;
pub use signature::{Signature, SignatureTrait};
pub use signature_bytes::SignatureBytes;

pub type AggregatePublicKey = PublicKey;
pub type AggregatePublicKeyBytes = PublicKeyBytes;
pub type AggregateSignature = Signature;
pub type AggregateSignatureBytes = SignatureBytes;
