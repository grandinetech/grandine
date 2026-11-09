pub use bls_core::*;

macro_rules! implement_backend {
    ($backend:path) => {
        pub use $backend::{
            aggregate_public_key::AggregatePublicKey, public_key::PublicKey,
            public_key_bytes::PublicKeyBytes, secret_key::SecretKey,
            secret_key_bytes::SecretKeyBytes, signature::Signature,
            signature_bytes::SignatureBytes,
        };

        pub type AggregatePublicKeyBytes = PublicKeyBytes;
        pub type AggregateSignature = Signature;
        pub type AggregateSignatureBytes = SignatureBytes;
    };
}

#[cfg(feature = "blst")]
implement_backend!(bls_blst);

#[cfg(feature = "zkcrypto")]
implement_backend!(bls_zkcrypto);

#[cfg(all(feature = "zkcrypto", target_os = "zkvm"))]
pub use bls_zkcrypto::signature::set_rand_seed;
