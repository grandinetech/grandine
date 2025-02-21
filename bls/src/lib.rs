pub use bls_core::*;

macro_rules! implement_backend {
    ($backend:path) => {
        pub use $backend::{
            cached_public_key::CachedPublicKey, public_key::PublicKey,
            public_key_bytes::PublicKeyBytes, secret_key::SecretKey,
            secret_key_bytes::SecretKeyBytes, signature::Signature,
            signature_bytes::SignatureBytes,
        };

        pub type AggregatePublicKey = PublicKey;
        pub type AggregatePublicKeyBytes = PublicKeyBytes;
        pub type AggregateSignature = Signature;
        pub type AggregateSignatureBytes = SignatureBytes;
    };
}

#[cfg(feature = "arkworks")]
implement_backend!(bls_arkworks);

#[cfg(feature = "blst")]
implement_backend!(bls_blst);

#[cfg(feature = "zkcrypto")]
implement_backend!(bls_zkcrypto);
