use super::{public_key::PublicKey, public_key_bytes::PublicKeyBytes};

use bls_core::{impl_cached_public_key, traits::CachedPublicKey as CachedPublicKeyTrait};

impl_cached_public_key!(
    CachedPublicKeyTrait,
    CachedPublicKey,
    PublicKeyBytes,
    PublicKey
);
