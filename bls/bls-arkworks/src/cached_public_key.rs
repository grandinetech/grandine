use bls_core::{impl_cached_public_key, CachedPublicKey as CachedPublicKeyTrait};

use super::{public_key::PublicKey, public_key_bytes::PublicKeyBytes};

impl_cached_public_key!(
    CachedPublicKeyTrait,
    CachedPublicKey,
    PublicKeyBytes,
    PublicKey
);
