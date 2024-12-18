use derive_more::derive::AsRef;
use fixed_hash::construct_fixed_hash;
use impl_serde::impl_fixed_hash_serde;

use bls_core::{impl_public_key_bytes, traits::COMPRESSED_SIZE};

use super::public_key::PublicKey;

construct_fixed_hash! {
    #[derive(AsRef)]
    pub struct PublicKeyBytes(COMPRESSED_SIZE);
}

impl_fixed_hash_serde!(PublicKeyBytes, COMPRESSED_SIZE);

impl_public_key_bytes!(PublicKeyBytes);

impl From<PublicKey> for PublicKeyBytes {
    #[inline]
    fn from(public_key: PublicKey) -> Self {
        Self(public_key.as_raw().compress())
    }
}
