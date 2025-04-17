use core::fmt::Debug;
use once_cell::race::OnceBox;
use serde::{Deserialize, Serialize};
use ssz::{SszHash, SszRead, SszSize, SszWrite};

use crate::{error::Error, PublicKey};

use super::public_key_bytes::PublicKeyBytes;

#[derive(Default, derivative::Derivative, Deserialize, Serialize)]
#[derivative(PartialEq, Eq)]
#[serde(transparent)]
pub struct CachedPublicKey {
    bytes: PublicKeyBytes,

    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    decompressed: OnceBox<PublicKey>,
}

impl From<PublicKeyBytes> for CachedPublicKey {
    #[inline]
    fn from(bytes: PublicKeyBytes) -> Self {
        Self {
            bytes,
            decompressed: once_cell::race::OnceBox::new(),
        }
    }
}

impl From<PublicKey> for CachedPublicKey {
    #[inline]
    fn from(public_key: PublicKey) -> Self {
        Self::new(public_key.into(), public_key)
    }
}

impl Clone for CachedPublicKey {
    fn clone(&self) -> Self {
        let Self {
            bytes,
            ref decompressed,
        } = *self;
        match decompressed.get().copied() {
            Some(public_key) => Self::new(bytes, public_key),
            None => bytes.into(),
        }
    }
}

impl CachedPublicKey {
    pub fn new(bytes: PublicKeyBytes, public_key: PublicKey) -> Self {
        let decompressed = once_cell::race::OnceBox::new();
        decompressed
            .set(Box::new(public_key))
            .expect("decompressed is empty because OnceBox::new returns an empty cell");

        Self {
            bytes,
            decompressed,
        }
    }

    pub fn as_bytes(&self) -> &PublicKeyBytes {
        &self.bytes
    }

    pub fn to_bytes(&self) -> PublicKeyBytes {
        self.bytes
    }

    pub fn decompress(&self) -> Result<&PublicKey, Error> {
        self.decompressed.get_or_try_init(|| PublicKey::try_from(self.bytes).map(Box::new))
    }
}

impl Debug for CachedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedPublicKey")
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl SszSize for CachedPublicKey {
    const SIZE: ssz::Size = PublicKeyBytes::SIZE;
}

impl<C> SszRead<C> for CachedPublicKey {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ssz::ReadError> {
        Ok(Self {
            bytes: <PublicKeyBytes as ssz::SszReadDefault>::from_ssz_default(bytes)?,
            decompressed: once_cell::race::OnceBox::new(),
        })
    }
}

impl SszWrite for CachedPublicKey {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        self.bytes.write_fixed(bytes);
    }
}

impl SszHash for CachedPublicKey {
    type PackingFactor = <PublicKeyBytes as SszHash>::PackingFactor;

    #[inline]
    fn hash_tree_root(&self) -> ssz::H256 {
        self.bytes.hash_tree_root()
    }
}
