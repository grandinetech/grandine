use derivative::Derivative;
use once_cell::race::OnceBox;
use serde::{Deserialize, Serialize};
use ssz::{ReadError, Size, SszHash, SszRead, SszReadDefault as _, SszSize, SszWrite, H256};

use crate::{error::Error, traits::BlsCachedPublicKey};

use super::{public_key::PublicKey, public_key_bytes::PublicKeyBytes};

#[derive(Default, Debug, Derivative, Deserialize, Serialize)]
#[derivative(PartialEq, Eq)]
#[serde(transparent)]
pub struct CachedPublicKey {
    bytes: PublicKeyBytes,
    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    decompressed: OnceBox<PublicKey>,
}

// `OnceBox` does not implement `Clone`.
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

impl From<PublicKeyBytes> for CachedPublicKey {
    #[inline]
    fn from(bytes: PublicKeyBytes) -> Self {
        Self {
            bytes,
            decompressed: OnceBox::new(),
        }
    }
}

impl From<PublicKey> for CachedPublicKey {
    #[inline]
    fn from(public_key: PublicKey) -> Self {
        Self::new(public_key.into(), public_key)
    }
}

impl SszSize for CachedPublicKey {
    const SIZE: Size = PublicKeyBytes::SIZE;
}

impl<C> SszRead<C> for CachedPublicKey {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Self {
            bytes: PublicKeyBytes::from_ssz_default(bytes)?,
            decompressed: OnceBox::new(),
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
    fn hash_tree_root(&self) -> H256 {
        self.bytes.hash_tree_root()
    }
}

impl BlsCachedPublicKey for CachedPublicKey {
    type PublicKeyBytes = PublicKeyBytes;
    type PublicKey = PublicKey;

    fn new(bytes: PublicKeyBytes, public_key: PublicKey) -> Self {
        let decompressed = OnceBox::new();

        decompressed
            .set(Box::new(public_key))
            .expect("decompressed is empty because OnceBox::new returns an empty cell");

        Self {
            bytes,
            decompressed,
        }
    }

    #[inline]
    fn as_bytes(&self) -> &PublicKeyBytes {
        &self.bytes
    }

    #[inline]
    fn to_bytes(&self) -> PublicKeyBytes {
        self.bytes
    }

    #[inline]
    fn decompress(&self) -> Result<&PublicKey, Error> {
        self.decompressed
            .get_or_try_init(|| self.bytes.try_into().map(Box::new))
    }
}
