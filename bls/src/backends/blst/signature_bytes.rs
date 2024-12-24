use derive_more::AsRef;
use fixed_hash::construct_fixed_hash;
use impl_serde::impl_fixed_hash_serde;
use ssz::{BytesToDepth, MerkleTree, ReadError, Size, SszHash, SszRead, SszSize, SszWrite, H256};
use typenum::{Unsigned as _, U1, U96};

use crate::traits::SignatureBytes as SignatureBytesTrait;

use super::signature::Signature;

type CompressedSize = U96;

construct_fixed_hash! {
    #[derive(AsRef)]
    pub struct SignatureBytes(CompressedSize::USIZE);
}

impl_fixed_hash_serde!(SignatureBytes, CompressedSize::USIZE);

impl From<Signature> for SignatureBytes {
    #[inline]
    fn from(signature: Signature) -> Self {
        Self(signature.as_raw().compress())
    }
}

impl SszSize for SignatureBytes {
    const SIZE: Size = Size::Fixed {
        size: CompressedSize::USIZE,
    };
}

impl<C> SszRead<C> for SignatureBytes {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Self::from_slice(bytes))
    }
}

impl SszWrite for SignatureBytes {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.as_bytes());
    }
}

impl SszHash for SignatureBytes {
    type PackingFactor = U1;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        MerkleTree::<BytesToDepth<CompressedSize>>::merkleize_bytes(self)
    }
}

impl SignatureBytesTrait for SignatureBytes {
    #[inline]
    #[must_use]
    fn empty() -> Self {
        let mut bytes = Self::zero();

        // The first byte of an empty signature must be 0xc0.
        bytes.as_mut()[0] = 0xc0;

        bytes
    }

    #[inline]
    #[must_use]
    fn is_empty(self) -> bool {
        self == Self::empty()
    }
}
