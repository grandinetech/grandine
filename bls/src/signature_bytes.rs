use fixed_hash::construct_fixed_hash;
use impl_serde::impl_fixed_hash_serde;
use ssz::{SszHash, SszRead, SszSize, SszWrite};

construct_fixed_hash! {
    #[derive(derive_more::AsRef)]
    pub struct SignatureBytes(96);
}

impl_fixed_hash_serde!(SignatureBytes, 96);

impl SszSize for SignatureBytes {
    const SIZE: ssz::Size = ssz::Size::Fixed { size: 96 };
}

impl<C> SszRead<C> for SignatureBytes {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ssz::ReadError> {
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
    type PackingFactor = typenum::U1;

    #[inline]
    fn hash_tree_root(&self) -> ssz::H256 {
        ssz::MerkleTree::<ssz::BytesToDepth<typenum::U96>>::merkleize_bytes(self)
    }
}

impl SignatureBytes {
    #[inline]
    pub fn empty() -> Self {
        let mut bytes = Self::zero();
        bytes.as_mut()[0] = 0xc0;
        bytes
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self == Self::empty()
    }
}
