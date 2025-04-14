use derive_more::derive::AsRef;
use fixed_hash::construct_fixed_hash;
use impl_serde::impl_fixed_hash_serde;
use ssz::{SszRead, SszSize, SszWrite};

pub const COMPRESSED_SIZE: usize = 48;

construct_fixed_hash! {
    #[derive(AsRef)]
    pub struct PublicKeyBytes(COMPRESSED_SIZE);
}

impl_fixed_hash_serde!(PublicKeyBytes, COMPRESSED_SIZE);

impl hex::FromHex for PublicKeyBytes {
    type Error = <[u8; COMPRESSED_SIZE] as hex::FromHex>::Error;

    fn from_hex<T: AsRef<[u8]>>(digits: T) -> Result<Self, Self::Error> {
        hex::FromHex::from_hex(digits).map(Self)
    }
}

impl SszSize for PublicKeyBytes {
    const SIZE: ssz::Size = ssz::Size::Fixed {
        size: COMPRESSED_SIZE,
    };
}

impl<C> SszRead<C> for PublicKeyBytes {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ssz::ReadError> {
        Ok(Self::from_slice(bytes))
    }
}

impl SszWrite for PublicKeyBytes {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.as_bytes());
    }
}

impl ssz::SszHash for PublicKeyBytes {
    type PackingFactor = typenum::U1;

    #[inline]
    fn hash_tree_root(&self) -> ssz::H256 {
        ssz::MerkleTree::<ssz::BytesToDepth<typenum::U48>>::merkleize_bytes(self)
    }
}
