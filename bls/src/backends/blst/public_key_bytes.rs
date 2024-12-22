use derive_more::AsRef;
use fixed_hash::construct_fixed_hash;
use hex::FromHex;
use impl_serde::impl_fixed_hash_serde;
use ssz::{BytesToDepth, MerkleTree, ReadError, Size, SszHash, SszRead, SszSize, SszWrite, H256};
use typenum::{Unsigned as _, U1, U48};

use crate::traits::BlsPublicKeyBytes;

use super::public_key::PublicKey;

type CompressedSize = U48;

construct_fixed_hash! {
    #[derive(AsRef)]
    pub struct PublicKeyBytes(CompressedSize::USIZE);
}

impl_fixed_hash_serde!(PublicKeyBytes, CompressedSize::USIZE);

impl From<PublicKey> for PublicKeyBytes {
    #[inline]
    fn from(public_key: PublicKey) -> Self {
        Self(public_key.as_raw().compress())
    }
}

impl FromHex for PublicKeyBytes {
    type Error = <[u8; CompressedSize::USIZE] as FromHex>::Error;

    fn from_hex<T: AsRef<[u8]>>(digits: T) -> Result<Self, Self::Error> {
        FromHex::from_hex(digits).map(Self)
    }
}

impl SszSize for PublicKeyBytes {
    const SIZE: Size = Size::Fixed {
        size: CompressedSize::USIZE,
    };
}

impl<C> SszRead<C> for PublicKeyBytes {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Ok(Self::from_slice(bytes))
    }
}

impl SszWrite for PublicKeyBytes {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.as_bytes());
    }
}

impl SszHash for PublicKeyBytes {
    type PackingFactor = U1;

    #[inline]
    fn hash_tree_root(&self) -> H256 {
        MerkleTree::<BytesToDepth<CompressedSize>>::merkleize_bytes(self)
    }
}

impl BlsPublicKeyBytes for PublicKeyBytes {
    type PublicKey = PublicKey;
}
