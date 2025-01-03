use bls12_381::G2Affine;
use derive_more::AsRef;
use fixed_hash::construct_fixed_hash;
use impl_serde::impl_fixed_hash_serde;
use typenum::Unsigned as _;

use crate::{
    impl_signature_bytes,
    traits::{CompressedSize, SignatureBytes as SignatureBytesTrait},
};

use super::signature::Signature;

impl_signature_bytes!(SignatureBytesTrait, SignatureBytes, CompressedSize::USIZE);

impl From<Signature> for SignatureBytes {
    #[inline]
    fn from(signature: Signature) -> Self {
        Self(G2Affine::from(signature.as_raw()).to_compressed())
    }
}
