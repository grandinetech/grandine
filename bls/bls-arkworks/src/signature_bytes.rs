use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use derive_more::AsRef;
use fixed_hash::construct_fixed_hash;
use impl_serde::impl_fixed_hash_serde;
use typenum::Unsigned as _;

use bls_core::{
    impl_signature_bytes,
    traits::{CompressedSize, SignatureBytes as SignatureBytesTrait},
};

use super::signature::Signature;

impl_signature_bytes!(SignatureBytesTrait, SignatureBytes, CompressedSize::USIZE);

impl From<Signature> for SignatureBytes {
    #[inline]
    fn from(signature: Signature) -> Self {
        let mut bytes = [0u8; CompressedSize::USIZE];
        signature
            .as_raw()
            .into_affine()
            .serialize_compressed(&mut bytes[..])
            .unwrap();
        Self(bytes)
    }
}
