#![expect(unexpected_cfgs, reason = "construct_fixed_hash! uses cfg internally")]

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
        Self(signature.as_raw().compress())
    }
}
