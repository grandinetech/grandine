use core::num::NonZeroU64;

use blst::{
    blst_scalar,
    min_pk::{AggregateSignature as RawAggregateSignature, Signature as RawSignature},
    BLST_ERROR,
};
use derive_more::From;
use itertools::Itertools as _;
use rand::Rng as _;

use crate::{consts::DOMAIN_SEPARATION_TAG, Error, PublicKey, SignatureBytes};

const MULTI_VERIFY_RANDOM_BYTES: usize = size_of::<NonZeroU64>();
const MULTI_VERIFY_RANDOM_BITS: usize = MULTI_VERIFY_RANDOM_BYTES * 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug, From)]
pub struct Signature(RawSignature);

impl Default for Signature {
    #[inline]
    fn default() -> Self {
        SignatureBytes::empty()
            .try_into()
            .expect("compressed signature constructed in SignatureBytes::empty is valid")
    }
}

impl From<Signature> for SignatureBytes {
    #[inline]
    fn from(signature: Signature) -> Self {
        Self(signature.as_raw().compress())
    }
}

impl TryFrom<SignatureBytes> for Signature {
    type Error = Error;

    #[inline]
    fn try_from(bytes: SignatureBytes) -> Result<Self, Self::Error> {
        RawSignature::uncompress(bytes.as_bytes())
            .map(Self)
            .map_err(Into::into)
    }
}

impl Signature {
    #[must_use]
    pub fn verify(self, message: impl AsRef<[u8]>, public_key: PublicKey) -> bool {
        let result = self.as_raw().verify(
            true,
            message.as_ref(),
            DOMAIN_SEPARATION_TAG,
            &[],
            public_key.as_raw(),
            false,
        );

        result == BLST_ERROR::BLST_SUCCESS
    }

    #[inline]
    #[must_use]
    pub fn aggregate(mut self, other: Self) -> Self {
        self.aggregate_in_place(other);
        self
    }

    #[inline]
    pub fn aggregate_in_place(&mut self, other: Self) {
        let mut self_aggregate = RawAggregateSignature::from_signature(self.as_raw());
        let other_aggregate = RawAggregateSignature::from_signature(other.as_raw());
        self_aggregate.add_aggregate(&other_aggregate);
        self.0 = self_aggregate.to_signature();
    }

    #[must_use]
    pub fn fast_aggregate_verify<'keys>(
        &self,
        message: impl AsRef<[u8]>,
        public_keys: impl IntoIterator<Item = &'keys PublicKey>,
    ) -> bool {
        let public_keys = public_keys.into_iter().map(PublicKey::as_raw).collect_vec();

        let result = self.as_raw().fast_aggregate_verify(
            true,
            message.as_ref(),
            DOMAIN_SEPARATION_TAG,
            public_keys.as_slice(),
        );

        result == BLST_ERROR::BLST_SUCCESS
    }

    #[must_use]
    pub fn multi_verify<'all>(
        messages: impl IntoIterator<Item = &'all [u8]>,
        signatures: impl IntoIterator<Item = &'all Self>,
        public_keys: impl IntoIterator<Item = &'all PublicKey>,
    ) -> bool {
        let messages = messages.into_iter().collect_vec();
        let signatures = signatures.into_iter().map(Self::as_raw).collect_vec();
        let public_keys = public_keys.into_iter().map(PublicKey::as_raw).collect_vec();

        // `ThreadRng` is cryptographically secure.
        let mut rng = rand::thread_rng();

        let randoms = core::iter::repeat_with(|| {
            let mut scalar = blst_scalar::default();
            let nonzero_bytes = rng.gen::<NonZeroU64>().get().to_le_bytes();
            scalar.b[..MULTI_VERIFY_RANDOM_BYTES].copy_from_slice(&nonzero_bytes);
            scalar
        })
        .take(signatures.len())
        .collect_vec();

        let result = RawSignature::verify_multiple_aggregate_signatures(
            messages.as_slice(),
            DOMAIN_SEPARATION_TAG,
            public_keys.as_slice(),
            false,
            signatures.as_slice(),
            false,
            randoms.as_slice(),
            MULTI_VERIFY_RANDOM_BITS,
        );

        result == BLST_ERROR::BLST_SUCCESS
    }

    const fn as_raw(&self) -> &RawSignature {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use std_ext::CopyExt as _;
    use tap::{Conv as _, TryConv as _};

    use crate::{SecretKey, SecretKeyBytes};

    use super::*;

    const MESSAGE: &str = "foo";

    #[test]
    fn signature_verify_succeeds_on_correct_triple() {
        let secret_key = secret_key();
        let public_key = secret_key.to_public_key();
        let signature = secret_key.sign(MESSAGE);

        assert!(signature.verify(MESSAGE, public_key));
    }

    #[test]
    fn signature_verify_fails_on_incorrect_public_key() {
        let secret_key = secret_key();
        let public_key = PublicKey::default();
        let signature = secret_key.sign(MESSAGE);

        assert!(!signature.verify(MESSAGE, public_key));
    }

    #[test]
    fn signature_verify_fails_on_incorrect_signature() {
        let secret_key = secret_key();
        let public_key = secret_key.to_public_key();
        let signature = Signature::default();

        assert!(!signature.verify(MESSAGE, public_key));
    }

    fn secret_key() -> SecretKey {
        b"????????????????????????????????"
            .copy()
            .conv::<SecretKeyBytes>()
            .try_conv::<SecretKey>()
            .expect("bytes encode a valid secret key")
    }
}
