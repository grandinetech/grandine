use core::num::NonZeroU64;
use std::sync::Arc;

use blst::{
    BLST_ERROR, blst_scalar,
    min_pk::{
        AggregatePublicKey as RawAggregatePublicKey, AggregateSignature as RawAggregateSignature,
        Signature as RawSignature,
    },
};
use derive_more::From;
use itertools::{Either, Itertools as _};
use rand::Rng as _;
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};

use bls_core::{
    consts::DOMAIN_SEPARATION_TAG,
    error::Error,
    traits::{Signature as SignatureTrait, SignatureBytes as SignatureBytesTrait},
};

use super::{public_key::PublicKey, signature_bytes::SignatureBytes};

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

impl TryFrom<SignatureBytes> for Signature {
    type Error = Error;

    #[inline]
    fn try_from(bytes: SignatureBytes) -> Result<Self, Self::Error> {
        RawSignature::uncompress(bytes.as_bytes())
            .map(Self)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl SignatureTrait for Signature {
    type SignatureBytes = SignatureBytes;
    type PublicKey = PublicKey;

    fn verify(&self, message: impl AsRef<[u8]>, public_key: &Self::PublicKey) -> bool {
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
    fn aggregate_in_place(&mut self, other: Self) {
        let mut self_aggregate = RawAggregateSignature::from_signature(self.as_raw());
        let other_aggregate = RawAggregateSignature::from_signature(other.as_raw());
        self_aggregate.add_aggregate(&other_aggregate);
        self.0 = self_aggregate.to_signature();
    }

    fn fast_aggregate_verify(
        &self,
        message: impl AsRef<[u8]>,
        public_keys: impl IntoIterator<Item = Arc<PublicKey>>,
    ) -> bool {
        let raw_keys = public_keys
            .into_iter()
            .map(|key| *key.as_raw())
            .collect_vec();

        let public_keys = raw_keys.iter().collect_vec();

        let result = self.as_raw().fast_aggregate_verify(
            true,
            message.as_ref(),
            DOMAIN_SEPARATION_TAG,
            public_keys.as_slice(),
        );

        result == BLST_ERROR::BLST_SUCCESS
    }

    fn multi_verify<'all>(
        messages: impl IntoIterator<Item = &'all [u8]>,
        signatures: impl IntoIterator<Item = &'all Self>,
        public_keys: impl IntoIterator<Item = &'all PublicKey>,
    ) -> bool {
        let messages = messages.into_iter().collect_vec();
        let signatures = signatures.into_iter().map(Self::as_raw).collect_vec();
        let public_keys = public_keys.into_iter().map(PublicKey::as_raw).collect_vec();

        if messages.len() != signatures.len() || signatures.len() != public_keys.len() {
            return false;
        }

        let (singles, groups): (Vec<_>, Vec<_>) = messages
            .into_iter()
            .zip(signatures.into_iter().zip(public_keys))
            .into_group_map()
            .into_iter()
            .partition_map(|(message, group)| match group.as_slice() {
                [(signature, public_key)] => Either::Left((message, **signature, **public_key)),
                _ => Either::Right((message, group)),
            });

        let Some(combined) = groups
            .into_par_iter()
            .map(|(message, group)| {
                let (signatures, public_keys): (Vec<_>, Vec<_>) = group
                    .iter()
                    .map(|(signature, public_key)| (**signature, **public_key))
                    .unzip();

                // `ThreadRng` is cryptographically secure.
                let mut rng = rand::thread_rng();

                // Without a scalar each, signatures over one message could cancel in the sum.
                let randoms =
                    core::iter::repeat_with(|| rng.r#gen::<NonZeroU64>().get().to_le_bytes())
                        .take(signatures.len())
                        .flatten()
                        .collect_vec();

                // Rejects infinity signatures, the only ones that match an infinity member key.
                let Ok(signature) = RawAggregateSignature::aggregate_with_randomness(
                    &signatures,
                    &randoms,
                    MULTI_VERIFY_RANDOM_BITS,
                    true,
                ) else {
                    return None;
                };

                let Ok(public_key) = RawAggregatePublicKey::aggregate_with_randomness(
                    &public_keys,
                    &randoms,
                    MULTI_VERIFY_RANDOM_BITS,
                    false,
                ) else {
                    return None;
                };

                Some((
                    message,
                    signature.to_signature(),
                    public_key.to_public_key(),
                ))
            })
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };

        let (grouped_messages, grouped_signatures, grouped_public_keys): (Vec<_>, Vec<_>, Vec<_>) =
            singles.into_iter().chain(combined).multiunzip();

        // `ThreadRng` is cryptographically secure.
        let mut rng = rand::thread_rng();

        let randoms = core::iter::repeat_with(|| {
            let mut scalar = blst_scalar::default();
            let nonzero_bytes = rng.r#gen::<NonZeroU64>().get().to_le_bytes();
            scalar.b[..MULTI_VERIFY_RANDOM_BYTES].copy_from_slice(&nonzero_bytes);
            scalar
        })
        .take(grouped_signatures.len())
        .collect_vec();

        let result = RawSignature::verify_multiple_aggregate_signatures(
            grouped_messages.as_slice(),
            DOMAIN_SEPARATION_TAG,
            grouped_public_keys.iter().collect_vec().as_slice(),
            false,
            grouped_signatures.iter().collect_vec().as_slice(),
            true,
            randoms.as_slice(),
            MULTI_VERIFY_RANDOM_BITS,
        );

        result == BLST_ERROR::BLST_SUCCESS
    }
}

impl Signature {
    #[must_use]
    pub const fn as_raw(&self) -> &RawSignature {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use bls_core::SecretKey as _;
    use tap::{Conv as _, TryConv as _};

    use crate::{secret_key::SecretKey, secret_key_bytes::SecretKeyBytes};

    use super::*;

    const MESSAGE: &str = "foo";
    const OTHER_MESSAGE: &str = "bar";

    #[test]
    fn signature_verify_succeeds_on_correct_triple() {
        let secret_key = secret_key(b'?');
        let public_key = SecretKey::to_public_key(&secret_key);
        let signature = SecretKey::sign(&secret_key, MESSAGE);

        assert!(Signature::verify(&signature, MESSAGE, &public_key));
    }

    #[test]
    fn signature_verify_fails_on_incorrect_public_key() {
        let secret_key = secret_key(b'?');
        let public_key = PublicKey::default();
        let signature = SecretKey::sign(&secret_key, MESSAGE);

        assert!(!Signature::verify(&signature, MESSAGE, &public_key));
    }

    #[test]
    fn signature_verify_fails_on_incorrect_signature() {
        let secret_key = secret_key(b'?');
        let public_key = SecretKey::to_public_key(&secret_key);
        let signature = Signature::default();

        assert!(!Signature::verify(&signature, MESSAGE, &public_key));
    }

    #[test]
    fn signature_multi_verify_succeeds_on_shared_and_distinct_messages() {
        let secret_key_1 = secret_key(b'?');
        let secret_key_2 = secret_key(b'!');
        let secret_key_3 = secret_key(b'#');
        let public_key_1 = SecretKey::to_public_key(&secret_key_1);
        let public_key_2 = SecretKey::to_public_key(&secret_key_2);
        let public_key_3 = SecretKey::to_public_key(&secret_key_3);
        let signature_1 = SecretKey::sign(&secret_key_1, MESSAGE);
        let signature_2 = SecretKey::sign(&secret_key_2, MESSAGE);
        let signature_3 = SecretKey::sign(&secret_key_3, OTHER_MESSAGE);

        assert!(Signature::multi_verify(
            [
                MESSAGE.as_bytes(),
                MESSAGE.as_bytes(),
                OTHER_MESSAGE.as_bytes(),
            ],
            [&signature_1, &signature_2, &signature_3],
            [&public_key_1, &public_key_2, &public_key_3],
        ));
    }

    // A plain sum over one message ignores swapped signatures; the random scalars must not.
    #[test]
    fn signature_multi_verify_fails_on_swapped_signatures_over_same_message() {
        let secret_key_1 = secret_key(b'?');
        let secret_key_2 = secret_key(b'!');
        let public_key_1 = SecretKey::to_public_key(&secret_key_1);
        let public_key_2 = SecretKey::to_public_key(&secret_key_2);
        let signature_1 = SecretKey::sign(&secret_key_1, MESSAGE);
        let signature_2 = SecretKey::sign(&secret_key_2, MESSAGE);

        assert!(!Signature::multi_verify(
            [MESSAGE.as_bytes(); 2],
            [&signature_2, &signature_1],
            [&public_key_1, &public_key_2],
        ));
    }

    // Zipping would drop the unmatched message and verify only the rest.
    #[test]
    fn signature_multi_verify_fails_on_mismatched_lengths() {
        let secret_key = secret_key(b'?');
        let public_key = SecretKey::to_public_key(&secret_key);
        let signature = SecretKey::sign(&secret_key, MESSAGE);

        assert!(!Signature::multi_verify(
            [MESSAGE.as_bytes(), OTHER_MESSAGE.as_bytes()],
            [&signature],
            [&public_key],
        ));
    }

    // One bad member of a group fails the batch even when every other message checks out.
    #[test]
    fn signature_multi_verify_fails_on_invalid_signature_in_group() {
        let secret_key_1 = secret_key(b'?');
        let secret_key_2 = secret_key(b'!');
        let secret_key_3 = secret_key(b'#');
        let public_key_1 = SecretKey::to_public_key(&secret_key_1);
        let public_key_2 = SecretKey::to_public_key(&secret_key_2);
        let public_key_3 = SecretKey::to_public_key(&secret_key_3);
        let signature_1 = SecretKey::sign(&secret_key_1, MESSAGE);
        let signature_2 = SecretKey::sign(&secret_key_2, OTHER_MESSAGE);
        let signature_3 = SecretKey::sign(&secret_key_3, OTHER_MESSAGE);

        assert!(!Signature::multi_verify(
            [
                MESSAGE.as_bytes(),
                MESSAGE.as_bytes(),
                OTHER_MESSAGE.as_bytes(),
            ],
            [&signature_1, &signature_2, &signature_3],
            [&public_key_1, &public_key_2, &public_key_3],
        ));
    }

    // A member keyed at infinity drops out of its group's sum; only the signature check rejects it.
    #[test]
    fn signature_multi_verify_fails_on_infinity_member_in_group() {
        let secret_key = secret_key(b'?');
        let public_key = SecretKey::to_public_key(&secret_key);
        let signature = SecretKey::sign(&secret_key, MESSAGE);

        assert!(!Signature::multi_verify(
            [MESSAGE.as_bytes(); 2],
            [&Signature::default(), &signature],
            [&PublicKey::default(), &public_key],
        ));
    }

    fn secret_key(byte: u8) -> SecretKey {
        [byte; 32]
            .conv::<SecretKeyBytes>()
            .try_conv::<SecretKey>()
            .expect("bytes encode a valid secret key")
    }
}
