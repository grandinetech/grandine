use core::fmt::Debug;

use derive_more::derive::From;

use crate::{public_key::PublicKeyTrait, Backend, Error, PublicKey, SignatureBytes};

pub trait SignatureTrait: Clone + Copy + PartialEq + Eq + Debug + Default + 'static
where
    Self::PublicKey: 'static,
{
    type PublicKey: PublicKeyTrait;

    fn verify(&self, message: impl AsRef<[u8]>, public_key: Self::PublicKey) -> bool;

    fn aggregate_in_place(&mut self, other: Self);

    fn fast_aggregate_verify<'keys>(
        &self,
        message: impl AsRef<[u8]>,
        public_keys: impl IntoIterator<Item = &'keys Self::PublicKey>,
    ) -> bool;

    fn multi_verify<'all>(
        messages: impl IntoIterator<Item = &'all [u8]>,
        signatures: impl IntoIterator<Item = &'all Self>,
        public_keys: impl IntoIterator<Item = &'all Self::PublicKey>,
    ) -> bool;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, From)]
pub enum Signature {
    #[cfg(feature = "blst")]
    Blst(blst::Signature),
}

#[allow(irrefutable_let_patterns)]
#[allow(unreachable_patterns)]
impl Signature {
    pub fn verify(&self, message: impl AsRef<[u8]>, public_key: PublicKey) -> bool {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(v) => {
                let PublicKey::Blst(public_key) = public_key else {
                    panic!("mixed backends");
                };

                v.verify(message, public_key)
            }
        }
    }

    #[must_use]
    pub fn aggregate(mut self, other: Self) -> Self {
        self.aggregate_in_place(other);
        self
    }

    pub fn aggregate_in_place(&mut self, other: Self) {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(v) => {
                let Self::Blst(other) = other else {
                    panic!("mixed backends");
                };
                v.aggregate_in_place(other);
            }
        }
    }

    pub fn fast_aggregate_verify<'keys>(
        &self,
        message: impl AsRef<[u8]>,
        public_keys: impl IntoIterator<Item = &'keys PublicKey>,
    ) -> bool {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(v) => v.fast_aggregate_verify(
                message,
                public_keys.into_iter().map(|key| match key {
                    PublicKey::Blst(k) => k,
                    _ => panic!("mixed backends"),
                }),
            ),
        }
    }

    pub fn multi_verify<'all>(
        messages: impl IntoIterator<Item = &'all [u8]>,
        signatures: impl IntoIterator<Item = &'all Self>,
        public_keys: impl IntoIterator<Item = &'all PublicKey>,
    ) -> bool {
        let mut signatures = signatures.into_iter();
        let Some(first_signature) = signatures.next() else {
            todo!();
        };

        match first_signature {
            #[cfg(feature = "blst")]
            Signature::Blst(blst) => blst::Signature::multi_verify(
                messages,
                std::iter::once(blst).chain(signatures.map(|sig| match sig {
                    Signature::Blst(sig) => sig,
                    _ => panic!("mixed backends"),
                })),
                public_keys.into_iter().map(|pubkey| match pubkey {
                    PublicKey::Blst(key) => key,
                    _ => panic!("mixed backends"),
                }),
            ),
        }
    }

    pub fn try_from_with_backend(bytes: SignatureBytes, backend: Backend) -> Result<Self, Error> {
        match backend {
            #[cfg(feature = "blst")]
            Backend::Blst => Ok(Signature::Blst(blst::Signature::try_from(bytes)?)),
        }
    }

    pub fn default_with_backend(backend: Backend) -> Self {
        match backend {
            #[cfg(feature = "blst")]
            Backend::Blst => Signature::Blst(blst::Signature::default()),
        }
    }
}

impl Into<SignatureBytes> for Signature {
    fn into(self) -> SignatureBytes {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(sig) => sig.into(),
        }
    }
}

#[cfg(feature = "blst")]
pub(crate) mod blst {
    use core::num::NonZeroU64;

    use blst::{
        blst_scalar,
        min_pk::{AggregateSignature as RawAggregateSignature, Signature as RawSignature},
        BLST_ERROR,
    };
    use derive_more::From;
    use itertools::Itertools as _;
    use rand::Rng as _;

    use crate::{
        consts::DOMAIN_SEPARATION_TAG, error::Error, public_key::blst::PublicKey,
        signature::SignatureTrait, signature_bytes::SignatureBytes,
    };

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

    impl Into<SignatureBytes> for Signature {
        fn into(self) -> SignatureBytes {
            SignatureBytes(self.as_raw().compress())
        }
    }

    impl SignatureTrait for Signature {
        type PublicKey = PublicKey;

        #[must_use]
        fn verify(&self, message: impl AsRef<[u8]>, public_key: Self::PublicKey) -> bool {
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

        #[must_use]
        fn fast_aggregate_verify<'keys>(
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
        fn multi_verify<'all>(
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
    }

    impl Signature {
        #[must_use]
        pub const fn as_raw(&self) -> &RawSignature {
            &self.0
        }
    }
}
