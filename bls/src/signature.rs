use core::fmt::Debug;

use derive_more::derive::From;

use crate::{backend::backend, public_key::PublicKeyTrait, Backend, Error, PublicKey, SignatureBytes};

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

    #[cfg(feature = "zkcrypto")]
    Zkcrypto(zkcrypto::Signature)
}

impl Default for Signature {
    fn default() -> Self {
        match backend() {
            #[cfg(feature = "blst")]
            Backend::Blst => Signature::Blst(blst::Signature::default()),

            #[cfg(feature = "zkcrypto")]
            Backend::Zkcrypto => Signature::Zkcrypto(zkcrypto::Signature::default()),
        }
    }
}

impl TryFrom<SignatureBytes> for Signature {
    type Error = Error;

    fn try_from(bytes: SignatureBytes) -> Result<Self, Self::Error> {
        match backend() {
            #[cfg(feature = "blst")]
            Backend::Blst => Ok(Signature::Blst(blst::Signature::try_from(bytes)?)),

            #[cfg(feature = "zkcrypto")]
            Backend::Zkcrypto => Ok(Signature::Zkcrypto(zkcrypto::Signature::try_from(bytes)?)),
        }
    }
}

impl Into<SignatureBytes> for Signature {
    fn into(self) -> SignatureBytes {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(sig) => sig.into(),

            #[cfg(feature = "zkcrypto")]
            Self::Zkcrypto(sig) => sig.into(),
        }
    }
}

#[allow(irrefutable_let_patterns)]
#[allow(unreachable_patterns)]
impl SignatureTrait for Signature {
    type PublicKey = PublicKey;

    fn verify(&self, message: impl AsRef<[u8]>, public_key: PublicKey) -> bool {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(v) => v.verify(message, public_key.as_blst()),

            #[cfg(feature = "zkcrypto")]
            Self::Zkcrypto(v) => v.verify(message, public_key.as_zkcrypto()),
        }
    }

    fn aggregate_in_place(&mut self, other: Self) {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(v) => v.aggregate_in_place(other.as_blst()),

            #[cfg(feature = "zkcrypto")]
            Self::Zkcrypto(v) => v.aggregate_in_place(other.as_zkcrypto()),
        }
    }

    fn fast_aggregate_verify<'keys>(
        &self,
        message: impl AsRef<[u8]>,
        public_keys: impl IntoIterator<Item = &'keys PublicKey>,
    ) -> bool {
        match self {
            #[cfg(feature = "blst")]
            Self::Blst(v) => v.fast_aggregate_verify(
                message,
                public_keys.into_iter().map(|key| key.as_blst_ref()),
            ),

            #[cfg(feature = "zkcrypto")]
            Self::Zkcrypto(v) => v.fast_aggregate_verify(
                message,
                public_keys.into_iter().map(|key| key.as_zkcrypto_ref())
            )
        }
    }

    fn multi_verify<'all>(
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
            Signature::Blst(sig) => blst::Signature::multi_verify(
                messages,
                std::iter::once(sig).chain(signatures.map(|sig| sig.as_blst_ref())),
                public_keys.into_iter().map(|pubkey| pubkey.as_blst_ref()),
            ),

            #[cfg(feature = "zkcrypto")]
            Signature::Zkcrypto(sig) => zkcrypto::Signature::multi_verify(
                messages,
                std::iter::once(sig).chain(signatures.map(|sig| sig.as_zkcrypto_ref())),
                public_keys.into_iter().map(|pubkey| pubkey.as_zkcrypto_ref())
            )
        }
    }
}

impl Signature {
    #[must_use]
    pub fn aggregate(mut self, other: Self) -> Self {
        self.aggregate_in_place(other);
        self
    }

    #[cfg(feature = "blst")]
    pub(crate) fn as_blst(self) -> blst::Signature {
        *self.as_blst_ref()
    }

    #[cfg(feature = "blst")]
    pub(crate) fn as_blst_ref(&self) -> &blst::Signature {
        match self {
            Self::Blst(v) => v,

            _ => panic!("mixed backends"),
        }
    }

    #[cfg(feature = "zkcrypto")]
    pub(crate) fn as_zkcrypto(self) -> zkcrypto::Signature {
        *self.as_zkcrypto_ref()
    }

    #[cfg(feature = "zkcrypto")]
    pub(crate) fn as_zkcrypto_ref(&self) -> &zkcrypto::Signature {
        match self {
            Self::Zkcrypto(v) => v,
        
            _ => panic!("mixed backends"),
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

#[cfg(feature = "zkcrypto")]
pub(crate) mod zkcrypto {
    use bls12_381::{hash_to_curve::{ExpandMsgXmd, HashToCurve}, pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
    use derive_more::derive::From;
    use rand::thread_rng;
    use sha2::Sha256;
    use ff::Field;

    use crate::{public_key::zkcrypto::PublicKey, Error, SignatureBytes, DOMAIN_SEPARATION_TAG};
    use super::SignatureTrait;

    #[derive(Clone, Copy, PartialEq, Eq, Debug, From)]
    pub struct Signature(G2Projective);

    impl Default for Signature {
        #[inline]
        fn default() -> Self {
            Self(G2Projective::identity())
        }
    }

    impl TryFrom<SignatureBytes> for Signature {
        type Error = Error;
    
        fn try_from(bytes: SignatureBytes) -> Result<Self, Self::Error> {
            let point: G2Affine = Option::from(G2Affine::from_compressed(bytes.as_ref())).ok_or(Error::DecompressionFailed)?;

            if !bool::from(point.is_torsion_free()) {
                return Err(Error::DecompressionFailed);
            }

            Ok(Self(point.into()))
        }
    }

    impl Into<SignatureBytes> for Signature {
        fn into(self) -> SignatureBytes {
            let aff: G2Affine = self.0.into();

            SignatureBytes(aff.to_compressed())
        }
    }

    impl SignatureTrait for Signature {
        type PublicKey = PublicKey;
    
        fn verify(&self, message: impl AsRef<[u8]>, public_key: Self::PublicKey) -> bool {
            let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
                [message.as_ref()],
                DOMAIN_SEPARATION_TAG, 
            );

            let gt1 = pairing(&G1Affine::from(public_key.as_raw()), &G2Affine::from(h));
            let gt2 = pairing(&G1Affine::generator(), &G2Affine::from(self.as_raw()));

            gt1 == gt2
        }
    
        fn aggregate_in_place(&mut self, other: Self) {
            self.0 = self.as_raw().add(other.as_raw())
        }
    
        fn fast_aggregate_verify<'keys>(
            &self,
            message: impl AsRef<[u8]>,
            public_keys: impl IntoIterator<Item = &'keys Self::PublicKey>,
        ) -> bool {
            if bool::from(self.as_raw().is_identity()) {
                return false;
            }

            let agg_pk = public_keys.into_iter().fold(G1Projective::identity(), |acc, pk| acc + pk.as_raw());

            let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([message.as_ref()], DOMAIN_SEPARATION_TAG);

            pairing(&agg_pk.into(), &h.into()) == pairing(&G1Affine::generator(), &self.as_raw().into())
        }
    
        fn multi_verify<'all>(
            messages: impl IntoIterator<Item = &'all [u8]>,
            signatures: impl IntoIterator<Item = &'all Self>,
            public_keys: impl IntoIterator<Item = &'all Self::PublicKey>,
        ) -> bool {
            let mut rng = thread_rng();

            let msgs = messages.into_iter().collect::<Vec<_>>();
            let sigs = signatures.into_iter().map(Self::as_raw).collect::<Vec<_>>();
            let pks = public_keys.into_iter().map(PublicKey::as_raw).collect::<Vec<_>>();

            if msgs.len() != sigs.len() || sigs.len() != pks.len() {
                return false;
            }

            if sigs.iter().any(|sig| bool::from(sig.is_identity())) {
                return false;
            }

            let rand_scalars = (0..sigs.len()).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();

            let mut agg_sig = G2Projective::identity();
            let mut lhs = pairing(&G1Affine::generator(), &G2Affine::identity());

            for i in 0..sigs.len() {
                let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([msgs[i]], DOMAIN_SEPARATION_TAG);

                agg_sig += sigs[i] * rand_scalars[i];

                lhs += pairing(&(pks[i] * rand_scalars[i]).into(), &h.into());
            }

            lhs == pairing(&G1Affine::generator(), &agg_sig.into())
        }
    }

    impl Signature {
        pub(crate) const fn as_raw(&self) -> &G2Projective {
            &self.0
        }
    }
}