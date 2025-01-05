use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use derive_more::From;
use ff::Field;
use rand::thread_rng;
use sha2::Sha256;

use crate::{consts::DOMAIN_SEPARATION_TAG, error::Error, traits::Signature as SignatureTrait};

use super::{public_key::PublicKey, signature_bytes::SignatureBytes};

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

    #[inline]
    fn try_from(bytes: SignatureBytes) -> Result<Self, Self::Error> {
        let point: G2Affine = Option::from(G2Affine::from_compressed(bytes.as_ref()))
            .ok_or(Error::DecompressionFailed)?;

        if !bool::from(point.is_torsion_free()) {
            return Err(Error::DecompressionFailed);
        }

        Ok(Self(point.into()))
    }
}

impl SignatureTrait for Signature {
    type SignatureBytes = SignatureBytes;
    type PublicKey = PublicKey;

    #[must_use]
    fn verify(&self, message: impl AsRef<[u8]>, public_key: &Self::PublicKey) -> bool {
        let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            &[message.as_ref()],
            DOMAIN_SEPARATION_TAG,
        );

        let gt1 = pairing(&G1Affine::from(public_key.as_raw()), &G2Affine::from(h));
        let gt2 = pairing(&G1Affine::generator(), &G2Affine::from(self.as_raw()));

        gt1 == gt2
    }

    #[inline]
    fn aggregate_in_place(&mut self, other: Self) {
        self.as_raw().add(other.as_raw());
    }

    #[must_use]
    fn fast_aggregate_verify<'keys>(
        &self,
        message: impl AsRef<[u8]>,
        public_keys: impl IntoIterator<Item = &'keys PublicKey>,
    ) -> bool {
        let agg_pk = public_keys
            .into_iter()
            .fold(G1Projective::identity(), |acc, pk| acc + pk.as_raw());

        let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            &[message.as_ref()],
            DOMAIN_SEPARATION_TAG,
        );

        let gt1 = pairing(&agg_pk.into(), &h.into());
        let gt2 = pairing(&G1Affine::generator(), &self.as_raw().into());

        gt1 == gt2
    }

    #[must_use]
    fn multi_verify<'all>(
        messages: impl IntoIterator<Item = &'all [u8]>,
        signatures: impl IntoIterator<Item = &'all Self>,
        public_keys: impl IntoIterator<Item = &'all PublicKey>,
    ) -> bool {
        let mut rng = thread_rng();

        let msgs: Vec<_> = messages.into_iter().collect();
        let sigs: Vec<_> = signatures.into_iter().collect();
        let pks: Vec<_> = public_keys.into_iter().collect();

        if msgs.len() != sigs.len() || sigs.len() != pks.len() {
            return false;
        }

        let rand_scalars: Vec<_> = (0..sigs.len()).map(|_| Scalar::random(&mut rng)).collect();

        let mut agg_sig = G2Projective::identity();
        let mut agg_pk = G1Projective::identity();
        let mut agg_hm = G2Projective::identity();

        for (((&msg, sig), pk), r) in msgs.iter().zip(sigs).zip(pks).zip(&rand_scalars) {
            let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
                &[msg],
                DOMAIN_SEPARATION_TAG,
            );

            agg_sig += sig.0 * r;
            agg_pk += pk.as_raw() * r;
            agg_hm += h * r;
        }

        pairing(&agg_pk.into(), &agg_hm.into()) == pairing(&G1Affine::generator(), &agg_sig.into())
    }
}

impl Signature {
    pub(crate) const fn as_raw(&self) -> &G2Projective {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backends::zkcrypto::{secret_key::SecretKey, secret_key_bytes::SecretKeyBytes},
        traits::SecretKey as _,
    };

    const MESSAGE: &str = "foo";

    #[test]
    fn signature_verify_succeeds_on_correct_triple() {
        let secret_key = secret_key();
        let public_key = SecretKey::to_public_key(&secret_key);
        let signature = SecretKey::sign(&secret_key, MESSAGE);

        assert!(Signature::verify(&signature, MESSAGE, &public_key));
    }

    #[test]
    fn signature_verify_fails_on_incorrect_public_key() {
        let secret_key = secret_key();
        let public_key = PublicKey::default();
        let signature = SecretKey::sign(&secret_key, MESSAGE);

        assert!(!Signature::verify(&signature, MESSAGE, &public_key));
    }

    #[test]
    fn signature_verify_fails_on_incorrect_signature() {
        let secret_key = secret_key();
        let public_key = SecretKey::to_public_key(&secret_key);
        let signature = Signature::default();

        assert!(!Signature::verify(&signature, MESSAGE, &public_key));
    }

    fn secret_key() -> SecretKey {
        let bytes = b"????????????????????????????????";
        SecretKey::try_from(SecretKeyBytes {
            bytes: bytes.to_owned(),
        })
        .expect("bytes encode a valid secret key")
    }
}
