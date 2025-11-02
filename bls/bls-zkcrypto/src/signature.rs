use std::sync::Arc;

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use bls_core::{consts::DOMAIN_SEPARATION_TAG, error::Error, traits::Signature as SignatureTrait};
use derive_more::From;
use ff::Field;
use itertools::Itertools as _;
#[cfg(target_os = "zkvm")]
use once_cell::sync::OnceCell;
#[cfg(target_os = "zkvm")]
use rand_chacha::rand_core::SeedableRng;
use sha2::Sha256;

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

#[cfg(target_os = "zkvm")]
static RAND_SEED: once_cell::sync::OnceCell<[u8; 32]> = once_cell::sync::OnceCell::new();
#[cfg(target_os = "zkvm")]
pub fn set_rand_seed(seed: [u8; 32]) {
    let _ = RAND_SEED.set(seed);
}

impl SignatureTrait for Signature {
    type SignatureBytes = SignatureBytes;
    type PublicKey = PublicKey;

    fn verify(&self, message: impl AsRef<[u8]>, public_key: &Self::PublicKey) -> bool {
        let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            [message.as_ref()],
            DOMAIN_SEPARATION_TAG,
        );

        let gt1 = pairing(&G1Affine::from(public_key.as_raw()), &G2Affine::from(h));
        let gt2 = pairing(&G1Affine::generator(), &G2Affine::from(self.as_raw()));

        gt1 == gt2
    }

    #[inline]
    fn aggregate_in_place(&mut self, other: Self) {
        self.0 = self.as_raw().add(other.as_raw());
    }

    fn fast_aggregate_verify(
        &self,
        message: impl AsRef<[u8]>,
        public_keys: impl IntoIterator<Item = Arc<PublicKey>>,
    ) -> bool {
        if bool::from(self.as_raw().is_identity()) {
            return false;
        }

        let agg_pk = public_keys
            .into_iter()
            .fold(G1Projective::identity(), |acc, pk| acc + pk.as_raw());

        let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            [message.as_ref()],
            DOMAIN_SEPARATION_TAG,
        );

        pairing(&agg_pk.into(), &h.into()) == pairing(&G1Affine::generator(), &self.as_raw().into())
    }

    fn multi_verify<'all>(
        messages: impl IntoIterator<Item = &'all [u8]>,
        signatures: impl IntoIterator<Item = &'all Self>,
        public_keys: impl IntoIterator<Item = &'all PublicKey>,
    ) -> bool {
        let msgs: Vec<&[u8]> = messages.into_iter().collect_vec();
        let sigs: Vec<&G2Projective> = signatures.into_iter().map(Self::as_raw).collect_vec();
        let pks: Vec<&G1Projective> = public_keys.into_iter().map(PublicKey::as_raw).collect_vec();

        #[cfg(not(target_os = "zkvm"))]
        let mut rng = rand::thread_rng();

        #[cfg(target_os = "zkvm")]
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(
            OnceCell::<[u8; 32]>::get(&RAND_SEED).unwrap().clone(),
        );

        if msgs.len() != sigs.len() || sigs.len() != pks.len() {
            return false;
        }

        if sigs.iter().any(|sig| bool::from(sig.is_identity())) {
            return false;
        }

        let rand_scalars: Vec<Scalar> = (0..sigs.len())
            .map(|_| Scalar::random(&mut rng))
            .collect_vec();

        let mut agg_sig = G2Projective::identity();
        let mut lhs = pairing(&G1Affine::generator(), &G2Affine::identity());

        for i in 0..sigs.len() {
            let h = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
                [msgs[i]],
                DOMAIN_SEPARATION_TAG,
            );

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

#[cfg(test)]
mod tests {
    use bls_core::SecretKey as _;

    use crate::{secret_key::SecretKey, secret_key_bytes::SecretKeyBytes};

    use super::*;

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
