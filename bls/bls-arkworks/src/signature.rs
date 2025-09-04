use ark_bls12_381::{g2, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    short_weierstrass::Projective,
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, UniformRand};
use ark_serialize::CanonicalDeserialize;
use bls_core::{consts::DOMAIN_SEPARATION_TAG, error::Error, traits::Signature as SignatureTrait};
use derive_more::From;
use itertools::Itertools as _;
use rand::thread_rng;
use sha2::Sha256;

use super::{public_key::PublicKey, signature_bytes::SignatureBytes};

#[derive(Clone, Copy, PartialEq, Eq, Debug, From)]
pub struct Signature(G2Projective);

impl Default for Signature {
    #[inline]
    fn default() -> Self {
        Self(G2Projective::default())
    }
}

impl TryFrom<SignatureBytes> for Signature {
    type Error = Error;

    #[inline]
    fn try_from(bytes: SignatureBytes) -> Result<Self, Self::Error> {
        let point = G2Affine::deserialize_compressed::<&[u8]>(bytes.as_ref())
            .map_err(|_| Error::DecompressionFailed)?;

        Ok(Self(point.into()))
    }
}

impl SignatureTrait for Signature {
    type SignatureBytes = SignatureBytes;
    type PublicKey = PublicKey;

    #[must_use]
    fn verify(&self, message: impl AsRef<[u8]>, public_key: Self::PublicKey) -> bool {
        let h = MapToCurveBasedHasher::<
            Projective<g2::Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<g2::Config>,
        >::new(DOMAIN_SEPARATION_TAG)
        .unwrap()
        .hash(message.as_ref())
        .unwrap();

        let gt1 = Bls12_381::pairing(public_key.as_raw(), &G2Affine::from(h));
        let gt2 = Bls12_381::pairing(&G1Affine::generator(), self.as_raw().into_affine());

        gt1 == gt2
    }

    #[inline]
    fn aggregate_in_place(&mut self, other: Self) {
        self.0 = *self.as_raw() + *other.as_raw();
    }

    #[must_use]
    fn fast_aggregate_verify<'keys>(
        &self,
        message: impl AsRef<[u8]>,
        public_keys: impl IntoIterator<Item = &'keys PublicKey>,
    ) -> bool {
        if bool::from(self.as_raw().into_affine().is_zero()) {
            return false;
        }

        let agg_pk = public_keys
            .into_iter()
            .fold(G1Projective::default(), |acc, pk| acc + pk.as_raw());

        let h = MapToCurveBasedHasher::<
            Projective<g2::Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<g2::Config>,
        >::new(DOMAIN_SEPARATION_TAG)
        .unwrap()
        .hash(message.as_ref())
        .unwrap();

        Bls12_381::pairing(&agg_pk.into_affine(), &h)
            == Bls12_381::pairing(&G1Affine::generator(), &self.as_raw().into_affine())
    }

    #[must_use]
    fn multi_verify<'all>(
        messages: impl IntoIterator<Item = &'all [u8]>,
        signatures: impl IntoIterator<Item = &'all Self>,
        public_keys: impl IntoIterator<Item = &'all PublicKey>,
    ) -> bool {
        let mut rng = thread_rng();

        let msgs: Vec<&[u8]> = messages.into_iter().collect_vec();
        let sigs: Vec<&G2Projective> = signatures.into_iter().map(Self::as_raw).collect_vec();
        let pks: Vec<&G1Projective> = public_keys.into_iter().map(PublicKey::as_raw).collect_vec();

        if msgs.len() != sigs.len() || sigs.len() != pks.len() {
            return false;
        }

        if sigs
            .iter()
            .any(|sig| bool::from(sig.into_affine().is_zero()))
        {
            return false;
        }

        let rand_scalars: Vec<Fr> = (0..sigs.len()).map(|_| Fr::rand(&mut rng)).collect_vec();

        let mut agg_sig = G2Projective::default();
        let mut lhs = Bls12_381::pairing(&G1Affine::generator(), &G2Affine::identity());

        for i in 0..sigs.len() {
            let h = MapToCurveBasedHasher::<
                Projective<g2::Config>,
                DefaultFieldHasher<Sha256, 128>,
                WBMap<g2::Config>,
            >::new(DOMAIN_SEPARATION_TAG)
            .unwrap()
            .hash(msgs[i])
            .unwrap();

            agg_sig += *sigs[i] * rand_scalars[i];

            lhs += Bls12_381::pairing(&(*pks[i] * rand_scalars[i]), &h);
        }

        lhs == Bls12_381::pairing(&G1Affine::generator(), &agg_sig.into_affine())
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

        assert!(Signature::verify(&signature, MESSAGE, public_key));
    }

    #[test]
    fn signature_verify_fails_on_incorrect_public_key() {
        let secret_key = secret_key();
        let public_key = PublicKey::default();
        let signature = SecretKey::sign(&secret_key, MESSAGE);

        assert!(!Signature::verify(&signature, MESSAGE, public_key));
    }

    #[test]
    fn signature_verify_fails_on_incorrect_signature() {
        let secret_key = secret_key();
        let public_key = SecretKey::to_public_key(&secret_key);
        let signature = Signature::default();

        assert!(!Signature::verify(&signature, MESSAGE, public_key));
    }

    fn secret_key() -> SecretKey {
        let bytes = b"????????????????????????????????";
        SecretKey::try_from(SecretKeyBytes {
            bytes: bytes.to_owned(),
        })
        .expect("bytes encode a valid secret key")
    }
}
