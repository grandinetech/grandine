#![expect(clippy::module_name_repetitions)]

use anyhow::{ensure, Result};
use bls::{
    traits::{CachedPublicKey as _, PublicKey as _, Signature as _, SignatureBytes as _},
    AggregatePublicKey, AggregateSignature, CachedPublicKey, PublicKey, Signature, SignatureBytes,
};
use derive_more::Constructor;
use enumset::{EnumSet, EnumSetType};
use rayon::iter::{IntoParallelRefIterator as _, ParallelBridge as _, ParallelIterator as _};
use static_assertions::assert_not_impl_any;
use tap::TryConv as _;
use types::phase0::primitives::H256;

use crate::error::{Error, SignatureKind};

pub trait Verifier {
    const IS_NULL: bool;

    fn reserve(&mut self, additional: usize);

    fn verify_singular(
        &mut self,
        message: H256,
        signature_bytes: SignatureBytes,
        cached_public_key: &CachedPublicKey,
        signature_kind: SignatureKind,
    ) -> Result<()>;

    fn verify_aggregate<'keys>(
        &mut self,
        message: H256,
        signature_bytes: SignatureBytes,
        public_keys: impl IntoIterator<IntoIter = impl Iterator<Item = &'keys PublicKey> + Send>,
        signature_kind: SignatureKind,
    ) -> Result<()>;

    /// [`eth_fast_aggregate_verify`](https://github.com/ethereum/consensus-specs/blob/86fb82b221474cc89387fa6436806507b3849d88/specs/altair/bls.md#eth_fast_aggregate_verify)
    ///
    /// This used to be inlined in `verify_sync_aggregate_signature`. We factored out the emptiness
    /// check to be able to run `bls/eth_fast_aggregate_verify` test cases.
    fn verify_aggregate_allowing_empty<'keys>(
        &mut self,
        message: H256,
        signature_bytes: SignatureBytes,
        public_keys: impl IntoIterator<IntoIter = impl Iterator<Item = &'keys PublicKey> + Send>,
        signature_kind: SignatureKind,
    ) -> Result<()> {
        if signature_bytes.is_empty() {
            ensure!(
                public_keys.into_iter().next().is_none(),
                Error::SignatureInvalid(signature_kind),
            );

            return Ok(());
        }

        self.verify_aggregate(message, signature_bytes, public_keys, signature_kind)
    }

    fn extend(
        &mut self,
        triples: impl IntoIterator<Item = Triple>,
        signature_kind: SignatureKind,
    ) -> Result<()>;

    fn finish(&self) -> Result<()>;

    fn has_option(&self, option: VerifierOption) -> bool;
}

impl<V: Verifier> Verifier for &mut V {
    const IS_NULL: bool = V::IS_NULL;

    #[inline]
    fn reserve(&mut self, additional: usize) {
        (*self).reserve(additional)
    }

    #[inline]
    fn verify_singular(
        &mut self,
        message: H256,
        signature_bytes: SignatureBytes,
        cached_public_key: &CachedPublicKey,
        signature_kind: SignatureKind,
    ) -> Result<()> {
        (*self).verify_singular(message, signature_bytes, cached_public_key, signature_kind)
    }

    #[inline]
    fn verify_aggregate<'keys>(
        &mut self,
        message: H256,
        signature_bytes: SignatureBytes,
        public_keys: impl IntoIterator<IntoIter = impl Iterator<Item = &'keys PublicKey> + Send>,
        signature_kind: SignatureKind,
    ) -> Result<()> {
        (*self).verify_aggregate(message, signature_bytes, public_keys, signature_kind)
    }

    #[inline]
    fn extend(
        &mut self,
        triples: impl IntoIterator<Item = Triple>,
        signature_kind: SignatureKind,
    ) -> Result<()> {
        (*self).extend(triples, signature_kind)
    }

    #[inline]
    fn finish(&self) -> Result<()> {
        (**self).finish()
    }

    #[inline]
    fn has_option(&self, option: VerifierOption) -> bool {
        (**self).has_option(option)
    }
}

pub struct NullVerifier;

impl Verifier for NullVerifier {
    const IS_NULL: bool = true;

    #[inline]
    fn reserve(&mut self, _additional: usize) {}

    #[inline]
    fn verify_singular(
        &mut self,
        _message: H256,
        _signature_bytes: SignatureBytes,
        _cached_public_key: &CachedPublicKey,
        _signature_kind: SignatureKind,
    ) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn verify_aggregate<'keys>(
        &mut self,
        _message: H256,
        _signature_bytes: SignatureBytes,
        _public_keys: impl IntoIterator<IntoIter = impl Iterator<Item = &'keys PublicKey> + Send>,
        _signature_kind: SignatureKind,
    ) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn extend(
        &mut self,
        _triples: impl IntoIterator<Item = Triple>,
        _signature_kind: SignatureKind,
    ) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn finish(&self) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn has_option(&self, _option: VerifierOption) -> bool {
        false
    }
}

pub struct SingleVerifier;

impl Verifier for SingleVerifier {
    const IS_NULL: bool = false;

    #[inline]
    fn reserve(&mut self, _additional: usize) {}

    #[inline]
    fn verify_singular(
        &mut self,
        message: H256,
        signature_bytes: SignatureBytes,
        cached_public_key: &CachedPublicKey,
        signature_kind: SignatureKind,
    ) -> Result<()> {
        let public_key = *cached_public_key.decompress()?;
        let triple = Triple::new(message, signature_bytes, public_key);
        self.extend(core::iter::once(triple), signature_kind)
    }

    #[inline]
    fn verify_aggregate<'keys>(
        &mut self,
        message: H256,
        signature_bytes: SignatureBytes,
        public_keys: impl IntoIterator<IntoIter = impl Iterator<Item = &'keys PublicKey> + Send>,
        signature_kind: SignatureKind,
    ) -> Result<()> {
        // `Signature::fast_aggregate_verify` is faster than aggregating public keys with Rayon.
        // It's enough to make block processing 14-21% faster, though it's only useful when
        // verifying signatures individually. Block processing now uses `Signature::multi_verify`,
        // which is even faster.
        ensure!(
            signature_bytes
                .try_conv::<AggregateSignature>()?
                .fast_aggregate_verify(message, public_keys.into_iter()),
            Error::SignatureInvalid(signature_kind),
        );

        Ok(())
    }

    #[inline]
    fn extend(
        &mut self,
        triples: impl IntoIterator<Item = Triple>,
        signature_kind: SignatureKind,
    ) -> Result<()> {
        for triple in triples {
            let Triple {
                message,
                signature_bytes,
                public_key,
            } = triple;

            let signature = Signature::try_from(signature_bytes)?;

            ensure!(
                signature.verify(message, &public_key),
                Error::SignatureInvalid(signature_kind),
            );
        }

        Ok(())
    }

    #[inline]
    fn finish(&self) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn has_option(&self, _option: VerifierOption) -> bool {
        false
    }
}

#[derive(Default)]
pub struct MultiVerifier {
    triples: Vec<Triple>,
    options: EnumSet<VerifierOption>,
}

impl Verifier for MultiVerifier {
    const IS_NULL: bool = false;

    #[inline]
    fn reserve(&mut self, additional: usize) {
        self.triples.reserve_exact(additional);
    }

    #[inline]
    fn verify_singular(
        &mut self,
        message: H256,
        signature_bytes: SignatureBytes,
        cached_public_key: &CachedPublicKey,
        _signature_kind: SignatureKind,
    ) -> Result<()> {
        let public_key = *cached_public_key.decompress()?;
        let triple = Triple::new(message, signature_bytes, public_key);
        self.triples.push(triple);
        Ok(())
    }

    #[inline]
    fn verify_aggregate<'keys>(
        &mut self,
        message: H256,
        signature_bytes: SignatureBytes,
        public_keys: impl IntoIterator<IntoIter = impl Iterator<Item = &'keys PublicKey> + Send>,
        signature_kind: SignatureKind,
    ) -> Result<()> {
        let mut triple = Triple::default();
        triple.verify_aggregate(message, signature_bytes, public_keys, signature_kind)?;
        self.triples.push(triple);
        Ok(())
    }

    #[inline]
    fn extend(
        &mut self,
        triples: impl IntoIterator<Item = Triple>,
        _signature_kind: SignatureKind,
    ) -> Result<()> {
        self.triples.extend(triples);
        Ok(())
    }

    #[inline]
    fn finish(&self) -> Result<()> {
        if self.triples.is_empty() {
            return Ok(());
        }

        let messages = self.triples.iter().map(|triple| triple.message.as_bytes());

        let signatures = self
            .triples
            .par_iter()
            .map(|triple| triple.signature_bytes.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        let public_keys = self.triples.iter().map(|triple| &triple.public_key);

        ensure!(
            Signature::multi_verify(messages, signatures.iter(), public_keys),
            Error::SignatureInvalid(SignatureKind::Multi),
        );

        Ok(())
    }

    #[inline]
    fn has_option(&self, option: VerifierOption) -> bool {
        self.options.contains(option)
    }
}

impl From<Vec<Triple>> for MultiVerifier {
    fn from(triples: Vec<Triple>) -> Self {
        Self {
            triples,
            ..Self::default()
        }
    }
}

impl MultiVerifier {
    pub fn new(options: impl IntoIterator<Item = VerifierOption>) -> Self {
        Self {
            options: EnumSet::from_iter(options),
            ..Self::default()
        }
    }
}

#[derive(Default, Constructor)]
pub struct Triple {
    message: H256,
    signature_bytes: SignatureBytes,
    public_key: PublicKey,
}

// `Triple` was originally an alias for a tuple and thus implemented `Copy`.
// The implicit copying nearly caused a bug by making code like this compile:
// ```
// let triple = Triple::default();
// validate(…, …, triple)?;
// Ok(triple)
// ```
assert_not_impl_any!(Triple: Copy);

// The unimplemented methods could be implemented without much difficulty,
// but they're not used anywhere.
impl Verifier for Triple {
    const IS_NULL: bool = false;

    #[inline]
    fn reserve(&mut self, _additional: usize) {
        unimplemented!("<Triple as Verifier>::reserve is not used anywhere")
    }

    #[inline]
    fn verify_singular(
        &mut self,
        _message: H256,
        _signature_bytes: SignatureBytes,
        _cached_public_key: &CachedPublicKey,
        _signature_kind: SignatureKind,
    ) -> Result<()> {
        unimplemented!("<Triple as Verifier>::verify_singular is not used anywhere")
    }

    #[inline]
    fn verify_aggregate<'keys>(
        &mut self,
        message: H256,
        signature_bytes: SignatureBytes,
        public_keys: impl IntoIterator<IntoIter = impl Iterator<Item = &'keys PublicKey> + Send>,
        _signature_kind: SignatureKind,
    ) -> Result<()> {
        // TODO(Grandine Team): This may no longer be true as of Rayon 1.6.1. Benchmark again.
        // The `ParallelBridge::par_bridge` here outperforms "native" parallel iterators.
        let public_key = public_keys
            .into_iter()
            .par_bridge()
            .copied()
            .reduce(AggregatePublicKey::default, AggregatePublicKey::aggregate);

        *self = Self::new(message, signature_bytes, public_key);

        Ok(())
    }

    #[inline]
    fn extend(
        &mut self,
        _triples: impl IntoIterator<Item = Self>,
        _signature_kind: SignatureKind,
    ) -> Result<()> {
        unimplemented!("<Triple as Verifier>::extend is not used anywhere")
    }

    #[inline]
    fn finish(&self) -> Result<()> {
        unimplemented!("<Triple as Verifier>::finish is not used anywhere")
    }

    #[inline]
    fn has_option(&self, _option: VerifierOption) -> bool {
        false
    }
}

// TODO(Grandine Team): The first 2 variants are no longer used at runtime because
//                      `BlockVerificationPool` is only used for Phase 0 blocks.
//                      Try removing them or redesigning to make options unnecessary.
#[expect(clippy::enum_variant_names)]
#[derive(EnumSetType)]
pub enum VerifierOption {
    SkipBlockBaseSignatures,
    SkipBlockSyncAggregateSignature,
    SkipRandaoVerification,
}

#[cfg(test)]
mod tests {
    use bls::{traits::SecretKey as _, SecretKey, SecretKeyBytes};
    use std_ext::CopyExt as _;
    use tap::{Conv as _, TryConv as _};

    use super::*;

    #[test]
    fn multi_verifier_finalize_succeeds_with_0_signatures() -> Result<()> {
        MultiVerifier::default().finish()
    }

    #[test]
    fn multi_verifier_finalize_succeeds_with_1_signature() -> Result<()> {
        let secret_key = secret_key();
        let public_key = secret_key.to_public_key().into();
        let message = H256::default();
        let signature = secret_key.sign(message).into();

        let mut verifier = MultiVerifier::default();
        verifier.verify_singular(message, signature, &public_key, SignatureKind::Block)?;
        verifier.finish()
    }

    fn secret_key() -> SecretKey {
        b"????????????????????????????????"
            .copy()
            .conv::<SecretKeyBytes>()
            .try_conv::<SecretKey>()
            .expect("bytes encode a valid secret key")
    }
}
