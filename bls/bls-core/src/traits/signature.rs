use core::fmt::Debug;
use std::sync::Arc;

use super::{PublicKey as PublicKeyTrait, SignatureBytes as SignatureBytesTrait};

pub trait Signature: Clone + Copy + PartialEq + Eq + Debug + Default + 'static
where
    Self::PublicKey: 'static,
{
    type SignatureBytes: SignatureBytesTrait;
    type PublicKey: PublicKeyTrait;

    fn verify(&self, message: impl AsRef<[u8]>, public_key: &Self::PublicKey) -> bool;

    #[must_use]
    fn aggregate(mut self, other: Self) -> Self {
        self.aggregate_in_place(other);
        self
    }

    fn aggregate_in_place(&mut self, other: Self);

    fn fast_aggregate_verify(
        &self,
        message: impl AsRef<[u8]>,
        public_keys: impl IntoIterator<Item = Arc<Self::PublicKey>>,
    ) -> bool;

    fn multi_verify<'all>(
        messages: impl IntoIterator<Item = &'all [u8]>,
        signatures: impl IntoIterator<Item = &'all Self>,
        public_keys: impl IntoIterator<Item = &'all Self::PublicKey>,
    ) -> bool;
}
