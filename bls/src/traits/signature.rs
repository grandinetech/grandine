use core::fmt::Debug;

use super::{PublicKey as PublicKeyTrait, SignatureBytes as SignatureBytesTrait};

pub trait Signature: Clone + Copy + PartialEq + Eq + Debug + Default + 'static
where
    Self::PublicKey: 'static,
{
    type SignatureBytes: SignatureBytesTrait;
    type PublicKey: PublicKeyTrait;

    fn verify(&self, message: impl AsRef<[u8]>, public_key: &Self::PublicKey) -> bool;
    fn aggregate(self, other: Self) -> Self;
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
