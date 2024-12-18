use super::{PublicKey as PublicKeyTrait, SignatureBytes as SignatureBytesTrait};
use crate::Error;
use core::fmt::Debug;

pub trait Signature<C, const N: usize>:
    Clone + Copy + PartialEq + Eq + Debug + Default + 'static
where
    Self::PublicKey: 'static,
{
    type SignatureBytes: SignatureBytesTrait<C, N>;
    type PublicKey: PublicKeyTrait<C>;

    fn try_from(bytes: Self::SignatureBytes) -> Result<Self, Error>;
    fn into(self) -> Self::SignatureBytes;
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
