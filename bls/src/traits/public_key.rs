use super::PublicKeyBytes as PublicKeyBytesTrait;
use crate::Error;
use core::fmt::Debug;

pub trait PublicKey<C>: Clone + Copy + PartialEq + Eq + Default + Debug {
    type PublicKeyBytes: PublicKeyBytesTrait<C>;

    fn try_from(bytes: Self::PublicKeyBytes) -> Result<Self, Error>;
    fn into(self) -> Self::PublicKeyBytes;
    fn aggregate(self, other: Self) -> Self;
    fn aggregate_in_place(&mut self, other: Self);
    fn aggregate_nonempty(keys: impl IntoIterator<Item = Self>) -> Result<Self, Error>;
}
