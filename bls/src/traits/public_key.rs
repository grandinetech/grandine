use core::fmt::Debug;

use crate::error::Error;

use super::PublicKeyBytes as PublicKeyBytesTrait;

pub trait PublicKey:
    Clone + Copy + PartialEq + Eq + Default + Debug + TryFrom<Self::PublicKeyBytes>
{
    type PublicKeyBytes: PublicKeyBytesTrait;

    fn aggregate(self, other: Self) -> Self;
    fn aggregate_in_place(&mut self, other: Self);
    fn aggregate_nonempty(keys: impl IntoIterator<Item = Self>) -> Result<Self, Error>;
}
