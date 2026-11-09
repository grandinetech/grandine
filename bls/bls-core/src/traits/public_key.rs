use core::fmt::Debug;

use crate::{DECOMPRESSED_SIZE, error::Error};

use super::PublicKeyBytes as PublicKeyBytesTrait;

pub trait PublicKey:
    Clone + Copy + PartialEq + Eq + Default + Debug + TryFrom<Self::PublicKeyBytes>
{
    type PublicKeyBytes: PublicKeyBytesTrait;

    fn deserialize_from_decompressed_bytes(bytes: &[u8]) -> Result<Self, Error>;

    fn serialize_to_decompressed_bytes(&self) -> [u8; DECOMPRESSED_SIZE];
}
