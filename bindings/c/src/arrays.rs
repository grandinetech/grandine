use ethereum_types::H64;
use primitive_types::{H160, H256, H384};
use ssz::Uint256;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct CH384(pub [u8; 48]);

impl Into<H384> for CH384 {
    fn into(self) -> H384 {
        H384(self.0)
    }
}

impl Default for CH384 {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct CH256(pub [u8; 32]);

impl Into<H256> for CH256 {
    fn into(self) -> H256 {
        H256(self.0)
    }
}

impl Into<Uint256> for CH256 {
    fn into(self) -> Uint256 {
        Uint256::from_be_bytes(self.0)
    }
}

impl From<Uint256> for CH256 {
    fn from(value: Uint256) -> Self {
        let mut output = [0u8; 32];
        value.into_raw().to_big_endian(&mut output);
        Self(output)
    }
}

impl From<H256> for CH256 {
    fn from(value: H256) -> Self {
        Self(value.0)
    }
}

#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct CH160([u8; 20]);

impl Into<H160> for CH160 {
    fn into(self) -> H160 {
        H160(self.0)
    }
}

impl From<H160> for CH160 {
    fn from(value: H160) -> Self {
        Self(value.0)
    }
}

#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct CH64([u8; 8]);

impl Into<H64> for CH64 {
    fn into(self) -> H64 {
        H64(self.0)
    }
}

impl From<H64> for CH64 {
    fn from(value: H64) -> Self {
        Self(value.0)
    }
}
