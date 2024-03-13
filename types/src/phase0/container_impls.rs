use bls::SignatureBytes;

use crate::phase0::containers::{
    BeaconBlockHeader, DepositData, DepositMessage, SignedBeaconBlockHeader,
};

impl BeaconBlockHeader {
    #[inline]
    #[must_use]
    pub const fn with_signature(self, signature: SignatureBytes) -> SignedBeaconBlockHeader {
        SignedBeaconBlockHeader {
            message: self,
            signature,
        }
    }
}

impl From<DepositData> for DepositMessage {
    #[inline]
    fn from(deposit_data: DepositData) -> Self {
        let DepositData {
            pubkey,
            withdrawal_credentials,
            amount,
            ..
        } = deposit_data;

        Self {
            pubkey,
            withdrawal_credentials,
            amount,
        }
    }
}
