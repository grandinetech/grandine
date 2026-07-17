//! Gloas containers from [`builder-specs`].
//!
//! [`builder-specs`]: https://github.com/ethereum/builder-specs/blob/main/specs/gloas/validator.md

use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz::{ByteList, ReadError, Size, Ssz, SszRead, SszReadDefault, SszSize};
use typenum::U4096;
use types::{
    gloas::containers::SignedExecutionPayloadBid,
    nonstandard::Phase,
    phase0::primitives::{Gwei, Slot},
    preset::Preset,
};

/// [`MAX_DATA_SIZE`] from `builder-specs` (Gloas).
///
/// [`MAX_DATA_SIZE`]: https://github.com/ethereum/builder-specs/blob/main/specs/gloas/builder.md#constants
pub type MaxDataSize = U4096;

#[derive(Clone, Debug, Default, Deserialize, Serialize, Ssz)]
pub struct RequestAuthV1 {
    /// UTF-8 builder URL bytes. Serialized as a `0x`-prefixed hex string in JSON.
    pub data: ByteList<MaxDataSize>,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Ssz)]
pub struct SignedRequestAuthV1 {
    pub message: RequestAuthV1,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Ssz)]
pub struct BuilderPreferencesV1 {
    #[serde(with = "serde_utils::string_or_native")]
    pub max_execution_payment: Gwei,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Ssz)]
pub struct BuilderPreferencesRequestV1 {
    pub preferences: BuilderPreferencesV1,
    pub auth: SignedRequestAuthV1,
}

#[derive(Debug, Deserialize)]
#[serde(
    bound = "",
    deny_unknown_fields,
    rename_all = "lowercase",
    tag = "version",
    content = "data"
)]
pub enum GetExecutionPayloadBidResponse<P: Preset> {
    Gloas(SignedExecutionPayloadBid<P>),
}

impl<P: Preset> SszSize for GetExecutionPayloadBidResponse<P> {
    const SIZE: Size = SignedExecutionPayloadBid::<P>::SIZE;
}

impl<P: Preset> SszRead<Phase> for GetExecutionPayloadBidResponse<P> {
    fn from_ssz_unchecked(phase: &Phase, bytes: &[u8]) -> Result<Self, ReadError> {
        // Container is Gloas-shaped; header may report any post-Gloas phase.
        if *phase >= Phase::Gloas {
            return Ok(Self::Gloas(SszReadDefault::from_ssz_default(bytes)?));
        }

        Err(ReadError::Custom {
            message: "execution payload bid response is only available from Gloas onwards",
        })
    }
}

impl<P: Preset> GetExecutionPayloadBidResponse<P> {
    #[must_use]
    pub fn into_bid(self) -> SignedExecutionPayloadBid<P> {
        match self {
            Self::Gloas(bid) => bid,
        }
    }
}
