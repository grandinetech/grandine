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
    /// Opaque authentication data (up to [`MAX_DATA_SIZE`] bytes). When nothing was agreed out of
    /// band, SHOULD default to the UTF-8 bytes of the builder's advertised URL. JSON: `0x`-prefixed hex.
    ///
    /// [`MAX_DATA_SIZE`]: MaxDataSize
    pub data: ByteList<MaxDataSize>,
    /// Proposal slot this request is authorized for.
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
    pub auth: SignedRequestAuthV1,
    pub preferences: BuilderPreferencesV1,
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

#[cfg(test)]
mod tests {
    use bls::SignatureBytes;
    use ssz::{SszReadDefault as _, SszWrite as _};

    use super::*;

    // SSZ field order is auth then preferences (fixed part ends at offset 12).
    #[test]
    fn builder_preferences_request_ssz_field_order_is_auth_then_preferences() {
        let auth = SignedRequestAuthV1 {
            message: RequestAuthV1 {
                data: ByteList::<MaxDataSize>::try_from(b"http://builder.example.com".to_vec())
                    .expect("builder URL fits MAX_DATA_SIZE"),
                slot: 42,
            },
            signature: SignatureBytes::default(),
        };
        let preferences = BuilderPreferencesV1 {
            max_execution_payment: 1_000_000_000,
        };
        let request = BuilderPreferencesRequestV1 {
            auth: auth.clone(),
            preferences,
        };

        let encoded = request.to_ssz().expect("SSZ encode");
        let auth_ssz = auth.to_ssz().expect("auth SSZ encode");

        assert_eq!(&encoded[..4], &12_u32.to_le_bytes());
        assert_eq!(
            &encoded[4..12],
            &preferences.max_execution_payment.to_le_bytes()
        );
        assert_eq!(&encoded[12..], auth_ssz.as_slice());

        let decoded =
            BuilderPreferencesRequestV1::from_ssz_default(&encoded).expect("SSZ decode round-trip");
        assert_eq!(decoded.auth.message.slot, 42);
        assert_eq!(decoded.auth.message.data, auth.message.data);
        assert_eq!(decoded.preferences.max_execution_payment, 1_000_000_000);
    }
}
