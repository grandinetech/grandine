//! Gloas containers from [`builder-specs`].
//!
//! [`builder-specs`]: https://github.com/ethereum/builder-specs/pull/165

use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz::{ByteList, Ssz};
use types::phase0::primitives::{Gwei, Slot};

use crate::consts::MaxDataSize;

#[derive(Clone, Debug, Default, Deserialize, Serialize, Ssz)]
pub struct RequestAuth {
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
pub struct SignedRequestAuth {
    pub message: RequestAuth,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Ssz)]
pub struct BuilderPreferences {
    #[serde(with = "serde_utils::string_or_native")]
    pub max_execution_payment: Gwei,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Ssz)]
pub struct BuilderPreferencesRequest {
    pub auth: SignedRequestAuth,
    pub preferences: BuilderPreferences,
}

#[cfg(test)]
mod tests {
    use bls::SignatureBytes;
    use ssz::{SszReadDefault as _, SszWrite as _};

    use super::*;

    // SSZ field order is auth then preferences (fixed part ends at offset 12).
    #[test]
    fn builder_preferences_request_ssz_field_order_is_auth_then_preferences() {
        let auth = SignedRequestAuth {
            message: RequestAuth {
                data: ByteList::<MaxDataSize>::try_from(b"http://builder.example.com".to_vec())
                    .expect("builder URL fits MAX_DATA_SIZE"),
                slot: 42,
            },
            signature: SignatureBytes::default(),
        };
        let preferences = BuilderPreferences {
            max_execution_payment: 1_000_000_000,
        };
        let request = BuilderPreferencesRequest {
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
            BuilderPreferencesRequest::from_ssz_default(&encoded).expect("SSZ decode round-trip");
        assert_eq!(decoded.auth.message.slot, 42);
        assert_eq!(decoded.auth.message.data, auth.message.data);
        assert_eq!(decoded.preferences.max_execution_payment, 1_000_000_000);
    }
}
