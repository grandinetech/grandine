//! Gloas builder containers a validator or dedicated builder client sends to a beacon node.
//!
//! [`BuilderRequestAuth`] and [`SignedBuilderRequestAuth`] are forwarded to a builder unchanged,
//! so both share the same type as in the builder spec.
//!
//! - <https://github.com/ethereum/builder-specs/blob/b5ec384aeddba1aa2fea257a7492b363dfbc1a52/types/gloas/request_auth.yaml>
//! - <https://github.com/ethereum/beacon-APIs/blob/159622d983a703eb03a8a37bb1edeab7ffc3b6bc/types/gloas/request_auth.yaml>
//! - <https://github.com/ethereum/beacon-APIs/blob/159622d983a703eb03a8a37bb1edeab7ffc3b6bc/types/gloas/builder_entry.yaml>
//! - <https://github.com/ethereum/beacon-APIs/blob/159622d983a703eb03a8a37bb1edeab7ffc3b6bc/types/gloas/builder_preferences_entry.yaml>

use bls::{PublicKeyBytes, SignatureBytes};
use serde::{Deserialize, Serialize};
use ssz::{ByteList, ContiguousList, Ssz};
use types::phase0::primitives::{Gwei, Slot};

use crate::consts::{MaxBuilderAuthDataSize, MaxBuilderEntries, MaxBuilderPubkeys};

pub use crate::gloas::builder_url::{BuilderUrl, BuilderUrlError};

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct BuilderRequestAuth {
    pub data: ByteList<MaxBuilderAuthDataSize>,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SignedBuilderRequestAuth {
    pub message: BuilderRequestAuth,
    pub signature: SignatureBytes,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct BuilderEntry {
    pub url: BuilderUrl,
    pub auth: SignedBuilderRequestAuth,
    pub builder_pubkeys: ContiguousList<PublicKeyBytes, MaxBuilderPubkeys>,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_execution_payment: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub min_bid: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_boost_factor: u64,
}

/// `min_bid` and `builder_boost_factor` apply to bids received over p2p,
/// a requested bid is governed by its own [`BuilderEntry`].
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct BuilderConfig {
    #[serde(with = "serde_utils::string_or_native")]
    pub min_bid: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub builder_boost_factor: u64,
    pub builders: ContiguousList<BuilderEntry, MaxBuilderEntries>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct BuilderPreferencesEntry {
    pub proposer_pubkey: PublicKeyBytes,
    pub url: BuilderUrl,
    pub auth: SignedBuilderRequestAuth,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_execution_payment: Gwei,
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use ssz::{SszReadDefault as _, SszWrite as _};

    use super::*;

    // from <https://github.com/ethereum/builder-specs/tree/38f11441c194d150386f567b4d7087ec86d4118c/examples/gloas>
    const SIGNATURE: [u8; 96] = hex!(
        "1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505
         cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc
         1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    );

    const SIGNED_BUILDER_REQUEST_AUTH_SSZ: [u8; 120] = hex!(
        "64000000
         1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505
         cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc
         1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505
         0c000000
         0100000000000000
         1234567890abcdef"
    );

    const BUILDER_URL: &str = "https://builder.example.com";

    const BUILDER_PUBKEY: [u8; 48] = hex!(
        "93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3
         a2753e5f3e8b1cfe39b56f43611df74a"
    );

    fn signed_builder_request_auth() -> SignedBuilderRequestAuth {
        SignedBuilderRequestAuth {
            message: BuilderRequestAuth {
                data: hex!("1234567890abcdef")
                    .to_vec()
                    .try_into()
                    .expect("8 bytes fit in MaxBuilderAuthDataSize"),
                slot: 1,
            },
            signature: SIGNATURE.into(),
        }
    }

    fn builder_entry() -> BuilderEntry {
        BuilderEntry {
            url: BUILDER_URL.try_into().expect("URL should be valid"),
            auth: signed_builder_request_auth(),
            builder_pubkeys: ContiguousList::try_from(vec![BUILDER_PUBKEY.into()])
                .expect("one pubkey fits in MaxBuilderPubkeys"),
            max_execution_payment: 1_000_000_000,
            min_bid: 10_000_000,
            builder_boost_factor: 100,
        }
    }

    #[test]
    fn signed_builder_request_auth_ssz_matches_spec_example() {
        assert_eq!(
            signed_builder_request_auth()
                .to_ssz()
                .expect("container should be serializable"),
            SIGNED_BUILDER_REQUEST_AUTH_SSZ,
        );

        assert_eq!(
            SignedBuilderRequestAuth::from_ssz_default(SIGNED_BUILDER_REQUEST_AUTH_SSZ)
                .expect("spec example should be deserializable"),
            signed_builder_request_auth(),
        );
    }

    // `url` is a plain string in JSON even though it is a `ByteList` in SSZ.
    #[test]
    fn builder_entry_json_encodes_url_as_a_string() {
        let json = serde_json::to_value(builder_entry()).expect("entry should be serializable");

        assert_eq!(json["url"], BUILDER_URL);
        assert_eq!(json["max_execution_payment"], "1000000000");
        assert_eq!(json["min_bid"], "10000000");
        assert_eq!(json["builder_boost_factor"], "100");

        assert_eq!(
            serde_json::from_value::<BuilderEntry>(json).expect("entry should be deserializable"),
            builder_entry(),
        );
    }

    #[test]
    fn builder_url_rejects_empty_in_both_encodings() {
        BuilderUrl::try_from("").expect_err("an empty URL should be rejected");

        BuilderUrl::from_ssz_default([]).expect_err("an empty URL should be rejected");

        serde_json::from_str::<BuilderUrl>("\"\"").expect_err("an empty URL should be rejected");
    }
}
