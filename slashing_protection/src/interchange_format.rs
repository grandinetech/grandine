//! Implementation of [EIP-3076](https://eips.ethereum.org/EIPS/eip-3076).

use std::path::Path;

use anyhow::{ensure, Result};
use bls::PublicKeyBytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use types::phase0::primitives::{Epoch, Slot, H256};

const INTERCHANGE_FORMAT_VERSION: InterchangeFormatVersion = 5;

type InterchangeFormatVersion = usize;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterchangeFormat {
    pub metadata: InterchangeMeta,
    pub data: Vec<InterchangeData>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterchangeMeta {
    #[serde(with = "serde_utils::string_or_native")]
    pub interchange_format_version: InterchangeFormatVersion,
    pub genesis_validators_root: H256,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterchangeData {
    pub pubkey: PublicKeyBytes,
    pub signed_blocks: Vec<InterchangeBlock>,
    pub signed_attestations: Vec<InterchangeAttestation>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterchangeBlock {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<H256>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterchangeAttestation {
    #[serde(with = "serde_utils::string_or_native")]
    pub source_epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    pub target_epoch: Epoch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<H256>,
}

impl InterchangeData {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signed_attestations.is_empty() && self.signed_blocks.is_empty()
    }
}

impl InterchangeFormat {
    #[must_use]
    pub const fn new(genesis_validators_root: H256, data: Vec<InterchangeData>) -> Self {
        Self {
            metadata: InterchangeMeta {
                interchange_format_version: INTERCHANGE_FORMAT_VERSION,
                genesis_validators_root,
            },
            data,
        }
    }

    pub fn load_from_file(file: impl AsRef<Path>) -> Result<Self> {
        let bytes = fs_err::read(file)?;
        let data = serde_json::from_slice(bytes.as_slice())?;
        Ok(data)
    }

    pub fn validate(&self, genesis_validators_root: H256) -> Result<()> {
        let version = self.metadata.interchange_format_version;

        ensure!(
            version == INTERCHANGE_FORMAT_VERSION,
            Error::UnsupportedVersion { version },
        );

        let in_chain = genesis_validators_root;
        let in_metadata = self.metadata.genesis_validators_root;

        ensure!(
            in_chain == in_metadata,
            Error::GenesisValidatorsRootMismatch {
                in_chain,
                in_metadata,
            },
        );

        Ok(())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.iter().all(InterchangeData::is_empty)
    }
}

#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
enum Error {
    #[error(
        "unsupported interchange format version \
         (supported: {INTERCHANGE_FORMAT_VERSION}, in metadata: {version})"
    )]
    UnsupportedVersion { version: InterchangeFormatVersion },
    #[error(
        "incorrect genesis validators root \
         (in current chain: {in_chain:?}, in metadata: {in_metadata:?})"
    )]
    GenesisValidatorsRootMismatch { in_chain: H256, in_metadata: H256 },
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use serde_json::json;

    use super::*;

    #[test]
    fn interchange_format_unsupported_version_test() -> Result<()> {
        let json = json!({
            "metadata": {
                "interchange_format_version": "4",
                "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673",
            },
            "data": [],
        });

        let interchange = serde_json::from_value::<InterchangeFormat>(json)?;

        let result = interchange
            .validate(H256::zero())
            .expect_err("interchange format version is not supported");

        assert_eq!(
            result.downcast_ref(),
            Some(&Error::UnsupportedVersion { version: 4 }),
        );

        Ok(())
    }

    #[test]
    fn interchange_format_mismatched_genesis_validators_root() -> Result<()> {
        let json = json!({
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673",
            },
            "data": [],
        });

        let interchange = serde_json::from_value::<InterchangeFormat>(json)?;

        let result = interchange
            .validate(H256::zero())
            .expect_err("genesis_validators_root is different");

        assert_eq!(
            result.downcast_ref(),
            Some(&Error::GenesisValidatorsRootMismatch {
                in_chain: H256::zero(),
                in_metadata: H256(hex!(
                    "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
                )),
            }),
        );

        Ok(())
    }

    #[test]
    fn interchange_format_valid_metadata() -> Result<()> {
        let json = json!({
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673",
            },
            "data": [],
        });

        let interchange = serde_json::from_value::<InterchangeFormat>(json)?;

        interchange.validate(
            hex!("04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673").into(),
        )
    }

    #[test]
    fn interchange_format_from_json_test() -> Result<()> {
        let json = json!({
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673",
            },
            "data": [
                {
                    "pubkey": "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed",
                    "signed_blocks": [
                        {
                            "slot": "81952",
                            "signing_root": "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b",
                        },
                        {
                            "slot": "81951",
                        },
                    ],
                    "signed_attestations": [
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3007",
                            "signing_root": "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d",
                        },
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3008",
                        },
                    ],
                },
            ],
        });

        let expected_interchange = InterchangeFormat {
            metadata: InterchangeMeta {
                interchange_format_version: 5,
                genesis_validators_root: hex!("04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673").into(),
            },
            data: vec![
                InterchangeData {
                    pubkey: hex!("b845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed").into(),
                    signed_blocks: vec![
                        InterchangeBlock {
                            slot: 81952,
                            signing_root: Some(hex!("4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b").into()),
                        },
                        InterchangeBlock {
                            slot: 81951,
                            signing_root: None,
                        }
                    ],
                    signed_attestations: vec![
                        InterchangeAttestation {
                            source_epoch: 2290,
                            target_epoch: 3007,
                            signing_root: Some(hex!("587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d").into()),
                        },
                        InterchangeAttestation {
                            source_epoch: 2290,
                            target_epoch: 3008,
                            signing_root: None,
                        },
                    ],
                },
            ],
        };

        let interchange = serde_json::from_value::<InterchangeFormat>(json)?;

        assert_eq!(interchange, expected_interchange);

        Ok(())
    }

    #[test]
    fn interchange_format_emptiness_test() {
        let mut interchange = InterchangeFormat {
            metadata: InterchangeMeta {
                interchange_format_version: 5,
                genesis_validators_root: hex!(
                    "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
                )
                .into(),
            },
            data: vec![],
        };

        assert!(interchange.is_empty());

        let empty_interchange_data = InterchangeData {
            pubkey: hex!("b845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bec").into(),
            signed_blocks: vec![],
            signed_attestations: vec![],
        };

        assert!(empty_interchange_data.is_empty());

        interchange.data.push(empty_interchange_data);

        // interchange with empty interchange data should also be considered empty
        assert!(interchange.is_empty());

        let interchange_data = InterchangeData {
            pubkey: hex!("b845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed").into(),
            signed_blocks: vec![
                InterchangeBlock {
                    slot: 81952,
                    signing_root: Some(hex!("4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b").into()),
                },
            ],
            signed_attestations: vec![],
        };

        assert!(!interchange_data.is_empty());

        interchange.data.push(interchange_data);

        assert!(!interchange.is_empty());
    }
}
