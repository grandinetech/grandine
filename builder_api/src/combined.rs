use bls::{PublicKeyBytes, SignatureBytes};
use enum_iterator::Sequence;
use serde::Deserialize;
use ssz::{ContiguousList, ReadError, Size, SszRead, SszReadDefault, SszSize};
use types::{
    bellatrix::containers::ExecutionPayload as BellatrixExecutionPayload,
    capella::containers::ExecutionPayload as CapellaExecutionPayload,
    combined::{ExecutionPayload, ExecutionPayloadHeader},
    deneb::primitives::KzgCommitment,
    electra::containers::ExecutionRequests,
    nonstandard::{Phase, WithBlobsAndMev},
    phase0::primitives::Uint256,
    preset::Preset,
};

use crate::{
    bellatrix::containers::SignedBuilderBid as BellatrixSignedBuilderBid,
    capella::containers::SignedBuilderBid as CapellaSignedBuilderBid,
    deneb::containers::{
        BlobsBundle as DenebBlobsBundle,
        ExecutionPayloadAndBlobsBundle as DenebExecutionPayloadAndBlobsBundle,
        SignedBuilderBid as DenebSignedBuilderBid,
    },
    electra::containers::SignedBuilderBid as ElectraSignedBuilderBid,
    fulu::containers::SignedBuilderBid as FuluSignedBuilderBid,
};

#[derive(Debug, Deserialize)]
#[serde(
    bound = "",
    deny_unknown_fields,
    rename_all = "lowercase",
    tag = "version",
    content = "data"
)]
pub enum SignedBuilderBid<P: Preset> {
    Bellatrix(BellatrixSignedBuilderBid<P>),
    Capella(CapellaSignedBuilderBid<P>),
    Deneb(DenebSignedBuilderBid<P>),
    Electra(ElectraSignedBuilderBid<P>),
    Fulu(FuluSignedBuilderBid<P>),
}

impl<P: Preset> SszSize for SignedBuilderBid<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 2 }>([
        BellatrixSignedBuilderBid::<P>::SIZE,
        CapellaSignedBuilderBid::<P>::SIZE,
        DenebSignedBuilderBid::<P>::SIZE,
        ElectraSignedBuilderBid::<P>::SIZE,
        FuluSignedBuilderBid::<P>::SIZE,
    ]);
}

impl<P: Preset> SszRead<Phase> for SignedBuilderBid<P> {
    fn from_ssz_unchecked(phase: &Phase, bytes: &[u8]) -> Result<Self, ReadError> {
        let block = match phase {
            Phase::Phase0 => {
                return Err(ReadError::Custom {
                    message: "signed builder bid is not available in Phase 0",
                });
            }
            Phase::Altair => {
                return Err(ReadError::Custom {
                    message: "signed builder bid is not available in Altair",
                });
            }
            Phase::Bellatrix => Self::Bellatrix(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Capella => Self::Capella(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Deneb => Self::Deneb(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Electra => Self::Electra(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Fulu => Self::Fulu(SszReadDefault::from_ssz_default(bytes)?),
        };

        Ok(block)
    }
}

impl<P: Preset> SignedBuilderBid<P> {
    #[must_use]
    pub(crate) const fn pubkey(&self) -> PublicKeyBytes {
        match self {
            Self::Bellatrix(response) => response.message.pubkey,
            Self::Capella(response) => response.message.pubkey,
            Self::Deneb(response) => response.message.pubkey,
            Self::Electra(response) => response.message.pubkey,
            Self::Fulu(response) => response.message.pubkey,
        }
    }

    #[must_use]
    pub(crate) const fn signature(&self) -> SignatureBytes {
        match self {
            Self::Bellatrix(response) => response.signature,
            Self::Capella(response) => response.signature,
            Self::Deneb(response) => response.signature,
            Self::Electra(response) => response.signature,
            Self::Fulu(response) => response.signature,
        }
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> Phase {
        match self {
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
            Self::Fulu(_) => Phase::Fulu,
        }
    }

    #[must_use]
    pub fn execution_payload_header(self) -> ExecutionPayloadHeader<P> {
        match self {
            Self::Bellatrix(response) => {
                ExecutionPayloadHeader::Bellatrix(*response.message.header)
            }
            Self::Capella(response) => ExecutionPayloadHeader::Capella(*response.message.header),
            Self::Deneb(response) => ExecutionPayloadHeader::Deneb(*response.message.header),
            Self::Electra(response) => ExecutionPayloadHeader::Deneb(*response.message.header),
            Self::Fulu(response) => ExecutionPayloadHeader::Deneb(*response.message.header),
        }
    }

    #[must_use]
    pub const fn execution_requests(&self) -> Option<&ExecutionRequests<P>> {
        match self {
            Self::Bellatrix(_) | Self::Capella(_) | Self::Deneb(_) => None,
            Self::Electra(response) => Some(&response.message.execution_requests),
            Self::Fulu(response) => Some(&response.message.execution_requests),
        }
    }

    #[must_use]
    pub const fn blob_kzg_commitments(
        &self,
    ) -> Option<&ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>> {
        match self {
            Self::Bellatrix(_) | Self::Capella(_) => None,
            Self::Deneb(response) => Some(&response.message.blob_kzg_commitments),
            Self::Electra(response) => Some(&response.message.blob_kzg_commitments),
            Self::Fulu(response) => Some(&response.message.blob_kzg_commitments),
        }
    }

    #[must_use]
    pub const fn mev(&self) -> Uint256 {
        match self {
            Self::Bellatrix(response) => response.message.value,
            Self::Capella(response) => response.message.value,
            Self::Deneb(response) => response.message.value,
            Self::Electra(response) => response.message.value,
            Self::Fulu(response) => response.message.value,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(
    bound = "",
    deny_unknown_fields,
    rename_all = "lowercase",
    tag = "version",
    content = "data"
)]
pub enum ExecutionPayloadAndBlobsBundle<P: Preset> {
    Bellatrix(BellatrixExecutionPayload<P>),
    Capella(CapellaExecutionPayload<P>),
    Deneb(DenebExecutionPayloadAndBlobsBundle<P>),
    Electra(DenebExecutionPayloadAndBlobsBundle<P>),
    Fulu(DenebExecutionPayloadAndBlobsBundle<P>),
}

impl<P: Preset> SszSize for ExecutionPayloadAndBlobsBundle<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 4 }>([
        BellatrixExecutionPayload::<P>::SIZE,
        CapellaExecutionPayload::<P>::SIZE,
        DenebExecutionPayloadAndBlobsBundle::<P>::SIZE,
    ]);
}

impl<P: Preset> SszRead<Phase> for ExecutionPayloadAndBlobsBundle<P> {
    fn from_ssz_unchecked(phase: &Phase, bytes: &[u8]) -> Result<Self, ReadError> {
        let block = match phase {
            Phase::Phase0 => {
                return Err(ReadError::Custom {
                    message: "execution payload and blobs bundle is not available in Phase 0",
                });
            }
            Phase::Altair => {
                return Err(ReadError::Custom {
                    message: "execution payload and blobs bundle is not available in Altair",
                });
            }
            Phase::Bellatrix => Self::Bellatrix(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Capella => Self::Capella(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Deneb => Self::Deneb(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Electra => Self::Electra(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Fulu => Self::Fulu(SszReadDefault::from_ssz_default(bytes)?),
        };

        Ok(block)
    }
}

impl<P: Preset> From<ExecutionPayloadAndBlobsBundle<P>>
    for WithBlobsAndMev<ExecutionPayload<P>, P>
{
    fn from(response: ExecutionPayloadAndBlobsBundle<P>) -> Self {
        match response {
            ExecutionPayloadAndBlobsBundle::Bellatrix(execution_payload) => {
                Self::with_default(execution_payload.into())
            }
            ExecutionPayloadAndBlobsBundle::Capella(execution_payload) => {
                Self::with_default(execution_payload.into())
            }
            ExecutionPayloadAndBlobsBundle::Deneb(payload_with_blobs_bundle)
            | ExecutionPayloadAndBlobsBundle::Electra(payload_with_blobs_bundle)
            | ExecutionPayloadAndBlobsBundle::Fulu(payload_with_blobs_bundle) => {
                let DenebExecutionPayloadAndBlobsBundle {
                    execution_payload,
                    blobs_bundle,
                } = payload_with_blobs_bundle;

                let DenebBlobsBundle {
                    commitments,
                    proofs,
                    blobs,
                } = blobs_bundle;

                Self::new(
                    execution_payload.into(),
                    Some(commitments),
                    Some(proofs),
                    Some(blobs),
                    None,
                    None,
                )
            }
        }
    }
}

#[cfg(test)]
impl<P: Preset> ExecutionPayloadAndBlobsBundle<P> {
    pub(crate) const fn phase(&self) -> Phase {
        match self {
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
            Self::Fulu(_) => Phase::Fulu,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Result, Value};
    use test_case::test_case;
    use types::preset::Mainnet;

    use super::*;

    #[test_case(
        json!({
            "version": "bellatrix",
            "data": {
                "message": {
                    "header": {
                        "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                        "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "block_number": "1",
                        "gas_limit": "1",
                        "gas_used": "1",
                        "timestamp": "1",
                        "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "base_fee_per_gas": "1",
                        "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    },
                    "value": "1",
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                },
                "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
            },
        }),
        Phase::Bellatrix;
        "https://github.com/ethereum/builder-specs/blob/v0.3.0/examples/bellatrix/signed_builder_bid.json"
    )]
    #[test_case(
        json!({
            "version": "capella",
            "data": {
                "message": {
                    "header": {
                        "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                        "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "block_number": "1",
                        "gas_limit": "1",
                        "gas_used": "1",
                        "timestamp": "1",
                        "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "base_fee_per_gas": "1",
                        "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "withdrawals_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    },
                    "value": "1",
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                },
                "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
            },
        }),
        Phase::Capella;
        "https://github.com/ethereum/builder-specs/blob/v0.3.0/examples/capella/signed_builder_bid.json"
    )]
    #[test_case(
        json!({
            "version": "deneb",
            "data": {
                "message": {
                    "header": {
                        "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                        "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "block_number": "1",
                        "gas_limit": "1",
                        "gas_used": "1",
                        "timestamp": "1",
                        "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "base_fee_per_gas": "1",
                        "blob_gas_used": "1",
                        "excess_blob_gas": "1",
                        "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "withdrawals_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                    },
                    "blob_kzg_commitments": [
                        "0xa94170080872584e54a1cf092d845703b13907f2e6b3b1c0ad573b910530499e3bcd48c6378846b80d2bfa58c81cf3d5"
                    ],
                    "value": "1",
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
                },
                "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
            },
        }),
        Phase::Deneb;
        "https://github.com/ethereum/builder-specs/blob/v0.4.0/examples/deneb/signed_builder_bid.json"
    )]
    #[test_case(
        json!({
            "version": "electra",
            "data": {
                "message": {
                    "header": {
                        "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                        "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "block_number": "1",
                        "gas_limit": "1",
                        "gas_used": "1",
                        "timestamp": "1",
                        "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "base_fee_per_gas": "1",
                        "blob_gas_used": "1",
                        "excess_blob_gas": "1",
                        "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                        "withdrawals_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                    },
                    "blob_kzg_commitments": [
                        "0xa94170080872584e54a1cf092d845703b13907f2e6b3b1c0ad573b910530499e3bcd48c6378846b80d2bfa58c81cf3d5"
                    ],
                    "execution_requests": {
                    "deposits": [
                        {
                            "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                            "withdrawal_credentials": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                            "amount": "1",
                            "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
                            "index": "1",
                        }
                    ],
                    "withdrawals": [
                        {
                            "source_address": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                            "validator_pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                            "amount": "1",
                        }
                    ],
                    "consolidations": [
                        {
                            "source_address": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                            "source_pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                            "target_pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                        }
                    ]
                    },
                    "value": "1",
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
                },
                "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
            }
        }),
        Phase::Electra;
        "https://github.com/ethereum/builder-specs/blob/5cb324e34e173d963d1233e238bf50e4d7497653/examples/electra/signed_builder_bid.json"
    )]
    fn deserializes_signed_builder_bid_example(json: Value, expected_phase: Phase) -> Result<()> {
        let response = serde_json::from_value::<SignedBuilderBid<Mainnet>>(json)?;
        assert_eq!(response.phase(), expected_phase);
        Ok(())
    }

    #[test_case(
        json!({
            "version": "bellatrix",
            "data": {
                "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "block_number": "1",
                "gas_limit": "1",
                "gas_used": "1",
                "timestamp": "1",
                "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "base_fee_per_gas": "1",
                "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "transactions": [
                    "0x02f878831469668303f51d843b9ac9f9843b9aca0082520894c93269b73096998db66be0441e836d873535cb9c8894a19041886f000080c001a031cc29234036afbf9a1fb9476b463367cb1f957ac0b919b69bbc798436e604aaa018c4e9c3914eb27aadd0b91e10b18655739fcf8c1fc398763a9f1beecb8ddc86",
                ],
            },
        }),
        Phase::Bellatrix;
        "https://github.com/ethereum/builder-specs/blob/v0.4.0/examples/bellatrix/execution_payload.json"
    )]
    #[test_case(
        json!({
            "version": "capella",
            "data": {
                "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "block_number": "1",
                "gas_limit": "1",
                "gas_used": "1",
                "timestamp": "1",
                "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "base_fee_per_gas": "1",
                "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "transactions": [
                    "0x02f878831469668303f51d843b9ac9f9843b9aca0082520894c93269b73096998db66be0441e836d873535cb9c8894a19041886f000080c001a031cc29234036afbf9a1fb9476b463367cb1f957ac0b919b69bbc798436e604aaa018c4e9c3914eb27aadd0b91e10b18655739fcf8c1fc398763a9f1beecb8ddc86",
                ],
                "withdrawals": [
                    {
                        "index": "1",
                        "validator_index": "1",
                        "address": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                        "amount": "32000000000"
                    },
                ],
            },
        }),
        Phase::Capella;
        "https://github.com/ethereum/builder-specs/blob/v0.4.0/examples/capella/execution_payload.json"
    )]
    #[test_case(
        json!({
            "version": "deneb",
            "data": {
                "execution_payload": {
                    "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                    "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "block_number": "1",
                    "gas_limit": "1",
                    "gas_used": "1",
                    "timestamp": "1",
                    "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "base_fee_per_gas": "1",
                    "blob_gas_used": "1",
                    "excess_blob_gas": "1",
                    "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                    "transactions": [
                        "0x02f878831469668303f51d843b9ac9f9843b9aca0082520894c93269b73096998db66be0441e836d873535cb9c8894a19041886f000080c001a031cc29234036afbf9a1fb9476b463367cb1f957ac0b919b69bbc798436e604aaa018c4e9c3914eb27aadd0b91e10b18655739fcf8c1fc398763a9f1beecb8ddc86",
                    ],
                    "withdrawals": [
                        {
                            "index": "1",
                            "validator_index": "1",
                            "address": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                            "amount": "32000000000"
                        },
                    ],
                },
                "blobs_bundle": {
                    "commitments": [
                        "0x8dab030c51e16e84be9caab84ee3d0b8bbec1db4a0e4de76439da8424d9b957370a10a78851f97e4b54d2ce1ab0d686f",
                    ],
                    "proofs": [
                        "0xb4021b0de10f743893d4f71e1bf830c019e832958efd6795baf2f83b8699a9eccc5dc99015d8d4d8ec370d0cc333c06a",
                    ],
                    "blobs": [
                        // TODO(feature/deneb):
                        // example in builder spec repo seems to contain blob hash as a leftover from removal of blinded blob sidecars.
                        // "0x24564723180fcb3d994104538d351c8dcbde12d541676bb736cf678018ca4739",
                    ],
                },
            },
        }),
        Phase::Deneb;
        "https://github.com/ethereum/builder-specs/blob/v0.4.0/examples/deneb/execution_payload_and_blobs_bundle.json"
    )]
    fn deserializes_execution_payload_and_blobs_bundle(
        json: Value,
        expected_phase: Phase,
    ) -> Result<()> {
        let response = serde_json::from_value::<ExecutionPayloadAndBlobsBundle<Mainnet>>(json)?;
        assert_eq!(response.phase(), expected_phase);
        Ok(())
    }
}
