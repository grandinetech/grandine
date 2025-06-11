use core::{
    fmt::{Formatter, Result as FmtResult},
    marker::PhantomData,
};
use std::sync::Arc;

use ethereum_types::H64;
use serde::{
    de::Visitor,
    ser::{Error as _, SerializeSeq as _},
    Deserialize, Deserializer, Serialize,
};
use ssz::{ByteList, ByteVector, ContiguousList, ContiguousVector, SszReadDefault, SszWrite as _};
use typenum::Unsigned;
use types::{
    bellatrix::{
        containers::ExecutionPayload as BellatrixExecutionPayload,
        primitives::{Gas, Transaction, Wei},
    },
    capella::{
        containers::{ExecutionPayload as CapellaExecutionPayload, Withdrawal},
        primitives::WithdrawalIndex,
    },
    combined::ExecutionPayload,
    deneb::{
        containers::{BlobIdentifier, ExecutionPayload as DenebExecutionPayload},
        primitives::{Blob, KzgCommitment, KzgProof, KzgProofs},
    },
    electra::containers::{
        ConsolidationRequest, DepositRequest, ExecutionRequests, WithdrawalRequest,
    },
    fulu::containers::DataColumnIdentifier,
    nonstandard::{Phase, WithBlobsAndMev},
    phase0::primitives::{
        ExecutionAddress, ExecutionBlockHash, ExecutionBlockNumber, Gwei, UnixSeconds,
        ValidatorIndex, H256,
    },
    preset::Preset,
};

const SUPPORTED_REQUEST_TYPES: &[&str; 3] = &[
    RequestType::Deposits.request_type(),
    RequestType::Withdrawals.request_type(),
    RequestType::Consolidations.request_type(),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RequestType {
    Deposits,
    Withdrawals,
    Consolidations,
}

impl RequestType {
    #[must_use]
    pub const fn request_type(self) -> &'static str {
        match self {
            Self::Deposits => "0x00",
            Self::Withdrawals => "0x01",
            Self::Consolidations => "0x02",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Deposits => "deposit",
            Self::Withdrawals => "withdrawal",
            Self::Consolidations => "consolidation",
        }
    }
}

/// [`ExecutionPayloadV1`](https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#executionpayloadv1)
#[derive(Deserialize, Serialize)]
#[serde(bound = "", rename_all = "camelCase")]
pub struct ExecutionPayloadV1<P: Preset> {
    pub parent_hash: ExecutionBlockHash,
    pub fee_recipient: ExecutionAddress,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: ByteVector<P::BytesPerLogsBloom>,
    pub prev_randao: H256,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub block_number: ExecutionBlockNumber,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub gas_limit: Gas,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub gas_used: Gas,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub timestamp: UnixSeconds,
    pub extra_data: Arc<ByteList<P::MaxExtraDataBytes>>,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub base_fee_per_gas: Wei,
    pub block_hash: ExecutionBlockHash,
    pub transactions: Arc<ContiguousList<Transaction<P>, P::MaxTransactionsPerPayload>>,
}

impl<P: Preset> From<BellatrixExecutionPayload<P>> for ExecutionPayloadV1<P> {
    fn from(payload: BellatrixExecutionPayload<P>) -> Self {
        let BellatrixExecutionPayload {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
        } = payload;

        Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
        }
    }
}

impl<P: Preset> From<ExecutionPayloadV1<P>> for BellatrixExecutionPayload<P> {
    fn from(payload: ExecutionPayloadV1<P>) -> Self {
        let ExecutionPayloadV1 {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
        } = payload;

        Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
        }
    }
}

/// [`ExecutionPayloadV2`](https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/shanghai.md#executionpayloadv2)
#[derive(Deserialize, Serialize)]
#[serde(bound = "", rename_all = "camelCase")]
pub struct ExecutionPayloadV2<P: Preset> {
    pub parent_hash: ExecutionBlockHash,
    pub fee_recipient: ExecutionAddress,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: ByteVector<P::BytesPerLogsBloom>,
    pub prev_randao: H256,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub block_number: ExecutionBlockNumber,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub gas_limit: Gas,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub gas_used: Gas,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub timestamp: UnixSeconds,
    pub extra_data: Arc<ByteList<P::MaxExtraDataBytes>>,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub base_fee_per_gas: Wei,
    pub block_hash: ExecutionBlockHash,
    pub transactions: Arc<ContiguousList<Transaction<P>, P::MaxTransactionsPerPayload>>,
    pub withdrawals: ContiguousList<WithdrawalV1, P::MaxWithdrawalsPerPayload>,
}

impl<P: Preset> From<CapellaExecutionPayload<P>> for ExecutionPayloadV2<P> {
    fn from(payload: CapellaExecutionPayload<P>) -> Self {
        let CapellaExecutionPayload {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
            withdrawals,
        } = payload;

        let withdrawals = withdrawals.map(Into::into);

        Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
            withdrawals,
        }
    }
}

impl<P: Preset> From<ExecutionPayloadV2<P>> for CapellaExecutionPayload<P> {
    fn from(payload: ExecutionPayloadV2<P>) -> Self {
        let ExecutionPayloadV2 {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
            withdrawals,
        } = payload;

        let withdrawals = withdrawals.map(Into::into);

        Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
            withdrawals,
        }
    }
}

/// [`ExecutionPayloadV3`](https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/experimental/blob-extension.md#executionpayloadv3)
#[derive(Deserialize, Serialize)]
#[serde(bound = "", rename_all = "camelCase")]
pub struct ExecutionPayloadV3<P: Preset> {
    pub parent_hash: ExecutionBlockHash,
    pub fee_recipient: ExecutionAddress,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: ByteVector<P::BytesPerLogsBloom>,
    pub prev_randao: H256,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub block_number: ExecutionBlockNumber,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub gas_limit: Gas,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub gas_used: Gas,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub timestamp: UnixSeconds,
    pub extra_data: Arc<ByteList<P::MaxExtraDataBytes>>,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub base_fee_per_gas: Wei,
    pub block_hash: ExecutionBlockHash,
    pub transactions: Arc<ContiguousList<Transaction<P>, P::MaxTransactionsPerPayload>>,
    pub withdrawals: ContiguousList<WithdrawalV1, P::MaxWithdrawalsPerPayload>,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub blob_gas_used: Gas,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub excess_blob_gas: Gas,
}

impl<P: Preset> From<DenebExecutionPayload<P>> for ExecutionPayloadV3<P> {
    fn from(payload: DenebExecutionPayload<P>) -> Self {
        let DenebExecutionPayload {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
            withdrawals,
            blob_gas_used,
            excess_blob_gas,
        } = payload;

        let withdrawals = withdrawals.map(Into::into);

        Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
            withdrawals,
            blob_gas_used,
            excess_blob_gas,
        }
    }
}

impl<P: Preset> From<ExecutionPayloadV3<P>> for DenebExecutionPayload<P> {
    fn from(payload: ExecutionPayloadV3<P>) -> Self {
        let ExecutionPayloadV3 {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
            withdrawals,
            blob_gas_used,
            excess_blob_gas,
        } = payload;

        let withdrawals = withdrawals.map(Into::into);

        Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
            withdrawals,
            blob_gas_used,
            excess_blob_gas,
        }
    }
}

// #[derive(Deserialize, Serialize)]
// #[serde(bound = "", rename_all = "camelCase")]
// pub struct BlobsBundleV1<P: Preset> {
//     pub commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
//     pub proofs: ContiguousList<KzgProof, P::MaxBlobCommitmentsPerBlock>,
//     pub blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
// }

// Merge `BlobsBundleV1` with `BlobsBundleV2` by using the same `proofs` max length
//
/// [`BlobsBundleV1`](https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/experimental/blob-extension.md#blobsbundlev1)
/// [`BlobsBundleV2`](https://github.com/ethereum/execution-apis/blob/5d634063ccfd897a6974ea589c00e2c1d889abc9/src/engine/osaka.md#blobsbundlev2)
#[derive(Deserialize, Serialize)]
#[serde(bound = "", rename_all = "camelCase")]
pub struct BlobsBundle<P: Preset> {
    pub commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
    pub proofs: KzgProofs<P>,
    pub blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

/// [`ForkChoiceStateV1`](https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#forkchoicestatev1)
#[expect(clippy::struct_field_names)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkChoiceStateV1 {
    pub head_block_hash: ExecutionBlockHash,
    pub safe_block_hash: ExecutionBlockHash,
    pub finalized_block_hash: ExecutionBlockHash,
}

/// [`PayloadAttributesV1`](https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#payloadattributesv1)
#[derive(Copy, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAttributesV1 {
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub timestamp: UnixSeconds,
    pub prev_randao: H256,
    pub suggested_fee_recipient: ExecutionAddress,
}

/// [`PayloadAttributesV2`](https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/shanghai.md#payloadattributesv2)
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAttributesV2<P: Preset> {
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub timestamp: UnixSeconds,
    pub prev_randao: H256,
    pub suggested_fee_recipient: ExecutionAddress,
    pub withdrawals: ContiguousList<WithdrawalV1, P::MaxWithdrawalsPerPayload>,
}

/// [`PayloadAttributesV3`](https://github.com/ethereum/execution-apis/blob/fe8e13c288c592ec154ce25c534e26cb7ce0530d/src/engine/cancun.md#payloadattributesv3)
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAttributesV3<P: Preset> {
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub timestamp: UnixSeconds,
    pub prev_randao: H256,
    pub suggested_fee_recipient: ExecutionAddress,
    pub withdrawals: ContiguousList<WithdrawalV1, P::MaxWithdrawalsPerPayload>,
    pub parent_beacon_block_root: H256,
}

/// [`engine_getPayloadV1` response](https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#response-2).
pub type EngineGetPayloadV1Response<P> = ExecutionPayloadV1<P>;

impl<P: Preset> From<EngineGetPayloadV1Response<P>> for WithBlobsAndMev<ExecutionPayload<P>, P> {
    fn from(response: EngineGetPayloadV1Response<P>) -> Self {
        Self::with_default(ExecutionPayload::Bellatrix(response.into()))
    }
}

/// [`engine_getPayloadV2` response] specialized for Capella.
///
/// [`execution_payload`] could also contain an [`ExecutionPayloadV1`],
/// but we never call `engine_getPayloadV2` with Bellatrix payload IDs.
///
/// [`engine_getPayloadV2` response]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/shanghai.md#response-2
/// [`execution_payload`]:            #structfield.execution_payload
#[derive(Deserialize)]
#[serde(bound = "", rename_all = "camelCase")]
pub struct EngineGetPayloadV2Response<P: Preset> {
    pub execution_payload: ExecutionPayloadV2<P>,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub block_value: Wei,
}

impl<P: Preset> From<EngineGetPayloadV2Response<P>> for WithBlobsAndMev<ExecutionPayload<P>, P> {
    fn from(response: EngineGetPayloadV2Response<P>) -> Self {
        let EngineGetPayloadV2Response {
            execution_payload,
            block_value,
        } = response;

        let execution_payload = ExecutionPayload::Capella(execution_payload.into());

        Self::with_default(execution_payload).with_mev(block_value)
    }
}

/// [`engine_getPayloadV3` response] specialized for Deneb.
///
/// [`engine_getPayloadV3` response]: https://github.com/ethereum/execution-apis/blob/fe8e13c288c592ec154ce25c534e26cb7ce0530d/src/engine/cancun.md#response-2
/// [`execution_payload`]:            #structfield.execution_payload
#[derive(Deserialize)]
#[serde(bound = "", rename_all = "camelCase")]
pub struct EngineGetPayloadV3Response<P: Preset> {
    pub execution_payload: ExecutionPayloadV3<P>,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub block_value: Wei,
    pub blobs_bundle: BlobsBundle<P>,
    pub should_override_builder: bool,
}

impl<P: Preset> From<EngineGetPayloadV3Response<P>> for WithBlobsAndMev<ExecutionPayload<P>, P> {
    fn from(response: EngineGetPayloadV3Response<P>) -> Self {
        let EngineGetPayloadV3Response {
            execution_payload,
            block_value,
            blobs_bundle,
            ..
        } = response;

        let execution_payload = ExecutionPayload::Deneb(execution_payload.into());

        let BlobsBundle {
            commitments,
            proofs,
            blobs,
        } = blobs_bundle;

        Self::new(
            execution_payload,
            Some(commitments),
            Some(proofs),
            Some(blobs),
            Some(block_value),
            None,
        )
    }
}

#[derive(Deserialize)]
#[serde(bound = "", rename_all = "camelCase")]
pub struct EngineGetPayloadV4Response<P: Preset> {
    pub execution_payload: ExecutionPayloadV3<P>,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub block_value: Wei,
    pub blobs_bundle: BlobsBundle<P>,
    pub should_override_builder: bool,
    pub execution_requests: RawExecutionRequests<P>,
}

impl<P: Preset> From<EngineGetPayloadV4Response<P>> for WithBlobsAndMev<ExecutionPayload<P>, P> {
    fn from(response: EngineGetPayloadV4Response<P>) -> Self {
        let EngineGetPayloadV4Response {
            execution_payload,
            block_value,
            blobs_bundle,
            execution_requests,
            ..
        } = response;

        let execution_payload = ExecutionPayload::Deneb(execution_payload.into());

        let BlobsBundle {
            commitments,
            proofs,
            blobs,
        } = blobs_bundle;

        Self::new(
            execution_payload,
            Some(commitments),
            Some(proofs),
            Some(blobs),
            Some(block_value),
            Some(execution_requests.into()),
        )
    }
}

#[derive(Deserialize)]
#[serde(bound = "", rename_all = "camelCase")]
pub struct EngineGetPayloadV5Response<P: Preset> {
    pub execution_payload: ExecutionPayloadV3<P>,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub block_value: Wei,
    pub blobs_bundle: BlobsBundle<P>,
    pub should_override_builder: bool,
    pub execution_requests: RawExecutionRequests<P>,
}

impl<P: Preset> From<EngineGetPayloadV5Response<P>> for WithBlobsAndMev<ExecutionPayload<P>, P> {
    fn from(response: EngineGetPayloadV5Response<P>) -> Self {
        let EngineGetPayloadV5Response {
            execution_payload,
            block_value,
            blobs_bundle,
            execution_requests,
            ..
        } = response;

        let execution_payload = ExecutionPayload::Deneb(execution_payload.into());

        let BlobsBundle {
            commitments,
            proofs,
            blobs,
        } = blobs_bundle;

        Self::new(
            execution_payload,
            Some(commitments),
            Some(proofs),
            Some(blobs),
            Some(block_value),
            Some(execution_requests.into()),
        )
    }
}

#[derive(Clone, Serialize)]
#[serde(untagged, bound = "")]
pub enum PayloadAttributes<P: Preset> {
    Bellatrix(PayloadAttributesV1),
    Capella(PayloadAttributesV2<P>),
    Deneb(PayloadAttributesV3<P>),
    Electra(PayloadAttributesV3<P>),
    Fulu(PayloadAttributesV3<P>),
}

impl<P: Preset> PayloadAttributes<P> {
    #[must_use]
    pub const fn phase(&self) -> Phase {
        match self {
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
            Self::Fulu(_) => Phase::Fulu,
        }
    }
}

/// [`PayloadStatusV1`](https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#payloadstatusv1)
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Serialize))]
pub struct PayloadStatusV1 {
    pub status: PayloadValidationStatus,
    pub latest_valid_hash: Option<ExecutionBlockHash>,
    pub validation_error: Option<String>,
}

/// [`WithdrawalV1`](https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/shanghai.md#withdrawalv1)
#[derive(Copy, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalV1 {
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub index: WithdrawalIndex,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub validator_index: ValidatorIndex,
    pub address: ExecutionAddress,
    #[serde(with = "serde_utils::prefixed_hex_quantity")]
    pub amount: Gwei,
}

impl From<Withdrawal> for WithdrawalV1 {
    fn from(withdrawal: Withdrawal) -> Self {
        let Withdrawal {
            index,
            validator_index,
            address,
            amount,
        } = withdrawal;

        Self {
            index,
            validator_index,
            address,
            amount,
        }
    }
}

impl From<WithdrawalV1> for Withdrawal {
    fn from(withdrawal: WithdrawalV1) -> Self {
        let WithdrawalV1 {
            index,
            validator_index,
            address,
            amount,
        } = withdrawal;

        Self {
            index,
            validator_index,
            address,
            amount,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(test, derive(Serialize))]
pub enum PayloadValidationStatus {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
}

impl PayloadValidationStatus {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }

    #[must_use]
    pub const fn is_invalid(self) -> bool {
        matches!(self, Self::Invalid | Self::InvalidBlockHash)
    }

    #[must_use]
    pub const fn is_syncing(self) -> bool {
        matches!(self, Self::Syncing)
    }
}

/// [`engine_forkchoiceUpdated` response](https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#response-1)
#[derive(Debug)]
pub struct ForkChoiceUpdatedResponse {
    pub payload_status: PayloadStatusV1,
    pub payload_id: Option<PayloadId>,
}

#[derive(Clone, Copy, Debug)]
pub enum PayloadId {
    Bellatrix(H64),
    Capella(H64),
    Deneb(H64),
    Electra(H64),
    Fulu(H64),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadStatusWithBlockHash {
    pub block_hash: ExecutionBlockHash,
    pub payload_status: PayloadStatus,
}

// `PayloadStatusV1` is deserialized from data containing keys in `camelCase`,
// whereas `consensus-spec-tests` and `grandine-snapshot-tests` use `snake_case`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadStatus {
    status: PayloadValidationStatus,
    latest_valid_hash: Option<ExecutionBlockHash>,
    validation_error: Option<String>,
}

impl From<PayloadStatus> for PayloadStatusV1 {
    fn from(payload_status: PayloadStatus) -> Self {
        let PayloadStatus {
            status,
            latest_valid_hash,
            validation_error,
        } = payload_status;

        Self {
            status,
            latest_valid_hash,
            validation_error,
        }
    }
}

#[cfg_attr(test, derive(Clone, Default, Debug, Eq, PartialEq))]
pub struct RawExecutionRequests<P: Preset>(
    ContiguousList<DepositRequest, P::MaxDepositRequestsPerPayload>,
    ContiguousList<WithdrawalRequest, P::MaxWithdrawalRequestsPerPayload>,
    ContiguousList<ConsolidationRequest, P::MaxConsolidationRequestsPerPayload>,
);

impl<P: Preset> Serialize for RawExecutionRequests<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self(deposit_requests, withdrawal_requests, consolidation_requests) = self;
        let mut seq = serializer.serialize_seq(None)?;

        if !deposit_requests.is_empty() {
            let bytes = deposit_requests.to_ssz().map_err(S::Error::custom)?;
            seq.serialize_element(&format_args!(
                "{}{}",
                RequestType::Deposits.request_type(),
                const_hex::encode(bytes).as_str()
            ))?;
        }

        if !withdrawal_requests.is_empty() {
            let bytes = withdrawal_requests.to_ssz().map_err(S::Error::custom)?;
            seq.serialize_element(&format_args!(
                "{}{}",
                RequestType::Withdrawals.request_type(),
                const_hex::encode(bytes).as_str()
            ))?;
        }

        if !consolidation_requests.is_empty() {
            let bytes = consolidation_requests.to_ssz().map_err(S::Error::custom)?;

            seq.serialize_element(&format_args!(
                "{}{}",
                RequestType::Consolidations.request_type(),
                const_hex::encode(bytes).as_str(),
            ))?;
        }

        seq.end()
    }
}

impl<'de, P: Preset> Deserialize<'de> for RawExecutionRequests<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawExecutionRequestsVisitor<P: Preset> {
            _phantom_data: PhantomData<P>,
        }

        fn decode_requests<B, E, T, N>(
            bytes: B,
            request_type: RequestType,
            prev_request_type: &mut Option<RequestType>,
        ) -> Result<ContiguousList<T, N>, E>
        where
            E: serde::de::Error,
            B: AsRef<[u8]>,
            N: Unsigned,
            T: SszReadDefault,
        {
            if let Some(prev_request_type) = prev_request_type {
                if *prev_request_type >= request_type {
                    return Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Bytes(bytes.as_ref()),
                        &format!(
                            "{} requests to be unique and in ascending order",
                            request_type.label(),
                        )
                        .as_str(),
                    ));
                }
            }

            *prev_request_type = Some(request_type);

            let bytes = hex::decode(bytes).map_err(serde::de::Error::custom)?;

            if bytes.is_empty() {
                return Err(serde::de::Error::invalid_value(
                    serde::de::Unexpected::Bytes(&bytes),
                    &format!(
                        "empty {} requests to be excluded from the response",
                        request_type.label(),
                    )
                    .as_str(),
                ));
            }

            ContiguousList::from_ssz_default(bytes).map_err(serde::de::Error::custom)
        }

        impl<'de, P: Preset> Visitor<'de> for RawExecutionRequestsVisitor<P> {
            type Value = RawExecutionRequests<P>;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                formatter.write_str("a sequence of execution requests")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut prev_request_type = None;
                let mut deposit_requests = ContiguousList::default();
                let mut withdrawal_requests = ContiguousList::default();
                let mut consolidation_requests = ContiguousList::default();

                while let Some(next_element) = seq.next_element::<String>()? {
                    if let Some(digits) =
                        next_element.strip_prefix(RequestType::Deposits.request_type())
                    {
                        deposit_requests =
                            decode_requests(digits, RequestType::Deposits, &mut prev_request_type)?;

                        continue;
                    }

                    if let Some(digits) =
                        next_element.strip_prefix(RequestType::Withdrawals.request_type())
                    {
                        withdrawal_requests = decode_requests(
                            digits,
                            RequestType::Withdrawals,
                            &mut prev_request_type,
                        )?;

                        continue;
                    }

                    if let Some(digits) =
                        next_element.strip_prefix(RequestType::Consolidations.request_type())
                    {
                        consolidation_requests = decode_requests(
                            digits,
                            RequestType::Consolidations,
                            &mut prev_request_type,
                        )?;

                        continue;
                    }

                    return Err(serde::de::Error::unknown_variant(
                        &next_element,
                        SUPPORTED_REQUEST_TYPES,
                    ));
                }

                Ok(RawExecutionRequests(
                    deposit_requests,
                    withdrawal_requests,
                    consolidation_requests,
                ))
            }
        }

        let visitor = RawExecutionRequestsVisitor {
            _phantom_data: PhantomData,
        };

        deserializer.deserialize_seq(visitor)
    }
}

impl<P: Preset> From<ExecutionRequests<P>> for RawExecutionRequests<P> {
    fn from(execution_requests: ExecutionRequests<P>) -> Self {
        let ExecutionRequests {
            deposits,
            withdrawals,
            consolidations,
        } = execution_requests;

        Self(deposits, withdrawals, consolidations)
    }
}

impl<P: Preset> From<RawExecutionRequests<P>> for ExecutionRequests<P> {
    fn from(raw_execution_requests: RawExecutionRequests<P>) -> Self {
        let RawExecutionRequests(deposits, withdrawals, consolidations) = raw_execution_requests;

        Self {
            deposits,
            withdrawals,
            consolidations,
        }
    }
}

#[derive(Deserialize)]
#[serde(bound = "")]
pub struct BlobAndProofV1<P: Preset> {
    pub blob: Blob<P>,
    pub proof: KzgProof,
}

#[derive(Deserialize)]
#[serde(bound = "", rename_all = "camelCase")]
pub struct BlobAndProofV2<P: Preset> {
    pub blob: Blob<P>,
    pub proofs: ContiguousVector<KzgProof, P::CellsPerExtBlob>,
}

pub enum EngineGetBlobsParams {
    Blobs(Vec<BlobIdentifier>),
    DataColumns(Vec<DataColumnIdentifier>),
}

impl From<Vec<BlobIdentifier>> for EngineGetBlobsParams {
    fn from(params: Vec<BlobIdentifier>) -> Self {
        Self::Blobs(params)
    }
}

impl From<Vec<DataColumnIdentifier>> for EngineGetBlobsParams {
    fn from(params: Vec<DataColumnIdentifier>) -> Self {
        Self::DataColumns(params)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use hex_literal::hex;
    use serde_json::{json, Value};
    use types::{
        electra::containers::ConsolidationRequest, phase0::primitives::H160, preset::Mainnet,
    };

    use super::*;

    #[test]
    fn test_bellatrix_execution_payload_conversion_and_serialization() -> Result<()> {
        let payload_v1 = ExecutionPayloadV1::from(sample_bellatrix_payload().value);
        let actual_json = serde_json::to_value(&payload_v1)?;
        let expected_json = sample_bellatrix_payload_json();

        assert_eq!(actual_json, expected_json);

        Ok(())
    }

    #[test]
    fn test_capella_execution_payload_conversion_and_serialization() -> Result<()> {
        let payload_v2 = ExecutionPayloadV2::from(sample_capella_payload().value);
        let actual_json = serde_json::to_value(&payload_v2)?;
        let expected_json = sample_capella_payload_json();

        assert_eq!(actual_json, expected_json);

        Ok(())
    }

    #[test]
    fn test_engine_get_payload_v1_response_deserialization_and_conversion() -> Result<()> {
        let json = sample_bellatrix_payload_json();
        let response = serde_json::from_value::<EngineGetPayloadV1Response<Mainnet>>(json)?;
        let actual_payload = WithBlobsAndMev::from(response);
        let expected_payload = sample_bellatrix_payload().map(Into::into);

        assert_eq!(actual_payload, expected_payload);

        Ok(())
    }

    #[test]
    fn test_engine_get_payload_v1_response_with_extra_fields_deserialization_and_conversion(
    ) -> Result<()> {
        let json = sample_bellatrix_payload_with_extra_fields_json();
        let response = serde_json::from_value::<EngineGetPayloadV1Response<Mainnet>>(json)?;
        let actual_payload = WithBlobsAndMev::from(response);
        let expected_payload = sample_bellatrix_payload().map(Into::into);

        assert_eq!(actual_payload, expected_payload);

        Ok(())
    }

    #[test]
    fn test_engine_get_payload_v2_response_deserialization_and_conversion() -> Result<()> {
        let json = sample_capella_response_json();
        let response = serde_json::from_value::<EngineGetPayloadV2Response<Mainnet>>(json)?;
        let actual_payload = WithBlobsAndMev::from(response);
        let expected_payload = sample_capella_payload().map(Into::into);

        assert_eq!(actual_payload, expected_payload);

        Ok(())
    }

    #[test]
    fn test_engine_get_payload_v3_response_deserialization_and_conversion() -> Result<()> {
        let json = sample_deneb_response_json();
        let response = serde_json::from_value::<EngineGetPayloadV3Response<Mainnet>>(json)?;
        let actual_payload = WithBlobsAndMev::from(response);
        let expected_payload = sample_deneb_payload().map(Into::into);

        assert_eq!(actual_payload, expected_payload);

        Ok(())
    }

    #[test]
    fn test_default_raw_execution_requests_roundtrip() -> Result<()> {
        let serialized = serde_json::to_value(RawExecutionRequests::<Mainnet>::default())?;
        assert_eq!(serialized, json!([]));

        assert_eq!(
            serde_json::from_value::<RawExecutionRequests::<Mainnet>>(json!([]))?,
            RawExecutionRequests::<Mainnet>::default(),
        );

        Ok(())
    }

    #[test]
    fn test_non_default_raw_execution_requests_roundtrip() -> Result<()> {
        let execution_requests = ExecutionRequests::<Mainnet> {
            deposits: ContiguousList::try_from(vec![
                DepositRequest {
                    pubkey: hex!("92f9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb688").into(),
                    withdrawal_credentials: hex!("02000000000000000000000065d08a056c17ae13370565b04cf77d2afa1cb9fa").into(),
                    amount: 1_000_000_000_000,
                    signature: hex!("a13741d65b47825c147201cfce3360438d4011fe81b455e86226c95a2669bfde14712ba36d1c2f44371a98bf28ff38370ce7d28c65872bf65ff88d6014468676029e298903c89c51c27ab5f07e178b8b14d3ca191e2ce3b24703629e3994e05b").into(),
                    index: 0,
                },
                DepositRequest {
                    pubkey: hex!("90a58546229c585cef35f3afab904411530303d95c371e246a2e9a1ef6beb5db7a98c2fd79a388709a30ec782576a5d6").into(),
                    withdrawal_credentials: hex!("02000000000000000000000065d08a056c17ae13370565b04cf77d2afa1cb9fa").into(),
                    amount: 1_000_000_000_000,
                    signature: hex!("b23e205d2fcfc3e9d3ae58c0f78b55b19f97f59eaf43d85113a1960ee2c38f6b4ef705302e46e0593fc41ba5632b047a14d76dc82bb2619d7c73e0d89da2eda2ea11fff9036c2d08f9d457c07f23b1411ecd13ff0e9c00eeb85d851bae2494e0").into(),
                    index: 1,
                }
            ])?,
            withdrawals: ContiguousList::try_from(vec![
                WithdrawalRequest {
                    source_address: ExecutionAddress::repeat_byte(2),
                    validator_pubkey: hex!("aaf9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb688").into(),
                    amount: 4_000_000_000_000,
                },
            ])?,
            consolidations: ContiguousList::try_from(vec![
                ConsolidationRequest {
                    source_pubkey: hex!("aaf9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb688").into(),
                    source_address: ExecutionAddress::repeat_byte(3),
                    target_pubkey: hex!("abc9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb688").into(),
                },
            ])?,
        };

        let raw_execution_requests = RawExecutionRequests::from(execution_requests);
        let serialized = serde_json::to_value(raw_execution_requests.clone())?;

        let expected_serialzed = json!([
            "0x0092f9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb68802000000000000000000000065d08a056c17ae13370565b04cf77d2afa1cb9fa0010a5d4e8000000a13741d65b47825c147201cfce3360438d4011fe81b455e86226c95a2669bfde14712ba36d1c2f44371a98bf28ff38370ce7d28c65872bf65ff88d6014468676029e298903c89c51c27ab5f07e178b8b14d3ca191e2ce3b24703629e3994e05b000000000000000090a58546229c585cef35f3afab904411530303d95c371e246a2e9a1ef6beb5db7a98c2fd79a388709a30ec782576a5d602000000000000000000000065d08a056c17ae13370565b04cf77d2afa1cb9fa0010a5d4e8000000b23e205d2fcfc3e9d3ae58c0f78b55b19f97f59eaf43d85113a1960ee2c38f6b4ef705302e46e0593fc41ba5632b047a14d76dc82bb2619d7c73e0d89da2eda2ea11fff9036c2d08f9d457c07f23b1411ecd13ff0e9c00eeb85d851bae2494e00100000000000000",
            "0x010202020202020202020202020202020202020202aaf9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb68800409452a3030000",
            "0x020303030303030303030303030303030303030303aaf9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb688abc9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb688",
        ]);

        assert_eq!(serialized, expected_serialzed);
        assert_eq!(
            serde_json::from_value::<RawExecutionRequests::<Mainnet>>(expected_serialzed)?,
            raw_execution_requests,
        );

        Ok(())
    }

    #[test]
    fn test_invalid_prefix_raw_execution_requests_deserialization() {
        let payload = json!([
            "0x0392f9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb68802000000000000000000000065d08a056c17ae13370565b04cf77d2afa1cb9fa0010a5d4e8000000a13741d65b47825c147201cfce3360438d4011fe81b455e86226c95a2669bfde14712ba36d1c2f44371a98bf28ff38370ce7d28c65872bf65ff88d6014468676029e298903c89c51c27ab5f07e178b8b14d3ca191e2ce3b24703629e3994e05b000000000000000090a58546229c585cef35f3afab904411530303d95c371e246a2e9a1ef6beb5db7a98c2fd79a388709a30ec782576a5d602000000000000000000000065d08a056c17ae13370565b04cf77d2afa1cb9fa0010a5d4e8000000b23e205d2fcfc3e9d3ae58c0f78b55b19f97f59eaf43d85113a1960ee2c38f6b4ef705302e46e0593fc41ba5632b047a14d76dc82bb2619d7c73e0d89da2eda2ea11fff9036c2d08f9d457c07f23b1411ecd13ff0e9c00eeb85d851bae2494e00100000000000000",
        ]);

        let error = serde_json::from_value::<RawExecutionRequests<Mainnet>>(payload)
            .expect_err("execution requests object with invalid prefix should be rejected");

        assert!(error.to_string().starts_with("unknown variant"));
    }

    #[test]
    fn test_payload_status_v1_round_trip() -> Result<()> {
        let json = json!({
            "status": "VALID",
            "latestValidHash": null,
            "validationError": null,
        });

        let payload_status = PayloadStatusV1 {
            status: PayloadValidationStatus::Valid,
            latest_valid_hash: None,
            validation_error: None,
        };

        assert_eq!(
            serde_json::from_value::<PayloadStatusV1>(json.clone())?,
            payload_status,
        );
        assert_eq!(serde_json::to_value(payload_status)?, json);

        Ok(())
    }

    // JSON response from `geth` with an Eth1 block from the Kiln testnet.
    // Also available at <https://explorer.kiln.themerge.dev/block/55000>.
    // ```json
    // {
    //     "baseFeePerGas": "0xbc431d",
    //     "difficulty": "0x5f93d0df",
    //     "extraData": "0xd883010a11846765746888676f312e31372e38856c696e7578",
    //     "gasLimit": "0x7a1200",
    //     "gasUsed": "0x0",
    //     "hash": "0x3367b402ece0f97395af9f78310c2b658c2acb2f2ad8ca2ff4fd378f8f09259d",
    //     "logsBloom": "\
    //         0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
    //         00000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
    //         00000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
    //         00000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
    //         0000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
    //         0000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    //     "miner": "0x1cffe205e97976bb9d1ec006f5222360a89353e0",
    //     "mixHash": "0xd6b7cf258223c6b48b4e150ff853126a31e6684831f04e4eabed913677a31613",
    //     "nonce": "0x9e7860c5a4baa2b3",
    //     "number": "0xd6d8",
    //     "parentHash": "0x7a86795133291dabeee4280cd038d41734e351be69248d8d6b9be749ae080c71",
    //     "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    //     "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    //     "size": "0x21f",
    //     "stateRoot": "0x3247d18f18382e0d4faefe63aad39062ec833738add1faeb0c4ae8e2c2b0843e",
    //     "timestamp": "0x6230ab63",
    //     "totalDifficulty": "0x11ffd0b47178",
    //     "transactions": [],
    //     "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    //     "uncles": []
    // }
    // ```
    fn sample_bellatrix_payload_json() -> Value {
        json!({
            "parentHash": "0x7a86795133291dabeee4280cd038d41734e351be69248d8d6b9be749ae080c71",
            "feeRecipient": "0x1cffe205e97976bb9d1ec006f5222360a89353e0",
            "stateRoot": "0x3247d18f18382e0d4faefe63aad39062ec833738add1faeb0c4ae8e2c2b0843e",
            "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom": "\
                0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
                00000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
                00000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
                00000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
                0000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
                0000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "prevRandao": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "blockNumber": "0xd6d8",
            "gasLimit": "0x7a1200",
            "gasUsed": "0x0",
            "timestamp": "0x6230ab63",
            "extraData": "0x",
            "baseFeePerGas": "0xbc431d",
            "blockHash": "0x3367b402ece0f97395af9f78310c2b658c2acb2f2ad8ca2ff4fd378f8f09259d",
            "transactions": [],
        })
    }

    // Some execution clients respond to `engine_newPayloadV1` with objects that
    // contain fields from later versions. We ran into this while testing in Zhejiang.
    fn sample_bellatrix_payload_with_extra_fields_json() -> Value {
        let mut json = sample_bellatrix_payload_json();

        json["withdrawals"] = Value::Null;

        json
    }

    fn sample_capella_payload_json() -> Value {
        let mut json = sample_bellatrix_payload_json();

        json["withdrawals"] = json!([
            {
                "index": "0x18553",
                "validatorIndex": "0x7c2d9",
                "address": "0xf97e180c050e5ab072211ad2c213eb5aee4df134",
                "amount": "0x58624",
            },
            {
                "index": "0x18554",
                "validatorIndex": "0x7c2da",
                "address": "0xf97e180c050e5ab072211ad2c213eb5aee4df134",
                "amount": "0x4aa63",
            },
        ]);

        json
    }

    fn sample_deneb_payload_json() -> Value {
        let mut json = sample_capella_payload_json();

        json["blobGasUsed"] = json!("0x20000");
        json["excessBlobGas"] = json!("0x5380000");

        json
    }

    fn sample_capella_response_json() -> Value {
        json!({
            "executionPayload": sample_capella_payload_json(),
            "blockValue": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        })
    }

    fn sample_deneb_response_json() -> Value {
        json!({
            "executionPayload": sample_deneb_payload_json(),
            "blockValue": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "blobsBundle": json!({
                "commitments": [
                    "0xa0902ddda342e7a8026216c2bd322576bab9272a5b9e7234d2c41dbf61904ffe42845019ea4c80fb040252029fa44038"
                ],
                "proofs": [
                    "0xa9f7f1a31c8526ccc04e6a4658520923fc7415606e3581c8aa4fb07f5b1367f2d24d2014dc04570614dcb88ea7fdd409"
                ],
                "blobs": []
            }),
            "shouldOverrideBuilder": false,
        })
    }

    fn sample_bellatrix_payload() -> WithBlobsAndMev<BellatrixExecutionPayload<Mainnet>, Mainnet> {
        let payload = BellatrixExecutionPayload {
            parent_hash: H256(hex!(
                "7a86795133291dabeee4280cd038d41734e351be69248d8d6b9be749ae080c71"
            )),
            fee_recipient: H160(hex!("1CffE205e97976bb9D1Ec006f5222360a89353E0")),
            state_root: H256(hex!(
                "3247d18f18382e0d4faefe63aad39062ec833738add1faeb0c4ae8e2c2b0843e"
            )),
            receipts_root: H256(hex!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            )),
            logs_bloom: ByteVector::default(),
            prev_randao: H256::default(),
            block_number: 55000,
            gas_limit: 8_000_000,
            gas_used: 0,
            timestamp: 1_647_356_771,
            extra_data: Arc::default(),
            base_fee_per_gas: Wei::from_u64(12_337_949),
            block_hash: H256(hex!(
                "3367b402ece0f97395af9f78310c2b658c2acb2f2ad8ca2ff4fd378f8f09259d"
            )),
            transactions: Arc::default(),
        };

        WithBlobsAndMev::with_default(payload)
    }

    fn sample_capella_payload() -> WithBlobsAndMev<CapellaExecutionPayload<Mainnet>, Mainnet> {
        let payload = CapellaExecutionPayload {
            parent_hash: H256(hex!(
                "7a86795133291dabeee4280cd038d41734e351be69248d8d6b9be749ae080c71"
            )),
            fee_recipient: H160(hex!("1CffE205e97976bb9D1Ec006f5222360a89353E0")),
            state_root: H256(hex!(
                "3247d18f18382e0d4faefe63aad39062ec833738add1faeb0c4ae8e2c2b0843e"
            )),
            receipts_root: H256(hex!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            )),
            logs_bloom: ByteVector::default(),
            prev_randao: H256::default(),
            block_number: 55000,
            gas_limit: 8_000_000,
            gas_used: 0,
            timestamp: 1_647_356_771,
            extra_data: Arc::default(),
            base_fee_per_gas: Wei::from_u64(12_337_949),
            block_hash: H256(hex!(
                "3367b402ece0f97395af9f78310c2b658c2acb2f2ad8ca2ff4fd378f8f09259d"
            )),
            transactions: Arc::default(),
            withdrawals: [
                Withdrawal {
                    index: 99667,
                    validator_index: 508_633,
                    address: H160(hex!("f97e180c050e5ab072211ad2c213eb5aee4df134")),
                    amount: 362_020,
                },
                Withdrawal {
                    index: 99668,
                    validator_index: 508_634,
                    address: H160(hex!("f97e180c050e5ab072211ad2c213eb5aee4df134")),
                    amount: 305_763,
                },
            ]
            .try_into()
            .expect("length is under maximum"),
        };

        WithBlobsAndMev::with_default(payload).with_mev(Wei::MAX)
    }

    fn sample_deneb_payload() -> WithBlobsAndMev<DenebExecutionPayload<Mainnet>, Mainnet> {
        let payload = DenebExecutionPayload {
            parent_hash: H256(hex!(
                "7a86795133291dabeee4280cd038d41734e351be69248d8d6b9be749ae080c71"
            )),
            fee_recipient: H160(hex!("1CffE205e97976bb9D1Ec006f5222360a89353E0")),
            state_root: H256(hex!(
                "3247d18f18382e0d4faefe63aad39062ec833738add1faeb0c4ae8e2c2b0843e"
            )),
            receipts_root: H256(hex!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            )),
            logs_bloom: ByteVector::default(),
            prev_randao: H256::default(),
            block_number: 55000,
            gas_limit: 8_000_000,
            gas_used: 0,
            timestamp: 1_647_356_771,
            extra_data: Arc::default(),
            base_fee_per_gas: Wei::from_u64(12_337_949),
            block_hash: H256(hex!(
                "3367b402ece0f97395af9f78310c2b658c2acb2f2ad8ca2ff4fd378f8f09259d"
            )),
            transactions: Arc::default(),
            withdrawals: [
                Withdrawal {
                    index: 99667,
                    validator_index: 508_633,
                    address: H160(hex!("f97e180c050e5ab072211ad2c213eb5aee4df134")),
                    amount: 362_020,
                },
                Withdrawal {
                    index: 99668,
                    validator_index: 508_634,
                    address: H160(hex!("f97e180c050e5ab072211ad2c213eb5aee4df134")),
                    amount: 305_763,
                },
            ]
            .try_into()
            .expect("length is under maximum"),
            blob_gas_used: 0x0002_0000,
            excess_blob_gas: 87_556_096,
        };

        let kzg_commitments = [
            KzgCommitment::from_slice(&hex!("a0902ddda342e7a8026216c2bd322576bab9272a5b9e7234d2c41dbf61904ffe42845019ea4c80fb040252029fa44038"))
        ].try_into().expect("length is under maximum");

        let kzg_proofs = [
            KzgProof::from_slice(&hex!("a9f7f1a31c8526ccc04e6a4658520923fc7415606e3581c8aa4fb07f5b1367f2d24d2014dc04570614dcb88ea7fdd409"))
        ].try_into().expect("length is under maximum");

        WithBlobsAndMev::new(
            payload,
            Some(kzg_commitments),
            Some(kzg_proofs),
            Some(ContiguousList::default()),
            Some(Wei::MAX),
            None,
        )
    }

    #[test]
    fn test_empty_deposit_requests() {
        let incorrect = json!(["0x00"]);
        let error = serde_json::from_value::<RawExecutionRequests<Mainnet>>(incorrect)
            .expect_err("deserializing empty deposit requests should return an error");

        assert_eq!(
            error.to_string(),
            "invalid value: byte array, expected empty deposit requests \
             to be excluded from the response",
        );
    }

    #[test]
    fn test_empty_withdrawal_requests() {
        let incorrect = json!(["0x01"]);
        let error = serde_json::from_value::<RawExecutionRequests<Mainnet>>(incorrect)
            .expect_err("deserializing empty withdrawal requests should return an error");

        assert_eq!(
            error.to_string(),
            "invalid value: byte array, expected empty withdrawal requests \
             to be excluded from the response",
        );
    }

    #[test]
    fn test_empty_consolidation_requests() {
        let incorrect = json!(["0x02"]);
        let error = serde_json::from_value::<RawExecutionRequests<Mainnet>>(incorrect)
            .expect_err("deserializing empty consolidation requests should return an error");

        assert_eq!(
            error.to_string(),
            "invalid value: byte array, expected empty consolidation requests \
             to be excluded from the response",
        );
    }

    #[test]
    fn test_duplicate_execution_requests() {
        let incorrect = json!([
            "0x010202020202020202020202020202020202020202aaf9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb68800409452a3030000",
            "0x010202020202020202020202020202020202020202aaf9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb68800409452a3030000",
        ]);

        let error = serde_json::from_value::<RawExecutionRequests<Mainnet>>(incorrect)
            .expect_err("deserializing duplicate execution requests should return an error");

        assert_eq!(
            error.to_string(),
            "invalid value: byte array, expected withdrawal requests to be unique \
             and in ascending order",
        );
    }

    #[test]
    fn test_execution_requests_incorrect_ordering() {
        let incorrect = json!([
            "0x020303030303030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0x0092f9fe7570a6650d030bb2227d699c744303d08a887cd2e1592e30906cd8cedf9646c1a1afd902235bb36620180eb68802000000000000000000000065d08a056c17ae13370565b04cf77d2afa1cb9fa0010a5d4e8000000a13741d65b47825c147201cfce3360438d4011fe81b455e86226c95a2669bfde14712ba36d1c2f44371a98bf28ff38370ce7d28c65872bf65ff88d6014468676029e298903c89c51c27ab5f07e178b8b14d3ca191e2ce3b24703629e3994e05b000000000000000090a58546229c585cef35f3afab904411530303d95c371e246a2e9a1ef6beb5db7a98c2fd79a388709a30ec782576a5d602000000000000000000000065d08a056c17ae13370565b04cf77d2afa1cb9fa0010a5d4e8000000b23e205d2fcfc3e9d3ae58c0f78b55b19f97f59eaf43d85113a1960ee2c38f6b4ef705302e46e0593fc41ba5632b047a14d76dc82bb2619d7c73e0d89da2eda2ea11fff9036c2d08f9d457c07f23b1411ecd13ff0e9c00eeb85d851bae2494e00100000000000000",
        ]);

        let error = serde_json::from_value::<RawExecutionRequests<Mainnet>>(incorrect)
            .expect_err("deserializing out of order execution requests should result in an error");

        assert_eq!(
            error.to_string(),
            "invalid value: byte array, expected deposit requests to be unique \
             and in ascending order",
        );
    }
}
