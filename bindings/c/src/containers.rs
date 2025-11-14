use execution_engine::{
    BlobAndProofV1, BlobAndProofV2, BlobsBundleV1, BlobsBundleV2, EngineGetPayloadV2Response,
    EngineGetPayloadV3Response, EngineGetPayloadV4Response, EngineGetPayloadV5Response,
    ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, ForkChoiceStateV1,
    PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3, PayloadStatusV1,
    PayloadValidationStatus, RawExecutionRequests, WithdrawalV1,
};
use generic_array::ArrayLength;
use ssz::{ByteVector, ContiguousList, ContiguousVector, SszReadDefault, SszWrite};
use std::sync::Arc;
use try_from_iterator::TryFromIterator;
use types::{
    bellatrix::primitives::Transaction, deneb::primitives::Blob,
    electra::containers::ExecutionRequests, preset::Mainnet,
};

use crate::{
    arrays::{CH160, CH256, CH384, CH64},
    generic::{CByteVector, COption, CVec},
};

#[derive(Debug)]
#[repr(C)]
pub struct CExecutionPayloadV1 {
    parent_hash: CH256,
    fee_recipient: CH160,
    state_root: CH256,
    receipts_root: CH256,
    logs_bloom: CByteVector,
    prev_randao: CH256,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: CByteVector,
    base_fee_per_gas: CH256,
    block_hash: CH256,
    transactions: CVec<CTransaction>,
}

impl From<ExecutionPayloadV1<Mainnet>> for CExecutionPayloadV1 {
    fn from(value: ExecutionPayloadV1<Mainnet>) -> Self {
        Self {
            parent_hash: value.parent_hash.into(),
            fee_recipient: value.fee_recipient.into(),
            state_root: value.state_root.into(),
            receipts_root: value.receipts_root.into(),
            logs_bloom: value.logs_bloom.into(),
            prev_randao: value.prev_randao.into(),
            block_number: value.block_number,
            gas_limit: value.gas_limit,
            gas_used: value.gas_used,
            timestamp: value.timestamp,
            extra_data: value.extra_data.as_bytes().into(),
            base_fee_per_gas: value.base_fee_per_gas.into(),
            block_hash: value.block_hash.into(),
            transactions: value
                .transactions
                .iter()
                .map(|transaction| transaction.clone().into())
                .collect::<CVec<_>>(),
        }
    }
}

impl Into<ExecutionPayloadV1<Mainnet>> for CExecutionPayloadV1 {
    fn into(self) -> ExecutionPayloadV1<Mainnet> {
        ExecutionPayloadV1::<Mainnet> {
            parent_hash: self.parent_hash.into(),
            fee_recipient: self.fee_recipient.into(),
            state_root: self.state_root.into(),
            receipts_root: self.receipts_root.into(),
            logs_bloom: self.logs_bloom.into(),
            prev_randao: self.prev_randao.into(),
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: Arc::new(self.extra_data.into()),
            base_fee_per_gas: self.base_fee_per_gas.into(),
            block_hash: self.block_hash.into(),
            // TODO: don't panic here
            transactions: Arc::new(
                ContiguousList::try_from_iter(self.transactions.into_iter().map(Into::into))
                    .unwrap(),
            ),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CExecutionPayloadV2 {
    parent_hash: CH256,
    fee_recipient: CH160,
    state_root: CH256,
    receipts_root: CH256,
    logs_bloom: CByteVector,
    prev_randao: CH256,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: CByteVector,
    base_fee_per_gas: CH256,
    block_hash: CH256,
    transactions: CVec<CTransaction>,
    withdrawals: CVec<CWithdrawalV1>,
}

impl From<ExecutionPayloadV2<Mainnet>> for CExecutionPayloadV2 {
    fn from(value: ExecutionPayloadV2<Mainnet>) -> Self {
        CExecutionPayloadV2 {
            parent_hash: value.parent_hash.into(),
            fee_recipient: value.fee_recipient.into(),
            state_root: value.state_root.into(),
            receipts_root: value.receipts_root.into(),
            logs_bloom: value.logs_bloom.into(),
            prev_randao: value.prev_randao.into(),
            block_number: value.block_number,
            gas_limit: value.gas_limit,
            gas_used: value.gas_used,
            timestamp: value.timestamp,
            extra_data: value.extra_data.as_bytes().into(),
            base_fee_per_gas: value.base_fee_per_gas.into(),
            block_hash: value.block_hash.into(),
            transactions: value
                .transactions
                .iter()
                .map(|transaction| transaction.clone().into())
                .collect(),
            withdrawals: value.withdrawals.into_iter().map(Into::into).collect(),
        }
    }
}

impl Into<ExecutionPayloadV2<Mainnet>> for CExecutionPayloadV2 {
    fn into(self) -> ExecutionPayloadV2<Mainnet> {
        ExecutionPayloadV2 {
            parent_hash: self.parent_hash.into(),
            fee_recipient: self.fee_recipient.into(),
            state_root: self.state_root.into(),
            receipts_root: self.receipts_root.into(),
            logs_bloom: self.logs_bloom.into(),
            prev_randao: self.prev_randao.into(),
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: Arc::new(self.extra_data.into()),
            base_fee_per_gas: self.base_fee_per_gas.into(),
            block_hash: self.block_hash.into(),
            // TODO: don't panic here
            transactions: Arc::new(
                ContiguousList::try_from_iter(self.transactions.into_iter().map(Into::into))
                    .unwrap(),
            ),
            // TODO: don't panic here
            withdrawals: ContiguousList::try_from_iter(
                self.withdrawals.into_iter().map(Into::into),
            )
            .unwrap(),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CExecutionPayloadV3 {
    parent_hash: CH256,
    fee_recipient: CH160,
    state_root: CH256,
    receipts_root: CH256,
    logs_bloom: CByteVector,
    prev_randao: CH256,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: CByteVector,
    base_fee_per_gas: CH256,
    block_hash: CH256,
    transactions: CVec<CTransaction>,
    withdrawals: CVec<CWithdrawalV1>,
    blob_gas_used: u64,
    excess_blob_gas: u64,
}

impl From<ExecutionPayloadV3<Mainnet>> for CExecutionPayloadV3 {
    fn from(value: ExecutionPayloadV3<Mainnet>) -> Self {
        CExecutionPayloadV3 {
            parent_hash: value.parent_hash.into(),
            fee_recipient: value.fee_recipient.into(),
            state_root: value.state_root.into(),
            receipts_root: value.receipts_root.into(),
            logs_bloom: value.logs_bloom.into(),
            prev_randao: value.prev_randao.into(),
            block_number: value.block_number,
            gas_limit: value.gas_limit,
            gas_used: value.gas_used,
            timestamp: value.timestamp,
            extra_data: value.extra_data.as_bytes().into(),
            base_fee_per_gas: value.base_fee_per_gas.into(),
            block_hash: value.block_hash.into(),
            withdrawals: value.withdrawals.into_iter().map(Into::into).collect(),
            blob_gas_used: value.blob_gas_used,
            excess_blob_gas: value.excess_blob_gas,
            transactions: value
                .transactions
                .iter()
                .map(|transaction| transaction.clone().into())
                .collect(),
        }
    }
}

impl Into<ExecutionPayloadV3<Mainnet>> for CExecutionPayloadV3 {
    fn into(self) -> ExecutionPayloadV3<Mainnet> {
        ExecutionPayloadV3 {
            parent_hash: self.parent_hash.into(),
            fee_recipient: self.fee_recipient.into(),
            state_root: self.state_root.into(),
            receipts_root: self.receipts_root.into(),
            logs_bloom: self.logs_bloom.into(),
            prev_randao: self.prev_randao.into(),
            block_number: self.block_number.into(),
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: Arc::new(self.extra_data.into()),
            base_fee_per_gas: self.base_fee_per_gas.into(),
            block_hash: self.block_hash.into(),
            // TODO: don't panic here
            transactions: Arc::new(
                ContiguousList::try_from_iter(
                    self.transactions.into_iter().map(Into::into).into_iter(),
                )
                .unwrap(),
            ),
            // TODO: don't panic here
            withdrawals: ContiguousList::try_from_iter(
                self.withdrawals.into_iter().map(Into::into),
            )
            .unwrap(),
            blob_gas_used: self.blob_gas_used,
            excess_blob_gas: self.excess_blob_gas,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CEngineGetPayloadV2Response {
    execution_payload: CExecutionPayloadV2,
    block_value: CH256,
}

impl Into<EngineGetPayloadV2Response<Mainnet>> for CEngineGetPayloadV2Response {
    fn into(self) -> EngineGetPayloadV2Response<Mainnet> {
        EngineGetPayloadV2Response {
            execution_payload: self.execution_payload.into(),
            block_value: self.block_value.into(),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CEngineGetPayloadV3Response {
    execution_payload: CExecutionPayloadV3,
    block_value: CH256,
    blobs_bundle: CBlobsBundleV1,
    should_override_builder: bool,
}

impl Into<EngineGetPayloadV3Response<Mainnet>> for CEngineGetPayloadV3Response {
    fn into(self) -> EngineGetPayloadV3Response<Mainnet> {
        let blobs_bundle: BlobsBundleV1<Mainnet> = self.blobs_bundle.into();

        EngineGetPayloadV3Response {
            execution_payload: self.execution_payload.into(),
            block_value: self.block_value.into(),
            blobs_bundle,
            should_override_builder: self.should_override_builder,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CEngineGetPayloadV4Response {
    execution_payload: CExecutionPayloadV3,
    block_value: CH256,
    blobs_bundle: CBlobsBundleV1,
    should_override_builder: bool,
    execution_requests: CExecutionRequests,
}

impl Into<EngineGetPayloadV4Response<Mainnet>> for CEngineGetPayloadV4Response {
    fn into(self) -> EngineGetPayloadV4Response<Mainnet> {
        let blobs_bundle: BlobsBundleV1<Mainnet> = self.blobs_bundle.into();

        EngineGetPayloadV4Response {
            execution_payload: self.execution_payload.into(),
            block_value: self.block_value.into(),
            blobs_bundle,
            should_override_builder: self.should_override_builder,
            execution_requests: self.execution_requests.into(),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CEngineGetPayloadV5Response {
    execution_payload: CExecutionPayloadV3,
    block_value: CH256,
    blobs_bundle: CBlobsBundleV1,
    should_override_builder: bool,
    execution_requests: CExecutionRequests,
}

impl Into<EngineGetPayloadV5Response<Mainnet>> for CEngineGetPayloadV5Response {
    fn into(self) -> EngineGetPayloadV5Response<Mainnet> {
        EngineGetPayloadV5Response {
            execution_payload: self.execution_payload.into(),
            block_value: self.block_value.into(),
            blobs_bundle: self.blobs_bundle.into(),
            should_override_builder: self.should_override_builder,
            execution_requests: self.execution_requests.into(),
        }
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct CPayloadAttributesV1 {
    timestamp: u64,
    prev_randao: CH256,
    suggested_fee_recipient: CH160,
}

impl From<PayloadAttributesV1> for CPayloadAttributesV1 {
    fn from(value: PayloadAttributesV1) -> Self {
        Self {
            timestamp: value.timestamp,
            prev_randao: value.prev_randao.into(),
            suggested_fee_recipient: value.suggested_fee_recipient.into(),
        }
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct CPayloadAttributesV2 {
    timestamp: u64,
    prev_randao: CH256,
    suggested_fee_recipient: CH160,
    withdrawals: CVec<CWithdrawalV1>,
}

impl From<PayloadAttributesV2<Mainnet>> for CPayloadAttributesV2 {
    fn from(value: PayloadAttributesV2<Mainnet>) -> Self {
        Self {
            timestamp: value.timestamp,
            prev_randao: value.prev_randao.into(),
            suggested_fee_recipient: value.suggested_fee_recipient.into(),
            withdrawals: value.withdrawals.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct CPayloadAttributesV3 {
    timestamp: u64,
    prev_randao: CH256,
    suggested_fee_recipient: CH160,
    withdrawals: CVec<CWithdrawalV1>,
    parent_beacon_block_root: CH256,
}

impl From<PayloadAttributesV3<Mainnet>> for CPayloadAttributesV3 {
    fn from(value: PayloadAttributesV3<Mainnet>) -> Self {
        Self {
            timestamp: value.timestamp,
            prev_randao: value.prev_randao.into(),
            suggested_fee_recipient: value.suggested_fee_recipient.into(),
            withdrawals: value.withdrawals.into_iter().map(Into::into).collect(),
            parent_beacon_block_root: value.parent_beacon_block_root.into(),
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum CPayloadValidationStatus {
    Valid = 0,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
}

impl Into<PayloadValidationStatus> for CPayloadValidationStatus {
    fn into(self) -> PayloadValidationStatus {
        match self {
            CPayloadValidationStatus::Valid => PayloadValidationStatus::Valid,
            CPayloadValidationStatus::Invalid => PayloadValidationStatus::Invalid,
            CPayloadValidationStatus::Syncing => PayloadValidationStatus::Syncing,
            CPayloadValidationStatus::Accepted => PayloadValidationStatus::Accepted,
            CPayloadValidationStatus::InvalidBlockHash => PayloadValidationStatus::InvalidBlockHash,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CPayloadStatusV1 {
    status: CPayloadValidationStatus,
    latest_valid_hash: COption<CH256>,
    // validation_error: COption<*const c_char>, FIXME
}

impl Into<PayloadStatusV1> for CPayloadStatusV1 {
    fn into(self) -> PayloadStatusV1 {
        let latest_valid_hash: Option<CH256> = self.latest_valid_hash.into();
        // let validation_error: Option<*const c_char> = self.validation_error.into();
        PayloadStatusV1 {
            status: self.status.into(),
            latest_valid_hash: latest_valid_hash.map(Into::into),
            validation_error: None,
        }
    }
}

#[repr(C)]
pub struct CForkChoiceStateV1 {
    head_block_hash: CH256,
    safe_block_hash: CH256,
    finalized_block_hash: CH256,
}

impl From<ForkChoiceStateV1> for CForkChoiceStateV1 {
    fn from(value: ForkChoiceStateV1) -> Self {
        Self {
            finalized_block_hash: value.finalized_block_hash.into(),
            head_block_hash: value.head_block_hash.into(),
            safe_block_hash: value.safe_block_hash.into(),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CForkChoiceUpdatedResponse {
    payload_status: CPayloadStatusV1,
    payload_id: COption<CH64>,
}

impl Into<eth1_api::RawForkChoiceUpdatedResponse> for CForkChoiceUpdatedResponse {
    fn into(self) -> eth1_api::RawForkChoiceUpdatedResponse {
        let payload_id: Option<CH64> = self.payload_id.into();

        eth1_api::RawForkChoiceUpdatedResponse {
            payload_id: payload_id.map(|v| v.into()),
            payload_status: self.payload_status.into(),
        }
    }
}

pub type CRequest = CByteVector;

#[derive(Debug)]
#[repr(C)]
pub struct CExecutionRequests(CVec<CRequest>);

impl From<ExecutionRequests<Mainnet>> for CExecutionRequests {
    fn from(value: ExecutionRequests<Mainnet>) -> Self {
        let mut execution_requests: Vec<CVec<u8>> = Vec::new();

        let mut deposits = value.deposits.to_ssz().unwrap();
        deposits.insert(0, 0x00);

        let mut withdrawals = value.withdrawals.to_ssz().unwrap();
        withdrawals.insert(0, 0x01);

        let mut consolidations = value.consolidations.to_ssz().unwrap();
        consolidations.insert(0, 0x02);

        if !value.deposits.is_empty() {
            execution_requests.push(deposits.into());
        }

        if !value.withdrawals.is_empty() {
            execution_requests.push(withdrawals.into());
        }

        if !value.consolidations.is_empty() {
            execution_requests.push(consolidations.into());
        }

        Self(execution_requests.into())
    }
}

impl Into<RawExecutionRequests<Mainnet>> for CExecutionRequests {
    fn into(self) -> RawExecutionRequests<Mainnet> {
        // TODO: don't panic here
        let deposits = self.0.get(0).unwrap();
        let withdrawals = self.0.get(1).unwrap();
        let consolidations = self.0.get(2).unwrap();

        let deposits = ContiguousList::from_ssz_default(deposits.as_bytes()).unwrap();
        let withdrawals = ContiguousList::from_ssz_default(withdrawals.as_bytes()).unwrap();
        let consolidations = ContiguousList::from_ssz_default(consolidations.as_bytes()).unwrap();

        ExecutionRequests::<Mainnet> {
            deposits,
            withdrawals,
            consolidations,
        }
        .into()
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CBlobAndProofV2 {
    proof: CVec<CH384>,
    blob: CByteVector,
}

impl Into<BlobAndProofV2<Mainnet>> for CBlobAndProofV2 {
    fn into(self) -> BlobAndProofV2<Mainnet> {
        // TODO: don't panic here
        BlobAndProofV2 {
            blob: self.blob.into(),
            proofs: ContiguousVector::try_from_iter(self.proof.into_iter().map(Into::into))
                .unwrap(),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CBlobAndProofV1 {
    proof: CH384,
    blob: CByteVector,
}

impl Into<BlobAndProofV1<Mainnet>> for CBlobAndProofV1 {
    fn into(self) -> BlobAndProofV1<Mainnet> {
        todo!()
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CBlobsBundleV1 {
    commitments: CVec<CH384>,
    proofs: CVec<CH384>,
    blobs: CVec<CByteVector>,
}

impl Into<BlobsBundleV1<Mainnet>> for CBlobsBundleV1 {
    fn into(self) -> BlobsBundleV1<Mainnet> {
        BlobsBundleV1 {
            // TODO: don't panic here
            commitments: ContiguousList::try_from_iter(
                self.commitments.into_iter().map(Into::into),
            )
            .unwrap(),
            proofs: ContiguousList::try_from_iter(self.proofs.into_iter().map(Into::into)).unwrap(),
            blobs: ContiguousList::try_from_iter(self.blobs.into_iter().map(Into::into)).unwrap(),
        }
    }
}

impl Into<BlobsBundleV2<Mainnet>> for CBlobsBundleV1 {
    fn into(self) -> BlobsBundleV2<Mainnet> {
        BlobsBundleV2 {
            // TODO: don't panic here
            commitments: ContiguousList::try_from_iter(
                self.commitments.into_iter().map(Into::into),
            )
            .unwrap(),
            proofs: ContiguousList::try_from_iter(self.proofs.into_iter().map(Into::into)).unwrap(),
            blobs: ContiguousList::try_from_iter(
                self.blobs
                    .into_iter()
                    .map(|v| Box::new(ByteVector::from(v.as_bytes()))),
            )
            .unwrap(),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CTransaction(CByteVector);

impl From<Transaction<Mainnet>> for CTransaction {
    fn from(value: Transaction<Mainnet>) -> Self {
        CTransaction(value.as_bytes().into())
    }
}

impl Into<Transaction<Mainnet>> for CTransaction {
    fn into(self) -> Transaction<Mainnet> {
        // TODO: don't panic here
        let vec: Vec<_> = self.0.into();
        Transaction::<Mainnet>::try_from(vec).unwrap()
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CWithdrawalV1 {
    index: u64,
    validator_index: u64,
    address: CH160,
    amount: u64,
}

impl From<WithdrawalV1> for CWithdrawalV1 {
    fn from(value: WithdrawalV1) -> Self {
        Self {
            index: value.index,
            validator_index: value.validator_index,
            address: value.address.into(),
            amount: value.amount,
        }
    }
}

impl Into<WithdrawalV1> for CWithdrawalV1 {
    fn into(self) -> WithdrawalV1 {
        WithdrawalV1 {
            index: self.index,
            validator_index: self.validator_index,
            address: self.address.into(),
            amount: self.amount,
        }
    }
}

impl<N: ArrayLength<u8>> From<ByteVector<N>> for CByteVector {
    fn from(value: ByteVector<N>) -> Self {
        value.as_bytes().to_vec().into()
    }
}

impl<N: ArrayLength<u8>> Into<ByteVector<N>> for CByteVector {
    fn into(self) -> ByteVector<N> {
        ByteVector::from(self.as_bytes())
    }
}

impl Into<Blob<Mainnet>> for CByteVector {
    fn into(self) -> Blob<Mainnet> {
        Box::new(self.into())
    }
}
