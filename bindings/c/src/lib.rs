use allocator as _;
use anyhow::Result;
use clap::{Error as ClapError, Parser};
use eth1_api::Eth1Block;
use execution_engine::{
    BlobsBundleV1, EngineGetPayloadV1Response, EngineGetPayloadV2Response,
    EngineGetPayloadV3Response, EngineGetPayloadV4Response, ExecutionPayloadV1, ExecutionPayloadV2,
    ExecutionPayloadV3, ForkChoiceStateV1, PayloadAttributesV1, PayloadAttributesV2,
    PayloadAttributesV3, PayloadStatusV1, PayloadValidationStatus, RawExecutionRequests,
    WithdrawalV1,
};
use libc::c_char;
use log::error;
use primitive_types::{H384, U256};
use runtime::{run, GrandineArgs};
use ssz::{ByteList, ByteVector, ContiguousList, SszReadDefault, SszWrite};
use std::{ffi::CStr, sync::Arc};
use try_from_iterator::TryFromIterator;
use typenum::marker_traits::Unsigned;
use types::preset::BytesPerBlob;
use types::{
    electra::containers::ExecutionRequests,
    phase0::primitives::{ExecutionBlockNumber, Uint256},
    preset::{Mainnet, Preset},
};
use web3::types::{BlockNumber, H160, H256, H64};
use web3::types::{Filter, Log, U64};

pub fn try_run(argc: u64, argv: *const *const c_char) -> Result<()> {
    let args = unsafe {
        std::iter::once("").chain(
            std::slice::from_raw_parts(argv, argc as usize)
                .into_iter()
                .filter_map(|it| CStr::from_ptr(*it).to_str().ok()),
        )
    };

    let args = GrandineArgs::try_parse_from(args)?;

    let config = args.try_into_config()?;

    run(config)
}

#[derive(Debug)]
#[repr(C)]
struct CResult<T> {
    value: T,
    error: u64,
}

impl<T> Into<Result<T>> for CResult<T> {
    fn into(self) -> Result<T> {
        if self.error == 0 {
            Ok(self.value)
        } else {
            anyhow::bail!("failed with error code {}", self.error)
        }
    }
}

#[derive(Debug)]
#[repr(C)]
struct COption<T> {
    is_something: bool,
    value: T,
}

impl<T: Clone> Clone for COption<T> {
    fn clone(&self) -> Self {
        Self {
            is_something: self.is_something.clone(),
            value: self.value.clone(),
        }
    }
}

impl<T> Into<Option<T>> for COption<T> {
    fn into(self) -> Option<T> {
        if self.is_something {
            Some(self.value)
        } else {
            None
        }
    }
}

impl<T: Default> From<Option<T>> for COption<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => COption {
                is_something: true,
                value,
            },
            None => COption {
                is_something: false,
                value: Default::default(),
            },
        }
    }
}

#[derive(Debug)]
#[repr(C)]
struct CEth1Block {
    hash: [u8; 32],
    parent_hash: [u8; 32],
    number: u64,
    timestamp: u64,
    total_difficulty: [u8; 32],
}

impl Into<Eth1Block> for CEth1Block {
    fn into(self) -> Eth1Block {
        Eth1Block {
            hash: self.hash.into(),
            parent_hash: self.parent_hash.into(),
            number: self.number,
            timestamp: self.timestamp,
            total_difficulty: Uint256::from_be_bytes(self.total_difficulty),
            deposit_events: Default::default(),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CTransaction {
    bytes: *const u8,
    bytes_len: u64,
}

#[repr(C)]
pub struct CExecutionPayloadV1 {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: *const u8,
    logs_bloom_len: u64,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: *const u8,
    extra_data_len: u64,
    base_fee_per_gas: [u8; 32],
    block_hash: [u8; 32],
    transactions: *const CTransaction,
    transactions_len: u64,
}

impl CExecutionPayloadV1 {
    fn convert(value: ExecutionPayloadV1<Mainnet>) -> (Self, Vec<CTransaction>) {
        let mut base_fee_per_gas = [0u8; 32];
        value
            .base_fee_per_gas
            .into_raw()
            .to_big_endian(&mut base_fee_per_gas);

        let transactions = value
            .transactions
            .as_ref()
            .iter()
            .map(|v| CTransaction {
                bytes: v.as_bytes().as_ptr(),
                bytes_len: v.as_bytes().len() as u64,
            })
            .collect::<Vec<_>>();
        let tr = transactions.as_ptr();

        (
            CExecutionPayloadV1 {
                parent_hash: value.parent_hash.0,
                fee_recipient: value.fee_recipient.0,
                state_root: value.state_root.0,
                receipts_root: value.receipts_root.0,
                logs_bloom: value.logs_bloom.as_bytes().as_ptr(),
                logs_bloom_len: value.logs_bloom.as_bytes().len() as u64,
                prev_randao: value.prev_randao.0,
                block_number: value.block_number,
                gas_limit: value.gas_limit,
                gas_used: value.gas_used,
                timestamp: value.timestamp,
                extra_data: value.extra_data.as_bytes().as_ptr(),
                extra_data_len: value.extra_data.as_bytes().len() as u64,
                base_fee_per_gas,
                block_hash: value.block_hash.0,
                transactions: tr,
                transactions_len: transactions.len() as u64,
            },
            transactions,
        )
    }
}

impl Into<EngineGetPayloadV1Response<Mainnet>> for CExecutionPayloadV1 {
    fn into(self) -> EngineGetPayloadV1Response<Mainnet> {
        let logs_bloom =
            unsafe { std::slice::from_raw_parts(self.logs_bloom, self.logs_bloom_len as usize) }
                .to_vec();
        let logs_bloom =
            ByteVector::<<Mainnet as Preset>::BytesPerLogsBloom>::from_ssz_default(&logs_bloom)
                .unwrap();

        let extra_data =
            unsafe { std::slice::from_raw_parts(self.extra_data, self.extra_data_len as usize) };
        let extra_data = Arc::new(
            ByteList::<<Mainnet as Preset>::MaxExtraDataBytes>::from_ssz_default(extra_data)
                .unwrap(),
        );

        let transactions = unsafe {
            std::slice::from_raw_parts(self.transactions, self.transactions_len as usize)
        };

        EngineGetPayloadV1Response::<Mainnet> {
            parent_hash: H256(self.parent_hash),
            fee_recipient: H160(self.fee_recipient),
            state_root: H256(self.state_root),
            receipts_root: H256(self.receipts_root),
            base_fee_per_gas: Uint256::from_be_bytes(self.base_fee_per_gas),
            logs_bloom,
            prev_randao: H256(self.prev_randao),
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data,
            block_hash: H256(self.block_hash),
            transactions: Arc::new(
                ContiguousList::try_from_iter(transactions.iter().map(|v| {
                    ByteList::try_from(
                        unsafe { std::slice::from_raw_parts(v.bytes, v.bytes_len as usize) }
                            .to_vec(),
                    )
                    .unwrap()
                }))
                .unwrap(),
            ),
        }
    }
}

#[repr(C)]
pub struct CWithdrawalV1 {
    index: u64,
    validator_index: u64,
    address: [u8; 20],
    amount: u64,
}

#[repr(C)]
pub struct CExecutionPayloadV2 {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: *const u8,
    logs_bloom_len: u64,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: *const u8,
    extra_data_len: u64,
    base_fee_per_gas: [u8; 32],
    block_hash: [u8; 32],
    transactions: *const CTransaction,
    transactions_len: u64,
    withdrawals: *const CWithdrawalV1,
    withdrawals_len: u64,
}

impl CExecutionPayloadV2 {
    fn convert(
        value: ExecutionPayloadV2<Mainnet>,
    ) -> (Self, Vec<CTransaction>, Vec<CWithdrawalV1>) {
        let mut base_fee_per_gas = [0u8; 32];
        value
            .base_fee_per_gas
            .into_raw()
            .to_big_endian(&mut base_fee_per_gas);

        let transactions = value
            .transactions
            .as_ref()
            .iter()
            .map(|v| CTransaction {
                bytes: v.as_bytes().as_ptr(),
                bytes_len: v.as_bytes().len() as u64,
            })
            .collect::<Vec<_>>();
        let tr = transactions.as_ptr();

        let withdrawals = value
            .withdrawals
            .as_ref()
            .iter()
            .map(|v| CWithdrawalV1 {
                address: v.address.0,
                amount: v.amount,
                index: v.index,
                validator_index: v.validator_index,
            })
            .collect::<Vec<_>>();
        let w = withdrawals.as_ptr();

        (
            CExecutionPayloadV2 {
                parent_hash: value.parent_hash.0,
                fee_recipient: value.fee_recipient.0,
                state_root: value.state_root.0,
                receipts_root: value.receipts_root.0,
                logs_bloom: value.logs_bloom.as_bytes().as_ptr(),
                logs_bloom_len: value.logs_bloom.as_bytes().len() as u64,
                prev_randao: value.prev_randao.0,
                block_number: value.block_number,
                gas_limit: value.gas_limit,
                gas_used: value.gas_used,
                timestamp: value.timestamp,
                extra_data: value.extra_data.as_bytes().as_ptr(),
                extra_data_len: value.extra_data.as_bytes().len() as u64,
                base_fee_per_gas,
                block_hash: value.block_hash.0,
                transactions: tr,
                transactions_len: transactions.len() as u64,
                withdrawals: w,
                withdrawals_len: withdrawals.len() as u64,
            },
            transactions,
            withdrawals,
        )
    }
}

impl Into<ExecutionPayloadV2<Mainnet>> for CExecutionPayloadV2 {
    fn into(self) -> ExecutionPayloadV2<Mainnet> {
        let logs_bloom =
            unsafe { std::slice::from_raw_parts(self.logs_bloom, self.logs_bloom_len as usize) }
                .to_vec();
        let logs_bloom =
            ByteVector::<<Mainnet as Preset>::BytesPerLogsBloom>::from_ssz_default(&logs_bloom)
                .unwrap();

        let extra_data =
            unsafe { std::slice::from_raw_parts(self.extra_data, self.extra_data_len as usize) };
        let extra_data = Arc::new(
            ByteList::<<Mainnet as Preset>::MaxExtraDataBytes>::from_ssz_default(extra_data)
                .unwrap(),
        );

        let transactions = unsafe {
            std::slice::from_raw_parts(self.transactions, self.transactions_len as usize)
        };

        let withdrawals =
            unsafe { std::slice::from_raw_parts(self.withdrawals, self.withdrawals_len as usize) };

        ExecutionPayloadV2::<Mainnet> {
            parent_hash: H256(self.parent_hash),
            fee_recipient: H160(self.fee_recipient),
            state_root: H256(self.state_root),
            receipts_root: H256(self.receipts_root),
            base_fee_per_gas: Uint256::from_be_bytes(self.base_fee_per_gas),
            logs_bloom,
            prev_randao: H256(self.prev_randao),
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data,
            block_hash: H256(self.block_hash),
            transactions: Arc::new(
                ContiguousList::try_from_iter(transactions.iter().map(|v| {
                    ByteList::try_from(
                        unsafe { std::slice::from_raw_parts(v.bytes, v.bytes_len as usize) }
                            .to_vec(),
                    )
                    .unwrap()
                }))
                .unwrap(),
            ),
            withdrawals: ContiguousList::try_from_iter(withdrawals.iter().map(|v| WithdrawalV1 {
                address: H160(v.address),
                amount: v.amount,
                index: v.index,
                validator_index: v.validator_index,
            }))
            .unwrap(),
        }
    }
}

#[repr(C)]
pub struct CExecutionPayloadV3 {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: *const u8,
    logs_bloom_len: u64,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: *const u8,
    extra_data_len: u64,
    base_fee_per_gas: [u8; 32],
    block_hash: [u8; 32],
    transactions: *const CTransaction,
    transactions_len: u64,
    withdrawals: *const CWithdrawalV1,
    withdrawals_len: u64,
    blob_gas_used: u64,
    excess_blob_gas: u64,
}

impl CExecutionPayloadV3 {
    fn convert(
        value: ExecutionPayloadV3<Mainnet>,
    ) -> (Self, Vec<CTransaction>, Vec<CWithdrawalV1>) {
        let mut base_fee_per_gas = [0u8; 32];
        value
            .base_fee_per_gas
            .into_raw()
            .to_big_endian(&mut base_fee_per_gas);

        let transactions = value
            .transactions
            .as_ref()
            .iter()
            .map(|v| CTransaction {
                bytes: v.as_bytes().as_ptr(),
                bytes_len: v.as_bytes().len() as u64,
            })
            .collect::<Vec<_>>();
        let tr = transactions.as_ptr();

        let withdrawals = value
            .withdrawals
            .as_ref()
            .iter()
            .map(|v| CWithdrawalV1 {
                address: v.address.0,
                amount: v.amount,
                index: v.index,
                validator_index: v.validator_index,
            })
            .collect::<Vec<_>>();
        let w = withdrawals.as_ptr();

        (
            CExecutionPayloadV3 {
                parent_hash: value.parent_hash.0,
                fee_recipient: value.fee_recipient.0,
                state_root: value.state_root.0,
                receipts_root: value.receipts_root.0,
                logs_bloom: value.logs_bloom.as_bytes().as_ptr(),
                logs_bloom_len: value.logs_bloom.as_bytes().len() as u64,
                prev_randao: value.prev_randao.0,
                block_number: value.block_number,
                gas_limit: value.gas_limit,
                gas_used: value.gas_used,
                timestamp: value.timestamp,
                extra_data: value.extra_data.as_bytes().as_ptr(),
                extra_data_len: value.extra_data.as_bytes().len() as u64,
                base_fee_per_gas,
                block_hash: value.block_hash.0,
                transactions: tr,
                transactions_len: transactions.len() as u64,
                withdrawals: w,
                withdrawals_len: withdrawals.len() as u64,
                blob_gas_used: value.blob_gas_used,
                excess_blob_gas: value.excess_blob_gas,
            },
            transactions,
            withdrawals,
        )
    }
}

impl Into<ExecutionPayloadV3<Mainnet>> for CExecutionPayloadV3 {
    fn into(self) -> ExecutionPayloadV3<Mainnet> {
        let logs_bloom =
            unsafe { std::slice::from_raw_parts(self.logs_bloom, self.logs_bloom_len as usize) }
                .to_vec();
        let logs_bloom =
            ByteVector::<<Mainnet as Preset>::BytesPerLogsBloom>::from_ssz_default(&logs_bloom)
                .unwrap();

        let extra_data =
            unsafe { std::slice::from_raw_parts(self.extra_data, self.extra_data_len as usize) };
        let extra_data = Arc::new(
            ByteList::<<Mainnet as Preset>::MaxExtraDataBytes>::from_ssz_default(extra_data)
                .unwrap(),
        );

        let transactions = unsafe {
            std::slice::from_raw_parts(self.transactions, self.transactions_len as usize)
        };

        let withdrawals =
            unsafe { std::slice::from_raw_parts(self.withdrawals, self.withdrawals_len as usize) };

        ExecutionPayloadV3::<Mainnet> {
            parent_hash: H256(self.parent_hash),
            fee_recipient: H160(self.fee_recipient),
            state_root: H256(self.state_root),
            receipts_root: H256(self.receipts_root),
            base_fee_per_gas: Uint256::from_be_bytes(self.base_fee_per_gas),
            logs_bloom,
            prev_randao: H256(self.prev_randao),
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data,
            block_hash: H256(self.block_hash),
            transactions: Arc::new(
                ContiguousList::try_from_iter(transactions.iter().map(|v| {
                    ByteList::try_from(
                        unsafe { std::slice::from_raw_parts(v.bytes, v.bytes_len as usize) }
                            .to_vec(),
                    )
                    .unwrap()
                }))
                .unwrap(),
            ),
            withdrawals: ContiguousList::try_from_iter(withdrawals.iter().map(|v| WithdrawalV1 {
                address: H160(v.address),
                amount: v.amount,
                index: v.index,
                validator_index: v.validator_index,
            }))
            .unwrap(),
            blob_gas_used: self.blob_gas_used,
            excess_blob_gas: self.excess_blob_gas,
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

#[derive(Clone, Debug)]
#[repr(C)]
pub struct CH256(pub [u8; 32]);

impl Into<H256> for CH256 {
    fn into(self) -> H256 {
        H256(self.0)
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
    head_block_hash: [u8; 32],
    safe_block_hash: [u8; 32],
    finalized_block_hash: [u8; 32],
}

impl From<ForkChoiceStateV1> for CForkChoiceStateV1 {
    fn from(value: ForkChoiceStateV1) -> Self {
        Self {
            finalized_block_hash: value.finalized_block_hash.0,
            head_block_hash: value.head_block_hash.0,
            safe_block_hash: value.safe_block_hash.0,
        }
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct CPayloadAttributesV1 {
    timestamp: u64,
    prev_randao: [u8; 32],
    suggested_fee_recipient: [u8; 20],
}

impl From<PayloadAttributesV1> for CPayloadAttributesV1 {
    fn from(value: PayloadAttributesV1) -> Self {
        Self {
            prev_randao: value.prev_randao.0,
            suggested_fee_recipient: value.suggested_fee_recipient.0,
            timestamp: value.timestamp,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CPayloadAttributesV2 {
    timestamp: u64,
    prev_randao: [u8; 32],
    suggested_fee_recipient: [u8; 20],
    withdrawals: *const CWithdrawalV1,
    withdrawals_len: u64,
}

impl Default for CPayloadAttributesV2 {
    fn default() -> Self {
        Self {
            timestamp: Default::default(),
            prev_randao: Default::default(),
            suggested_fee_recipient: Default::default(),
            withdrawals: std::ptr::null(),
            withdrawals_len: Default::default(),
        }
    }
}

impl CPayloadAttributesV2 {
    fn convert(value: PayloadAttributesV2<Mainnet>) -> (Self, Vec<CWithdrawalV1>) {
        let withdrawals = value
            .withdrawals
            .iter()
            .map(|v| CWithdrawalV1 {
                address: v.address.0,
                amount: v.amount,
                index: v.index,
                validator_index: v.validator_index,
            })
            .collect::<Vec<_>>();

        (
            Self {
                timestamp: value.timestamp,
                prev_randao: value.prev_randao.0,
                suggested_fee_recipient: value.suggested_fee_recipient.0,
                withdrawals: withdrawals.as_ptr(),
                withdrawals_len: withdrawals.len() as u64,
            },
            withdrawals,
        )
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CPayloadAttributesV3 {
    timestamp: u64,
    prev_randao: [u8; 32],
    suggested_fee_recipient: [u8; 20],
    withdrawals: *const CWithdrawalV1,
    withdrawals_len: u64,
    parent_beacon_block_root: [u8; 32],
}

impl Default for CPayloadAttributesV3 {
    fn default() -> Self {
        Self {
            timestamp: Default::default(),
            prev_randao: Default::default(),
            suggested_fee_recipient: Default::default(),
            withdrawals: std::ptr::null(),
            withdrawals_len: Default::default(),
            parent_beacon_block_root: Default::default(),
        }
    }
}

impl CPayloadAttributesV3 {
    fn convert(value: PayloadAttributesV3<Mainnet>) -> (Self, Vec<CWithdrawalV1>) {
        let withdrawals = value
            .withdrawals
            .iter()
            .map(|v| CWithdrawalV1 {
                address: v.address.0,
                amount: v.amount,
                index: v.index,
                validator_index: v.validator_index,
            })
            .collect::<Vec<_>>();

        (
            Self {
                timestamp: value.timestamp,
                prev_randao: value.prev_randao.0,
                suggested_fee_recipient: value.suggested_fee_recipient.0,
                withdrawals: withdrawals.as_ptr(),
                withdrawals_len: withdrawals.len() as u64,
                parent_beacon_block_root: value.parent_beacon_block_root.0,
            },
            withdrawals,
        )
    }
}

#[repr(C)]
pub struct CH64([u8; 8]);

impl Into<H64> for CH64 {
    fn into(self) -> H64 {
        H64(self.0)
    }
}

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

#[repr(C)]
pub struct CRequest {
    bytes: *const u8,
    bytes_len: u64,
}

#[repr(C)]
pub struct CExecutionRequests {
    requests: *const CRequest,
    requests_len: u64,
}

impl CExecutionRequests {
    fn from(value: ExecutionRequests<Mainnet>) -> (Self, Vec<u8>, Vec<u8>, Vec<u8>, Vec<CRequest>) {
        let deposits = value.deposits.to_ssz().unwrap();
        let withdrawals = value.withdrawals.to_ssz().unwrap();
        let consolidations = value.consolidations.to_ssz().unwrap();
        let execution_requests = vec![
            CRequest {
                bytes: deposits.as_ptr(),
                bytes_len: deposits.len() as u64,
            },
            CRequest {
                bytes: withdrawals.as_ptr(),
                bytes_len: withdrawals.len() as u64,
            },
            CRequest {
                bytes: consolidations.as_ptr(),
                bytes_len: consolidations.len() as u64,
            },
        ];

        (
            Self {
                requests: execution_requests.as_ptr(),
                requests_len: execution_requests.len() as u64,
            },
            deposits,
            withdrawals,
            consolidations,
            execution_requests,
        )
    }
}

impl Into<RawExecutionRequests<Mainnet>> for CExecutionRequests {
    fn into(self) -> RawExecutionRequests<Mainnet> {
        let requests =
            unsafe { std::slice::from_raw_parts(self.requests, self.requests_len as usize) };

        let deposits = unsafe {
            std::slice::from_raw_parts(requests[0].bytes, requests[0].bytes_len as usize)
        };
        let withdrawals = unsafe {
            std::slice::from_raw_parts(requests[1].bytes, requests[1].bytes_len as usize)
        };
        let consolidations = unsafe {
            std::slice::from_raw_parts(requests[2].bytes, requests[2].bytes_len as usize)
        };

        ExecutionRequests::<Mainnet> {
            deposits: ContiguousList::from_ssz_default(deposits).unwrap(),
            withdrawals: ContiguousList::from_ssz_default(withdrawals).unwrap(),
            consolidations: ContiguousList::from_ssz_default(consolidations).unwrap(),
        }
        .into()
    }
}

#[repr(C)]
pub struct CEngineGetPayloadV2Response {
    execution_payload: CExecutionPayloadV2,
    block_value: [u8; 32],
}

impl Into<EngineGetPayloadV2Response<Mainnet>> for CEngineGetPayloadV2Response {
    fn into(self) -> EngineGetPayloadV2Response<Mainnet> {
        EngineGetPayloadV2Response::<Mainnet> {
            block_value: Uint256::from_be_bytes(self.block_value),
            execution_payload: self.execution_payload.into(),
        }
    }
}

#[repr(C)]
pub struct CBlobsBundleV1 {
    commitments: *const [u8; 48],
    commitments_len: u64,
    proofs: *const [u8; 48],
    proofs_len: u64,
    blobs: *const *const u8,
    blobs_len: u64,
}

impl Into<BlobsBundleV1<Mainnet>> for CBlobsBundleV1 {
    fn into(self) -> BlobsBundleV1<Mainnet> {
        BlobsBundleV1::<Mainnet> {
            commitments: ContiguousList::try_from_iter(
                unsafe {
                    std::slice::from_raw_parts(self.commitments, self.commitments_len as usize)
                }
                .iter()
                .map(|&v| H384(v)),
            )
            .unwrap(),
            proofs: ContiguousList::try_from_iter(
                unsafe { std::slice::from_raw_parts(self.proofs, self.proofs_len as usize) }
                    .iter()
                    .map(|&v| H384(v)),
            )
            .unwrap(),
            blobs: ContiguousList::try_from_iter(
                unsafe { std::slice::from_raw_parts(self.blobs, self.blobs_len as usize) }
                    .iter()
                    .map(|&blob| {
                        let blob = unsafe {
                            std::slice::from_raw_parts(blob, BytesPerBlob::<Mainnet>::to_usize())
                        };

                        Box::new(ByteVector::from_ssz_default(blob).unwrap())
                    }),
            )
            .unwrap(),
        }
    }
}

#[repr(C)]
pub struct CEngineGetPayloadV3Response {
    execution_payload: CExecutionPayloadV3,
    block_value: [u8; 32],
    blobs_bundle: CBlobsBundleV1,
    should_override_builder: bool,
}

impl Into<EngineGetPayloadV3Response<Mainnet>> for CEngineGetPayloadV3Response {
    fn into(self) -> EngineGetPayloadV3Response<Mainnet> {
        EngineGetPayloadV3Response::<Mainnet> {
            execution_payload: self.execution_payload.into(),
            blobs_bundle: self.blobs_bundle.into(),
            block_value: Uint256::from_be_bytes(self.block_value),
            should_override_builder: self.should_override_builder,
        }
    }
}

#[repr(C)]
pub struct CEngineGetPayloadV4Response {
    execution_payload: CExecutionPayloadV3,
    block_value: [u8; 32],
    blobs_bundle: CBlobsBundleV1,
    should_override_builder: bool,
    execution_requests: CExecutionRequests,
}

impl Into<EngineGetPayloadV4Response<Mainnet>> for CEngineGetPayloadV4Response {
    fn into(self) -> EngineGetPayloadV4Response<Mainnet> {
        EngineGetPayloadV4Response::<Mainnet> {
            execution_payload: self.execution_payload.into(),
            blobs_bundle: self.blobs_bundle.into(),
            block_value: Uint256::from_be_bytes(self.block_value),
            should_override_builder: self.should_override_builder,
            execution_requests: self.execution_requests.into(),
        }
    }
}

#[repr(C)]
pub enum CBlockNumber {
    /// Finalized block
    Finalized,
    /// Safe block
    Safe,
    /// Latest block
    Latest,
    /// Earliest block (genesis)
    Earliest,
    /// Pending block (not yet part of the blockchain)
    Pending,
    /// Block by number from canon chain
    Number(u64),
}

#[repr(C)]
struct CH160([u8; 20]);

#[repr(C)]
pub struct CFilter {
    from_block: COption<u64>,
    to_block: COption<u64>,
    address: COption<CVec<CH160>>,
    topics: COption<CVec<COption<CVec<CH256>>>>,
    limit: COption<u64>,
}

fn block_number_into_u64(b: BlockNumber) -> u64 {
    match b {
        BlockNumber::Safe => u64::MAX - 3,
        BlockNumber::Finalized => u64::MAX - 2,
        BlockNumber::Latest => u64::MAX - 1,
        BlockNumber::Pending => u64::MAX,
        BlockNumber::Earliest => 0,
        BlockNumber::Number(number) => number.as_u64(),
    }
}

impl CFilter {
    fn from(
        value: Filter,
    ) -> (
        Self,
        Option<Vec<CH160>>,
        Vec<Vec<CH256>>,
        Option<Vec<COption<CVec<CH256>>>>,
    ) {
        let address = value.address.map(|v| {
            let v: Vec<H160> = v.into();
            let v = v.into_iter().map(|c| CH160(c.0)).collect::<Vec<_>>();
            let cv: CVec<CH160> = (&v).into();

            (cv, v)
        });

        let (address, vec) = if let Some((a, v)) = address {
            (Some(a), Some(v))
        } else {
            (None, None)
        };

        let mut allocated_topics = Vec::new();

        let topics = value.topics.map(|v| {
            let vec = v
                .into_iter()
                .map(|v| {
                    if let Some(v) = v {
                        let v: Vec<H256> = v.into();
                        let v = v.iter().map(|v| CH256(v.0)).collect::<Vec<_>>();
                        allocated_topics.push(v);

                        COption {
                            is_something: true,
                            value: allocated_topics.last().unwrap().into(),
                        }
                    } else {
                        COption {
                            is_something: false,
                            value: Default::default(),
                        }
                    }
                })
                .collect::<Vec<COption<CVec<_>>>>();
            let cvec: CVec<_> = (&vec).into();

            (cvec, vec)
        });

        let (topics, vec2) = if let Some((t, v)) = topics {
            (Some(t), Some(v))
        } else {
            (None, None)
        };

        (
            CFilter {
                from_block: value.from_block.map(block_number_into_u64).into(),
                to_block: value.to_block.map(block_number_into_u64).into(),
                address: address.into(),
                topics: topics.into(),
                limit: value.limit.map(|v| v as u64).into(),
            },
            vec,
            allocated_topics,
            vec2,
        )
    }
}

#[repr(C)]
struct CVec<T> {
    data: *const T,
    data_len: u64,
}

impl<T: Clone> CVec<T> {
    fn convert(&self) -> Vec<T> {
        unsafe { std::slice::from_raw_parts(self.data, self.data_len as usize) }.to_vec()
    }
}

impl<T> CVec<T> {
    fn map_convert<V>(&self, mapper: impl FnMut(&T) -> V) -> Vec<V> {
        unsafe { std::slice::from_raw_parts(self.data, self.data_len as usize) }
            .iter()
            .map(mapper)
            .collect::<Vec<_>>()
    }
}

impl<T> Default for CVec<T> {
    fn default() -> Self {
        Self {
            data: std::ptr::null(),
            data_len: 0,
        }
    }
}

impl<T> Into<CVec<T>> for &Vec<T> {
    fn into(self) -> CVec<T> {
        CVec {
            data: self.as_ptr(),
            data_len: self.len() as u64,
        }
    }
}

#[repr(C)]
struct CLog {
    address: [u8; 20],
    topics: CVec<CH256>,
    data: CVec<u8>,
    block_hash: COption<CH256>,
    block_number: COption<u64>,
    transaction_hash: COption<CH256>,
    transaction_index: COption<u64>,
    log_index: COption<CH256>,
    transaction_log_index: COption<CH256>,
    log_type: COption<*const c_char>,
    removed: COption<bool>,
}

#[repr(C)]
struct CLogs {
    logs: *const CLog,
    logs_len: u64,
}

impl Into<Vec<Log>> for CLogs {
    fn into(self) -> Vec<Log> {
        let raw_slice = unsafe { std::slice::from_raw_parts(self.logs, self.logs_len as usize) };

        raw_slice
            .iter()
            .map(|log| {
                let block_hash: Option<CH256> = log.block_hash.clone().into();
                let block_number: Option<u64> = log.block_number.clone().into();
                let transaction_hash: Option<CH256> = log.transaction_hash.clone().into();
                let trnasaction_index: Option<u64> = log.transaction_index.clone().into();
                let log_index: Option<CH256> = log.log_index.clone().into();
                let transaction_log_index: Option<CH256> = log.transaction_log_index.clone().into();
                let log_type: Option<*const c_char> = log.log_type.clone().into();

                Log {
                    address: H160(log.address),
                    topics: log.topics.map_convert(|topic| H256(topic.0)),
                    data: web3::types::Bytes::from(log.data.convert()),
                    block_hash: block_hash.map(|h| H256(h.0)),
                    block_number: block_number.map(U64::from),
                    transaction_hash: transaction_hash.map(|h| H256(h.0)),
                    transaction_index: trnasaction_index.map(U64::from),
                    log_index: log_index.map(|h| U256::from_big_endian(&h.0)),
                    transaction_log_index: transaction_log_index
                        .map(|h| U256::from_big_endian(&h.0)),
                    log_type: log_type
                        .map(|str| unsafe { CStr::from_ptr(str) }.to_str().unwrap().to_string()),
                    removed: log.removed.clone().into(),
                }
            })
            .collect::<Vec<_>>()
    }
}

#[repr(C)]
pub struct CEmbedAdapter {
    eth_block_number: unsafe extern "C" fn() -> CResult<u64>,
    eth_get_block_by_hash: unsafe extern "C" fn(hash: [u8; 32]) -> CResult<COption<CEth1Block>>,
    eth_get_block_by_number: unsafe extern "C" fn(number: u64) -> CResult<COption<CEth1Block>>,
    eth_get_block_finalized: unsafe extern "C" fn() -> CResult<COption<CEth1Block>>,
    eth_get_block_safe: unsafe extern "C" fn() -> CResult<COption<CEth1Block>>,
    eth_get_block_latest: unsafe extern "C" fn() -> CResult<COption<CEth1Block>>,
    eth_get_block_earliest: unsafe extern "C" fn() -> CResult<COption<CEth1Block>>,
    eth_get_block_pending: unsafe extern "C" fn() -> CResult<COption<CEth1Block>>,
    eth_logs: unsafe extern "C" fn(filter: CFilter) -> CResult<CLogs>,
    engine_new_payload_v1:
        unsafe extern "C" fn(payload: CExecutionPayloadV1) -> CResult<CPayloadStatusV1>,
    engine_new_payload_v2:
        unsafe extern "C" fn(payload: CExecutionPayloadV2) -> CResult<CPayloadStatusV1>,
    engine_new_payload_v3: unsafe extern "C" fn(
        payload: CExecutionPayloadV3,
        versioned_hashes: *const *const u8,
        versioned_hashes_len: u64,
        parent_beacon_block_root: *const u8,
    ) -> CResult<CPayloadStatusV1>,
    engine_new_payload_v4: unsafe extern "C" fn(
        payload: CExecutionPayloadV3,
        versioned_hashes: *const *const u8,
        versioned_hashes_len: u64,
        parent_beacon_block_root: *const u8,
        execution_requests: CExecutionRequests,
    ) -> CResult<CPayloadStatusV1>,
    engine_forkchoice_updated_v1: unsafe extern "C" fn(
        state: CForkChoiceStateV1,
        payload: COption<CPayloadAttributesV1>,
    ) -> CResult<CForkChoiceUpdatedResponse>,
    engine_forkchoice_updated_v2: unsafe extern "C" fn(
        state: CForkChoiceStateV1,
        payload: COption<CPayloadAttributesV2>,
    ) -> CResult<CForkChoiceUpdatedResponse>,
    engine_forkchoice_updated_v3: unsafe extern "C" fn(
        state: CForkChoiceStateV1,
        payload: COption<CPayloadAttributesV3>,
    ) -> CResult<CForkChoiceUpdatedResponse>,
    engine_get_payload_v1:
        unsafe extern "C" fn(payload_id: *const u8) -> CResult<CExecutionPayloadV1>,
    engine_get_payload_v2:
        unsafe extern "C" fn(payload_id: *const u8) -> CResult<CEngineGetPayloadV2Response>,
    engine_get_payload_v3:
        unsafe extern "C" fn(payload_id: *const u8) -> CResult<CEngineGetPayloadV3Response>,
    engine_get_payload_v4:
        unsafe extern "C" fn(payload_id: *const u8) -> CResult<CEngineGetPayloadV4Response>,
}

impl eth1_api::EmbedAdapter for CEmbedAdapter {
    fn eth_block_number(&self) -> Result<ExecutionBlockNumber> {
        unsafe { (self.eth_block_number)() }.into()
    }

    fn eth_get_block_by_hash(&self, hash: H256) -> Result<Option<eth1_api::Eth1Block>> {
        <CResult<COption<CEth1Block>> as Into<Result<_>>>::into(unsafe {
            (self.eth_get_block_by_hash)(hash.0)
        })
        .map(|v| <COption<CEth1Block> as Into<Option<_>>>::into(v).map(|v: CEth1Block| v.into()))
    }

    fn eth_get_block_by_number(&self, number: BlockNumber) -> Result<Option<eth1_api::Eth1Block>> {
        let output = unsafe {
            match number {
                BlockNumber::Finalized => (self.eth_get_block_finalized)(),
                BlockNumber::Safe => (self.eth_get_block_safe)(),
                BlockNumber::Latest => (self.eth_get_block_latest)(),
                BlockNumber::Earliest => (self.eth_get_block_earliest)(),
                BlockNumber::Pending => (self.eth_get_block_pending)(),
                BlockNumber::Number(number) => (self.eth_get_block_by_number)(number.as_u64()),
            }
        };

        <CResult<COption<CEth1Block>> as Into<Result<_>>>::into(output).map(|v| {
            <COption<CEth1Block> as Into<Option<_>>>::into(v).map(|v: CEth1Block| v.into())
        })
    }

    fn eth_logs(&self, filter: web3::types::Filter) -> Result<Vec<web3::types::Log>> {
        let (filter, vec1, vec2, vec3) = CFilter::from(filter);

        let output = unsafe { (self.eth_logs)(filter) };

        drop(vec1);
        drop(vec2);
        drop(vec3);

        let output: Result<_> = output.into();

        output.map(|v| v.into())
    }

    fn engine_new_payload_v1(
        &self,
        payload: ExecutionPayloadV1<types::preset::Mainnet>,
    ) -> Result<PayloadStatusV1> {
        let (p, vec) = CExecutionPayloadV1::convert(payload);

        let result = unsafe { (self.engine_new_payload_v1)(p) };

        drop(vec);

        let result: Result<_> = result.into();

        result.map(|v| v.into())
    }

    fn engine_new_payload_v2(
        &self,
        payload: ExecutionPayloadV2<types::preset::Mainnet>,
    ) -> Result<PayloadStatusV1> {
        let (p, vec1, vec2) = CExecutionPayloadV2::convert(payload);

        let result = unsafe { (self.engine_new_payload_v2)(p) };

        drop(vec1);
        drop(vec2);

        let result: Result<_> = result.into();

        result.map(|v| v.into())
    }

    fn engine_new_payload_v3(
        &self,
        payload: ExecutionPayloadV3<types::preset::Mainnet>,
        versioned_hashes: Vec<web3::types::H256>,
        parent_beacon_block_root: web3::types::H256,
    ) -> Result<PayloadStatusV1> {
        let (p, vec1, vec2) = CExecutionPayloadV3::convert(payload);

        let versioned_hashes = versioned_hashes
            .iter()
            .map(|hash| hash.0.as_ptr())
            .collect::<Vec<_>>();

        let result = unsafe {
            (self.engine_new_payload_v3)(
                p,
                versioned_hashes.as_ptr(),
                versioned_hashes.len() as u64,
                parent_beacon_block_root.0.as_ptr(),
            )
        };

        drop(vec1);
        drop(vec2);
        drop(versioned_hashes);

        let result: Result<_> = result.into();

        result.map(|v| v.into())
    }

    fn engine_new_payload_v4(
        &self,
        payload: ExecutionPayloadV3<types::preset::Mainnet>,
        versioned_hashes: Vec<web3::types::H256>,
        parent_beacon_block_root: web3::types::H256,
        execution_requests: ExecutionRequests<types::preset::Mainnet>,
    ) -> Result<PayloadStatusV1> {
        let (p, vec1, vec2) = CExecutionPayloadV3::convert(payload);

        let versioned_hashes = versioned_hashes
            .iter()
            .map(|hash| hash.0.as_ptr())
            .collect::<Vec<_>>();

        let (execution_requests, vec3, vec4, vec5, vec6) =
            CExecutionRequests::from(execution_requests);

        let result = unsafe {
            (self.engine_new_payload_v4)(
                p,
                versioned_hashes.as_ptr(),
                versioned_hashes.len() as u64,
                parent_beacon_block_root.0.as_ptr(),
                execution_requests,
            )
        };

        drop(vec1);
        drop(vec2);
        drop(vec3);
        drop(vec4);
        drop(vec5);
        drop(vec6);
        drop(versioned_hashes);

        let result: Result<_> = result.into();

        result.map(|v| v.into())
    }

    fn engine_forkchoice_updated_v1(
        &self,
        state: ForkChoiceStateV1,
        payload: Option<PayloadAttributesV1>,
    ) -> Result<eth1_api::RawForkChoiceUpdatedResponse> {
        let state = state.into();
        let payload: Option<CPayloadAttributesV1> = payload.map(|v| v.into());
        let payload = payload.into();
        let result = unsafe { (self.engine_forkchoice_updated_v1)(state, payload) };

        let result: Result<_> = result.into();

        result.map(|v| v.into())
    }

    fn engine_forkchoice_updated_v2(
        &self,
        state: ForkChoiceStateV1,
        payload: Option<PayloadAttributesV2<types::preset::Mainnet>>,
    ) -> Result<eth1_api::RawForkChoiceUpdatedResponse> {
        let state: CForkChoiceStateV1 = state.into();
        let payload = payload.map(CPayloadAttributesV2::convert);
        let (payload, vec) = match payload {
            Some((value, vec)) => (
                COption {
                    is_something: true,
                    value,
                },
                Some(vec),
            ),
            None => (
                COption {
                    is_something: false,
                    value: Default::default(),
                },
                None,
            ),
        };
        let result = unsafe { (self.engine_forkchoice_updated_v2)(state, payload) };

        drop(vec);

        let result: Result<_> = result.into();

        result.map(|v| v.into())
    }

    fn engine_forkchoice_updated_v3(
        &self,
        state: ForkChoiceStateV1,
        payload: Option<PayloadAttributesV3<types::preset::Mainnet>>,
    ) -> Result<eth1_api::RawForkChoiceUpdatedResponse> {
        let state: CForkChoiceStateV1 = state.into();
        let payload = payload.map(CPayloadAttributesV3::convert);
        let (payload, vec) = match payload {
            Some((value, vec)) => (
                COption {
                    is_something: true,
                    value,
                },
                Some(vec),
            ),
            None => (
                COption {
                    is_something: false,
                    value: Default::default(),
                },
                None,
            ),
        };
        let result = unsafe { (self.engine_forkchoice_updated_v3)(state, payload) };

        drop(vec);

        let result: Result<_> = result.into();

        result.map(|v| v.into())
    }

    fn engine_get_payload_v1(
        &self,
        payload_id: web3::types::H64,
    ) -> Result<EngineGetPayloadV1Response<types::preset::Mainnet>> {
        let output = unsafe { (self.engine_get_payload_v1)(payload_id.as_ptr()) };
        let output: Result<_> = output.into();
        output.map(|v| v.into())
    }

    fn engine_get_payload_v2(
        &self,
        payload_id: web3::types::H64,
    ) -> Result<EngineGetPayloadV2Response<types::preset::Mainnet>> {
        let output = unsafe { (self.engine_get_payload_v2)(payload_id.as_ptr()) };
        let output: Result<_> = output.into();
        output.map(|v| v.into())
    }

    fn engine_get_payload_v3(
        &self,
        payload_id: web3::types::H64,
    ) -> Result<EngineGetPayloadV3Response<types::preset::Mainnet>> {
        let output = unsafe { (self.engine_get_payload_v3)(payload_id.as_ptr()) };
        let output: Result<_> = output.into();
        output.map(|v| v.into())
    }

    fn engine_get_payload_v4(
        &self,
        payload_id: web3::types::H64,
    ) -> Result<EngineGetPayloadV4Response<types::preset::Mainnet>> {
        let output = unsafe { (self.engine_get_payload_v4)(payload_id.as_ptr()) };
        let output: Result<_> = output.into();
        output.map(|v| v.into())
    }
}

#[no_mangle]
pub extern "C" fn grandine_set_execution_layer_adapter(adapter: CEmbedAdapter) {
    eth1_api::set_adapter(Box::new(adapter)).unwrap();
}

#[no_mangle]
pub extern "C" fn grandine_run(argc: u64, argv: *const *const c_char) -> u64 {
    if let Err(error) = try_run(argc, argv) {
        error.downcast_ref().map(ClapError::exit);
        error!("{error:?}");

        return 1;
    }

    return 0;
}
