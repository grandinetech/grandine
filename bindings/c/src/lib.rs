use allocator as _;
use anyhow::{bail, Result};
use clap::{Error as ClapError, Parser};
use eth1_api::{EmbedAdapter, Eth1Block};
use execution_engine::{
    BlobAndProofV1, BlobAndProofV2, BlobsBundleV1, BlobsBundleV2, EngineGetPayloadV1Response,
    EngineGetPayloadV2Response, EngineGetPayloadV3Response, EngineGetPayloadV4Response,
    EngineGetPayloadV5Response, ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3,
    ForkChoiceStateV1, PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3,
    PayloadStatusV1, PayloadValidationStatus, RawExecutionRequests, WithdrawalV1,
};
use libc::c_char;
use log::error;
use primitive_types::{H384, U256};
use runtime::{grandine_args::GrandineArgs, run};
use ssz::{ByteList, ByteVector, ContiguousList, ContiguousVector, SszReadDefault, SszWrite};
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

macro_rules! impl_c_vec {
    ($type_name:ident, $inner:ty) => {
        impl $type_name {
            fn convert(&self) -> Vec<$inner> {
                unsafe { std::slice::from_raw_parts(self.data, self.data_len as usize) }.to_vec()
            }

            fn map_convert<V>(&self, mapper: impl FnMut(&$inner) -> V) -> Vec<V> {
                unsafe { std::slice::from_raw_parts(self.data, self.data_len as usize) }
                    .iter()
                    .map(mapper)
                    .collect::<Vec<_>>()
            }
        }

        impl Default for $type_name {
            fn default() -> Self {
                Self {
                    data: std::ptr::null(),
                    data_len: 0,
                }
            }
        }

        impl Into<$type_name> for &Vec<$inner> {
            fn into(self) -> $type_name {
                $type_name {
                    data: self.as_ptr(),
                    data_len: self.len() as u64,
                }
            }
        }
    };
}

macro_rules! impl_c_result {
    ($type_name:ident, $inner: ty) => {
        impl Into<Result<$inner>> for $type_name {
            fn into(self) -> Result<$inner> {
                if self.error == 0 {
                    Ok(self.value)
                } else {
                    anyhow::bail!("failed with error code {}", self.error)
                }
            }
        }
    };
}
#[derive(Debug, Clone)]
#[repr(C)]
struct CResultU64 {
    value: u64,
    error: u64,
}

impl_c_result!(CResultU64, u64);

#[derive(Debug)]
#[repr(C)]
struct CResultCOptionCEth1Block {
    value: COptionCEth1Block,
    error: u64,
}
impl_c_result!(CResultCOptionCEth1Block, COptionCEth1Block);

#[derive(Debug)]
#[repr(C)]
struct CResultCPayloadStatusV1 {
    value: CPayloadStatusV1,
    error: u64,
}
impl_c_result!(CResultCPayloadStatusV1, CPayloadStatusV1);

#[derive(Debug)]
#[repr(C)]
struct CResultCForkChoiceUpdatedResponse {
    value: CForkChoiceUpdatedResponse,
    error: u64,
}
impl_c_result!(
    CResultCForkChoiceUpdatedResponse,
    CForkChoiceUpdatedResponse
);

#[derive(Debug)]
#[repr(C)]
struct CResultCExecutionPayloadV1 {
    value: CExecutionPayloadV1,
    error: u64,
}
impl_c_result!(CResultCExecutionPayloadV1, CExecutionPayloadV1);

#[derive(Debug)]
#[repr(C)]
struct CResultCEngineGetPayloadV2Response {
    value: CEngineGetPayloadV2Response,
    error: u64,
}
impl_c_result!(
    CResultCEngineGetPayloadV2Response,
    CEngineGetPayloadV2Response
);

#[derive(Debug)]
#[repr(C)]
struct CResultCEngineGetPayloadV3Response {
    value: CEngineGetPayloadV3Response,
    error: u64,
}
impl_c_result!(
    CResultCEngineGetPayloadV3Response,
    CEngineGetPayloadV3Response
);

#[derive(Debug)]
#[repr(C)]
struct CResultCEngineGetPayloadV4Response {
    value: CEngineGetPayloadV4Response,
    error: u64,
}
impl_c_result!(
    CResultCEngineGetPayloadV4Response,
    CEngineGetPayloadV4Response
);

#[derive(Debug, Default)]
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

#[derive(Debug)]
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

#[derive(Debug)]
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

#[derive(Debug)]
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
pub struct CH384(pub [u8; 48]);

impl Into<H384> for CH384 {
    fn into(self) -> H384 {
        H384(self.0)
    }
}

impl Default for CH384 {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct CH256(pub [u8; 32]);

impl Into<H256> for CH256 {
    fn into(self) -> H256 {
        H256(self.0)
    }
}

macro_rules! impl_c_option {
    ($type_name:ident, $inner:ty) => {
        impl Into<Option<$inner>> for $type_name {
            fn into(self) -> Option<$inner> {
                if self.is_something {
                    Some(self.value)
                } else {
                    None
                }
            }
        }

        impl From<Option<$inner>> for $type_name {
            fn from(value: Option<$inner>) -> Self {
                match value {
                    Some(value) => $type_name {
                        is_something: true,
                        value,
                    },
                    None => $type_name {
                        is_something: false,
                        value: Default::default(),
                    },
                }
            }
        }
    };
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct COptionCH256 {
    is_something: bool,
    value: CH256,
}

impl_c_option!(COptionCH256, CH256);

#[derive(Clone, Debug)]
#[repr(C)]
pub struct COptionCH64 {
    is_something: bool,
    value: CH64,
}

impl_c_option!(COptionCH64, CH64);

#[derive(Clone, Debug)]
#[repr(C)]
pub struct COptionU64 {
    is_something: bool,
    value: u64,
}

impl_c_option!(COptionU64, u64);

#[derive(Debug)]
#[repr(C)]
pub struct COptionCVecCH160 {
    is_something: bool,
    value: CVecCH160,
}

impl_c_option!(COptionCVecCH160, CVecCH160);

#[derive(Clone, Debug)]
#[repr(C)]
pub struct COptionCVecCH256 {
    is_something: bool,
    value: CVecCH256,
}
impl_c_option!(COptionCVecCH256, CVecCH256);

#[derive(Clone, Debug)]
#[repr(C)]
pub struct COptionCVecCOptionCVecCH256 {
    is_something: bool,
    value: CVecCOptionCVecCH256,
}
impl_c_option!(COptionCVecCOptionCVecCH256, CVecCOptionCVecCH256);

#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct COptionCStr {
    is_something: bool,
    value: CCharPtr,
}

#[derive(Clone, Debug)]
struct CCharPtr(*const c_char);

impl Default for CCharPtr {
    fn default() -> Self {
        Self(std::ptr::null())
    }
}

impl_c_option!(COptionCStr, CCharPtr);

#[derive(Clone, Debug)]
#[repr(C)]
pub struct COptionBool {
    is_something: bool,
    value: bool,
}
impl_c_option!(COptionBool, bool);

#[derive(Debug)]
#[repr(C)]
pub struct COptionCEth1Block {
    is_something: bool,
    value: CEth1Block,
}
impl_c_option!(COptionCEth1Block, CEth1Block);

#[derive(Debug)]
#[repr(C)]
pub struct COptionCPayloadAttributesV1 {
    is_something: bool,
    value: CPayloadAttributesV1,
}
impl_c_option!(COptionCPayloadAttributesV1, CPayloadAttributesV1);

#[derive(Debug)]
#[repr(C)]
pub struct COptionCPayloadAttributesV2 {
    is_something: bool,
    value: CPayloadAttributesV2,
}
impl_c_option!(COptionCPayloadAttributesV2, CPayloadAttributesV2);

#[derive(Debug)]
#[repr(C)]
pub struct COptionCPayloadAttributesV3 {
    is_something: bool,
    value: CPayloadAttributesV3,
}
impl_c_option!(COptionCPayloadAttributesV3, CPayloadAttributesV3);

#[derive(Debug)]
#[repr(C)]
pub struct CPayloadStatusV1 {
    status: CPayloadValidationStatus,
    latest_valid_hash: COptionCH256,
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

#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct CH64([u8; 8]);

impl Into<H64> for CH64 {
    fn into(self) -> H64 {
        H64(self.0)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CForkChoiceUpdatedResponse {
    payload_status: CPayloadStatusV1,
    payload_id: COptionCH64,
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

#[derive(Debug)]
#[repr(C)]
pub struct CExecutionRequests {
    requests: *const CRequest,
    requests_len: u64,
}

#[derive(Debug)]
#[repr(C)]
pub struct CBlobAndProofV2 {
    proof: *const CH384,
    blob: *const u8,
}

impl Default for CBlobAndProofV2 {
    fn default() -> Self {
        Self {
            proof: core::ptr::null(),
            blob: core::ptr::null(),
        }
    }
}

impl Clone for CBlobAndProofV2 {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl From<&CBlobAndProofV2> for BlobAndProofV2<Mainnet> {
    fn from(value: &CBlobAndProofV2) -> Self {
        BlobAndProofV2::<Mainnet> {
            blob: Box::new(
                unsafe { core::slice::from_raw_parts(value.blob, BytesPerBlob::<Mainnet>::USIZE) }
                    .into(),
            ),
            proofs: ContiguousVector::<H384, <Mainnet as Preset>::CellsPerExtBlob>::try_from_iter(
                unsafe {
                    core::slice::from_raw_parts(
                        value.proof,
                        <Mainnet as Preset>::CellsPerExtBlob::USIZE,
                    )
                }
                .iter()
                .map(|v| v.clone().into()),
            )
            .unwrap(),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CBlobAndProofV1 {
    proof: CH384,
    blob: *const u8,
}

impl Clone for CBlobAndProofV1 {
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            blob: todo!(),
        }
    }
}

impl Default for CBlobAndProofV1 {
    fn default() -> Self {
        Self {
            proof: Default::default(),
            blob: core::ptr::null(),
        }
    }
}

impl From<&COptionCBlobAndProofV1> for Option<BlobAndProofV1<Mainnet>> {
    fn from(value: &COptionCBlobAndProofV1) -> Self {
        if !value.is_something {
            None
        } else {
            let value = &value.value;
            Some(BlobAndProofV1::<Mainnet> {
                proof: value.proof.clone().into(),
                blob: Box::new(
                    unsafe {
                        core::slice::from_raw_parts(value.blob, BytesPerBlob::<Mainnet>::USIZE)
                    }
                    .into(),
                ),
            })
        }
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct COptionCBlobAndProofV1 {
    is_something: bool,
    value: CBlobAndProofV1,
}

impl_c_option!(COptionCBlobAndProofV1, CBlobAndProofV1);

#[derive(Debug)]
#[repr(C)]
struct CVecCOptionCBlobAndProofV1 {
    data: *const COptionCBlobAndProofV1,
    data_len: u64,
}

impl_c_vec!(CVecCOptionCBlobAndProofV1, COptionCBlobAndProofV1);

#[derive(Debug)]
#[repr(C)]
struct CResultCVecCOptionCBlobAndProofV1 {
    value: CVecCOptionCBlobAndProofV1,
    error: u64,
}
impl_c_result!(
    CResultCVecCOptionCBlobAndProofV1,
    CVecCOptionCBlobAndProofV1
);

#[repr(C)]
struct CVecCBlobAndProofV2 {
    data: *const CBlobAndProofV2,
    data_len: u64,
}

impl_c_vec!(CVecCBlobAndProofV2, CBlobAndProofV2);

#[repr(C)]
struct COptionCVecCBlobAndProofV2 {
    is_something: bool,
    value: CVecCBlobAndProofV2,
}

impl_c_option!(COptionCVecCBlobAndProofV2, CVecCBlobAndProofV2);

#[repr(C)]
struct CResultCOptionCVecCBlobAndProofV2 {
    value: COptionCVecCBlobAndProofV2,
    error: u64,
}

impl_c_result!(
    CResultCOptionCVecCBlobAndProofV2,
    COptionCVecCBlobAndProofV2
);

impl CExecutionRequests {
    fn from(value: ExecutionRequests<Mainnet>) -> (Self, Vec<u8>, Vec<u8>, Vec<u8>, Vec<CRequest>) {
        let mut execution_requests = Vec::new();

        let mut deposits = value.deposits.to_ssz().unwrap();
        deposits.insert(0, 0x00);
        let mut withdrawals = value.withdrawals.to_ssz().unwrap();
        withdrawals.insert(0, 0x01);
        let mut consolidations = value.consolidations.to_ssz().unwrap();
        consolidations.insert(0, 0x02);

        if !value.deposits.is_empty() {
            execution_requests.push(CRequest {
                bytes: deposits.as_ptr(),
                bytes_len: deposits.len() as u64,
            });
        }

        if !value.withdrawals.is_empty() {
            execution_requests.push(CRequest {
                bytes: withdrawals.as_ptr(),
                bytes_len: withdrawals.len() as u64,
            });
        }

        if !value.consolidations.is_empty() {
            // TODO: must prefix bytes with header
            execution_requests.push(CRequest {
                bytes: consolidations.as_ptr(),
                bytes_len: consolidations.len() as u64,
            });
        }

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

#[derive(Debug)]
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

#[derive(Debug)]
#[repr(C)]
pub struct CBlobsBundleV1 {
    commitments: *const *const u8,
    commitments_len: u64,
    proofs: *const *const u8,
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
                .map(|&v| {
                    H384(
                        unsafe { std::slice::from_raw_parts(v, 48) }
                            .try_into()
                            .unwrap(),
                    )
                }),
            )
            .unwrap(),
            proofs: ContiguousList::try_from_iter(
                unsafe { std::slice::from_raw_parts(self.proofs, self.proofs_len as usize) }
                    .iter()
                    .map(|&v| {
                        H384(
                            unsafe { std::slice::from_raw_parts(v, 48) }
                                .try_into()
                                .unwrap(),
                        )
                    }),
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

impl Into<BlobsBundleV2<Mainnet>> for CBlobsBundleV1 {
    fn into(self) -> BlobsBundleV2<Mainnet> {
        BlobsBundleV2::<Mainnet> {
            commitments: ContiguousList::try_from_iter(
                unsafe {
                    std::slice::from_raw_parts(self.commitments, self.commitments_len as usize)
                }
                .iter()
                .map(|&v| {
                    H384(
                        unsafe { std::slice::from_raw_parts(v, 48) }
                            .try_into()
                            .unwrap(),
                    )
                }),
            )
            .unwrap(),
            proofs: ContiguousList::try_from_iter(
                unsafe { std::slice::from_raw_parts(self.proofs, self.proofs_len as usize) }
                    .iter()
                    .map(|&v| {
                        H384(
                            unsafe { std::slice::from_raw_parts(v, 48) }
                                .try_into()
                                .unwrap(),
                        )
                    }),
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

#[derive(Debug)]
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

#[derive(Debug)]
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

#[derive(Debug)]
#[repr(C)]
pub struct CEngineGetPayloadV5Response {
    execution_payload: CExecutionPayloadV3,
    block_value: [u8; 32],
    blobs_bundle: CBlobsBundleV1,
    should_override_builder: bool,
    execution_requests: CExecutionRequests,
}

#[derive(Debug)]
#[repr(C)]
struct CResultCEngineGetPayloadV5Response {
    value: CEngineGetPayloadV5Response,
    error: u64,
}
impl_c_result!(
    CResultCEngineGetPayloadV5Response,
    CEngineGetPayloadV5Response
);

impl Into<EngineGetPayloadV5Response<Mainnet>> for CEngineGetPayloadV5Response {
    fn into(self) -> EngineGetPayloadV5Response<Mainnet> {
        EngineGetPayloadV5Response::<Mainnet> {
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

#[derive(Clone, Debug, Default)]
#[repr(C)]
struct CH160([u8; 20]);

#[repr(C)]
pub struct CFilter {
    from_block: COptionU64,
    to_block: COptionU64,
    address: COptionCVecCH160,
    topics: COptionCVecCOptionCVecCH256,
    limit: COptionU64,
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

// impl CFilter {
//     fn from(
//         value: Filter,
//     ) -> (
//         Self,
//         Option<Vec<CH160>>,
//         Vec<Vec<CH256>>,
//         Option<Vec<COptionCVecCH256>>,
//     ) {
//         let address = value.address.map(|v| {
//             let v: Vec<H160> = v.0.into();
//             let v = v.into_iter().map(|c| CH160(c.0)).collect::<Vec<_>>();
//             let cv: CVecCH160 = (&v).into();

//             (cv, v)
//         });

//         let (address, vec) = if let Some((a, v)) = address {
//             (Some(a), Some(v))
//         } else {
//             (None, None)
//         };

//         let mut allocated_topics = Vec::new();

//         let topics = value.topics.map(|v| {
//             let vec = v
//                 .into_iter()
//                 .map(|v| {
//                     if let Some(v) = v {
//                         let v: Vec<H256> = v.0.into();
//                         let v = v.iter().map(|v| CH256(v.0)).collect::<Vec<_>>();
//                         allocated_topics.push(v);

//                         COptionCVecCH256 {
//                             is_something: true,
//                             value: allocated_topics.last().unwrap().into(),
//                         }
//                     } else {
//                         COptionCVecCH256 {
//                             is_something: false,
//                             value: Default::default(),
//                         }
//                     }
//                 })
//                 .collect::<Vec<COptionCVecCH256>>();
//             let cvec: CVecCOptionCVecCH256 = (&vec).into();

//             (cvec, vec)
//         });

//         let (topics, vec2) = if let Some((t, v)) = topics {
//             (Some(t), Some(v))
//         } else {
//             (None, None)
//         };

//         (
//             CFilter {
//                 from_block: value.from_block.map(block_number_into_u64).into(),
//                 to_block: value.to_block.map(block_number_into_u64).into(),
//                 address: address.into(),
//                 topics: topics.into(),
//                 limit: value.limit.map(|v| v as u64).into(),
//             },
//             vec,
//             allocated_topics,
//             vec2,
//         )
//     }
// }

#[derive(Debug)]
#[repr(C)]
struct CVecCH160 {
    data: *const CH160,
    data_len: u64,
}

impl_c_vec!(CVecCH160, CH160);

#[derive(Clone, Debug)]
#[repr(C)]
struct CVecCH256 {
    data: *const CH256,
    data_len: u64,
}
impl_c_vec!(CVecCH256, CH256);

#[derive(Clone, Debug)]
#[repr(C)]
struct CVecCOptionCVecCH256 {
    data: *const COptionCVecCH256,
    data_len: u64,
}
impl_c_vec!(CVecCOptionCVecCH256, COptionCVecCH256);

#[derive(Debug)]
#[repr(C)]
struct CVecU8 {
    data: *const u8,
    data_len: u64,
}
impl_c_vec!(CVecU8, u8);

#[repr(C)]
pub struct CEmbedAdapter {
    engine_new_payload_v1:
        unsafe extern "C" fn(payload: CExecutionPayloadV1) -> CResultCPayloadStatusV1,
    engine_new_payload_v2:
        unsafe extern "C" fn(payload: CExecutionPayloadV2) -> CResultCPayloadStatusV1,
    engine_new_payload_v3: unsafe extern "C" fn(
        payload: CExecutionPayloadV3,
        versioned_hashes: *const *const u8,
        versioned_hashes_len: u64,
        parent_beacon_block_root: *const u8,
    ) -> CResultCPayloadStatusV1,
    engine_new_payload_v4: unsafe extern "C" fn(
        payload: CExecutionPayloadV3,
        versioned_hashes: *const *const u8,
        versioned_hashes_len: u64,
        parent_beacon_block_root: *const u8,
        execution_requests: CExecutionRequests,
    ) -> CResultCPayloadStatusV1,
    engine_forkchoice_updated_v1: unsafe extern "C" fn(
        state: CForkChoiceStateV1,
        payload: COptionCPayloadAttributesV1,
    ) -> CResultCForkChoiceUpdatedResponse,
    engine_forkchoice_updated_v2: unsafe extern "C" fn(
        state: CForkChoiceStateV1,
        payload: COptionCPayloadAttributesV2,
    ) -> CResultCForkChoiceUpdatedResponse,
    engine_forkchoice_updated_v3: unsafe extern "C" fn(
        state: CForkChoiceStateV1,
        payload: COptionCPayloadAttributesV3,
    ) -> CResultCForkChoiceUpdatedResponse,
    engine_get_payload_v1:
        unsafe extern "C" fn(payload_id: *const u8) -> CResultCExecutionPayloadV1,
    engine_get_payload_v2:
        unsafe extern "C" fn(payload_id: *const u8) -> CResultCEngineGetPayloadV2Response,
    engine_get_payload_v3:
        unsafe extern "C" fn(payload_id: *const u8) -> CResultCEngineGetPayloadV3Response,
    engine_get_payload_v4:
        unsafe extern "C" fn(payload_id: *const u8) -> CResultCEngineGetPayloadV4Response,
    engine_get_payload_v5:
        unsafe extern "C" fn(payload_id: *const u8) -> CResultCEngineGetPayloadV5Response,
    engine_get_blobs_v1: unsafe extern "C" fn(
        versioned_hashes: *const *const u8,
        versioned_hashes_len: u64,
    ) -> CResultCVecCOptionCBlobAndProofV1,
    engine_get_blobs_v2: unsafe extern "C" fn(
        versioned_hashes: *const *const u8,
        versioned_hashes_len: u64,
    ) -> CResultCOptionCVecCBlobAndProofV2,
    free: unsafe extern "C" fn(ptr: *const core::ffi::c_void),
}

impl eth1_api::EmbedAdapter for CEmbedAdapter {
    fn eth_block_number(&self) -> Result<ExecutionBlockNumber> {
        bail!("not implemented");
    }

    fn eth_get_block_by_hash(&self, hash: H256) -> Result<Option<eth1_api::Eth1Block>> {
        bail!("not implemented");
    }

    fn eth_get_block_by_number(&self, number: BlockNumber) -> Result<Option<eth1_api::Eth1Block>> {
        bail!("not implemented");
    }

    fn eth_logs(&self, filter: web3::types::Filter) -> Result<Vec<web3::types::Log>> {
        bail!("not implemented");
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
                COptionCPayloadAttributesV2 {
                    is_something: true,
                    value,
                },
                Some(vec),
            ),
            None => (
                COptionCPayloadAttributesV2 {
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
                COptionCPayloadAttributesV3 {
                    is_something: true,
                    value,
                },
                Some(vec),
            ),
            None => (
                COptionCPayloadAttributesV3 {
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

    fn engine_get_payload_v5(
        &self,
        payload_id: H64,
    ) -> Result<EngineGetPayloadV5Response<Mainnet>> {
        let output = unsafe { (self.engine_get_payload_v5)(payload_id.as_ptr()) };
        let output: Result<_> = output.into();
        output.map(|v| v.into())
    }

    fn engine_get_blobs_v1(
        &self,
        versioned_hashes: Vec<types::deneb::primitives::VersionedHash>,
    ) -> Result<Vec<Option<BlobAndProofV1<Mainnet>>>> {
        let versioned_hashes = versioned_hashes
            .iter()
            .map(|hash| hash.0.as_ptr())
            .collect::<Vec<_>>();

        let output = unsafe {
            (self.engine_get_blobs_v1)(versioned_hashes.as_ptr(), versioned_hashes.len() as u64)
        };

        drop(versioned_hashes);

        let output: Result<_, _> = output.into();

        output.map(|value| {
            value.map_convert(|item| -> Option<BlobAndProofV1<Mainnet>> { item.into() })
        })
    }

    fn engine_get_blobs_v2(
        &self,
        versioned_hashes: Vec<types::deneb::primitives::VersionedHash>,
    ) -> Result<Option<Vec<execution_engine::BlobAndProofV2<Mainnet>>>> {
        let versioned_hashes = versioned_hashes
            .iter()
            .map(|hash| hash.0.as_ptr())
            .collect::<Vec<_>>();

        let output = unsafe {
            (self.engine_get_blobs_v2)(versioned_hashes.as_ptr(), versioned_hashes.len() as u64)
        };

        drop(versioned_hashes);

        let output: Result<_, _> = output.into();

        output.map(|value| {
            let value: Option<CVecCBlobAndProofV2> = value.into();
            value.map(|blobs| blobs.map_convert(|item| -> BlobAndProofV2<Mainnet> { item.into() }))
        })
    }
}

#[no_mangle]
pub extern "C" fn grandine_set_execution_layer_adapter(adapter: CEmbedAdapter) {
    eth1_api::set_adapter(Box::new(adapter)).unwrap();
}

pub fn try_run(argc: u64, argv: *const *const c_char) -> Result<()> {
    let args = unsafe {
        std::iter::once("").chain(
            std::slice::from_raw_parts(argv, argc as usize)
                .into_iter()
                .filter_map(|it| CStr::from_ptr(*it).to_str().ok()),
        )
    };

    let args = GrandineArgs::try_parse_from(args)?;

    run(args)
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
