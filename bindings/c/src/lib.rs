use std::ffi::{c_char, c_void, CStr};

use allocator as _;
use anyhow::{bail, Result};
use clap::{Error as ClapError, Parser};
use execution_engine::{
    BlobAndProofV1, EngineGetPayloadV1Response, EngineGetPayloadV2Response,
    EngineGetPayloadV3Response, EngineGetPayloadV4Response, EngineGetPayloadV5Response,
    ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, ForkChoiceStateV1,
    PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3, PayloadStatusV1,
};
use runtime::{grandine_args::GrandineArgs, run, shutdown};
use tracing::error;
use types::{
    electra::containers::ExecutionRequests, phase0::primitives::ExecutionBlockNumber,
    preset::Mainnet,
};
use web3::types::{BlockNumber, H256, H64};

use crate::{
    arrays::{CH256, CH64},
    containers::{
        CBlobAndProofV1, CBlobAndProofV2, CEngineGetPayloadV2Response, CEngineGetPayloadV3Response,
        CEngineGetPayloadV4Response, CEngineGetPayloadV5Response, CExecutionPayloadV1,
        CExecutionPayloadV2, CExecutionPayloadV3, CExecutionRequests, CForkChoiceStateV1,
        CForkChoiceUpdatedResponse, CPayloadAttributesV1, CPayloadAttributesV2,
        CPayloadAttributesV3, CPayloadStatusV1,
    },
    generic::{CErrorMessage, COption, CResult, CVec, GRANDINE_ERROR_GENERIC},
};

pub use crate::containers::CPayloadValidationStatus;

mod arrays;
mod containers;
mod generic;

#[repr(C)]
pub struct CEmbedAdapter {
    engine_new_payload_v1:
        unsafe extern "C" fn(payload: CExecutionPayloadV1) -> CResult<CPayloadStatusV1>,
    engine_new_payload_v2:
        unsafe extern "C" fn(payload: CExecutionPayloadV2) -> CResult<CPayloadStatusV1>,
    engine_new_payload_v3: unsafe extern "C" fn(
        payload: CExecutionPayloadV3,
        versioned_hashes: CVec<CH256>,
        parent_beacon_block_root: CH256,
    ) -> CResult<CPayloadStatusV1>,
    engine_new_payload_v4: unsafe extern "C" fn(
        payload: CExecutionPayloadV3,
        versioned_hashes: CVec<CH256>,
        parent_beacon_block_root: CH256,
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
    engine_get_payload_v1: unsafe extern "C" fn(payload_id: CH64) -> CResult<CExecutionPayloadV1>,
    engine_get_payload_v2:
        unsafe extern "C" fn(payload_id: CH64) -> CResult<CEngineGetPayloadV2Response>,
    engine_get_payload_v3:
        unsafe extern "C" fn(payload_id: CH64) -> CResult<CEngineGetPayloadV3Response>,
    engine_get_payload_v4:
        unsafe extern "C" fn(payload_id: CH64) -> CResult<CEngineGetPayloadV4Response>,
    engine_get_payload_v5:
        unsafe extern "C" fn(payload_id: CH64) -> CResult<CEngineGetPayloadV5Response>,
    engine_get_blobs_v1: unsafe extern "C" fn(
        versioned_hashes: CVec<CH256>,
    ) -> CResult<CVec<COption<CBlobAndProofV1>>>,
    engine_get_blobs_v2: unsafe extern "C" fn(
        versioned_hashes: CVec<CH256>,
    ) -> CResult<COption<CVec<CBlobAndProofV2>>>,
}

impl eth1_api::EmbedAdapter for CEmbedAdapter {
    fn eth_block_number(&self) -> Result<ExecutionBlockNumber> {
        bail!("Method not implemented");
    }

    fn eth_get_block_by_hash(&self, _hash: H256) -> Result<Option<eth1_api::Eth1Block>> {
        bail!("Method not implemented");
    }

    fn eth_get_block_by_number(&self, _number: BlockNumber) -> Result<Option<eth1_api::Eth1Block>> {
        bail!("Method not implemented");
    }

    fn eth_logs(&self, _filter: web3::types::Filter) -> Result<Vec<web3::types::Log>> {
        bail!("Method not implemented");
    }

    fn engine_new_payload_v1(
        &self,
        payload: ExecutionPayloadV1<types::preset::Mainnet>,
    ) -> Result<PayloadStatusV1> {
        let payload = payload.into();

        let result = unsafe { (self.engine_new_payload_v1)(payload) };

        Result::<_>::from(result).map(Into::into)
    }

    fn engine_new_payload_v2(
        &self,
        payload: ExecutionPayloadV2<types::preset::Mainnet>,
    ) -> Result<PayloadStatusV1> {
        let payload = payload.into();

        let result = unsafe { (self.engine_new_payload_v2)(payload) };

        Result::<_>::from(result).map(Into::into)
    }

    fn engine_new_payload_v3(
        &self,
        payload: ExecutionPayloadV3<types::preset::Mainnet>,
        versioned_hashes: Vec<web3::types::H256>,
        parent_beacon_block_root: web3::types::H256,
    ) -> Result<PayloadStatusV1> {
        let payload = payload.into();
        let versioned_hashes = versioned_hashes
            .into_iter()
            .map(Into::into)
            .collect::<CVec<_>>();
        let parent_beacon_block_root = parent_beacon_block_root.into();

        let result = unsafe {
            (self.engine_new_payload_v3)(payload, versioned_hashes, parent_beacon_block_root)
        };

        Result::<_>::from(result).map(Into::into)
    }

    fn engine_new_payload_v4(
        &self,
        payload: ExecutionPayloadV3<types::preset::Mainnet>,
        versioned_hashes: Vec<web3::types::H256>,
        parent_beacon_block_root: web3::types::H256,
        execution_requests: ExecutionRequests<types::preset::Mainnet>,
    ) -> Result<PayloadStatusV1> {
        let payload = payload.into();
        let versioned_hashes = versioned_hashes
            .into_iter()
            .map(Into::into)
            .collect::<CVec<_>>();
        let parent_beacon_block_root = parent_beacon_block_root.into();
        let execution_requests = execution_requests.try_into()?;

        let result = unsafe {
            (self.engine_new_payload_v4)(
                payload,
                versioned_hashes,
                parent_beacon_block_root,
                execution_requests,
            )
        };

        Result::from(result).map(Into::into)
    }

    fn engine_forkchoice_updated_v1(
        &self,
        state: ForkChoiceStateV1,
        payload: Option<PayloadAttributesV1>,
    ) -> Result<eth1_api::RawForkChoiceUpdatedResponse> {
        let state = state.into();
        let payload: Option<CPayloadAttributesV1> = payload.map(Into::into);
        let payload = payload.into();
        let result = unsafe { (self.engine_forkchoice_updated_v1)(state, payload) };

        Result::<_>::from(result).map(Into::into)
    }

    fn engine_forkchoice_updated_v2(
        &self,
        state: ForkChoiceStateV1,
        payload: Option<PayloadAttributesV2<types::preset::Mainnet>>,
    ) -> Result<eth1_api::RawForkChoiceUpdatedResponse> {
        let state: CForkChoiceStateV1 = state.into();
        let payload: Option<CPayloadAttributesV2> = payload.map(Into::into);
        let payload = payload.into();
        let result = unsafe { (self.engine_forkchoice_updated_v2)(state, payload) };

        Result::from(result).map(Into::into)
    }

    fn engine_forkchoice_updated_v3(
        &self,
        state: ForkChoiceStateV1,
        payload: Option<PayloadAttributesV3<types::preset::Mainnet>>,
    ) -> Result<eth1_api::RawForkChoiceUpdatedResponse> {
        let state: CForkChoiceStateV1 = state.into();
        let payload: Option<CPayloadAttributesV3> = payload.map(Into::into);
        let payload = payload.into();
        let result = unsafe { (self.engine_forkchoice_updated_v3)(state, payload) };

        Result::<_>::from(result).map(Into::into)
    }

    fn engine_get_payload_v1(
        &self,
        payload_id: web3::types::H64,
    ) -> Result<EngineGetPayloadV1Response<types::preset::Mainnet>> {
        let result = unsafe { (self.engine_get_payload_v1)(payload_id.into()) };
        Result::<_>::from(result).and_then(|v| Ok(v.try_into()?))
    }

    fn engine_get_payload_v2(
        &self,
        payload_id: web3::types::H64,
    ) -> Result<EngineGetPayloadV2Response<types::preset::Mainnet>> {
        let result = unsafe { (self.engine_get_payload_v2)(payload_id.into()) };
        Result::<_>::from(result).and_then(|v| Ok(v.try_into()?))
    }

    fn engine_get_payload_v3(
        &self,
        payload_id: web3::types::H64,
    ) -> Result<EngineGetPayloadV3Response<types::preset::Mainnet>> {
        let result = unsafe { (self.engine_get_payload_v3)(payload_id.into()) };
        Result::<_>::from(result).and_then(|v| Ok(v.try_into()?))
    }

    fn engine_get_payload_v4(
        &self,
        payload_id: web3::types::H64,
    ) -> Result<EngineGetPayloadV4Response<types::preset::Mainnet>> {
        let result = unsafe { (self.engine_get_payload_v4)(payload_id.into()) };
        Result::<_>::from(result).and_then(|v| Ok(v.try_into()?))
    }

    fn engine_get_payload_v5(
        &self,
        payload_id: H64,
    ) -> Result<EngineGetPayloadV5Response<Mainnet>> {
        let result = unsafe { (self.engine_get_payload_v5)(payload_id.into()) };
        Result::<_>::from(result).and_then(|v| Ok(v.try_into()?))
    }

    fn engine_get_blobs_v1(
        &self,
        versioned_hashes: Vec<types::deneb::primitives::VersionedHash>,
    ) -> Result<Vec<Option<BlobAndProofV1<Mainnet>>>> {
        let versioned_hashes = versioned_hashes
            .into_iter()
            .map(|hash| hash.into())
            .collect::<CVec<_>>();

        let result = unsafe { (self.engine_get_blobs_v1)(versioned_hashes) };

        let result: Result<_> = result.into();

        result.and_then(|v| {
            v.into_iter()
                .map(|blob| {
                    let blob: Option<CBlobAndProofV1> = blob.into();
                    let Some(blob) = blob else {
                        return Ok(None);
                    };

                    blob.try_into().map(Some).map_err(Into::into)
                })
                .collect::<Result<Vec<_>, _>>()
        })
    }

    fn engine_get_blobs_v2(
        &self,
        versioned_hashes: Vec<types::deneb::primitives::VersionedHash>,
    ) -> Result<Option<Vec<execution_engine::BlobAndProofV2<Mainnet>>>> {
        let versioned_hashes = versioned_hashes
            .into_iter()
            .map(|hash| hash.into())
            .collect::<CVec<_>>();

        let result = unsafe { (self.engine_get_blobs_v2)(versioned_hashes) };

        let result: Result<_> = result.into();

        result.and_then(|blobs| {
            let blobs: Option<CVec<CBlobAndProofV2>> = blobs.into();

            let Some(blobs) = blobs else {
                return Ok(None);
            };

            Ok(Some(
                blobs
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?,
            ))
        })
    }
}

#[no_mangle]
pub extern "C" fn grandine_set_execution_layer_adapter(adapter: CEmbedAdapter) -> CResult<u8> {
    let res = eth1_api::set_adapter(Box::new(adapter));

    match res {
        Ok(()) => CResult::ok(0), // returned value doesn't mean anything, just cbindgen doesn't allow structs with empty tuple ()
        Err(error) => CResult::err(GRANDINE_ERROR_GENERIC, Some(format!("{error:?}"))),
    }
}

#[no_mangle]
pub extern "C" fn grandine_alloc(size: usize) -> *mut c_void {
    Box::into_raw(vec![0u8; size].into_boxed_slice()) as *mut c_void
}

/// Copies string to a pointer managed by grandine.
/// CErrorMessage must be passed back to grandine, where it will be automatically cleaned up.
#[no_mangle]
pub unsafe extern "C" fn grandine_error_message(str: *const c_char) -> CErrorMessage {
    CErrorMessage::new(str)
}

#[no_mangle]
pub extern "C" fn grandine_shutdown() {
    shutdown();
}

#[no_mangle]
pub unsafe extern "C" fn grandine_run(argc: u64, argv: *const *const c_char) -> u64 {
    unsafe fn try_run(argc: u64, argv: *const *const c_char) -> Result<()> {
        let args = std::iter::once("").chain(
            std::slice::from_raw_parts(argv, argc as usize)
                .into_iter()
                .filter_map(|it| CStr::from_ptr(*it).to_str().ok()),
        );

        let args = GrandineArgs::try_parse_from(args)?;

        run(args)
    }

    if let Err(error) = try_run(argc, argv) {
        error.downcast_ref().map(ClapError::exit);
        error!("{error:?}");

        return 1;
    }

    return 0;
}
