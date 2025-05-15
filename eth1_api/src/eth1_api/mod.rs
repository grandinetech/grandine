#[cfg(feature = "embed")]
mod embed_api;
#[cfg(feature = "embed")]
pub use embed_api::*;

#[cfg(not(feature = "embed"))]
mod http_api;
#[cfg(not(feature = "embed"))]
pub use http_api::*;

pub const ENGINE_FORKCHOICE_UPDATED_V1: &str = "engine_forkchoiceUpdatedV1";
pub const ENGINE_FORKCHOICE_UPDATED_V2: &str = "engine_forkchoiceUpdatedV2";
pub const ENGINE_FORKCHOICE_UPDATED_V3: &str = "engine_forkchoiceUpdatedV3";
pub const ENGINE_GET_CLIENT_VERSION_V1: &str = "engine_getClientVersionV1";
pub const ENGINE_GET_EL_BLOBS_V1: &str = "engine_getBlobsV1";
pub const ENGINE_GET_PAYLOAD_V1: &str = "engine_getPayloadV1";
pub const ENGINE_GET_PAYLOAD_V2: &str = "engine_getPayloadV2";
pub const ENGINE_GET_PAYLOAD_V3: &str = "engine_getPayloadV3";
pub const ENGINE_GET_PAYLOAD_V4: &str = "engine_getPayloadV4";
pub const ENGINE_NEW_PAYLOAD_V1: &str = "engine_newPayloadV1";
pub const ENGINE_NEW_PAYLOAD_V2: &str = "engine_newPayloadV2";
pub const ENGINE_NEW_PAYLOAD_V3: &str = "engine_newPayloadV3";
pub const ENGINE_NEW_PAYLOAD_V4: &str = "engine_newPayloadV4";

pub const CAPABILITIES: &[&str] = &[
    ENGINE_FORKCHOICE_UPDATED_V1,
    ENGINE_FORKCHOICE_UPDATED_V2,
    ENGINE_FORKCHOICE_UPDATED_V3,
    ENGINE_GET_EL_BLOBS_V1,
    ENGINE_GET_PAYLOAD_V1,
    ENGINE_GET_PAYLOAD_V2,
    ENGINE_GET_PAYLOAD_V3,
    ENGINE_GET_PAYLOAD_V4,
    ENGINE_NEW_PAYLOAD_V1,
    ENGINE_NEW_PAYLOAD_V2,
    ENGINE_NEW_PAYLOAD_V3,
    ENGINE_NEW_PAYLOAD_V4,
];
