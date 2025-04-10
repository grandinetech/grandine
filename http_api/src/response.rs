use anyhow::Result;
use axum::{
    http::{header::ACCEPT, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use http_api_utils::ETH_CONSENSUS_VERSION;
use mediatype::{MediaType, MediaTypeList};
use mime::APPLICATION_OCTET_STREAM;
use serde::Serialize;
use ssz::SszWrite;
use tap::Pipe as _;
use types::{bellatrix::primitives::Wei, nonstandard::Phase, phase0::primitives::H256};

use crate::error::Error;

const ETH_CONSENSUS_BLOCK_VALUE: &str = "eth-consensus-block-value";
const ETH_EXECUTION_PAYLOAD_BLINDED: &str = "eth-execution-payload-blinded";
const ETH_EXECUTION_PAYLOAD_VALUE: &str = "eth-execution-payload-value";

pub struct AlwaysJson;

pub enum JsonOrSsz {
    Json,
    Ssz,
}

#[derive(Serialize)]
pub struct EthResponse<T, M = (), F = AlwaysJson> {
    data: T,

    // These are returned in both JSON body fields and headers.
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<Phase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    consensus_block_value: Option<Wei>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_payload_blinded: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_payload_value: Option<Wei>,

    // These are returned only in JSON body fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<M>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependent_root: Option<H256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_optimistic: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finalized: Option<bool>,

    #[serde(skip)]
    format: F,
}

impl<T: Serialize, M: Serialize> IntoResponse for EthResponse<T, M, AlwaysJson> {
    fn into_response(self) -> Response {
        let run = || {
            let response_headers = self.response_headers()?;
            let response_body = self.into_json();
            Ok((response_headers, response_body))
        };

        run().map_err(Error::Internal).into_response()
    }
}

impl<T: SszWrite + Serialize, M: Serialize> IntoResponse for EthResponse<T, M, JsonOrSsz> {
    fn into_response(self) -> Response {
        let run = || {
            let response_headers = self.response_headers()?;

            let response_body = match self.format {
                JsonOrSsz::Json => self.into_json().into_response(),
                JsonOrSsz::Ssz => self.data.to_ssz()?.into_response(),
            };

            Ok((response_headers, response_body))
        };

        run().map_err(Error::Internal).into_response()
    }
}

impl<T, M, F> EthResponse<T, M, F> {
    const fn new(data: T, format: F) -> Self {
        Self {
            data,
            version: None,
            consensus_block_value: None,
            execution_payload_blinded: None,
            execution_payload_value: None,
            meta: None,
            dependent_root: None,
            execution_optimistic: None,
            finalized: None,
            format,
        }
    }

    pub const fn version(mut self, phase: Phase) -> Self {
        self.version = Some(phase);
        self
    }

    pub const fn consensus_block_value(mut self, consensus_block_value: Option<Wei>) -> Self {
        self.consensus_block_value = consensus_block_value;
        self
    }

    pub const fn execution_payload_blinded(mut self, execution_payload_blinded: bool) -> Self {
        self.execution_payload_blinded = Some(execution_payload_blinded);
        self
    }

    pub const fn execution_payload_value(mut self, execution_payload_value: Wei) -> Self {
        self.execution_payload_value = Some(execution_payload_value);
        self
    }

    pub const fn dependent_root(mut self, dependent_root: H256) -> Self {
        self.dependent_root = Some(dependent_root);
        self
    }

    pub const fn execution_optimistic(mut self, execution_optimistic: bool) -> Self {
        self.execution_optimistic = Some(execution_optimistic);
        self
    }

    pub const fn finalized(mut self, finalized: bool) -> Self {
        self.finalized = Some(finalized);
        self
    }

    fn response_headers(&self) -> Result<HeaderMap> {
        let mut response_headers = HeaderMap::new();

        if let Some(phase) = self.version {
            let header_value = phase.as_ref().try_into()?;
            response_headers.insert(ETH_CONSENSUS_VERSION, header_value);
        }

        if let Some(value) = self.consensus_block_value {
            let header_value = value.to_string().try_into()?;
            response_headers.insert(ETH_CONSENSUS_BLOCK_VALUE, header_value);
        }

        if let Some(blinded) = self.execution_payload_blinded {
            let header_value = HeaderValue::from_static(if blinded { "true" } else { "false" });
            response_headers.insert(ETH_EXECUTION_PAYLOAD_BLINDED, header_value);
        }

        if let Some(value) = self.execution_payload_value {
            let header_value = value.to_string().try_into()?;
            response_headers.insert(ETH_EXECUTION_PAYLOAD_VALUE, header_value);
        }

        Ok(response_headers)
    }

    fn into_json(self) -> Json<EthResponse<T, M, AlwaysJson>> {
        let Self {
            data,
            version,
            consensus_block_value,
            execution_payload_blinded,
            execution_payload_value,
            meta,
            dependent_root,
            execution_optimistic,
            finalized,
            format: _,
        } = self;

        let response_body = EthResponse {
            data,
            version,
            consensus_block_value,
            execution_payload_blinded,
            execution_payload_value,
            meta,
            dependent_root,
            execution_optimistic,
            finalized,
            format: AlwaysJson,
        };

        Json(response_body)
    }
}

impl<T, F> EthResponse<T, (), F> {
    pub fn meta<M>(self, meta: M) -> EthResponse<T, M, F> {
        let Self {
            data,
            version,
            consensus_block_value,
            execution_payload_blinded,
            execution_payload_value,
            meta: _,
            dependent_root,
            execution_optimistic,
            finalized,
            format,
        } = self;

        EthResponse {
            data,
            version,
            consensus_block_value,
            execution_payload_blinded,
            execution_payload_value,
            meta: Some(meta),
            dependent_root,
            execution_optimistic,
            finalized,
            format,
        }
    }
}

impl<T> EthResponse<T, (), AlwaysJson> {
    pub const fn json(data: T) -> Self {
        Self::new(data, AlwaysJson)
    }
}

impl<T> EthResponse<T, (), JsonOrSsz> {
    // `axum` recommends using `axum::TypedHeader` instead of extracting all headers,
    // but the `headers` crate does not provide a type for the `Accept` header.
    // See <https://github.com/hyperium/headers/issues/53>.
    pub fn json_or_ssz(data: T, request_headers: &HeaderMap) -> Result<Self> {
        if let Some(accept_header) = request_headers.get(ACCEPT) {
            if let Some(accept) = accept_content_type(accept_header.to_str()?)? {
                if accept == APPLICATION_OCTET_STREAM.as_ref() {
                    return Ok(Self::new(data, JsonOrSsz::Ssz));
                }
            }
        }

        Ok(Self::new(data, JsonOrSsz::Json))
    }
}

fn accept_content_type(accept_header: &str) -> Result<Option<String>> {
    let mut scored_types = vec![];

    for media_type in MediaTypeList::new(accept_header) {
        let MediaType {
            ty, subty, params, ..
        } = media_type?;

        let essence = format!("{ty}/{subty}");
        let q = params
            .iter()
            .find(|(name, _)| name == "q")
            .map(|(_, value)| value.as_str());

        scored_types.push((q, essence));
    }

    scored_types.sort_by_key(|scored_type| scored_type.0);

    scored_types
        .last()
        .map(|(_, essence)| essence)
        .cloned()
        .pipe(Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accept_content_type() -> Result<()> {
        assert_eq!(
            accept_content_type("application/octet-stream;q=1,application/json;q=0.9")?,
            Some("application/octet-stream".to_owned()),
        );

        assert_eq!(
            accept_content_type("application/octet-stream;q=0.9,application/json;q=1")?,
            Some("application/json".to_owned()),
        );

        assert_eq!(
            accept_content_type("application/octet-stream")?,
            Some("application/octet-stream".to_owned()),
        );

        assert_eq!(accept_content_type("")?, None);

        Ok(())
    }
}
