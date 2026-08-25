use core::time::Duration;
use std::sync::Arc;

use bls::PublicKeyBytes;
use parse_display::Display;
use prometheus_metrics::Metrics;
use serde::{Deserialize, Serialize};
use types::phase0::{
    containers::SignedBeaconBlockHeader,
    primitives::{CommitteeIndex, H256, Slot, ValidatorIndex},
};

pub const ETH_CONSENSUS_VERSION: &str = "eth-consensus-version";

/// <https://ethereum.github.io/beacon-APIs/#/Validator/getAttesterDuties>
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ValidatorAttesterDutyResponse {
    #[serde(with = "serde_utils::string_or_native")]
    pub committee_index: CommitteeIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub committee_length: usize,
    #[serde(with = "serde_utils::string_or_native")]
    pub committees_at_slot: u64,
    pub pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_committee_index: usize,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
}

/// <https://ethereum.github.io/beacon-APIs/#/Validator/getSyncCommitteeDuties>
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ValidatorSyncDutyResponse {
    pub pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub validator_sync_committee_indices: Vec<usize>,
}

/// <https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader>
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockHeadersResponse {
    pub root: H256,
    pub canonical: bool,
    pub header: SignedBeaconBlockHeader,
}

#[derive(Clone, Copy)]
enum ApiType {
    Http,
    Metrics,
    Validator,
}

#[derive(Clone)]
pub struct ApiMetrics {
    api_type: ApiType,
    prometheus_metrics: Arc<Metrics>,
}

impl ApiMetrics {
    #[must_use]
    pub const fn http(prometheus_metrics: Arc<Metrics>) -> Self {
        Self {
            api_type: ApiType::Http,
            prometheus_metrics,
        }
    }

    #[must_use]
    pub const fn metrics(prometheus_metrics: Arc<Metrics>) -> Self {
        Self {
            api_type: ApiType::Metrics,
            prometheus_metrics,
        }
    }

    #[must_use]
    pub const fn validator(prometheus_metrics: Arc<Metrics>) -> Self {
        Self {
            api_type: ApiType::Validator,
            prometheus_metrics,
        }
    }

    pub fn set_response_time(&self, labels: &[&str], response_duration: Duration) {
        match self.api_type {
            ApiType::Http => self
                .prometheus_metrics
                .set_http_api_response_time(labels, response_duration),
            ApiType::Metrics => self
                .prometheus_metrics
                .set_metrics_api_response_time(labels, response_duration),
            ApiType::Validator => self
                .prometheus_metrics
                .set_validator_api_response_time(labels, response_duration),
        }
    }
}

#[derive(Clone, Copy, Debug, Display)]
#[display(style = "lowercase")]
pub enum Direction {
    Request,
    Response,
}
