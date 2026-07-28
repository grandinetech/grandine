//! Shared Beacon Node REST API request and response types.
//!
//! These mirror the JSON payloads of the standard Beacon Node API and are used
//! by both the `http_api` server (deserialize) and the standalone `builder`
//! client (serialize), so the wire format stays defined in one place.
//!
//! For now this holds only the types that genuinely have two sides in the
//! workspace. The remaining request/response types still live in `http_api`,
//! where they have a single consumer; we expect to move them all here once the
//! validator client is decoupled and becomes a second consumer of the wire
//! format.

use bls::PublicKeyBytes;
use parse_display::{Display, FromStr};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use types::{
    gloas::{containers::Builder, primitives::BuilderIndex},
    phase0::{
        containers::Checkpoint,
        primitives::{H256, Slot, UnixSeconds, ValidatorIndex, Version},
    },
};

/// `GET /eth/v1/beacon/genesis`
#[expect(clippy::struct_field_names)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetGenesisResponse {
    #[serde(with = "serde_utils::string_or_native")]
    pub genesis_time: UnixSeconds,
    pub genesis_validators_root: H256,
    pub genesis_fork_version: Version,
}

/// `GET /eth/v1/validator/duties/proposer/{epoch}`
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ValidatorProposerDutyResponse {
    pub pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Display, FromStr, DeserializeFromStr, SerializeDisplay,
)]
#[display(style = "snake_case")]
pub enum BuilderStatus {
    Pending,
    Active,
    Exited,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, FromStr, DeserializeFromStr, SerializeDisplay,
)]
pub enum BuilderId {
    #[display("{0}")]
    BuilderIndex(BuilderIndex),
    #[display("{0:?}")]
    PublicKey(PublicKeyBytes),
}

/// `POST /eth/v1/beacon/states/{state_id}/builders` request body
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BuildersQuery {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<BuilderId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statuses: Vec<BuilderStatus>,
}

/// `GET /eth/v1/beacon/states/{state_id}/finality_checkpoints` response body
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StateFinalityCheckpointsResponse {
    pub previous_justified: Checkpoint,
    pub current_justified: Checkpoint,
    pub finalized: Checkpoint,
}

/// `POST /eth/v1/beacon/states/{state_id}/builders` response body
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StateBuilderResponse {
    #[serde(with = "serde_utils::string_or_native")]
    pub index: BuilderIndex,
    pub status: BuilderStatus,
    pub builder: Builder,
}
