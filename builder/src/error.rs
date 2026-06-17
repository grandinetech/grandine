//! Typed outcomes for builder paths that give up partway through.

use execution_engine::PayloadId;
use thiserror::Error;
use tracing::{debug, warn};
use types::{
    bellatrix::primitives::Gas,
    phase0::primitives::{Gwei, H256, Slot},
};

#[derive(Debug, Error)]
pub enum BuilderError {
    #[error("skipping bid for slot {slot}: {source}")]
    BidHandling { slot: Slot, source: BidError },
    #[error("envelope handling failed for head {head:?}: {error:?}")]
    EnvelopeHandling { head: H256, error: anyhow::Error },
    #[error("failed to refresh builder set at head {head:?}: {error:?}; the bid path will retry")]
    BuilderSetRefresh { head: H256, error: anyhow::Error },
    #[error("engine_forkchoiceUpdated failed for slot {slot}: {error:?}")]
    ForkchoiceUpdated { slot: Slot, error: anyhow::Error },
    #[error("failed to decode SSE event: {0:?}")]
    SseDecode(anyhow::Error),
    #[error("clock tick error: {0:?}")]
    ClockTick(anyhow::Error),
}

impl BuilderError {
    pub fn log(&self) {
        if self.is_debug() {
            debug!("{self}");
        } else {
            warn!("{self}");
        }
    }

    const fn is_debug(&self) -> bool {
        match self {
            Self::BidHandling { source, .. } => source.is_debug(),
            Self::BuilderSetRefresh { .. } => true,
            Self::EnvelopeHandling { .. }
            | Self::ForkchoiceUpdated { .. }
            | Self::SseDecode(_)
            | Self::ClockTick(_) => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum BidError {
    #[error("beacon head slot {head_slot} lags by more than max_empty_slots ({max_empty_slots})")]
    HeadLagging {
        head_slot: Slot,
        max_empty_slots: u64,
    },
    #[error("no proposer preferences seen for the slot")]
    NoProposerPreferences,
    #[error("no payload was prepared for the slot")]
    NoPendingBuild,
    #[error("pending build on orphaned parent {parent:?} is no longer head ({head:?})")]
    OrphanedParent { parent: H256, head: H256 },
    #[error(
        "none of our pubkeys are in the active builder set; \
         no bid can be published until one is registered and active"
    )]
    NotAnActiveBuilder { first_occurrence: bool },
    #[error("no builder can cover bid value {value} gwei")]
    NoCoverableBuilder { value: Gwei },
    #[error("failed to fetch builder set for balance check: {0:?}")]
    BuilderSetUnavailable(anyhow::Error),
    #[error("engine_getPayload failed for payload_id {payload_id:?}: {error:?}")]
    GetPayloadFailed {
        payload_id: PayloadId,
        error: anyhow::Error,
    },
    #[error("failed to sign bids: {0:?}")]
    SigningFailed(anyhow::Error),
    #[error(
        "built gas_limit {gas_limit} not target-compatible \
         (parent_gas_limit: {parent_gas_limit}, target_gas_limit: {target_gas_limit})"
    )]
    GasLimitIncompatible {
        gas_limit: Gas,
        parent_gas_limit: Gas,
        target_gas_limit: Gas,
    },
}

impl BidError {
    const fn is_debug(&self) -> bool {
        match self {
            Self::NotAnActiveBuilder { first_occurrence } => !*first_occurrence,
            Self::HeadLagging { .. }
            | Self::NoProposerPreferences
            | Self::NoPendingBuild
            | Self::OrphanedParent { .. }
            | Self::NoCoverableBuilder { .. } => true,
            Self::BuilderSetUnavailable(_)
            | Self::GetPayloadFailed { .. }
            | Self::SigningFailed(_)
            | Self::GasLimitIncompatible { .. } => false,
        }
    }
}
