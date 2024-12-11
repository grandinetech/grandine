use core::future::Future;

use anyhow::{Error, Result};
use eth2_libp2p::GossipId;
use serde::Serialize;
use strum::IntoStaticStr;

pub enum Origin {
    Api,
    Gossip(GossipId),
}

pub enum PoolAdditionOutcome {
    Accept,
    Ignore,
    Reject(PoolRejectionReason, Error),
}

impl PoolAdditionOutcome {
    #[must_use]
    pub const fn is_publishable(&self) -> bool {
        matches!(self, Self::Accept)
    }
}

#[expect(clippy::enum_variant_names)]
#[derive(IntoStaticStr, Serialize)]
#[strum(serialize_all = "snake_case")]
pub enum PoolRejectionReason {
    InvalidAttesterSlashing,
    InvalidBlsToExecutionChange,
    InvalidContributionAndProof,
    InvalidProposerSlashing,
    InvalidSyncCommitteeMessage,
    InvalidVoluntaryExit,
}

pub trait PoolTask: Send + 'static {
    type Output: Send;

    fn run(self) -> impl Future<Output = Result<Self::Output>> + Send;
}
