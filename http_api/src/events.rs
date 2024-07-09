use axum::{response::sse::Event, Error};
use serde::Serialize;
use serde_with::DeserializeFromStr;
use strum::{AsRefStr, EnumString};
use tokio::sync::broadcast::{self, Receiver, Sender};

#[derive(Clone, Copy, AsRefStr, EnumString, DeserializeFromStr)]
#[strum(serialize_all = "snake_case")]
pub enum Topic {
    Attestation,
    Block,
    BlsToExecutionChange,
    ChainReorg,
    ContributionAndProof,
    FinalizedCheckpoint,
    Head,
    VoluntaryExit,
}

impl Topic {
    pub fn build(self, data: impl Serialize) -> Result<Event, Error> {
        Event::default().event(self).json_data(data)
    }
}

pub struct EventChannels {
    pub attestations: Sender<Event>,
    pub blocks: Sender<Event>,
    pub bls_to_execution_changes: Sender<Event>,
    pub chain_reorgs: Sender<Event>,
    pub contribution_and_proofs: Sender<Event>,
    pub finalized_checkpoints: Sender<Event>,
    pub heads: Sender<Event>,
    pub voluntary_exits: Sender<Event>,
}

impl EventChannels {
    pub fn new(max_events: usize) -> Self {
        Self {
            attestations: broadcast::channel(max_events).0,
            blocks: broadcast::channel(max_events).0,
            bls_to_execution_changes: broadcast::channel(max_events).0,
            chain_reorgs: broadcast::channel(max_events).0,
            contribution_and_proofs: broadcast::channel(max_events).0,
            finalized_checkpoints: broadcast::channel(max_events).0,
            heads: broadcast::channel(max_events).0,
            voluntary_exits: broadcast::channel(max_events).0,
        }
    }

    pub fn receiver_for(&self, topic: Topic) -> Receiver<Event> {
        match topic {
            Topic::Attestation => &self.attestations,
            Topic::Block => &self.blocks,
            Topic::BlsToExecutionChange => &self.bls_to_execution_changes,
            Topic::ChainReorg => &self.chain_reorgs,
            Topic::ContributionAndProof => &self.contribution_and_proofs,
            Topic::FinalizedCheckpoint => &self.finalized_checkpoints,
            Topic::Head => &self.heads,
            Topic::VoluntaryExit => &self.voluntary_exits,
        }
        .subscribe()
    }
}
