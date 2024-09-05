use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use bls::AggregateSignature;
use ssz::BitVector;
use tokio::sync::RwLock;
use types::{
    altair::{
        containers::{SyncCommitteeContribution, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    phase0::primitives::{Slot, H256},
    preset::{Preset, SyncSubcommitteeSize},
};

pub type AggregateMap<P> = HashMap<ContributionData, Arc<RwLock<Vec<Aggregate<P>>>>>;
pub type SyncCommitteeMessageMap = HashMap<ContributionData, Arc<RwLock<SyncCommitteeMessageSet>>>;
pub type SyncCommitteeMessageSet = HashSet<SyncCommitteeMessage>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContributionData {
    pub slot: Slot,
    pub beacon_block_root: H256,
    pub subcommittee_index: SubcommitteeIndex,
}

impl<P: Preset> From<SyncCommitteeContribution<P>> for ContributionData {
    fn from(contribution: SyncCommitteeContribution<P>) -> Self {
        let SyncCommitteeContribution {
            slot,
            beacon_block_root,
            subcommittee_index,
            ..
        } = contribution;

        Self {
            slot,
            beacon_block_root,
            subcommittee_index,
        }
    }
}

impl ContributionData {
    pub const fn from_message(
        message: SyncCommitteeMessage,
        subcommittee_index: SubcommitteeIndex,
    ) -> Self {
        let SyncCommitteeMessage {
            slot,
            beacon_block_root,
            ..
        } = message;

        Self {
            slot,
            beacon_block_root,
            subcommittee_index,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct Aggregate<P: Preset> {
    pub aggregation_bits: BitVector<SyncSubcommitteeSize<P>>,
    pub signature: AggregateSignature,
}
