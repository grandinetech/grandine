use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_with::{As, DisplayFromStr};
use strum::IntoStaticStr;
use types::phase0::primitives::{CommitteeIndex, Epoch, Slot, SubnetId, ValidatorIndex};

pub type RequestId = usize;

#[derive(PartialEq, Eq)]
pub enum RPCRequestType {
    Range,
    Root,
}

#[derive(Debug, Serialize)]
pub struct AttestationSubnetActions {
    pub discoveries: Vec<SubnetPeerDiscovery>,
    pub enr: BTreeMap<SubnetId, bool>,
    pub subscriptions: BTreeMap<SubnetId, bool>,
}

impl AttestationSubnetActions {
    pub fn is_empty(&self) -> bool {
        self.discoveries.is_empty() && self.enr.is_empty() && self.subscriptions.is_empty()
    }
}

#[derive(Debug, Serialize)]
pub struct SubnetPeerDiscovery {
    pub subnet_id: SubnetId,
    pub expiration: Option<Slot>,
}

// All sync committee members must be subscribed to ensure subnet stability,
// so it doesn't make sense to discover peers while unsubscribed.
// This is why `Unsubscribe` does not have a `discover_peers` field.
// `Subscribe` and `DiscoverPeers` are only separate to make log messages more precise.
#[derive(Serialize)]
pub enum SyncCommitteeSubnetAction {
    /// Subscribe and discover peers.
    Subscribe,
    /// Discover peers but do not subscribe.
    DiscoverPeers,
    Unsubscribe,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeaconCommitteeSubscription {
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub committee_index: CommitteeIndex,
    #[serde(with = "serde_utils::string_or_native")]
    pub committees_at_slot: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub is_aggregator: bool,
}

#[derive(IntoStaticStr)]
pub enum PeerReportReason {
    ExpiredSyncBatch,
}

#[derive(PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncCommitteeSubscription {
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    #[serde(with = "As::<Vec<DisplayFromStr>>")]
    pub sync_committee_indices: Vec<usize>,
    #[serde(with = "serde_utils::string_or_native")]
    pub until_epoch: Epoch,
}
