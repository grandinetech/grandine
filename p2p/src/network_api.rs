use eth2_libp2p::{
    ConnectionDirection, Enr, EnrExt as _, EnrSyncCommitteeBitfield, Multiaddr,
    PeerConnectionStatus, PeerId, PeerInfo, types::EnrAttestationBitfield,
};
use fork_choice_control::Wait;
use serde::{Deserialize, Serialize};
use types::preset::Preset;

use crate::Network;

/// Translates Grandine's internal disconnect reason tag (the `reason` field on
/// `LastDisconnect`, which is a `'static` variant name of `GoodbyeReason`)
/// into the simplified `PeerDisconnectReason` vocabulary defined by the
/// beacon-API peer-scoring proposal.
fn map_disconnect_reason(reason: &str) -> &'static str {
    match reason {
        "BadScore" | "Banned" | "BannedIP" => "bad_score",
        "ClientShutdown" => "client_shutdown",
        "IrrelevantNetwork" => "irrelevant_network",
        "UnableToVerifyNetwork" => "unviable_fork",
        "TooManyPeers" => "too_many_peers",
        "Fault" => "io_error",
        _ => "unknown",
    }
}

/// Translates Grandine's internal downscore reason tag (the `reason` field on
/// `LastAction`, e.g. tags emitted by `rpc_error_msg` or report-peer call
/// sites) into the simplified `PeerScoreReason` vocabulary defined by the
/// beacon-API peer-scoring proposal.
fn map_downscore_reason(reason: &str) -> &'static str {
    match reason {
        "rpc_invalid_request" => "rpc_invalid_request",
        "rpc_rate_limited" => "rpc_rate_limited",
        "rpc_io_error" => "rpc_io_error",
        "rpc_stream_timeout" | "rpc_negotiation_timeout" => "rpc_timeout",
        "rpc_invalid_data" | "rpc_ssz_decode_error" => "rpc_invalid_response",
        _ => "unknown",
    }
}

#[derive(Debug, Deserialize)]
pub struct NodePeersQuery {
    #[serde(rename(deserialize = "state"))]
    states: Option<Vec<PeerState>>,
    #[serde(rename(deserialize = "direction"))]
    directions: Option<Vec<PeerDirection>>,
}

#[derive(Serialize)]
pub struct NodeIdentity {
    peer_id: String,
    enr: Enr,
    p2p_addresses: Vec<Multiaddr>,
    discovery_addresses: Vec<Multiaddr>,
    metadata: NodeMetadata,
}

#[derive(Serialize)]
pub struct NodePeer {
    peer_id: String,
    enr: Option<String>,
    last_seen_p2p_address: Multiaddr,
    state: PeerState,
    direction: PeerDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disconnect_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    downscore_reasons: Option<Vec<String>>,
}

impl NodePeer {
    fn from_peer_info(peer_info: &PeerInfo, peer_id: &PeerId) -> Option<Self> {
        let addr = peer_info
            .listening_addresses()
            .first()
            .cloned()
            .unwrap_or_else(Multiaddr::empty);

        let state = PeerState::try_from(peer_info.connection_status())?;

        let direction = peer_info.connection_direction().map(Into::into)?;

        let agent_version = peer_info.client().agent_string.clone();
        let score = Some(peer_info.score().score());
        // Per beacon-API spec, `disconnect_reason` MUST only be populated when
        // `state` is `disconnected` or `disconnecting`.
        let disconnect_reason = if matches!(
            state,
            PeerState::Disconnected | PeerState::Disconnecting
        ) {
            peer_info
                .last_disconnect()
                .map(|d| map_disconnect_reason(d.reason).to_string())
        } else {
            None
        };
        let downscore_reasons = peer_info
            .last_action()
            .map(|a| vec![map_downscore_reason(a.reason).to_string()]);

        Some(Self {
            peer_id: peer_id.to_string(),
            enr: peer_info.enr().map(Enr::to_base64),
            last_seen_p2p_address: addr,
            state,
            direction,
            agent_version,
            score,
            disconnect_reason,
            downscore_reasons,
        })
    }
}

pub struct NodePeerCount {
    pub connected: u64,
    pub connecting: u64,
    pub disconnected: u64,
    pub disconnecting: u64,
}

#[derive(Serialize)]
struct NodeMetadata {
    #[serde(with = "serde_utils::string_or_native")]
    seq_number: u64,
    attnets: EnrAttestationBitfield,
    syncnets: Option<EnrSyncCommitteeBitfield>,
    #[serde(with = "serde_utils::string_or_native")]
    custody_group_count: u64,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum PeerState {
    Connected,
    Connecting,
    Disconnected,
    Disconnecting,
}

impl PeerState {
    // TODO(Grandine Team): This could be simplified if `PeerConnectionStatus` implemented `Copy`.
    const fn try_from(status: &PeerConnectionStatus) -> Option<Self> {
        match status {
            PeerConnectionStatus::Connected { .. } => Some(Self::Connected),
            PeerConnectionStatus::Dialing { .. } => Some(Self::Connecting),
            PeerConnectionStatus::Disconnected { .. } => Some(Self::Disconnected),
            PeerConnectionStatus::Disconnecting { .. } => Some(Self::Disconnecting),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum PeerDirection {
    Inbound,
    Outbound,
}

// TODO(Grandine Team): This could be simplified if `ConnectionDirection` implemented `Copy`.
impl From<&ConnectionDirection> for PeerDirection {
    fn from(direction: &ConnectionDirection) -> Self {
        match direction {
            ConnectionDirection::Incoming => Self::Inbound,
            ConnectionDirection::Outgoing => Self::Outbound,
        }
    }
}

impl<P: Preset, W: Wait> Network<P, W> {
    #[must_use]
    pub fn node_identity(&self) -> NodeIdentity {
        let metadata = self.network_globals().local_metadata.read();
        let enr = self.network_globals().local_enr();

        let metadata = NodeMetadata {
            seq_number: metadata.seq_number(),
            attnets: metadata.attnets(),
            syncnets: metadata.syncnets(),
            custody_group_count: metadata.custody_group_count().unwrap_or(0),
        };

        NodeIdentity {
            peer_id: self.network_globals().local_peer_id().to_base58(),
            p2p_addresses: enr.multiaddr_p2p_tcp(),
            discovery_addresses: enr.multiaddr_p2p_udp(),
            enr,
            metadata,
        }
    }

    #[must_use]
    pub fn node_peer_count(&self) -> NodePeerCount {
        let mut connected = 0;
        let mut connecting = 0;
        let mut disconnected = 0;
        let mut disconnecting = 0;

        self.network_globals()
            .peers
            .read()
            .peers()
            .filter_map(|(_, peer_info)| PeerState::try_from(peer_info.connection_status()))
            .for_each(|peer_state| match peer_state {
                PeerState::Connected => connected += 1,
                PeerState::Connecting => connecting += 1,
                PeerState::Disconnected => disconnected += 1,
                PeerState::Disconnecting => disconnecting += 1,
            });

        NodePeerCount {
            connected,
            connecting,
            disconnected,
            disconnecting,
        }
    }

    #[must_use]
    pub fn node_peers(&self, query: &NodePeersQuery) -> Vec<NodePeer> {
        self.network_globals()
            .peers
            .read()
            .peers()
            .filter_map(|(peer_id, peer_info)| {
                let state = PeerState::try_from(peer_info.connection_status())?;

                let direction = peer_info.connection_direction()?.into();

                let allowed_by_direction = query
                    .directions
                    .as_ref()
                    .map(|directions| directions.contains(&direction))
                    .unwrap_or(true);

                let allowed_by_state = query
                    .states
                    .as_ref()
                    .map(|states| states.contains(&state))
                    .unwrap_or(true);

                (allowed_by_direction && allowed_by_state)
                    .then(|| NodePeer::from_peer_info(peer_info, peer_id))
                    .flatten()
            })
            .collect()
    }

    #[must_use]
    pub fn node_peer(&self, peer_id: &PeerId) -> Option<NodePeer> {
        self.network_globals()
            .peers
            .read()
            .peer_info(peer_id)
            .and_then(|peer_info| NodePeer::from_peer_info(peer_info, peer_id))
    }
}
