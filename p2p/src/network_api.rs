use eth2_libp2p::{
    types::EnrAttestationBitfield, ConnectionDirection, Enr, EnrExt as _, EnrSyncCommitteeBitfield,
    Multiaddr, PeerConnectionStatus, PeerId, PeerInfo,
};
use serde::{Deserialize, Serialize};
use types::preset::Preset;

use crate::Network;

#[derive(Deserialize, Serialize)]
pub struct NodePeersQuery {
    states: Option<Vec<PeerState>>,
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

        Some(Self {
            peer_id: peer_id.to_string(),
            enr: peer_info.enr().map(Enr::to_base64),
            last_seen_p2p_address: addr,
            state,
            direction,
        })
    }
}

#[derive(Serialize)]
pub struct NodePeerCount {
    connected: u64,
    connecting: u64,
    disconnected: u64,
    disconnecting: u64,
}

#[derive(Serialize)]
struct NodeMetadata {
    seq_number: u64,
    attnets: EnrAttestationBitfield,
    syncnets: Option<EnrSyncCommitteeBitfield>,
}

#[derive(PartialEq, Eq, Deserialize, Serialize)]
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

#[derive(PartialEq, Eq, Deserialize, Serialize)]
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

impl<P: Preset> Network<P> {
    #[must_use]
    pub fn node_identity(&self) -> NodeIdentity {
        let metadata = self.network_globals().local_metadata.read();
        let enr = self.network_globals().local_enr();

        let metadata = NodeMetadata {
            seq_number: metadata.seq_number(),
            attnets: metadata.attnets(),
            syncnets: metadata.syncnets(),
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
