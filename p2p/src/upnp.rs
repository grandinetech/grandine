use core::net::SocketAddr;

use anyhow::Result;
use eth2_libp2p::{ListenAddress, NetworkConfig};
use igd_next::{Gateway, PortMappingProtocol, SearchOptions};
use logging::{info_with_peers, warn_with_peers};

pub struct PortMappings {
    udp_mapping: u16,
}

impl Drop for PortMappings {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            warn_with_peers!("Unable to remove UPnP port mappings: {error}");
        }
    }
}

// TCP/QUIC port mappings are covered by `libp2p::upnp`
impl PortMappings {
    pub fn new(network_config: &NetworkConfig) -> Result<Self> {
        let gateway = igd_next::search_gateway(SearchOptions::default())?;
        let external_ip = gateway.get_external_ip()?;
        let udp_port = network_config.listen_addrs().udp_port();
        let upnp_udp_socket_addr = SocketAddr::new(external_ip, udp_port);

        let local_udp_addr = match network_config.listen_addrs() {
            ListenAddress::V4(addr) | ListenAddress::DualStack(addr, _) => {
                addr.discovery_socket_addr()
            }
            ListenAddress::V6(addr) => addr.discovery_socket_addr(),
        };

        gateway.add_port(
            PortMappingProtocol::UDP,
            udp_port,
            local_udp_addr,
            0,
            "grandine-upnp-udp",
        )?;

        info_with_peers!(
            "created UPnP mapping for discovery service {local_udp_addr}/{upnp_udp_socket_addr}"
        );

        Ok(Self {
            udp_mapping: udp_port,
        })
    }

    fn remove(&self) -> Result<()> {
        let gateway = igd_next::search_gateway(SearchOptions::default())?;
        remove_upnp_mapping(&gateway, PortMappingProtocol::UDP, self.udp_mapping);
        Ok(())
    }
}

fn remove_upnp_mapping(gateway: &Gateway, protocol: PortMappingProtocol, external_port: u16) {
    match gateway.remove_port(protocol, external_port) {
        Ok(()) => info_with_peers!("Removed UPnP mapping for {protocol} port {external_port}"),
        Err(error) => {
            warn_with_peers!(
                "Unable to remove UPnP mapping for {protocol} port {external_port}: {error}"
            );
        }
    }
}
