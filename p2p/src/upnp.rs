use std::net::{IpAddr, SocketAddr, SocketAddrV4};

use anyhow::{bail, Result};
use eth2_libp2p::{service::Network as Service, NetworkConfig};
use igd::{Gateway, PortMappingProtocol, SearchOptions};
use log::{info, warn};
use thiserror::Error;
use types::preset::Preset;

use crate::misc::RequestId;

#[allow(clippy::struct_field_names)]
pub struct PortMappings {
    tcp_mapping: u16,
    udp_mapping: Option<u16>,
    quic_mapping: Option<u16>,
}

impl Drop for PortMappings {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            warn!("Unable to remove UPnP port mappings: {error}");
        }
    }
}

impl PortMappings {
    pub fn new<P: Preset>(
        service: &mut Service<RequestId, P>,
        network_config: &NetworkConfig,
    ) -> Result<Self> {
        let gateway = igd::search_gateway(SearchOptions::default())?;
        let external_ip = IpAddr::V4(gateway.get_external_ip()?);
        let interfaces = if_addrs::get_if_addrs()?;

        // Find some local IPv4 interface (`gateway::add_port` expects `SocketAddrV4`).
        let interface = interfaces
            .iter()
            .find(|interface| !interface.is_loopback() && interface.ip().is_ipv4())
            .ok_or(Error::MissingLocalAddress)?;

        let local_address = match interface.ip() {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => bail!(Error::MissingCanonicalLocalAddress),
        };

        // Construct TCP mapping.
        let tcp_port = network_config.listen_addrs().tcp_port();
        let local_tcp_addr = SocketAddrV4::new(local_address, tcp_port);
        let upnp_tcp_socket_addr = SocketAddr::new(external_ip, tcp_port);

        info!("Creating UPnP mapping for local TCP port {upnp_tcp_socket_addr}:{tcp_port}");

        gateway.add_port(
            PortMappingProtocol::TCP,
            tcp_port,
            local_tcp_addr,
            0,
            "grandine-upnp-tcp",
        )?;

        // `eth2_libp2p` documentation for `Discovery::update_enr_tcp_port` says:
        // > Updates the local ENR TCP port.
        // > There currently isn't a case to update the address here. We opt for discovery to
        // > automatically update the external address.
        if let Err(error) = service.discovery_mut().update_enr_tcp_port(tcp_port) {
            warn!("Unable to update enr TCP socket: {error}");
        }

        // Construct UDP mapping.
        let udp_port = if network_config.disable_discovery {
            warn!("Discv5 service is disabled");

            None
        } else {
            let udp_port = network_config.listen_addrs().udp_port();
            let local_udp_addr = SocketAddrV4::new(local_address, udp_port);
            let upnp_udp_socket_addr = SocketAddr::new(external_ip, udp_port);

            info!("Creating UPnP mapping for local UDP port {upnp_udp_socket_addr}:{udp_port}");

            if let Err(error) = gateway.add_port(
                PortMappingProtocol::UDP,
                udp_port,
                local_udp_addr,
                0,
                "grandine-upnp-udp",
            ) {
                warn!("Unable to create UPnP mapping: {error}");
                None
            } else {
                if let Err(error) = service
                    .discovery_mut()
                    .update_enr_udp_socket(upnp_udp_socket_addr)
                {
                    warn!("Unable to update ENR UDP socket: {error}");
                }

                Some(udp_port)
            }
        };

        // Construct QUIC mapping
        let quic_port = if network_config.disable_quic_support {
            None
        } else {
            let quic_port = network_config.listen_addrs().quic_port();
            let local_quic_addr = SocketAddrV4::new(local_address, quic_port);
            let upnp_quic_socket_addr = SocketAddr::new(external_ip, quic_port);

            info!("Creating UPnP mapping for QUIC UDP port {upnp_quic_socket_addr}:{quic_port}");

            if let Err(error) = gateway.add_port(
                PortMappingProtocol::UDP,
                quic_port,
                local_quic_addr,
                0,
                "grandine-quic-udp",
            ) {
                warn!("Unable to create UPnP mapping: {error}");
                None
            } else {
                if let Err(error) = service.discovery_mut().update_enr_quic_port(quic_port) {
                    warn!("Unable to update QUIC ENR port: {error}");
                }

                Some(quic_port)
            }
        };

        Ok(Self {
            tcp_mapping: tcp_port,
            udp_mapping: udp_port,
            quic_mapping: quic_port,
        })
    }

    fn remove(&self) -> Result<()> {
        let gateway = igd::search_gateway(SearchOptions::default())?;

        remove_upnp_mapping(&gateway, PortMappingProtocol::TCP, self.tcp_mapping);

        if let Some(udp_mapping) = self.udp_mapping {
            remove_upnp_mapping(&gateway, PortMappingProtocol::UDP, udp_mapping);
        }

        if let Some(quic_mapping) = self.quic_mapping {
            remove_upnp_mapping(&gateway, PortMappingProtocol::UDP, quic_mapping);
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("unable to find local IP address")]
    MissingLocalAddress,
    #[error("unable to find canonical local IP address")]
    MissingCanonicalLocalAddress,
}

fn remove_upnp_mapping(gateway: &Gateway, protocol: PortMappingProtocol, external_port: u16) {
    match gateway.remove_port(protocol, external_port) {
        Ok(()) => info!("Removed UPnP mapping for {protocol} port {external_port}"),
        Err(error) => {
            warn!("Unable to remove UPnP mapping for {protocol} port {external_port}: {error}");
        }
    }
}
