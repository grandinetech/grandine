use core::time::Duration;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use educe::Educe;
use hyper::{server::conn::AddrIncoming, Result};
use tower_http::cors::AllowOrigin;

#[derive(Clone, Debug, Educe)]
#[educe(Default(expression = "Self::with_address(Ipv4Addr::LOCALHOST, 5052)"))]
pub struct HttpApiConfig {
    pub address: SocketAddr,
    pub allow_origin: AllowOrigin,
    pub max_events: usize,
    // `HttpApiConfig.timeout` is optional to prevent timeouts in tests.
    pub timeout: Option<Duration>,
}

impl HttpApiConfig {
    #[must_use]
    pub fn with_address(ip_address: impl Into<IpAddr>, port: u16) -> Self {
        let address = (ip_address, port).into();

        let allowed_origin = format!("http://{address}")
            .try_into()
            .expect("http:// followed by a socket address should be a valid header value");

        Self {
            address,
            allow_origin: AllowOrigin::list([allowed_origin]),
            max_events: 100,
            timeout: None,
        }
    }

    pub(crate) fn incoming(&self) -> Result<AddrIncoming> {
        AddrIncoming::bind(&self.address)
    }
}
