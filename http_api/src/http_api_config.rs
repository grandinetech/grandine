use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use tokio::net::TcpListener;
use tower_http::cors::AllowOrigin;

#[derive(Clone, Debug)]
pub struct HttpApiConfig {
    pub address: SocketAddr,
    pub allow_origin: AllowOrigin,
    // `HttpApiConfig.timeout` is optional to prevent timeouts in tests.
    pub timeout: Option<Duration>,
}

impl Default for HttpApiConfig {
    fn default() -> Self {
        Self::with_address(Ipv4Addr::LOCALHOST, 5052)
    }
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
            timeout: None,
        }
    }

    pub(crate) async fn listener(&self) -> Result<TcpListener> {
        TcpListener::bind(&self.address).await.map_err(Into::into)
    }
}
