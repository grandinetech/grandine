use core::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashSet, sync::Arc};

use arc_swap::ArcSwap;
use derive_more::Debug;
use std_ext::ArcExt as _;
use types::redacting_url::RedactingUrl;

use crate::ClientVersionV1;

const ORDERING: Ordering = Ordering::SeqCst;

pub type ClientVersions = Vec<ClientVersionV1>;

#[derive(Debug)]
pub struct Endpoint {
    is_online: AtomicBool,
    url: RedactingUrl,
    capabilities: ArcSwap<HashSet<String>>,
    client_versions: ArcSwap<ClientVersions>,
}

impl Endpoint {
    #[must_use]
    pub fn new(url: RedactingUrl) -> Self {
        Self {
            is_online: AtomicBool::new(true),
            url,
            capabilities: ArcSwap::from_pointee(HashSet::default()),
            client_versions: ArcSwap::from_pointee(vec![]),
        }
    }

    pub const fn url(&self) -> &RedactingUrl {
        &self.url
    }

    pub fn is_online(&self) -> bool {
        self.is_online.load(ORDERING)
    }

    pub fn supports(&self, capability: &str) -> bool {
        self.capabilities.load().contains(capability)
    }

    pub fn set_capabilities(&self, capabilities: HashSet<String>) {
        self.capabilities.store(Arc::new(capabilities));
    }

    pub fn set_client_versions(&self, client_versions: Vec<ClientVersionV1>) {
        self.client_versions.store(Arc::new(client_versions));
    }

    pub fn get_client_versions(&self) -> Arc<ClientVersions> {
        self.client_versions.load().clone_arc()
    }

    pub fn set_online_status(&self, is_online: bool) {
        self.is_online.store(is_online, ORDERING)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use anyhow::Result;

    use crate::{endpoints::Endpoint, eth1_api::ENGINE_GET_EL_BLOBS_V1};

    #[test]
    fn test_endpoint_online_status() -> Result<()> {
        let endpoint = Endpoint::new("https://example.net".parse()?);

        assert!(endpoint.is_online(), "initially the endpoint is online");
        endpoint.set_online_status(false);
        assert!(!endpoint.is_online());

        Ok(())
    }

    #[test]
    fn test_endpoint_capabilities() -> Result<()> {
        let endpoint = Endpoint::new("https://example.net".parse()?);

        assert!(!endpoint.supports(ENGINE_GET_EL_BLOBS_V1));
        endpoint.set_capabilities(HashSet::from([ENGINE_GET_EL_BLOBS_V1.to_owned()]));
        assert!(endpoint.supports(ENGINE_GET_EL_BLOBS_V1));

        Ok(())
    }
}
