use core::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashSet, sync::Arc};

use arc_swap::ArcSwap;
use derive_more::Debug;
use itertools::Itertools as _;
use std_ext::ArcExt as _;
use types::redacting_url::RedactingUrl;

use crate::ClientVersionV1;

const ORDERING: Ordering = Ordering::SeqCst;

pub type ClientVersions = Vec<ClientVersionV1>;

#[derive(Debug)]
#[expect(clippy::partial_pub_fields)]
pub struct Endpoint {
    is_online: AtomicBool,
    pub is_fallback: bool,
    pub url: RedactingUrl,
    capabilities: ArcSwap<HashSet<String>>,
    client_versions: ArcSwap<ClientVersions>,
}

impl Endpoint {
    pub const fn url(&self) -> &RedactingUrl {
        &self.url
    }

    pub fn is_online(&self) -> bool {
        self.is_online.load(ORDERING)
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

pub struct Endpoints {
    endpoints: Vec<Endpoint>,
}

impl Endpoints {
    pub fn new(urls: impl IntoIterator<Item = RedactingUrl>) -> Self {
        let endpoints = urls
            .into_iter()
            .enumerate()
            .map(|(index, url)| Endpoint {
                is_online: AtomicBool::new(true),
                is_fallback: index > 0,
                url,
                capabilities: ArcSwap::from_pointee(HashSet::default()),
                client_versions: ArcSwap::from_pointee(vec![]),
            })
            .collect();

        Self { endpoints }
    }

    pub const fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    pub fn el_offline(&self) -> bool {
        self.endpoints.iter().all(|endpoint| !endpoint.is_online())
    }

    pub fn endpoints_for_request(
        &self,
        capability: Option<&str>,
    ) -> impl Iterator<Item = &Endpoint> {
        self.endpoints
            .iter()
            .filter(|endpoint| {
                capability
                    .map(|capability| endpoint.capabilities.load().contains(capability))
                    .unwrap_or(true)
            })
            .sorted_by_key(|endpoint| !endpoint.is_online())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use anyhow::Result;

    use crate::{endpoints::Endpoints, eth1_api::ENGINE_GET_EL_BLOBS_V1};

    #[test]
    fn test_empty_endpoints() {
        let endpoints = Endpoints::new([]);

        assert!(endpoints.is_empty());
        assert!(endpoints.el_offline());

        let mut endpoints_for_request = endpoints.endpoints_for_request(None);

        assert!(endpoints_for_request.next().is_none());
    }

    #[test]
    fn test_endpoints() -> Result<()> {
        let endpoints = Endpoints::new([
            "https://example1.net".parse()?,
            "https://example2.net".parse()?,
        ]);

        assert!(!endpoints.is_empty());
        assert!(!endpoints.el_offline(), "initially endpoints are online");

        assert_eq!(
            endpoints
                .endpoints_for_request(None)
                .map(|endpoint| (endpoint.url().clone(), endpoint.is_online()))
                .collect::<Vec<_>>(),
            [
                ("https://example1.net".parse()?, true),
                ("https://example2.net".parse()?, true),
            ]
        );

        // set first endpoint to be offline
        let current_endpoint = endpoints
            .endpoints_for_request(None)
            .next()
            .expect("current endpoint should be present");

        current_endpoint.set_online_status(false);

        assert!(!current_endpoint.is_online());
        assert!(!endpoints.el_offline());

        // check that online endpoint is used for requests
        assert_eq!(
            endpoints
                .endpoints_for_request(None)
                .map(|endpoint| (endpoint.url().clone(), endpoint.is_online()))
                .collect::<Vec<_>>(),
            [
                ("https://example2.net".parse()?, true),
                ("https://example1.net".parse()?, false),
            ]
        );

        // set the fallback endpoint to be offline
        let current_endpoint = endpoints
            .endpoints_for_request(None)
            .next()
            .expect("current endpoint should be present");

        current_endpoint.set_online_status(false);

        assert!(!current_endpoint.is_online());
        assert!(endpoints.el_offline());

        assert_eq!(
            endpoints
                .endpoints_for_request(None)
                .map(|endpoint| (endpoint.url().clone(), endpoint.is_online()))
                .collect::<Vec<_>>(),
            [
                ("https://example1.net".parse()?, false),
                ("https://example2.net".parse()?, false),
            ]
        );

        Ok(())
    }

    #[test]
    fn test_endpoints_with_capabilities() -> Result<()> {
        let endpoints = Endpoints::new([
            "https://example1.net".parse()?,
            "https://example2.net".parse()?,
        ]);

        assert!(endpoints
            .endpoints_for_request(Some(ENGINE_GET_EL_BLOBS_V1))
            .next()
            .is_none());

        let current_endpoint = endpoints
            .endpoints_for_request(None)
            .next()
            .expect("current endpoint should be present");

        current_endpoint.set_capabilities(HashSet::from([ENGINE_GET_EL_BLOBS_V1.to_owned()]));

        assert_eq!(
            endpoints
                .endpoints_for_request(Some(ENGINE_GET_EL_BLOBS_V1))
                .map(|endpoint| endpoint.url().clone())
                .collect::<Vec<_>>(),
            ["https://example1.net".parse()?]
        );

        Ok(())
    }
}
