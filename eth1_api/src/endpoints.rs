use derive_more::Debug;
use types::redacting_url::RedactingUrl;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum EndpointStatus {
    Online,
    Offline,
}

impl EndpointStatus {
    const fn is_offline(self) -> bool {
        matches!(self, Self::Offline)
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Endpoint {
    index: usize,
    status: EndpointStatus,
    url: RedactingUrl,
}

impl Endpoint {
    pub const fn url(&self) -> &RedactingUrl {
        &self.url
    }

    pub const fn is_fallback(&self) -> bool {
        self.index > 0
    }
}

pub struct Endpoints {
    current: usize,
    endpoints: Vec<Endpoint>,
}

impl Endpoints {
    pub fn new(urls: impl IntoIterator<Item = RedactingUrl>) -> Self {
        let endpoints = urls
            .into_iter()
            .enumerate()
            .map(|(index, url)| Endpoint {
                index,
                status: EndpointStatus::Online,
                url,
            })
            .collect();

        Self {
            current: 0,
            endpoints,
        }
    }

    pub fn el_offline(&self) -> bool {
        self.endpoints
            .iter()
            .all(|endpoint| endpoint.status.is_offline())
    }

    pub fn current(&self) -> Option<&Endpoint> {
        self.endpoints.get(self.current)
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    pub fn peek_next(&self) -> Option<&Endpoint> {
        self.endpoints.get(self.next_index())
    }

    pub fn advance(&mut self) {
        self.current = self.next_index();
    }

    pub fn set_status(&mut self, status: EndpointStatus) {
        if let Some(current) = self.current_mut() {
            current.status = status;
        }
    }

    pub fn reset(&mut self) {
        self.current = 0;
    }

    const fn next_index(&self) -> usize {
        self.current.saturating_add(1)
    }

    fn current_mut(&mut self) -> Option<&mut Endpoint> {
        self.endpoints.get_mut(self.current)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::endpoints::{Endpoint, EndpointStatus, Endpoints};

    #[test]
    fn test_empty_endpoints() {
        let endpoints = Endpoints::new([]);

        assert!(endpoints.is_empty());
        assert!(endpoints.el_offline());

        assert_eq!(endpoints.current(), None);
        assert_eq!(endpoints.peek_next(), None);
    }

    #[test]
    fn test_endpoints() -> Result<()> {
        let mut endpoints = Endpoints::new([
            "https://example1.net".parse()?,
            "https://example2.net".parse()?,
        ]);

        assert!(!endpoints.is_empty());
        assert!(!endpoints.el_offline(), "initially endpoints are online");

        assert_eq!(
            endpoints.current().cloned(),
            Some(Endpoint {
                index: 0,
                status: EndpointStatus::Online,
                url: "https://example1.net".parse()?,
            }),
        );

        assert_eq!(
            endpoints.peek_next().cloned(),
            Some(Endpoint {
                index: 1,
                status: EndpointStatus::Online,
                url: "https://example2.net".parse()?,
            }),
        );

        endpoints.set_status(EndpointStatus::Offline);

        assert_eq!(
            endpoints.current().map(|endpoint| endpoint.status),
            Some(EndpointStatus::Offline),
        );

        endpoints.advance();

        assert_eq!(
            endpoints.current().cloned(),
            Some(Endpoint {
                index: 1,
                status: EndpointStatus::Online,
                url: "https://example2.net".parse()?,
            }),
        );

        assert_eq!(endpoints.peek_next(), None);
        assert!(!endpoints.el_offline());

        endpoints.set_status(EndpointStatus::Offline);
        endpoints.advance();

        assert!(!endpoints.is_empty());
        assert!(endpoints.el_offline());

        assert_eq!(endpoints.current(), None);
        assert_eq!(endpoints.peek_next(), None);

        endpoints.reset();

        // offline endpoints are still offline after reset
        assert!(endpoints.el_offline());

        assert_eq!(
            endpoints.current().cloned(),
            Some(Endpoint {
                index: 0,
                status: EndpointStatus::Offline,
                url: "https://example1.net".parse()?,
            }),
        );

        assert_eq!(
            endpoints.peek_next().cloned(),
            Some(Endpoint {
                index: 1,
                status: EndpointStatus::Offline,
                url: "https://example2.net".parse()?,
            }),
        );

        Ok(())
    }
}
