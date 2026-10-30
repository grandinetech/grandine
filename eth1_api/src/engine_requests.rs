use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow, ensure};
use execution_engine::{PayloadStatusV1, PayloadValidationStatus};
use futures::channel::oneshot;
use logging::{error_with_peers, warn_with_peers};
use reqwest::Client;
use serde_json::Value;
use tokio::task::JoinHandle;
use web3::{Transport as _, Web3, api::Namespace as _, helpers::CallFuture, transports::Http};

use crate::{auth::Auth, endpoints::Endpoint};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Payload,
    Forkchoice,
}

#[derive(Clone)]
pub struct Request {
    sequence: u64,
    kind: Kind,
    method: &'static str,
    params: Arc<[Value]>,
    timeout: core::time::Duration,
    observations: Arc<Mutex<Observations>>,
}

impl Request {
    pub fn new(
        sequence: u64,
        kind: Kind,
        method: &'static str,
        params: Vec<Value>,
        timeout: core::time::Duration,
    ) -> Self {
        Self {
            sequence,
            kind,
            method,
            params: params.into(),
            timeout,
            observations: Arc::default(),
        }
    }

    pub fn select(&self, endpoint: usize) {
        let mut observations = self
            .observations
            .lock()
            .expect("engine observations poisoned");
        observations.selected = Some(endpoint);
        observations.check(self.method, self.sequence);
    }

    fn mirror(&self) -> Self {
        let mut request = self.clone();
        if request.kind == Kind::Forkchoice {
            Arc::make_mut(&mut request.params)[1] = Value::Null;
        }
        request
    }
}

#[derive(Default)]
struct Observations {
    selected: Option<usize>,
    responses: Vec<(usize, PayloadValidationStatus)>,
    reported: bool,
}

impl Observations {
    fn check(&mut self, method: &str, sequence: u64) {
        let Some(selected) = self.selected else {
            return;
        };
        if self.reported {
            return;
        }
        let Some((_, selected_status)) =
            self.responses.iter().rev().find(|(id, _)| *id == selected)
        else {
            return;
        };
        for (endpoint, status) in &self.responses {
            if (selected_status.is_valid() && status.is_invalid())
                || (selected_status.is_invalid() && status.is_valid())
            {
                error_with_peers!(
                    "execution clients disagree on {method} request {sequence}: selected endpoint {selected} \
                     returned {selected_status:?}, endpoint {endpoint} returned {status:?}"
                );
                self.reported = true;
                break;
            }
        }
    }
}

struct Job {
    request: Request,
    reply: Option<oneshot::Sender<Result<Value>>>,
}

#[derive(Default)]
struct Queue {
    foreground: Option<Job>,
    payload: Option<Job>,
    forkchoice: Option<Job>,
    running: bool,
    last_forkchoice: u64,
    closed: bool,
}

impl Queue {
    fn next(&mut self) -> Option<Job> {
        loop {
            let job = if let Some(job) = self.foreground.take() {
                job
            } else {
                match (&self.payload, &self.forkchoice) {
                    (Some(payload), Some(forkchoice))
                        if payload.request.sequence < forkchoice.request.sequence =>
                    {
                        self.payload.take()?
                    }
                    (_, Some(_)) => self.forkchoice.take()?,
                    (Some(_), None) => self.payload.take()?,
                    (None, None) => return None,
                }
            };
            if job.reply.as_ref().is_some_and(oneshot::Sender::is_canceled) {
                continue;
            }
            if job.request.kind == Kind::Forkchoice {
                if job.request.sequence < self.last_forkchoice {
                    continue;
                }
                self.last_forkchoice = job.request.sequence;
            }
            return Some(job);
        }
    }
}

struct EndpointRequests {
    queue: Arc<Mutex<Queue>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    endpoint: Arc<Endpoint>,
    client: Client,
    auth: Arc<Auth>,
}

impl Drop for EndpointRequests {
    fn drop(&mut self) {
        self.close();
    }
}

impl EndpointRequests {
    fn close(&self) {
        let mut worker = self.worker.lock().expect("engine worker poisoned");
        *self.queue.lock().expect("engine queue poisoned") = Queue {
            closed: true,
            ..Queue::default()
        };
        if let Some(worker) = worker.take() {
            worker.abort();
        }
    }

    fn enqueue(&self, job: Job) -> Result<()> {
        let mut worker = self.worker.lock().expect("engine worker poisoned");
        let mut queue = self.queue.lock().expect("engine queue poisoned");
        ensure!(!queue.closed, "engine request dispatcher is stopped");
        if job.reply.is_some() {
            let pending = match job.request.kind {
                Kind::Payload => &mut queue.payload,
                Kind::Forkchoice => &mut queue.forkchoice,
            };
            if pending
                .as_ref()
                .is_some_and(|old| old.request.sequence <= job.request.sequence)
            {
                *pending = None;
            }
        }
        let slot = match (job.reply.is_some(), job.request.kind) {
            (true, _) => &mut queue.foreground,
            (false, Kind::Payload) => &mut queue.payload,
            (false, Kind::Forkchoice) => &mut queue.forkchoice,
        };
        ensure!(
            job.reply.is_none()
                || slot
                    .as_ref()
                    .is_none_or(|old| old.reply.as_ref().is_some_and(oneshot::Sender::is_canceled)),
            "concurrent foreground engine requests"
        );
        *slot = Some(job);
        if queue.running {
            return Ok(());
        }
        queue.running = true;
        let queue = Arc::clone(&self.queue);
        let endpoint = Arc::clone(&self.endpoint);
        let client = self.client.clone();
        let auth = Arc::clone(&self.auth);
        *worker = Some(tokio::spawn(async move {
            loop {
                let job = {
                    let mut queue = queue.lock().expect("engine queue poisoned");
                    let Some(job) = queue.next() else {
                        queue.running = false;
                        return;
                    };
                    job
                };
                let request = &job.request;
                let response: Result<(Value, PayloadValidationStatus)> = async {
                    let api = Web3::new(Http::with_client(
                        client.clone(),
                        endpoint.url().clone().into_url(),
                    ))
                    .eth();
                    let value: Value = CallFuture::new(api.transport().execute_with_headers(
                        request.method,
                        request.params.to_vec(),
                        auth.headers()?,
                        Some(request.timeout),
                    ))
                    .await?;
                    let status: PayloadStatusV1 = serde_json::from_value(match request.kind {
                        Kind::Payload => value.clone(),
                        Kind::Forkchoice => value["payloadStatus"].clone(),
                    })?;
                    Ok((value, status.status))
                }
                .await;
                endpoint.set_online_status(response.is_ok());
                if let Ok((_, status)) = &response {
                    let mut observations = request
                        .observations
                        .lock()
                        .expect("engine observations poisoned");
                    observations.responses.push((endpoint.index, *status));
                    observations.check(request.method, request.sequence);
                }
                let response = response.map(|(value, _)| value);
                if let Some(reply) = job.reply {
                    drop(reply.send(response));
                } else if let Err(error) = response {
                    warn_with_peers!(
                        "unable to update fallback EL {} with {}: {error:?}",
                        endpoint.url(),
                        request.method
                    );
                }
            }
        }));
        Ok(())
    }
}

pub struct EngineRequests {
    sequence: tokio::sync::Mutex<u64>,
    endpoints: Vec<EndpointRequests>,
}

impl EngineRequests {
    pub fn new(
        client: &Client,
        auth: &Arc<Auth>,
        endpoints: impl Iterator<Item = Arc<Endpoint>>,
    ) -> Self {
        Self {
            sequence: tokio::sync::Mutex::new(0),
            endpoints: endpoints
                .map(|endpoint| EndpointRequests {
                    queue: Arc::default(),
                    worker: Mutex::default(),
                    endpoint,
                    client: client.clone(),
                    auth: Arc::clone(auth),
                })
                .collect(),
        }
    }

    pub async fn begin_request(&self) -> Result<tokio::sync::MutexGuard<'_, u64>> {
        let mut sequence = self.sequence.lock().await;
        *sequence = sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("engine sequence exhausted"))?;
        Ok(sequence)
    }

    pub fn close(&self) {
        for endpoint in &self.endpoints {
            endpoint.close();
        }
    }

    pub fn mirror(&self, endpoint: usize, request: &Request) -> Result<()> {
        // shortcut: coalesce unsent updates and rely on EL sync; add replay if recovery tests require it.
        self.endpoints[endpoint].enqueue(Job {
            request: request.mirror(),
            reply: None,
        })
    }

    pub async fn request(&self, endpoint: usize, request: &Request) -> Result<Value> {
        let (reply, receiver) = oneshot::channel();
        self.endpoints[endpoint].enqueue(Job {
            request: request.clone(),
            reply: Some(reply),
        })?;
        receiver
            .await
            .map_err(|_| anyhow!("engine request worker stopped"))?
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use httpmock::{Method::POST, MockServer};
    use serde_json::json;

    use super::*;
    use crate::endpoints::Endpoints;

    fn request(sequence: u64, kind: Kind) -> Request {
        Request::new(
            sequence,
            kind,
            match kind {
                Kind::Payload => "engine_newPayloadV1",
                Kind::Forkchoice => "engine_forkchoiceUpdatedV1",
            },
            vec![
                json!({"headBlockHash": format!("0x{sequence:064x}")}),
                Value::Null,
            ],
            Duration::from_secs(8),
        )
    }

    #[test]
    fn foreground_does_not_send_an_older_fcu_after_a_newer_one() {
        let (reply, _receiver) = oneshot::channel();
        let mut queue = Queue {
            foreground: Some(Job {
                request: request(3, Kind::Forkchoice),
                reply: Some(reply),
            }),
            payload: Some(Job {
                request: request(2, Kind::Payload),
                reply: None,
            }),
            forkchoice: Some(Job {
                request: request(1, Kind::Forkchoice),
                reply: None,
            }),
            ..Queue::default()
        };
        assert_eq!(
            queue.next().expect("foreground request").request.sequence,
            3
        );
        assert_eq!(queue.next().expect("payload").request.sequence, 2);
        assert!(queue.next().is_none());
    }

    #[test]
    fn mirror_removes_build_attributes_without_changing_foreground() {
        let mut request = request(1, Kind::Forkchoice);
        Arc::make_mut(&mut request.params)[1] = json!({"timestamp":"0x1"});
        assert!(request.mirror().params[1].is_null());
        assert!(!request.params[1].is_null());
    }

    #[test]
    fn canceled_foreground_request_is_not_started() {
        let (reply, receiver) = oneshot::channel();
        drop(receiver);
        let mut queue = Queue {
            foreground: Some(Job {
                request: request(1, Kind::Forkchoice),
                reply: Some(reply),
            }),
            ..Queue::default()
        };
        assert!(queue.next().is_none());
    }

    #[tokio::test]
    async fn slow_mirror_keeps_only_latest_updates_without_blocking_foreground() -> Result<()> {
        let server = MockServer::start_async().await;
        let response = json!({"jsonrpc":"2.0", "id":1, "result":{
            "status":"VALID", "payloadStatus":{"status":"VALID"}, "payloadId":null
        }});
        server.mock(|when, then| {
            when.method(POST).path("/a");
            then.json_body(response.clone());
        });
        let fallback_server = MockServer::start_async().await;
        let (release, wait_for_release) = std::sync::mpsc::channel();
        let wait_for_release = Arc::new(Mutex::new(wait_for_release));
        let started = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let gate_started = Arc::clone(&started);
        let delayed_response = response.clone();
        let delayed = fallback_server.mock(move |when, then| {
            when.method(POST)
                .path("/b")
                .body_includes(format!("0x{:064x}", 1));
            then.respond_with(move |_| {
                gate_started.store(true, core::sync::atomic::Ordering::SeqCst);
                wait_for_release
                    .lock()
                    .expect("gate poisoned")
                    .recv()
                    .expect("release gate");
                httpmock::HttpMockResponse::builder()
                    .status(200)
                    .body(delayed_response.to_string())
                    .build()
            });
        });
        let latest = fallback_server.mock(|when, then| {
            when.method(POST)
                .path("/b")
                .body_excludes(format!("0x{:064x}", 1));
            then.json_body(response.clone());
        });
        let endpoints = Endpoints::new([
            server.url("/a").parse()?,
            fallback_server.url("/b").parse()?,
        ]);
        let requests = EngineRequests::new(&Client::new(), &Arc::default(), endpoints.shared());
        requests.mirror(1, &request(1, Kind::Forkchoice))?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !started.load(core::sync::atomic::Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        for sequence in 2..=20 {
            let kind = if sequence % 2 == 0 {
                Kind::Payload
            } else {
                Kind::Forkchoice
            };
            let request = request(sequence, kind);
            requests.mirror(1, &request)?;
            requests.request(0, &request).await?;
        }
        {
            let queue = requests.endpoints[1].queue.lock().expect("queue poisoned");
            assert!(queue.running);
            assert_eq!(
                queue
                    .payload
                    .as_ref()
                    .expect("latest payload")
                    .request
                    .sequence,
                20
            );
            assert_eq!(
                queue
                    .forkchoice
                    .as_ref()
                    .expect("latest FCU")
                    .request
                    .sequence,
                19
            );
        }
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !requests.endpoints[1]
                    .queue
                    .lock()
                    .expect("queue poisoned")
                    .running
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        delayed.assert_calls_async(1).await;
        latest.assert_calls_async(2).await;
        Ok(())
    }

    #[test]
    fn secondary_disagreement_requires_opposing_definitive_statuses() {
        let mut observations = Observations {
            selected: Some(0),
            responses: vec![
                (0, PayloadValidationStatus::Valid),
                (1, PayloadValidationStatus::Syncing),
            ],
            ..Observations::default()
        };
        observations.check("engine_newPayloadV1", 1);
        assert!(!observations.reported);
        observations
            .responses
            .push((1, PayloadValidationStatus::Invalid));
        observations.check("engine_newPayloadV1", 1);
        assert!(observations.reported);
    }

    #[tokio::test]
    async fn closing_dispatcher_rejects_new_requests() -> Result<()> {
        let endpoints = Endpoints::new(["http://127.0.0.1:1".parse()?]);
        let requests = EngineRequests::new(&Client::new(), &Arc::default(), endpoints.shared());
        requests.close();
        assert!(requests.mirror(0, &request(1, Kind::Forkchoice)).is_err());
        requests
            .request(0, &request(2, Kind::Forkchoice))
            .await
            .expect_err("dispatcher is closed");
        Ok(())
    }

    #[tokio::test]
    async fn dropping_dispatcher_cancels_its_worker() -> Result<()> {
        let server = MockServer::start_async().await;
        let mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200).body("{}").delay(Duration::from_secs(60));
        });
        let endpoints = Endpoints::new([server.url("/").parse()?]);
        let requests = EngineRequests::new(&Client::new(), &Arc::default(), endpoints.shared());
        let queue = Arc::downgrade(&requests.endpoints[0].queue);
        requests.mirror(0, &request(1, Kind::Forkchoice))?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while mock.calls_async().await == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        drop(requests);
        tokio::time::timeout(Duration::from_secs(5), async {
            while queue.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
}
