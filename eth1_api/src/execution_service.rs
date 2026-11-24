use core::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::Result;
use dedicated_executor::DedicatedExecutor;
use either::Either;
use execution_engine::{
    ExecutionServiceMessage, ForkChoiceUpdatedResponse, PayloadAttributes, PayloadStatusV1,
    PayloadValidationStatus,
};
use fork_choice_control::Wait;
use futures::{
    StreamExt as _,
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
};
use logging::{debug_with_peers, warn_with_peers};
use lru::LruCache;
use nonzero_ext::nonzero;
use std_ext::ArcExt as _;
use types::{
    combined::{ExecutionPayload, ExecutionPayloadParams},
    nonstandard::Phase,
    phase0::primitives::{ExecutionBlockHash, H256},
    preset::Preset,
};

use crate::{
    eth1_api::Eth1Api, messages::Eth1ApiToBlobFetcher, misc::ApiController,
    spawn_exchange_capabilities_and_versions_task,
};

// INVALID verdicts are rare. A forgotten one lets queued updates for its head through again.
const REJECTED_HEADS_CAPACITY: NonZeroUsize = nonzero!(64_usize);

pub struct ExecutionService<P: Preset, W: Wait> {
    api: Arc<Eth1Api>,
    controller: ApiController<P, W>,
    dedicated_executor: Arc<DedicatedExecutor>,
    rx: UnboundedReceiver<ExecutionServiceMessage<P>>,
    blob_fetcher_tx: UnboundedSender<Eth1ApiToBlobFetcher<P>>,
    rejected_heads: RejectedHeads,
}

impl<P: Preset, W: Wait> ExecutionService<P, W> {
    #[must_use]
    pub fn new(
        api: Arc<Eth1Api>,
        controller: ApiController<P, W>,
        dedicated_executor: Arc<DedicatedExecutor>,
        rx: UnboundedReceiver<ExecutionServiceMessage<P>>,
        blob_fetcher_tx: UnboundedSender<Eth1ApiToBlobFetcher<P>>,
    ) -> Self {
        Self {
            api,
            controller,
            dedicated_executor,
            rx,
            blob_fetcher_tx,
            rejected_heads: RejectedHeads::default(),
        }
    }

    #[expect(clippy::too_many_lines)]
    pub async fn run(mut self) -> Result<()> {
        while let Some(message) = self.rx.next().await {
            match message {
                ExecutionServiceMessage::ExchangeCapabilities => {
                    spawn_exchange_capabilities_and_versions_task(
                        self.api.clone_arc(),
                        &self.dedicated_executor,
                    );
                }
                ExecutionServiceMessage::GetBlobs(params) => {
                    // Fetch blobs from the EL in a separate task concurrently.
                    // Blob fetching from the EL should not delay the 'engine_forkchoiceUpdated'
                    // call, if all required blobs are received via gossip in the meantime.
                    //
                    // The message to trigger blob fetching should not be sent directly from
                    // `Mutator` to `ExecutionBlobFetcher`, as fetching must occur only after
                    // the execution payload is validated with the `engine_newPayload` call.
                    Eth1ApiToBlobFetcher::GetBlobs(params).send(&self.blob_fetcher_tx);
                }
                ExecutionServiceMessage::GetPayloadBodiesByHash {
                    block_hashes,
                    sender,
                } => {
                    let api = self.api.clone_arc();

                    self.dedicated_executor
                        .spawn(async move {
                            let response = api.get_payload_bodies_by_hash(block_hashes).await;

                            if sender.send(response).is_err() {
                                debug_with_peers!(
                                    "sending engine_getPayloadBodiesByHash result \
                                        failed because the receiver was dropped"
                                );
                            }
                        })
                        .detach();
                }
                ExecutionServiceMessage::NotifyForkchoiceUpdated {
                    head_eth1_block_hash,
                    head_beacon_block_root,
                    safe_eth1_block_hash,
                    finalized_eth1_block_hash,
                    payload_attributes,
                    sender,
                } => {
                    // The execution engine answers an INVALID head without a payload ID.
                    let payload_id = if self
                        .rejected_heads
                        .contains(head_eth1_block_hash, head_beacon_block_root)
                    {
                        let with_payload_attributes = payload_attributes.is_right();

                        let message = format!(
                            "skipping engine_forkchoiceUpdated call{} because the execution \
                             engine already returned INVALID status for the head \
                             (head_eth1_block_hash: {head_eth1_block_hash:?}, \
                             head_beacon_block_root: {head_beacon_block_root:?})",
                            if with_payload_attributes {
                                " with payload attributes"
                            } else {
                                ""
                            },
                        );

                        // A proposal waits for a payload ID. Without this warning,
                        // the only one would suggest a misconfiguration instead.
                        if with_payload_attributes {
                            warn_with_peers!("{message}");
                        } else {
                            debug_with_peers!("{message}");
                        }

                        None
                    } else {
                        let Some(response) = self
                            .notify_forkchoice_updated(
                                head_eth1_block_hash,
                                safe_eth1_block_hash,
                                finalized_eth1_block_hash,
                                payload_attributes,
                            )
                            .await
                        else {
                            continue;
                        };

                        let ForkChoiceUpdatedResponse {
                            payload_status,
                            payload_id,
                        } = response;

                        self.rejected_heads
                            .on_forkchoice_updated(head_eth1_block_hash, payload_status.status);

                        self.controller
                            .on_notified_fork_choice_update(head_eth1_block_hash, payload_status);

                        payload_id
                    };

                    if let Some(sender) = sender
                        && let Err(message) = sender.send(payload_id)
                    {
                        warn_with_peers!(
                            "sending engine_forkchoiceUpdated result \
                                failed because the receiver was dropped: {message:?}"
                        );
                    }
                }
                ExecutionServiceMessage::NotifyNewPayload {
                    beacon_block_root,
                    payload,
                    params,
                    sender,
                } => {
                    let response = self
                        .notify_new_payload(beacon_block_root, *payload.clone(), params)
                        .await;

                    match &response {
                        Ok(payload_status) => {
                            self.rejected_heads.on_new_payload(
                                beacon_block_root,
                                payload.block_hash(),
                                payload_status.status,
                            );

                            self.controller.on_notified_new_payload(
                                beacon_block_root,
                                payload.block_hash(),
                                payload_status.clone(),
                            );
                        }
                        Err(error) => {
                            warn_with_peers!("engine_newPayload call failed: {error:#}");

                            features::log!(
                                DebugEth1,
                                "engine_newPayload call failed \
                                 (beacon block root: {beacon_block_root:?}, \
                                  payload: {payload:?}, error: {error:#})",
                            );
                        }
                    }

                    if let Some(sender) = sender
                        && let Err(message) = sender.send(response)
                    {
                        warn_with_peers!(
                            "sending engine_newPayload result \
                                failed because the receiver was dropped: {message:?}"
                        );
                    }
                }
                ExecutionServiceMessage::Stop => {
                    Eth1ApiToBlobFetcher::Stop.send(&self.blob_fetcher_tx);

                    break;
                }
            }
        }

        Ok(())
    }

    async fn notify_forkchoice_updated(
        &self,
        head_eth1_block_hash: ExecutionBlockHash,
        safe_eth1_block_hash: ExecutionBlockHash,
        finalized_eth1_block_hash: ExecutionBlockHash,
        payload_attributes: Either<Phase, PayloadAttributes<P>>,
    ) -> Option<ForkChoiceUpdatedResponse> {
        let payload_id_expected = payload_attributes.as_ref().right().is_some();

        let response = self
            .api
            .forkchoice_updated(
                head_eth1_block_hash,
                safe_eth1_block_hash,
                finalized_eth1_block_hash,
                payload_attributes,
            )
            .await;

        match response {
            Ok(response) => {
                if response.payload_id.is_none() && payload_id_expected {
                    warn_with_peers!("payload_id expected but was none: {response:?}");
                }

                if response.payload_status.status.is_invalid() {
                    warn_with_peers!(
                        "engine_forkchoiceUpdated returned INVALID status \
                         (head_eth1_block_hash: {head_eth1_block_hash:?}, \
                          safe_eth1_block_hash: {safe_eth1_block_hash:?}, \
                          finalized_eth1_block_hash: {finalized_eth1_block_hash:?}, \
                          response: {response:?})",
                    );
                }

                if response.payload_status.status.is_syncing() {
                    warn_with_peers!(
                        "engine_forkchoiceUpdated returned SYNCING status \
                         (head_eth1_block_hash: {head_eth1_block_hash:?}, \
                          safe_eth1_block_hash: {safe_eth1_block_hash:?}, \
                          finalized_eth1_block_hash: {finalized_eth1_block_hash:?}, \
                          response: {response:?})",
                    );
                }

                Some(response)
            }
            Err(error) => {
                warn_with_peers!("engine_forkchoiceUpdated call failed: {error}");
                None
            }
        }
    }

    async fn notify_new_payload(
        &self,
        beacon_block_root: H256,
        payload: ExecutionPayload<P>,
        params: Option<ExecutionPayloadParams<P>>,
    ) -> Result<PayloadStatusV1> {
        let block_number = payload.block_number();
        let block_hash = payload.block_hash();
        let response = self.api.new_payload(payload, params).await?;

        if response.status.is_invalid() {
            warn_with_peers!(
                "engine_newPayload returned INVALID status \
                 (beacon_block_root: {beacon_block_root:?}, \
                  block_number: {block_number}, \
                  block_hash: {block_hash:?}, \
                  response: {response:?})",
            );
        }

        if response.status.is_syncing() {
            warn_with_peers!(
                "engine_newPayload returned SYNCING status \
                 (beacon_block_root: {beacon_block_root:?}, \
                  block_number: {block_number}, \
                  block_hash: {block_hash:?}, \
                  response: {response:?})",
            );
        }

        Ok(response)
    }
}

// Heads the execution engine has answered INVALID.
//
// Fork choice only learns of a verdict after the call returns.
// Updates queued before that may still carry the rejected head.
// Fork choice is about to give that head up, so they should not reach the execution engine.
// After an `engine_forkchoiceUpdated` verdict they would only be answered INVALID again.
// After an `engine_newPayload` verdict about the parameters, the execution engine may not know
// the payload and answer SYNCING. It would then sync towards a head fork choice is giving up.
//
// A later `engine_newPayload` verdict of VALID, SYNCING or ACCEPTED makes a head forgotten.
// The execution engine may have lost track of the old verdict, or reconsidered it.
// Post-Gloas fork choice refetches an invalidated envelope and accepts it if it is then valid.
// No later `engine_forkchoiceUpdated` verdict can do that, since updates for the head are skipped.
struct RejectedHeads {
    // Head hashes `engine_forkchoiceUpdated` answered INVALID.
    forkchoice_updated: LruCache<ExecutionBlockHash, ()>,
    // Payloads `engine_newPayload` answered INVALID, keyed by the beacon block they were sent for.
    // The verdict may be about the parameters sent along, such as the versioned hashes.
    // The same payload may be valid with another block's parameters, so the hash alone is not enough.
    // The block fixes them: they come from it, and the payload hash commits to the rest.
    new_payload: LruCache<(H256, ExecutionBlockHash), ()>,
}

impl Default for RejectedHeads {
    fn default() -> Self {
        Self {
            forkchoice_updated: LruCache::new(REJECTED_HEADS_CAPACITY),
            new_payload: LruCache::new(REJECTED_HEADS_CAPACITY),
        }
    }
}

impl RejectedHeads {
    fn on_forkchoice_updated(
        &mut self,
        head_block_hash: ExecutionBlockHash,
        status: PayloadValidationStatus,
    ) {
        if status.is_invalid() {
            self.forkchoice_updated.put(head_block_hash, ());
        }
    }

    fn on_new_payload(
        &mut self,
        beacon_block_root: H256,
        block_hash: ExecutionBlockHash,
        status: PayloadValidationStatus,
    ) {
        match status {
            // The block fixes the payload sent, so this covers payloads that do not hash to
            // `block_hash` too. Engine API versions after Paris report those as INVALID anyway.
            PayloadValidationStatus::Invalid | PayloadValidationStatus::InvalidBlockHash => {
                self.new_payload.put((beacon_block_root, block_hash), ());
            }
            PayloadValidationStatus::Valid
            | PayloadValidationStatus::Syncing
            | PayloadValidationStatus::Accepted => {
                self.new_payload.pop(&(beacon_block_root, block_hash));
                self.forkchoice_updated.pop(&block_hash);
            }
        }
    }

    fn contains(
        &self,
        head_block_hash: ExecutionBlockHash,
        head_beacon_block_root: Option<H256>,
    ) -> bool {
        self.forkchoice_updated.contains(&head_block_hash)
            || head_beacon_block_root
                .is_some_and(|root| self.new_payload.contains(&(root, head_block_hash)))
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    pub const ROOT: H256 = H256::repeat_byte(1);
    pub const OTHER_ROOT: H256 = H256::repeat_byte(2);
    pub const HASH: ExecutionBlockHash = H256::repeat_byte(3);
    const OTHER_HASH: ExecutionBlockHash = H256::repeat_byte(4);

    #[test_case(PayloadValidationStatus::Invalid, true)]
    #[test_case(PayloadValidationStatus::Valid, false)]
    #[test_case(PayloadValidationStatus::Syncing, false)]
    #[test_case(PayloadValidationStatus::Accepted, false)]
    fn forkchoice_updated_verdict_rejects_head_under_any_root(
        status: PayloadValidationStatus,
        rejected: bool,
    ) {
        let mut rejected_heads = RejectedHeads::default();

        rejected_heads.on_forkchoice_updated(HASH, status);

        assert_eq!(rejected_heads.contains(HASH, None), rejected);
        assert_eq!(rejected_heads.contains(HASH, Some(ROOT)), rejected);
        assert!(!rejected_heads.contains(OTHER_HASH, None));
    }

    #[test_case(PayloadValidationStatus::Invalid, true)]
    #[test_case(PayloadValidationStatus::InvalidBlockHash, true)]
    #[test_case(PayloadValidationStatus::Valid, false)]
    #[test_case(PayloadValidationStatus::Syncing, false)]
    #[test_case(PayloadValidationStatus::Accepted, false)]
    fn new_payload_verdict_rejects_head_only_under_same_root(
        status: PayloadValidationStatus,
        rejected: bool,
    ) {
        let mut rejected_heads = RejectedHeads::default();

        rejected_heads.on_new_payload(ROOT, HASH, status);

        assert_eq!(rejected_heads.contains(HASH, Some(ROOT)), rejected);
        assert!(!rejected_heads.contains(HASH, Some(OTHER_ROOT)));
        assert!(!rejected_heads.contains(HASH, None));
        assert!(!rejected_heads.contains(OTHER_HASH, Some(ROOT)));
    }

    #[test_case(PayloadValidationStatus::Valid)]
    #[test_case(PayloadValidationStatus::Syncing)]
    #[test_case(PayloadValidationStatus::Accepted)]
    fn later_new_payload_verdict_other_than_invalid_forgets_head(status: PayloadValidationStatus) {
        let mut rejected_heads = RejectedHeads::default();

        rejected_heads.on_forkchoice_updated(HASH, PayloadValidationStatus::Invalid);
        rejected_heads.on_new_payload(ROOT, HASH, PayloadValidationStatus::Invalid);
        rejected_heads.on_new_payload(OTHER_ROOT, HASH, PayloadValidationStatus::Invalid);
        rejected_heads.on_new_payload(ROOT, HASH, status);

        assert!(!rejected_heads.contains(HASH, None));
        assert!(!rejected_heads.contains(HASH, Some(ROOT)));

        // That verdict was for the parameters of another block.
        assert!(rejected_heads.contains(HASH, Some(OTHER_ROOT)));
    }

    #[test]
    fn later_new_payload_verdict_of_invalid_block_hash_keeps_head() {
        let mut rejected_heads = RejectedHeads::default();

        rejected_heads.on_forkchoice_updated(HASH, PayloadValidationStatus::Invalid);
        rejected_heads.on_new_payload(ROOT, HASH, PayloadValidationStatus::Invalid);
        rejected_heads.on_new_payload(ROOT, HASH, PayloadValidationStatus::InvalidBlockHash);

        assert!(rejected_heads.contains(HASH, None));
        assert!(rejected_heads.contains(HASH, Some(ROOT)));
    }

    #[test]
    fn oldest_verdicts_are_forgotten_first() {
        let mut rejected_heads = RejectedHeads::default();

        let capacity = u64::try_from(REJECTED_HEADS_CAPACITY.get())
            .expect("REJECTED_HEADS_CAPACITY should fit in u64");

        let hashes = (0..=capacity)
            .map(ExecutionBlockHash::from_low_u64_be)
            .collect::<Vec<_>>();

        for hash in &hashes {
            rejected_heads.on_forkchoice_updated(*hash, PayloadValidationStatus::Invalid);
        }

        assert!(!rejected_heads.contains(hashes[0], None));
        assert!(
            hashes[1..]
                .iter()
                .all(|hash| rejected_heads.contains(*hash, None))
        );
    }
}

// `ExecutionService` against an execution engine served over HTTP.
#[cfg(test)]
mod service_tests {
    use crossbeam_utils::sync::WaitGroup;
    use execution_engine::PayloadId;
    use fork_choice_control::controller::MutatorHandle;
    use futures::channel::{mpsc::UnboundedSender, oneshot};
    use httpmock::{Method, Mock, MockServer};
    use pubkey_cache::PubkeyCache;
    use serde_json::{Value, json};
    use types::{
        bellatrix::containers::ExecutionPayload as BellatrixExecutionPayload, config::Config,
        preset::Minimal,
    };

    use super::{
        tests::{HASH, OTHER_ROOT, ROOT},
        *,
    };
    use crate::test_chain::TestChain;

    struct Fixture {
        server: MockServer,
        service: ExecutionService<Minimal, WaitGroup>,
        tx: UnboundedSender<ExecutionServiceMessage<Minimal>>,
        mutator_handle: MutatorHandle<Minimal, WaitGroup>,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let config = Arc::new(Config::minimal().start_and_stay_in(Phase::Bellatrix));
            let pubkey_cache = Arc::new(PubkeyCache::default());
            let (genesis_state, _) = factory::min_genesis_state(&config, &pubkey_cache)?;
            let genesis_block = Arc::new(genesis::beacon_block(&genesis_state));

            let server = MockServer::start();

            // Fork choice gets a channel of its own, so only messages sent by tests reach the service.
            let TestChain {
                api,
                controller,
                mutator_handle,
                ..
            } = TestChain::new(
                &config,
                &pubkey_cache,
                genesis_block,
                genesis_state,
                clock::Tick::start_of_slot(1),
                Some(server.url("/").parse()?),
                futures::channel::mpsc::unbounded().0,
            )?;

            let (tx, rx) = futures::channel::mpsc::unbounded();

            let service = ExecutionService::new(
                api,
                controller,
                Arc::new(DedicatedExecutor::new(
                    "execution service tests",
                    1,
                    None,
                    None,
                )),
                rx,
                futures::channel::mpsc::unbounded().0,
            );

            Ok(Self {
                server,
                service,
                tx,
                mutator_handle,
            })
        }
    }

    fn respond<'server>(
        server: &'server MockServer,
        method: &str,
        result: &Value,
    ) -> Mock<'server> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "",
            "params": null,
            "id": 0,
            "result": result,
        });

        server.mock(|when, then| {
            when.method(Method::POST).path("/").body_includes(method);
            then.status(200).body(body.to_string());
        })
    }

    fn payload_status(status: &str) -> Value {
        json!({
            "status": status,
            "latestValidHash": null,
            "validationError": null,
        })
    }

    fn forkchoice_updated_result(status: &str) -> Value {
        json!({
            "payloadStatus": payload_status(status),
            "payloadId": "0x0102030405060708",
        })
    }

    fn new_payload(
        tx: &UnboundedSender<ExecutionServiceMessage<Minimal>>,
        beacon_block_root: H256,
    ) -> oneshot::Receiver<Result<PayloadStatusV1>> {
        let (sender, receiver) = oneshot::channel();

        let payload = BellatrixExecutionPayload::<Minimal> {
            block_hash: HASH,
            ..Default::default()
        };

        ExecutionServiceMessage::NotifyNewPayload {
            beacon_block_root,
            payload: Box::new(payload.into()),
            params: None,
            sender: Some(sender),
        }
        .send(tx);

        receiver
    }

    fn forkchoice_updated(
        tx: &UnboundedSender<ExecutionServiceMessage<Minimal>>,
        head_beacon_block_root: Option<H256>,
    ) -> oneshot::Receiver<Option<PayloadId>> {
        let (sender, receiver) = oneshot::channel();

        ExecutionServiceMessage::NotifyForkchoiceUpdated {
            head_eth1_block_hash: HASH,
            head_beacon_block_root,
            safe_eth1_block_hash: H256::zero(),
            finalized_eth1_block_hash: H256::zero(),
            payload_attributes: Either::Left(Phase::Bellatrix),
            sender: Some(sender),
        }
        .send(tx);

        receiver
    }

    // Handles every message sent so far, in order.
    async fn run(
        service: ExecutionService<Minimal, WaitGroup>,
        tx: &UnboundedSender<ExecutionServiceMessage<Minimal>>,
    ) -> Result<()> {
        ExecutionServiceMessage::Stop.send(tx);
        service.run().await
    }

    // `engine_newPayload` rejects the payload of the block the queued update is for.
    // An update for the same payload under another block still goes out.
    #[tokio::test]
    async fn update_for_head_rejected_by_new_payload_is_skipped() -> Result<()> {
        let Fixture {
            server,
            service,
            tx,
            mutator_handle: _mutator_handle,
        } = Fixture::new()?;

        let new_payload_mock = respond(&server, "engine_newPayloadV1", &payload_status("INVALID"));

        let forkchoice_updated_mock = respond(
            &server,
            "engine_forkchoiceUpdatedV1",
            &forkchoice_updated_result("VALID"),
        );

        let new_payload_receiver = new_payload(&tx, ROOT);
        let rejected_receiver = forkchoice_updated(&tx, Some(ROOT));
        let other_receiver = forkchoice_updated(&tx, Some(OTHER_ROOT));

        run(service, &tx).await?;

        assert_eq!(new_payload_mock.calls(), 1);
        assert_eq!(forkchoice_updated_mock.calls(), 1);
        assert!(new_payload_receiver.await??.status.is_invalid());
        assert!(rejected_receiver.await?.is_none());
        assert!(other_receiver.await?.is_some());

        Ok(())
    }

    // `engine_forkchoiceUpdated` rejects the head. A queued update for it is skipped under any root.
    #[tokio::test]
    async fn update_for_head_rejected_by_forkchoice_updated_is_skipped() -> Result<()> {
        let Fixture {
            server,
            service,
            tx,
            mutator_handle: _mutator_handle,
        } = Fixture::new()?;

        let forkchoice_updated_mock = respond(
            &server,
            "engine_forkchoiceUpdatedV1",
            &forkchoice_updated_result("INVALID"),
        );

        let first_receiver = forkchoice_updated(&tx, None);
        let second_receiver = forkchoice_updated(&tx, Some(OTHER_ROOT));

        run(service, &tx).await?;

        assert_eq!(forkchoice_updated_mock.calls(), 1);

        // The first answer comes from the execution engine.
        assert!(first_receiver.await?.is_some());
        assert!(second_receiver.await?.is_none());

        Ok(())
    }

    // A later verdict that is not INVALID lets updates for the head through again.
    #[tokio::test]
    async fn update_for_head_is_sent_again_after_head_is_no_longer_rejected() -> Result<()> {
        let Fixture {
            server,
            service,
            tx,
            mutator_handle: _mutator_handle,
        } = Fixture::new()?;

        let forkchoice_updated_mock = respond(
            &server,
            "engine_forkchoiceUpdatedV1",
            &forkchoice_updated_result("INVALID"),
        );

        let new_payload_mock = respond(&server, "engine_newPayloadV1", &payload_status("VALID"));

        let first_receiver = forkchoice_updated(&tx, None);
        let new_payload_receiver = new_payload(&tx, ROOT);
        let second_receiver = forkchoice_updated(&tx, None);

        run(service, &tx).await?;

        assert_eq!(new_payload_mock.calls(), 1);
        assert_eq!(forkchoice_updated_mock.calls(), 2);
        assert!(first_receiver.await?.is_some());
        assert!(new_payload_receiver.await??.status.is_valid());
        assert!(second_receiver.await?.is_some());

        Ok(())
    }
}
