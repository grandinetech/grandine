use core::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};
use std::sync::{Arc, Mutex as StdMutex};

use crossbeam_utils::sync::WaitGroup;
use execution_engine::{ExecutionPayloadV2, ExecutionServiceMessage, PayloadId};
use httpmock::{Method::POST, MockServer};
use serde_json::json;
use types::{preset::Minimal, traits::SignedBeaconBlock as _};

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cached_and_live_payload_failures_rebuild_once() -> Result<()> {
    check_retry(false, false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payload_retries_and_injected_statuses_reach_producer_and_controller() -> Result<()> {
    check_retry(true, false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn syncing_primary_uses_fallback_for_builds_and_head_validation() -> Result<()> {
    check_retry(true, true).await
}

#[expect(clippy::too_many_lines, clippy::default_trait_access)]
async fn check_retry(retry_succeeds: bool, syncing_primary: bool) -> Result<()> {
    let config = Arc::new(ChainConfig::minimal().start_and_stay_in(Phase::Capella));
    let pubkeys = Arc::new(PubkeyCache::default());
    let (state, _) = factory::min_genesis_state::<Minimal>(&config, &pubkeys)?;
    let anchor = BeaconBlock::from(Hc::new(CapellaBeaconBlock::<Minimal> {
        state_root: state.hash_tree_root(),
        ..CapellaBeaconBlock::default()
    }));
    let imported_payload = factory::execution_payload(&config, &state, 1, H256::repeat_byte(9))?;
    let (imported_block, _) = factory::block_with_payload(
        &config,
        &pubkeys,
        state.clone_arc(),
        1,
        H256::zero(),
        imported_payload.clone(),
    )?;
    let root = anchor.hash_tree_root();
    let anchor = Arc::new(anchor.with_signature(SignatureBytes::empty()));
    let server = MockServer::start_async().await;
    let calls = Arc::new(StdMutex::new(Vec::<String>::new()));
    let requests = Arc::clone(&calls);
    let payload = CapellaExecutionPayload::<Minimal> {
        block_hash: H256::repeat_byte(7),
        ..CapellaExecutionPayload::default()
    };
    let response = json!({"jsonrpc":"2.0", "id":1, "result":{
        "executionPayload":ExecutionPayloadV2::from(payload), "blockValue":"0x0"
    }})
    .to_string();
    server.mock(move |when, then| {
        when.method(POST).body_includes("engine_getPayloadV2");
        then.respond_with(move |request| {
            let mut calls = requests.lock().expect("request log poisoned");
            calls.push(String::from_utf8(request.body_bytes().to_vec()).expect("JSON request"));
            let body = if retry_succeeds && calls.len() == 2 {
                response.clone()
            } else {
                json!({"jsonrpc":"2.0", "id":1, "error":{"code":-38001,"message":"Unknown payload"}}).to_string()
            };
            httpmock::HttpMockResponse::builder().status(200).body(body).build()
        });
    });
    let builds = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&builds);
    let build_available = Arc::new(AtomicBool::new(true));
    let available = Arc::clone(&build_available);
    let fallback_fcu = server.mock(move |when, then| {
        when.method(POST)
            .body_includes("engine_forkchoiceUpdatedV2");
        then.respond_with(move |request| {
            let request: serde_json::Value =
                serde_json::from_slice(&request.body_bytes()).expect("JSON request");
            let payload_id = if request["params"][1].is_null() {
                serde_json::Value::Null
            } else {
                let generation = observed.fetch_add(1, Ordering::SeqCst).saturating_add(1);
                if available.load(Ordering::SeqCst) {
                    json!(format!("0x{generation:016x}"))
                } else {
                    serde_json::Value::Null
                }
            };
            let status = if available.load(Ordering::SeqCst) {
                "VALID"
            } else {
                "SYNCING"
            };
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(
                    json!({
                        "jsonrpc":"2.0", "id":request["id"], "result":{
                            "payloadStatus":{"status":status,
                                "latestValidHash":if status == "VALID" { request["params"][0]["headBlockHash"].clone() } else { serde_json::Value::Null }},
                            "payloadId":payload_id
                        }
                    })
                    .to_string(),
                )
                .build()
        });
    });
    let selected_valid = Arc::new(AtomicBool::new(true));
    let valid = Arc::clone(&selected_valid);
    let fallback_payload = server.mock(move |when, then| {
        when.method(POST).body_includes("engine_newPayloadV2");
        then.respond_with(move |request| {
            let request: serde_json::Value = serde_json::from_slice(&request.body_bytes()).expect("JSON request");
            let valid = valid.load(Ordering::SeqCst);
            httpmock::HttpMockResponse::builder().status(200).body(json!({
                "jsonrpc":"2.0", "id":request["id"], "result":{
                    "status":if valid { "VALID" } else { "INVALID" },
                    "latestValidHash":if valid { request["params"][0]["blockHash"].clone() } else { serde_json::Value::Null }
                }
            }).to_string()).build()
        });
    });
    let primary = MockServer::start_async().await;
    let primary_payload = primary.mock(|when, then| {
        when.method(POST).body_includes("engine_newPayloadV2");
        then.json_body(json!({"jsonrpc":"2.0","id":1,"result":{
            "status":if syncing_primary { "SYNCING" } else { "INVALID" },
            "latestValidHash":null
        }}));
    });
    let primary_available = Arc::new(AtomicBool::new(false));
    let available = Arc::clone(&primary_available);
    let primary_fcu = primary.mock(move |when, then| {
        when.method(POST).body_excludes("engine_newPayloadV2");
        then.respond_with(move |request| {
            if !syncing_primary || !available.load(Ordering::SeqCst) {
                return httpmock::HttpMockResponse::builder().status(500).build();
            }
            let request: serde_json::Value =
                serde_json::from_slice(&request.body_bytes()).expect("JSON request");
            httpmock::HttpMockResponse::builder().status(200).body(json!({
                "jsonrpc":"2.0","id":request["id"],"result":{
                    "payloadStatus":{"status":"SYNCING","latestValidHash":null},"payloadId":null
                }
            }).to_string()).build()
        });
    });
    let (engine_tx, engine_rx) = futures::channel::mpsc::unbounded();
    let api = Arc::new(eth1_api::Eth1Api::new(
        config.clone_arc(),
        reqwest::Client::new(),
        Arc::default(),
        vec![primary.url("/").parse()?, server.url("/").parse()?],
        None,
        None,
    ));
    if syncing_primary {
        api.forkchoice_updated::<Minimal>(
            H256::zero(),
            H256::zero(),
            H256::zero(),
            Either::Left(Phase::Capella),
        )
        .await?;
        primary_fcu.assert_calls_async(1).await;
        primary_available.store(true, Ordering::SeqCst);
    }
    let engine = Arc::new(Eth1ExecutionEngine::new(
        config.clone_arc(),
        api.clone_arc(),
        engine_tx.clone(),
    ));
    let events = Arc::new(fork_choice_control::EventChannels::default());
    let storage = Arc::new(fork_choice_control::Storage::new(
        config.clone_arc(),
        pubkeys.clone_arc(),
        database::Database::in_memory(),
        fork_choice_control::DEFAULT_ARCHIVAL_EPOCH_INTERVAL,
        Default::default(),
        true,
        fork_choice_control::DEFAULT_ZSTD_COMPRESSION_LEVEL,
    ));
    let (controller, _mutator) = fork_choice_control::Controller::<Minimal, _, _, WaitGroup>::new(
        config.clone_arc(),
        pubkeys,
        Default::default(),
        anchor,
        state,
        clock::Tick::start_of_slot(1),
        events.clone_arc(),
        engine.clone_arc(),
        None,
        futures::channel::mpsc::unbounded().0,
        futures::sink::drain(),
        futures::sink::drain(),
        futures::sink::drain(),
        futures::sink::drain(),
        futures::sink::drain(),
        storage,
        core::iter::empty(),
        true,
        Default::default(),
        Arc::default(),
        Some(2),
    )?;
    let executor = Arc::new(DedicatedExecutor::new("payload retry test", 2, None, None));
    let pool = AttestationAggPool::new(controller.clone_arc(), executor.clone_arc(), None, None);
    let (pool_tx, _) = futures::channel::mpsc::unbounded();
    let sync_pool = SyncCommitteeAggPool::new(
        executor.clone_arc(),
        controller.clone_arc(),
        pool_tx.clone(),
        None,
        None,
    );
    let (bls_pool, _bls_service) =
        BlsToExecutionChangePool::new(controller.clone_arc(), events, pool_tx, None);
    let payload_pool =
        PayloadAttestationAggPool::new(controller.clone_arc(), executor.clone_arc(), None);
    let configs = Arc::new(ProposerConfigs::new(
        Default::default(),
        Some(30_000_000),
        H256::zero(),
        keymanager::BuilderSettings::default(),
        Arc::new(keymanager::ValidatorDefinitionsWithStorage::new(
            Arc::default(),
            Default::default(),
        )),
    ));
    let producer = BlockProducer::new(
        configs,
        None,
        Arc::new(PayloadBuilderApi::new(
            config,
            reqwest::Client::new(),
            builder_api::BuilderApiFormat::default(),
            None,
        )),
        controller.clone_arc(),
        executor.clone_arc(),
        engine,
        pool,
        bls_pool,
        sync_pool,
        payload_pool,
        None,
        None,
    );
    let proposal_state = controller.preprocessed_state_at_current_slot_blocking()?;
    let context = producer.new_build_context(proposal_state, root, 0, BlockBuildOptions::default());
    let service = eth1_api::ExecutionService::new(
        api,
        controller.clone_arc(),
        executor.clone_arc(),
        engine_rx,
        futures::channel::mpsc::unbounded().0,
    );
    let service = tokio::spawn(service.run());
    for cached in [false, true] {
        builds.store(0, Ordering::SeqCst);
        calls.lock().expect("request log poisoned").clear();
        context
            .producer_context
            .payload_cache
            .lock()
            .await
            .cache_clear();
        if cached {
            context
                .producer_context
                .payload_id_cache
                .lock()
                .await
                .cache_set(
                    (root, 1),
                    PreparedPayloadId {
                        payload_id: PayloadId::Capella([0; 8].into()),
                        endpoint: Some(1),
                    },
                );
        }
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            context.local_execution_payload_result(),
        )
        .await?;
        if retry_succeeds {
            let payload = result?.expect("retry returns a payload");
            assert_eq!(payload.result.value.block_hash(), H256::repeat_byte(7));
        } else {
            assert!(result.is_err(), "retry error must reach the caller");
        }
        assert_eq!(builds.load(Ordering::SeqCst), if cached { 1 } else { 2 });
        let calls = calls.lock().expect("request log poisoned");
        assert_eq!(calls.len(), 2, "only one retrieval retry");
        assert!(calls[0].contains(if cached {
            "0x0000000000000000"
        } else {
            "0x0000000000000001"
        }));
        assert!(calls[1].contains(if cached {
            "0x0000000000000001"
        } else {
            "0x0000000000000002"
        }));
    }
    // A missing build ID is a build failure, not a failed getPayload that should be retried.
    build_available.store(false, Ordering::SeqCst);
    builds.store(0, Ordering::SeqCst);
    calls.lock().expect("request log poisoned").clear();
    context
        .producer_context
        .payload_id_cache
        .lock()
        .await
        .cache_clear();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            context.local_execution_payload_result()
        )
        .await??
        .is_none()
    );
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    assert!(calls.lock().expect("request log poisoned").is_empty());
    if syncing_primary {
        build_available.store(true, Ordering::SeqCst);
        let block_root = imported_block.message().hash_tree_root();
        controller.on_requested_block(imported_block.clone_arc(), None);
        tokio::time::timeout(Duration::from_secs(5), async {
            while controller.head_block_root().value != block_root
                || primary_payload.calls_async().await == 0
                || fallback_payload.calls_async().await == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let (sender, receiver) = futures::channel::oneshot::channel();
        engine_tx.unbounded_send(ExecutionServiceMessage::NotifyNewPayload {
            beacon_block_root: block_root,
            payload: Box::new(imported_payload.clone()),
            params: None,
            sender: Some(sender),
        })?;
        let status = tokio::time::timeout(Duration::from_secs(5), receiver).await???;
        assert!(
            status.status.is_valid(),
            "B's VALID must be selected after A's SYNCING"
        );
        controller.wait_for_tasks();
        assert_eq!(controller.head_block_root().value, block_root);
        assert!(
            !controller.snapshot().is_optimistic(),
            "selected NP validates the head before FCU"
        );
        // Ordinary FCU also selects B's VALID response without build attributes.
        let earlier_fcu = fallback_fcu.calls_async().await;
        let (sender, receiver) = futures::channel::oneshot::channel();
        engine_tx.unbounded_send(ExecutionServiceMessage::NotifyForkchoiceUpdated {
            head_eth1_block_hash: imported_payload.block_hash(),
            safe_eth1_block_hash: H256::zero(),
            finalized_eth1_block_hash: H256::zero(),
            payload_attributes: Either::Left(Phase::Capella),
            sender: Some(sender),
        })?;
        tokio::time::timeout(Duration::from_secs(5), receiver).await??;
        tokio::time::timeout(Duration::from_secs(5), async {
            while fallback_fcu.calls_async().await <= earlier_fcu {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        controller.wait_for_tasks();
        assert_eq!(controller.head_block_root().value, block_root);
        assert!(
            !controller.snapshot().is_optimistic(),
            "selected VALID responses keep the imported head validated"
        );
    }
    if retry_succeeds && !syncing_primary {
        // The selected EL validates the imported block; a mirror's INVALID must not invalidate it.
        build_available.store(true, Ordering::SeqCst);
        let earlier_primary_calls = primary_fcu.calls_async().await;
        let block_root = imported_block.message().hash_tree_root();
        controller.on_requested_block(imported_block, None);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if controller.head_block_root().value == block_root
                    && !controller.snapshot().is_optimistic()
                    && primary_payload.calls_async().await > 0
                    && primary_fcu.calls_async().await > earlier_primary_calls
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        // Wait for the subsequent FCU: the endpoint worker has then consumed the mirror response.
        let (sender, receiver) = futures::channel::oneshot::channel();
        engine_tx.unbounded_send(ExecutionServiceMessage::NotifyForkchoiceUpdated {
            head_eth1_block_hash: imported_payload.block_hash(),
            safe_eth1_block_hash: H256::zero(),
            finalized_eth1_block_hash: H256::zero(),
            payload_attributes: Either::Left(Phase::Capella),
            sender: Some(sender),
        })?;
        tokio::time::timeout(Duration::from_secs(5), receiver).await??;
        controller.wait_for_tasks();
        assert_eq!(controller.head_block_root().value, block_root);
        assert!(!controller.snapshot().is_optimistic());

        // Deliberately violate EL status idempotence to test forwarding a selected INVALID.
        selected_valid.store(false, Ordering::SeqCst);
        let (sender, receiver) = futures::channel::oneshot::channel();
        engine_tx.unbounded_send(ExecutionServiceMessage::NotifyNewPayload {
            beacon_block_root: block_root,
            payload: Box::new(imported_payload),
            params: None,
            sender: Some(sender),
        })?;
        let status = tokio::time::timeout(Duration::from_secs(5), receiver).await???;
        assert!(status.status.is_invalid());
        controller.wait_for_tasks();
        assert_ne!(controller.head_block_root().value, block_root);
    }
    engine_tx.unbounded_send(ExecutionServiceMessage::Stop)?;
    tokio::time::timeout(Duration::from_secs(5), service).await???;
    executor.shutdown();
    Ok(())
}
