use core::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use std::sync::{Arc, Mutex as StdMutex};

use crossbeam_utils::sync::WaitGroup;
use execution_engine::{ExecutionPayloadV2, ExecutionServiceMessage, PayloadId};
use httpmock::{Method::POST, MockServer};
use serde_json::json;
use types::preset::Minimal;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cached_and_live_payload_failures_rebuild_once() -> Result<()> {
    check_retry(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cached_and_live_payload_retries_can_succeed() -> Result<()> {
    check_retry(true).await
}

#[expect(clippy::too_many_lines, clippy::default_trait_access)]
async fn check_retry(retry_succeeds: bool) -> Result<()> {
    let config = Arc::new(ChainConfig::minimal().start_and_stay_in(Phase::Capella));
    let pubkeys = Arc::new(PubkeyCache::default());
    let (state, _) = factory::min_genesis_state::<Minimal>(&config, &pubkeys)?;
    let anchor = BeaconBlock::from(Hc::new(CapellaBeaconBlock::<Minimal> {
        state_root: state.hash_tree_root(),
        ..CapellaBeaconBlock::default()
    }));
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
    let (engine_tx, mut engine_rx) = futures::channel::mpsc::unbounded();
    let engine = Arc::new(Eth1ExecutionEngine::new(
        config.clone_arc(),
        Arc::new(eth1_api::Eth1Api::new(
            config.clone_arc(),
            reqwest::Client::new(),
            Arc::default(),
            vec![server.url("/").parse()?],
            None,
            None,
        )),
        engine_tx,
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
    let builds = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&builds);
    // Control only the build-ID reply; retrieval and retry execute the production code.
    let replies = tokio::spawn(async move {
        while let Some(message) = engine_rx.next().await {
            if let ExecutionServiceMessage::NotifyForkchoiceUpdated {
                sender: Some(sender),
                payload_attributes: Either::Right(_),
                ..
            } = message
            {
                let generation = observed.fetch_add(1, Ordering::SeqCst).saturating_add(1);
                let mut id = [0_u8; 8];
                id[7] = u8::try_from(generation).expect("two build attempts");
                sender
                    .send(Some(PreparedPayloadId {
                        payload_id: PayloadId::Capella(id.into()),
                        endpoint: Some(0),
                    }))
                    .expect("producer awaiting build ID");
            }
        }
    });
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
                        endpoint: Some(0),
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
    replies.abort();
    executor.shutdown();
    Ok(())
}
