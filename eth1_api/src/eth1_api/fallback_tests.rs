use std::sync::Mutex;

use execution_engine::{
    PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3, PayloadAttributesV4,
};
use httpmock::{Method::POST, MockServer};
use serde_json::json;
use ssz::ContiguousList;
use types::{
    phase0::primitives::{H160, H256},
    preset::Minimal,
};

use super::*;

async fn wait_for_calls(calls: &Mutex<Vec<(String, Value)>>, count: usize) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while calls.lock().expect("calls poisoned").len() < count {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
#[expect(clippy::too_many_lines)]
async fn all_payload_versions_preserve_parameters_on_both_endpoints() -> Result<()> {
    let server = MockServer::start_async().await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let received = Arc::clone(&calls);
    server.mock(move |when, then| {
        when.method(POST);
        then.respond_with(move |request| {
            let body: Value = serde_json::from_slice(&request.body_bytes()).expect("request JSON");
            received.lock().expect("calls poisoned").push((request.uri().path().to_owned(), body.clone()));
            httpmock::HttpMockResponse::builder().status(200).body(json!({
                "jsonrpc":"2.0", "id":body["id"], "result":{"status":"VALID", "latestValidHash":body["params"][0]["blockHash"]}
            }).to_string()).build()
        });
    });
    let api = Eth1Api::new(
        Arc::new(Config::minimal()),
        Client::new(),
        Arc::default(),
        vec![
            server.url("/primary").parse()?,
            server.url("/fallback").parse()?,
        ],
        None,
        None,
    );
    let root = H256::repeat_byte(7);
    let hashes = vec![H256::repeat_byte(1)];
    let mut electra = types::electra::containers::ExecutionRequests::<Minimal>::default();
    electra.deposits = [types::electra::containers::DepositRequest {
        amount: 42,
        ..Default::default()
    }]
    .try_into()?;
    let gloas = types::gloas::containers::ExecutionRequests::<Minimal> {
        deposits: electra.deposits.clone().into(),
        ..types::gloas::containers::ExecutionRequests::default()
    };
    let cases: [(ExecutionPayload<Minimal>, _, _, usize); 5] = [
        (
            ExecutionPayload::Bellatrix(types::bellatrix::containers::ExecutionPayload::default()),
            None,
            "engine_newPayloadV1",
            1,
        ),
        (
            ExecutionPayload::Capella(types::capella::containers::ExecutionPayload::default()),
            None,
            "engine_newPayloadV2",
            1,
        ),
        (
            ExecutionPayload::Deneb(types::deneb::containers::ExecutionPayload::default()),
            Some(ExecutionPayloadParams::Deneb {
                versioned_hashes: hashes.clone(),
                parent_beacon_block_root: root,
            }),
            "engine_newPayloadV3",
            3,
        ),
        (
            ExecutionPayload::Deneb(types::deneb::containers::ExecutionPayload::default()),
            Some(ExecutionPayloadParams::Electra {
                versioned_hashes: hashes.clone(),
                parent_beacon_block_root: root,
                execution_requests: electra,
            }),
            "engine_newPayloadV4",
            4,
        ),
        (
            ExecutionPayload::Gloas(types::gloas::containers::ExecutionPayload::default()),
            Some(ExecutionPayloadParams::Gloas {
                versioned_hashes: hashes.clone(),
                parent_beacon_block_root: root,
                execution_requests: gloas,
            }),
            "engine_newPayloadV5",
            4,
        ),
    ];
    for (payload, params, method, count) in cases {
        calls.lock().expect("calls poisoned").clear();
        assert!(api.new_payload(payload, params).await?.status.is_valid());
        wait_for_calls(&calls, 2).await?;
        let calls = calls.lock().expect("calls poisoned");
        assert_eq!(calls.len(), 2);
        assert_ne!(calls[0].0, calls[1].0);
        for (_, request) in calls.iter() {
            assert_eq!(request["method"], method);
            assert_eq!(request["params"].as_array().expect("params").len(), count);
            if count > 1 {
                assert_eq!(request["params"][1], json!(hashes));
                assert_eq!(request["params"][2], json!(root));
            }
            if count == 4 {
                assert!(
                    !request["params"][3]
                        .as_array()
                        .expect("execution requests")
                        .is_empty()
                );
            }
        }
        assert_eq!(calls[0].1["params"], calls[1].1["params"]);
    }
    Ok(())
}

#[tokio::test]
#[expect(clippy::too_many_lines)]
async fn all_forks_strip_only_secondary_build_attributes_and_keep_payload_owner() -> Result<()> {
    let server = MockServer::start_async().await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let received = Arc::clone(&calls);
    server.mock(move |when, then| {
        when.method(POST);
        then.respond_with(move |request| {
            let body: Value = serde_json::from_slice(&request.body_bytes()).expect("request JSON");
            received.lock().expect("calls poisoned").push((request.uri().path().to_owned(), body.clone()));
            let response = if body["method"].as_str().expect("method").starts_with("engine_getPayload") {
                json!({"jsonrpc":"2.0", "id":body["id"], "error":{"code":-38001,"message":"Unknown payload"}})
            } else {
                json!({"jsonrpc":"2.0", "id":body["id"], "result":{
                    "payloadStatus":{"status":"VALID", "latestValidHash":body["params"][0]["headBlockHash"]},
                    "payloadId":if body["params"][1].is_null() { Value::Null } else { json!("0x0000000000000001") }
                }})
            };
            httpmock::HttpMockResponse::builder().status(200).body(response.to_string()).build()
        });
    });
    let api = Eth1Api::new(
        Arc::new(Config::minimal()),
        Client::new(),
        Arc::default(),
        vec![
            server.url("/primary").parse()?,
            server.url("/fallback").parse()?,
        ],
        None,
        None,
    );
    let root = H256::repeat_byte(7);
    let v3 = PayloadAttributesV3::<Minimal> {
        timestamp: 12,
        prev_randao: root,
        suggested_fee_recipient: H160::zero(),
        withdrawals: ContiguousList::default(),
        parent_beacon_block_root: root,
    };
    let cases = [
        (
            PayloadAttributes::Bellatrix(PayloadAttributesV1 {
                timestamp: 12,
                prev_randao: root,
                suggested_fee_recipient: H160::zero(),
            }),
            "engine_forkchoiceUpdatedV1",
            "engine_getPayloadV1",
        ),
        (
            PayloadAttributes::Capella(PayloadAttributesV2 {
                timestamp: 12,
                prev_randao: root,
                suggested_fee_recipient: H160::zero(),
                withdrawals: ContiguousList::default(),
            }),
            "engine_forkchoiceUpdatedV2",
            "engine_getPayloadV2",
        ),
        (
            PayloadAttributes::Deneb(v3.clone()),
            "engine_forkchoiceUpdatedV3",
            "engine_getPayloadV3",
        ),
        (
            PayloadAttributes::Electra(v3.clone()),
            "engine_forkchoiceUpdatedV3",
            "engine_getPayloadV4",
        ),
        (
            PayloadAttributes::Fulu(v3),
            "engine_forkchoiceUpdatedV3",
            "engine_getPayloadV5",
        ),
        (
            PayloadAttributes::Gloas(PayloadAttributesV4 {
                timestamp: 12,
                prev_randao: root,
                suggested_fee_recipient: H160::zero(),
                withdrawals: ContiguousList::default(),
                parent_beacon_block_root: root,
                slot_number: 1,
                target_gas_limit: 30_000_000,
            }),
            "engine_forkchoiceUpdatedV4",
            "engine_getPayloadV6",
        ),
    ];
    for (attrs, fcu_method, get_method) in cases {
        calls.lock().expect("calls poisoned").clear();
        let phase = attrs.phase();
        let expected = serde_json::to_value(&attrs)?;
        let response = api
            .forkchoice_updated(root, root, root, Either::Right(attrs))
            .await?;
        let id = response.payload_id.expect("build ID");
        assert_eq!(id.endpoint, Some(0));
        wait_for_calls(&calls, 2).await?;
        assert!(api.get_payload::<Minimal>(id).await.is_err());
        {
            let calls = calls.lock().expect("calls poisoned");
            assert_eq!(calls.len(), 3);
            for (path, request) in &calls[..2] {
                assert_eq!(request["method"], fcu_method);
                assert_eq!(
                    request["params"][0],
                    json!({"headBlockHash":root,"safeBlockHash":root,"finalizedBlockHash":root})
                );
                assert_eq!(
                    request["params"][1],
                    if path == "/primary" {
                        expected.clone()
                    } else {
                        Value::Null
                    }
                );
            }
            assert_eq!(calls[2].0, "/primary");
            assert_eq!(calls[2].1["method"], get_method);
            assert_eq!(calls[2].1["params"], json!(["0x0000000000000001"]));
        }
        assert!(api.endpoints.get(0).expect("owner").is_online());
        // An attribute-free update for the same head is a new request, not a cached build response.
        let response = api
            .forkchoice_updated::<Minimal>(root, root, root, Either::Left(phase))
            .await?;
        assert!(response.payload_id.is_none());
        wait_for_calls(&calls, 5).await?;
        for (_, call) in &calls.lock().expect("calls poisoned")[3..] {
            assert_eq!(call["method"], fcu_method);
            assert!(call["params"][1].is_null());
        }
    }
    Ok(())
}

#[tokio::test]
async fn engine_statuses_are_results_but_malformed_responses_trigger_failover() -> Result<()> {
    for (status, fallback_status, expected) in [
        ("VALID", "INVALID", "VALID"),
        ("INVALID", "VALID", "INVALID"),
        ("INVALID_BLOCK_HASH", "VALID", "INVALID_BLOCK_HASH"),
        ("SYNCING", "VALID", "VALID"),
        ("ACCEPTED", "VALID", "VALID"),
        ("SYNCING", "INVALID", "INVALID"),
        ("ACCEPTED", "INVALID", "INVALID"),
        ("SYNCING", "INVALID_BLOCK_HASH", "INVALID_BLOCK_HASH"),
        ("SYNCING", "SYNCING", "SYNCING"),
        ("ACCEPTED", "ACCEPTED", "ACCEPTED"),
        ("SYNCING", "ACCEPTED", "SYNCING"),
        ("ACCEPTED", "SYNCING", "ACCEPTED"),
        ("SYNCING", "RPC_ERROR", "SYNCING"),
        ("ACCEPTED", "RPC_ERROR", "ACCEPTED"),
        ("MALFORMED", "VALID", "VALID"),
    ] {
        let server = MockServer::start_async().await;
        server.mock(|when, then| {
            when.method(POST).path("/primary");
            then.json_body(json!({"jsonrpc":"2.0","id":1,"result":{"status":status}}));
        });
        let mirror = server.mock(|when, then| {
            when.method(POST).path("/fallback");
            if fallback_status == "RPC_ERROR" {
                then.json_body(json!({"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"injected error"}}));
            } else {
                then.json_body(json!({"jsonrpc":"2.0","id":1,"result":{"status":fallback_status}}));
            }
        });
        let api = Eth1Api::new(
            Arc::new(Config::minimal()),
            Client::new(),
            Arc::default(),
            vec![
                server.url("/primary").parse()?,
                server.url("/fallback").parse()?,
            ],
            None,
            None,
        );
        let response = api
            .new_payload::<Minimal>(
                ExecutionPayload::Bellatrix(
                    types::bellatrix::containers::ExecutionPayload::default(),
                ),
                None,
            )
            .await?;
        assert_eq!(response.status, serde_json::from_value(json!(expected))?);
        tokio::time::timeout(Duration::from_secs(5), async {
            while mirror.calls_async().await == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        mirror.assert_calls_async(1).await;
        assert_eq!(
            api.endpoints.get(0).expect("primary").is_online(),
            status != "MALFORMED"
        );
    }
    Ok(())
}

#[tokio::test]
async fn engine_calls_report_missing_or_exhausted_endpoints() -> Result<()> {
    let server = MockServer::start_async().await;
    server.mock(|when, then| {
        when.method(POST);
        then.status(500);
    });
    for (urls, expected) in [
        (vec![], Error::NoEndpointsProvided),
        (vec![server.url("/").parse()?], Error::EndpointsExhausted),
    ] {
        let api = Eth1Api::new(
            Arc::new(Config::minimal()),
            Client::new(),
            Arc::default(),
            urls,
            None,
            None,
        );
        let error = api
            .new_payload::<Minimal>(
                ExecutionPayload::Bellatrix(
                    types::bellatrix::containers::ExecutionPayload::default(),
                ),
                None,
            )
            .await
            .expect_err("no available EL");
        assert_eq!(error.downcast::<Error>()?, expected);
        let error = api
            .forkchoice_updated::<Minimal>(
                H256::zero(),
                H256::zero(),
                H256::zero(),
                Either::Left(Phase::Bellatrix),
            )
            .await
            .expect_err("no available EL");
        assert_eq!(error.downcast::<Error>()?, expected);
    }
    Ok(())
}

#[tokio::test]
async fn recovered_but_syncing_primary_uses_the_ready_fallback_for_building() -> Result<()> {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let server = MockServer::start_async().await;
    let recovered = Arc::new(AtomicBool::new(false));
    let primary_recovered = Arc::clone(&recovered);
    server.mock(move |when, then| {
        when.method(POST).path("/primary");
        then.respond_with(move |request| {
            if !primary_recovered.load(Ordering::SeqCst) {
                return httpmock::HttpMockResponse::builder().status(500).build();
            }
            let request: Value =
                serde_json::from_slice(&request.body_bytes()).expect("request JSON");
            httpmock::HttpMockResponse::builder().status(200).body(json!({
                "jsonrpc":"2.0", "id":request["id"], "result":{
                    "payloadStatus":{"status":"SYNCING","latestValidHash":null}, "payloadId":null
                }
            }).to_string()).build()
        });
    });
    let builds = Arc::new(AtomicUsize::new(0));
    let observed_builds = Arc::clone(&builds);
    server.mock(move |when, then| {
        when.method(POST).path("/fallback");
        then.respond_with(move |request| {
            let request: Value = serde_json::from_slice(&request.body_bytes()).expect("request JSON");
            let id = if request["params"][1].is_null() {
                Value::Null
            } else {
                observed_builds.fetch_add(1, Ordering::SeqCst);
                json!("0x0000000000000001")
            };
            httpmock::HttpMockResponse::builder().status(200).body(json!({
                "jsonrpc":"2.0", "id":request["id"], "result":{
                    "payloadStatus":{"status":"VALID","latestValidHash":request["params"][0]["headBlockHash"]}, "payloadId":id
                }
            }).to_string()).build()
        });
    });
    let api = Eth1Api::new(
        Arc::new(Config::minimal()),
        Client::new(),
        Arc::default(),
        vec![
            server.url("/primary").parse()?,
            server.url("/fallback").parse()?,
        ],
        None,
        None,
    );
    let head = H256::repeat_byte(7);
    let attrs = PayloadAttributes::<Minimal>::Bellatrix(PayloadAttributesV1 {
        timestamp: 12,
        prev_randao: head,
        suggested_fee_recipient: H160::zero(),
    });
    let response = api
        .forkchoice_updated(head, head, head, Either::Right(attrs.clone()))
        .await?;
    assert_eq!(
        response.payload_id.expect("ready fallback build").endpoint,
        Some(1)
    );
    assert_eq!(builds.load(Ordering::SeqCst), 1);

    recovered.store(true, Ordering::SeqCst);
    api.forkchoice_updated::<Minimal>(head, head, head, Either::Left(Phase::Bellatrix))
        .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !api.endpoints.get(0).expect("primary").is_online() {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let response = api
        .forkchoice_updated(head, head, head, Either::Right(attrs))
        .await?;
    assert!(response.payload_status.status.is_valid());
    assert_eq!(
        response.payload_id.expect("fallback build").endpoint,
        Some(1)
    );
    assert!(api.endpoints.get(0).expect("primary").is_online());
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn syncing_fcu_tries_another_el_with_or_without_build_attributes() -> Result<()> {
    for (first, second, build, expected, owner) in [
        ("SYNCING", "VALID", true, "VALID", Some(1)),
        ("INVALID", "VALID", true, "INVALID", None),
        ("VALID_NO_ID", "VALID", true, "VALID", None),
        ("SYNCING", "INVALID", true, "INVALID", None),
        ("SYNCING", "SYNCING", true, "SYNCING", None),
        ("SYNCING", "RPC_ERROR", true, "SYNCING", None),
        ("SYNCING", "VALID", false, "VALID", None),
        ("SYNCING", "INVALID", false, "INVALID", None),
        ("SYNCING", "SYNCING", false, "SYNCING", None),
        ("SYNCING", "RPC_ERROR", false, "SYNCING", None),
        ("INVALID", "VALID", false, "INVALID", None),
    ] {
        let server = MockServer::start_async().await;
        let builds = Arc::new(Mutex::new(Vec::new()));
        for (path, status) in [("/primary", first), ("/fallback", second)] {
            let builds = Arc::clone(&builds);
            server.mock(move |when, then| {
                when.method(POST).path(path);
                then.respond_with(move |request| {
                    let request: Value = serde_json::from_slice(&request.body_bytes()).expect("request JSON");
                    let build = !request["params"][1].is_null();
                    if build { builds.lock().expect("builds poisoned").push(path); }
                    let body = if status == "RPC_ERROR" {
                        json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32603,"message":"injected error"}})
                    } else {
                        let valid = status.starts_with("VALID");
                        json!({"jsonrpc":"2.0","id":request["id"],"result":{
                            "payloadStatus":{"status":if valid { "VALID" } else { status },
                                "latestValidHash":if valid { request["params"][0]["headBlockHash"].clone() } else { Value::Null }},
                            "payloadId":if status == "VALID" && build { json!("0x0000000000000001") } else { Value::Null }
                        }})
                    };
                    httpmock::HttpMockResponse::builder().status(200).body(body.to_string()).build()
                });
            });
        }
        let api = Eth1Api::new(
            Arc::new(Config::minimal()),
            Client::new(),
            Arc::default(),
            vec![
                server.url("/primary").parse()?,
                server.url("/fallback").parse()?,
            ],
            None,
            None,
        );
        let head = H256::repeat_byte(7);
        let attrs = if build {
            Either::Right(PayloadAttributes::<Minimal>::Bellatrix(
                PayloadAttributesV1 {
                    timestamp: 12,
                    prev_randao: head,
                    suggested_fee_recipient: H160::zero(),
                },
            ))
        } else {
            Either::Left(Phase::Bellatrix)
        };
        let response = api.forkchoice_updated(head, head, head, attrs).await?;
        assert_eq!(
            response.payload_status.status,
            serde_json::from_value(json!(expected))?
        );
        assert_eq!(response.payload_id.and_then(|id| id.endpoint), owner);
        let expected_builds = if !build {
            vec![]
        } else if first == "SYNCING" {
            vec!["/primary", "/fallback"]
        } else {
            vec!["/primary"]
        };
        assert_eq!(*builds.lock().expect("builds poisoned"), expected_builds);
        assert!(api.endpoints.get(0).expect("primary").is_online());
    }
    Ok(())
}
