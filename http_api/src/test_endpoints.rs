// This makes `http_api::routing` less messy at the cost of coupling to `axum` even more.
#![allow(clippy::unused_async)]

use axum::{extract::State, Json};
use clock::Tick;
use execution_engine::PayloadStatusWithBlockHash;
use fork_choice_control::{P2pMessage, SyncMessage};
use operation_pools::PoolToP2pMessage;
use p2p::{ApiToP2p, ValidatorToP2p};
use serde::Serialize;
use types::preset::Preset;

use crate::{
    misc::{SpyReceiver, TestApiController},
    routing::TestState,
};

#[derive(Serialize)]
#[serde(bound = "")]
pub struct TakeMessagesResponse<P: Preset> {
    api_to_p2p: Vec<ApiToP2p<P>>,
    fc_to_p2p: Vec<P2pMessage<P>>,
    fc_to_sync: Vec<SyncMessage<P>>,
    pool_to_p2p: Vec<PoolToP2pMessage>,
    validator_to_p2p: Vec<ValidatorToP2p<P>>,
}

/// `POST /test/tick`
pub async fn post_tick<P: Preset>(
    State(controller): State<TestApiController<P>>,
    Json(tick): Json<Tick>,
) {
    controller.on_tick(tick);
}

/// `POST /test/payload_status`
pub async fn post_payload_status<P: Preset>(
    State(controller): State<TestApiController<P>>,
    Json(payload_status_with_block_hash): Json<PayloadStatusWithBlockHash>,
) {
    let PayloadStatusWithBlockHash {
        block_hash,
        payload_status,
    } = payload_status_with_block_hash;

    controller.on_notified_new_payload(block_hash, payload_status.into());
}

/// `POST /test/take_messages`
pub async fn post_take_messages<P: Preset>(
    State(test_state): State<TestState<P>>,
) -> Json<TakeMessagesResponse<P>> {
    async fn take<T: Send>(rx: SpyReceiver<T>) -> Vec<T> {
        let mut rx = rx.lock().await;

        core::iter::from_fn(|| {
            // Sending to a closed channel returns `Err(_)`.
            // Receiving from a closed channel with `try_next` returns `Ok(None)`.
            rx.try_next()
                .transpose()
                .expect("UnboundedReceiver::try_next failed because the sender was dropped")
                .ok()
        })
        .collect()
    }

    let TestState {
        api_to_p2p_rx,
        fc_to_p2p_rx,
        fc_to_sync_rx,
        pool_to_p2p_rx,
        validator_to_p2p_rx,
    } = test_state;

    Json(TakeMessagesResponse {
        api_to_p2p: take(api_to_p2p_rx).await,
        fc_to_p2p: take(fc_to_p2p_rx).await,
        fc_to_sync: take(fc_to_sync_rx).await,
        pool_to_p2p: take(pool_to_p2p_rx).await,
        validator_to_p2p: take(validator_to_p2p_rx).await,
    })
}
