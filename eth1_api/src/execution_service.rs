use std::sync::Arc;

use anyhow::Result;
use dedicated_executor::DedicatedExecutor;
use derive_more::Constructor;
use either::Either;
use execution_engine::{
    ExecutionServiceMessage, ForkChoiceUpdatedResponse, PayloadAttributes, PayloadStatusV1,
};
use fork_choice_control::Wait;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    StreamExt as _,
};
use log::warn;
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

#[derive(Constructor)]
pub struct ExecutionService<P: Preset, W: Wait> {
    api: Arc<Eth1Api>,
    controller: ApiController<P, W>,
    dedicated_executor: Arc<DedicatedExecutor>,
    rx: UnboundedReceiver<ExecutionServiceMessage<P>>,
    blob_fetcher_tx: UnboundedSender<Eth1ApiToBlobFetcher<P>>,
}

impl<P: Preset, W: Wait> ExecutionService<P, W> {
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
                ExecutionServiceMessage::NotifyForkchoiceUpdated {
                    head_eth1_block_hash,
                    safe_eth1_block_hash,
                    finalized_eth1_block_hash,
                    payload_attributes,
                    sender,
                } => {
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

                    self.controller
                        .on_notified_fork_choice_update(payload_status);

                    if let Some(sender) = sender {
                        if let Err(message) = sender.send(payload_id) {
                            warn!(
                                "sending engine_forkchoiceUpdated result \
                                 failed because the receiver was dropped: {message:?}"
                            );
                        }
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
                            self.controller.on_notified_new_payload(
                                beacon_block_root,
                                payload.block_hash(),
                                payload_status.clone(),
                            );
                        }
                        Err(error) => {
                            warn!("engine_newPayload call failed: {error}");

                            features::log!(
                                DebugEth1,
                                "engine_newPayload call failed \
                                 (beacon block root: {beacon_block_root:?}, \
                                  payload: {payload:?}, error: {error})",
                            );
                        }
                    }

                    if let Some(sender) = sender {
                        if let Err(message) = sender.send(response) {
                            warn!(
                                "sending engine_newPayload result \
                                failed because the receiver was dropped: {message:?}"
                            );
                        }
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
                    warn!("payload_id expected but was none: {response:?}");
                }

                if response.payload_status.status.is_invalid() {
                    warn!(
                        "engine_forkchoiceUpdated returned INVALID status \
                         (head_eth1_block_hash: {head_eth1_block_hash:?}, \
                          safe_eth1_block_hash: {safe_eth1_block_hash:?}, \
                          finalized_eth1_block_hash: {finalized_eth1_block_hash:?}, \
                          response: {response:?})",
                    );
                }

                if response.payload_status.status.is_syncing() {
                    warn!(
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
                warn!("engine_forkchoiceUpdated call failed: {error}");
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
            warn!(
                "engine_newPayload returned INVALID status \
                 (beacon_block_root: {beacon_block_root:?}, \
                  block_number: {block_number}, \
                  block_hash: {block_hash:?}, \
                  response: {response:?})",
            );
        }

        if response.status.is_syncing() {
            warn!(
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
